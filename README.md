# analytics

[![ci](https://github.com/cloudsforge-online/micro-analytics/actions/workflows/ci.yml/badge.svg)](https://github.com/cloudsforge-online/micro-analytics/actions/workflows/ci.yml) [![TypeScript](https://img.shields.io/badge/TypeScript-strict%20ESM-3178C6?logo=typescript&logoColor=white)](./tsconfig.base.json) [![node](https://img.shields.io/badge/node-%3E%3D22-5FA04E?logo=nodedotjs&logoColor=white)](./package.json) [![tests](https://img.shields.io/badge/tests-real%20Postgres-4169E1?logo=postgresql&logoColor=white)](./.github/workflows/ci.yml) [![licence](https://img.shields.io/badge/licence-MIT-blue)](./LICENSE)

<!-- absorbed-banner -->
> ## ⚠️ This code no longer deploys as a service. It runs inside `micro-agora`.
>
> Absorbed in wave **M1** (2026-08-28) of the estate's service-merge sequence.
>
> **The canonical source is [`micro-agora`](https://github.com/cloudsforge-online/micro-agora)
> at [`src/lantern/analytics/`](https://github.com/cloudsforge-online/micro-agora/tree/main/src/lantern/analytics).
> Edit there.** What is in this repository is the copy the merge was made from: it is frozen, no
> image is published from it, `cfctl bump` skips it, and nothing in the estate runs it.
> It arrived there in two steps: M1 merged it into `lantern`, and `lantern` itself became a module of `agora` later in the sequence. The nesting is preserved — the source sits at `src/lantern/analytics`, one level deeper than the modules that moved directly.
>
>
> **Why the repository still exists.** Its registry row survives as `absorbed(…)`, which is what
> keeps the Kubernetes `Service` of this name resolving — an `ExternalName` alias to `agora`, so
> every caller that addresses it by service name still reaches the code. `deployableRepos()` keeps
> the row and `releasableRepos()` drops it. The history here is also the history of the module.
>
> **What did not change**, and this is the point of the merge rather than an aside: the database is
> still its own, the routes are unchanged except where a collision forced a remount, the migrations
> still run under this module's name, and the trust boundary is unchanged. A merge moved a process
> boundary, not a responsibility.
>
> Everything below describes the domain, and remains accurate. Read the reasoning — including what
> was refused and why — in
> [`micro-deploy/docs/service-merge-plan.md`](https://github.com/cloudsforge-online/micro-deploy/blob/main/docs/service-merge-plan.md).

The estate's **product analytics plane**: a pseudonymised, append-only product event store fed by
the event bus, never by a third-party page tag.

Design authority: [`ecosystem/03-repository-responsibilities.md`](https://github.com/cloudsforge-online/micro-docs/blob/main/ecosystem/03-repository-responsibilities.md)

It is a **leaf**. Nothing in the estate calls it and it calls nothing at boot. Its only inputs are
signed deliveries from other services' outbox relays; its only outputs are aggregates.

It is also the **most dangerous service in the estate**, and everything below follows from that.
Every other service holds data about a person because it must. This one holds data about
*behaviour, at volume, for analysis* — the exact shape that becomes a re-identification incident.
So its privacy properties are written as **database constraints**, not as code: an attacker holding
a connection, and a code path nobody has written yet, are stopped by the same line.

**AD-21 is why it exists.** `org/.github/workflows/web-ci.yml` fails any frontend that ships a
Google, Segment, Hotjar or Mixpanel tag. That rule is only defensible because this service replaces
them.

---

## Pseudonymisation, and where the key lives

### The estate's specified construction has a defect, and it is fatal to the only promise made here

Four documents specify `subject_key = HMAC(user_id, analytics_pepper)`
(`02-target-architecture.md`, `11-data-and-contract-strategy.md`,
`13-operational-model.md`, `10-migration-strategy.md`). Taken literally that is a **pure
function of two things that both survive**, so it cannot be erased. Delete every row you like:
anyone holding the pepper and a candidate user id recomputes the key and finds that person's entire
four-hundred-day behavioural history. That is not a pseudonym, it is an index into a person — and
`10-migration-strategy.md` ("Pseudonymised events — `analytics` — Deleted by `subject_key`")
assumes an erasure it cannot deliver.

### What is here instead: a per-subject salt, which is the only thing that can be destroyed

```
lookup_key  = HMAC(pepper, "cf.analytics.lookup.v1|"  || subject)
subject_key = HMAC(pepper, "cf.analytics.subject.v1|" || subject || "|" || salt)
salt        = 32 bytes from the CSPRNG, minted once per subject
```

`lookup_key` is deterministic, so the same person's second event finds their first pseudonym —
which is what funnels and cohorts rest on. `subject_key` is not derivable from the subject alone,
because the salt is random and stored beside the lookup key. The two domain strings are versioned
so a future construction change is a *different* pseudonym rather than a silent reinterpretation of
the old one.

The raw subject exists inside exactly one function (`ingest.ts`'s `record` path), leaves it as a
64-character digest, and is **never stored**. `deriveSubject` is the only function in the repository
that takes one, and its return type contains no path back.

### Where the pepper lives

`ANALYTICS_PSEUDONYM_KEY`, read from the environment by `src/env.ts` at import, held in process
memory, and in **the deploy's secret store**. Nowhere else:

- **never written to this service's database.** There is no pepper column and there will not be
  one. `13-operational-model.md` requires it to be absent from any backup that also contains
  the identity database; keeping it out of this database is the strongest form of that available to
  a service that owns exactly one database.
- **never logged.** The logger declares `redactKeys: ['pseudonymKey', 'pepper', 'deliverySecrets']`,
  which closes the accident where somebody logs the whole config object while debugging.
- **never returned by a route**, and **never baked into an image layer** — there is no `ENV` line in
  the Dockerfile, and `.dockerignore` excludes `.env`, `.env.*` and `.git`.

It is required, has no default and no development fallback, and its SHAPE is asserted at boot by
`@cloudsforge/secrets`: the base64 or hex alphabet, at least 32 decoded **bytes**, a measured
Shannon entropy floor, and no placeholder marker anywhere in the normalised value. It is emphatically
**not** a character-count check any more — the floor that used to stand here asked for 32 characters
and the pepper this estate has been running is 40 characters of hyphenated `estate-only-...`
(micro-org #142/#189). A service that started with a weak or absent pepper would produce a store
that *looks* pseudonymised and is not, which is worse than one that refuses to start.

An attacker with a connection to this database therefore has, per subject: one HMAC under an
unknown key, one unrelated HMAC under the same unknown key, and thirty-two random bytes. There is
nothing there to test a guess against.

### Rotating the pepper is not a deploy, it is an amnesia

Every existing lookup key becomes unreachable, so every returning person is minted a **new**
pseudonym and their history splits in two. There is no re-keying path and there cannot be one:
re-keying needs the raw subjects, which this service does not have, by design. Rotate only in
response to disclosure, and expect every longitudinal metric to restart from that day.

### The database refuses a raw subject, whoever is asking

```sql
constraint events_subject_shape check (subject_key is null or subject_key ~ '^[0-9a-f]{64}$')
```

`INSERT INTO events` with `user:550e8400-…`, a bare UUID, an email, a handle, a wallet address or a
display name **fails** — with the service bypassed entirely, through a psql session, on any code
path anyone finds. `migrations.test.ts` proves it by inserting each of those directly. The same file
proves the other three:

| Constraint | What it makes impossible |
|---|---|
| `events_subject_shape` | a raw identifier in the event store |
| `events_person_has_pseudonym` | a person's event without a pseudonym, **and** a machine's event with one — both directions, so "distinct users" cannot quietly include a reconciliation job |
| `events_props_allowed` | a property key outside the catalogue, a nested value, or any string that is not a lowercase slug |
| `subject_keys_erased` | an "erasure" that kept the salt |

There is no `user_id`, `email`, `handle`, `address`, `amount`, `balance`, `ip` or `display_name`
column in any table. `11-data-and-contract-strategy.md` asks for that as a CI check; it is
`migrations.test.ts` reading `information_schema.columns` on the real migrated schema, which fails
the build in the same place and can see a column a grep over source would miss.

---

## No user free-text, ever

**This service never reads a producer's domain payload.** That is the second most important
sentence here after the one about the pepper.

`wallet.deposit.confirmed` carries an address and an exact amount. `market.listing.sold` carries a
listing title a seller typed. `identity.user.registered` carries a handle. All of them are in the
envelope this service receives and **not one is ever looked at**: `sanitise()` reads
`payload.analytics` — a separate, opt-in **analytics envelope** — and nothing else in the payload
exists as far as this service is concerned. The alternative (mapping each topic's domain payload
onto properties) puts a per-topic function in front of a listing title and trusts it to be careful;
twenty producers and a changelog later, one of them passes a name through.

Within that envelope, **every property name is allowlisted and every type is closed**. There is no
`string` type: a property is an enum member, a bounded `code` (≤12 lowercase characters — too short
for a name, far too short for an email or any chain address), a bounded integer, or a boolean. A
length-capped free-text type would still accept `"Spiros Savvanis"`; an enum cannot.

A refused property is **dropped and counted**, and the event is still stored. Refusing the whole
event would mean a producer that added one field lost every funnel it feeds — which is the pressure
that gets a privacy guard turned off. The producer is told exactly which keys were refused **in the
synchronous response to its own signed delivery**, where it already knew them. The database records
a count by day, reason and topic and **never the key itself**, because a key can be the personal
data (`{"spiros_lives_at": 1}`) just as easily as a value can.

Money arrives **bucketed** (`lt10`, `10_100`, `100_1k`, `1k_10k`, `gt10k`), never exact —
`13-operational-model.md`. Actual revenue comes from the ledger (`13:630`), never from here.
There is no amount column and no balance column.

---

## What erasure actually does

`identity.user.deleted` arrives on the bus like any other event. It does **not** become a row — a
row saying "this pseudonym was erased" is a record about the person who asked to be forgotten.
Instead:

```sql
update subject_keys set subject_key = null, salt = null, erased_at = now() where lookup_key = …
```

**The salt is destroyed.** After that, `subject_key` is unreachable from `subject` — not "hard",
unreachable: recomputing it would require guessing 32 bytes that no longer exist anywhere, under a
pepper that is not in this database. The events keep their now-orphaned pseudonym and become
anonymous data about nobody, which is exactly what `11-data-and-contract-strategy.md` already
claims of this service ("Nothing to do — it never held a `user_id`") and what the specified
construction could not have made true.

`subject_keys_erased` refuses a row that claims `erased_at` while still holding either half, so
"mark it deleted but keep the key" is not a bug anyone can introduce here. It is written as the two
legal states rather than as an equivalence, and that is not stylistic: the obvious equivalence is
satisfied by a row that nulled the *pseudonym* and kept the *salt*, which is erasure that erases
nothing. `migrations.test.ts` caught that before it shipped.

`pseudonym.test.ts` proves the whole of it, including the negative control — the same proof is run
against a mapping whose salt was retained, and it **fails**, so the assertion is not vacuous.

Two consequences, stated rather than implied:

- **The events are not deleted.** After the salt is gone they identify nobody, and deleting them
  would retroactively rewrite every historical funnel and cohort — which `13-operational-model.md`
  forbids in the strongest terms it uses anywhere ("a retention number that changed definition in
  March is a chart that lies about February").
- **The tombstone is a one-bit oracle.** The row survives holding only `lookup_key` and a timestamp,
  so somebody holding the pepper *and* a candidate user id can learn whether that person was erased.
  It is kept because it is what stops a late-arriving event minting a fresh pseudonym and starting a
  second behavioural profile for a forgotten user. One bit, to an attacker who already holds the
  pepper, versus a new history for someone who asked to be forgotten.

A late event for an erased subject is refused and counted as `erased_subject`, never stored.

---

## Retention is a job that runs

`11-data-and-contract-strategy.md` gives analytics events four hundred days. A retention policy
that lives only in a table in a document is a policy that has never deleted a row, so:

| Data | Horizon | Why |
|---|---|---|
| `events` | 400 days | `ANALYTICS_EVENT_RETENTION_DAYS` |
| `event_rollups`, `cohort_retention` | 1200 days | they outlive the events they were computed from; boot **refuses** the inversion, because a rollup that expired first would throw away the cheap summary and keep the expensive raw rows |
| `subject_keys` | pruned once every event it names has expired | a mapping that outlives its events is a pseudonym kept for no purpose |
| `inbox` | 30 days | a redelivery horizon, not an archive — `events_source_uniq` is still behind it |
| `idempotency_keys` | 30 days, unless the claim produced an artefact | the only link between a caller's key and what it made |

The sweep runs **hourly, as a leased job**, and `jobs.test.ts` plants a row past the horizon, runs
it, and asserts the row is gone — *and* asserts a row inside the horizon is still there, because a
sweep that deletes everything also passes a test that only checks the first half.

Order matters: events go first, so the subject prune sees the store as it will be and can drop a
mapping whose last event has just expired. The other way round keeps every mapping one sweep longer
than it needs to exist.

**Not partitioned yet.** `13-operational-model.md` says "append-only, partitioned monthly", and
that is the right answer at volume. It is deliberately deferred: declarative partitioning forces the
partition key into every unique constraint, so `source_event_id` becomes `(occurred_at,
source_event_id)` — which no longer refuses a redelivery whose producer restamped the time. The day
the DELETE is too slow is the day this becomes a migration, not before.

---

## The minimum cohort: **five**

Everything above protects the **store**. None of it protects the **answers**. "Seven users in the
1k–10k bucket deposited on Tuesday" is a statement about seven people, and "one user did" is a
statement about one, whatever the subject column holds. Anyone who knows one person registered on
Tuesday reads that row and learns what they did.

So **every count that leaves this service passes `suppress()`**, and any count derived from fewer
than five distinct subjects comes back as `{ suppressed: true }` carrying **no number at all** — not
a rounded one, not a range, not "fewer than five". A rounded small count is still a small count, and
"1–4" combined with a second query is arithmetic.

**Why five.** It is the smallest number that is a *threshold* rather than a gesture. Two and three
suppress only the cases that are obviously one person, which is the wrong question: a cell of four
out of a known population of six tells you about a specific four of them. Five is also the
conventional small-cell floor in disclosure control for published statistics, so it is the number an
auditor will already recognise rather than one this repository invented. It is deliberately *not*
higher, because a threshold set where ordinary product questions cannot be answered is a threshold
that gets lowered in an incident and never raised back.

It is applied to **distinct subjects**, never to events: ten events from one person and ten from ten
people are the same number of events and very different disclosures.

**Zero is deliberately not suppressed.** "Nobody did this" discloses nobody, and suppressing it
would make an empty funnel indistinguishable from a busy one — which is exactly how an operator ends
up lowering the threshold to find out which it was.

**It is a floor, not a default.** `ANALYTICS_MIN_COHORT` may be raised. `env.ts` **refuses to start**
on a value below five rather than clamping it, because clamping would let a deploy believe it had
set 1 and get 5 — and the difference between those two numbers is whether a funnel of one person is
published. A suppression threshold that can be set to 1 is not a suppression threshold.

Both halves of a retention cell are suppressed, and the cohort **size** is the one people forget: a
cell showing "3 of 40 active" discloses three people, and a cell showing "8 of 3" discloses the whole
cohort. Every funnel step is suppressed independently, so a funnel whose fourth step has three people
publishes its first three and withholds the fourth — the shape of the drop-off is the product
question, and the identity of the three is not available at any price.

### What this does not defend against, stated plainly

**Differencing.** An analyst who can run two overlapping queries whose subject sets differ by one
person can compute a suppressed cell from two unsuppressed ones. Closing that needs a per-principal
query budget, which is a larger piece of machinery than this service has. What *is* closed is the
direct read — the one an operator reaches for by accident. This is recorded here rather than implied
away.

---

## Scope matching: **exact**

`18-build-status.md §3.3h` records that the estate ships two scope matchers that disagree:

- `contracts/packages/auth/src/index.ts` — `granted.includes(required)`, **exact only**
- `runtime/packages/auth/src/index.ts` — honours one wildcard level, so `analytics:*` grants
  `analytics:read`

Both are shipped, both are CI-green, and §3.3h leaves it open on purpose because changing an
authorisation matcher is the highest-blast-radius edit in this estate.

**This service changes neither package and matches exactly**, in `hasExactScope` (`src/server.ts`) —
the same choice `micro-devplatform`, `micro-admin-api` and `micro-community` made, and made here for
a reason that applies with more force. A wildcard grants scopes that did not exist when the
credential was issued. In a service holding four hundred days of behaviour, that means a token minted
to read one funnel silently acquires whatever read is added next — and the next one might be the
cohort export. `hasScope` from `@cloudsforge/auth` is deliberately **not imported**, and
`server.test.ts` asserts both that `analytics:*` grants nothing and that the import is absent, so the
choice cannot drift back.

The scopes are `analytics:read` and `analytics:admin`. An operator (an admin user) may read. **An
ordinary user token may not, whatever it carries** — there is no per-user view of this data and there
is not going to be one, because a per-user view is the support question AD-21 exists to make
unanswerable (`13-operational-model.md`).

**There is no `analytics:ingest`, and that is the repair rather than an omission.** `POST /ingest`
demanded that scope and no producer in this estate could present it: an outbox relay sends the
delivery signature and the event id and nothing else — all twenty-one relays were read, not assumed,
`identity/src/outbox.ts` being the canonical one — so every event this service exists to consume
died `401` at the first line of the handler, and every funnel metric was computed against an empty
denominator behind a service reporting itself healthy. The route is now **MAC-only**, the same
repair `micro-notify` (`server.ts`) and `micro-activity` made, and the constant was deleted
rather than left unreferenced. `contracts/packages/auth` and `deploy/compose` still carry the now
unused scope; both are reported to their owners rather than edited from here.

---

## The rest of the shape

- **Consumer only, no broker.** `POST /ingest` takes a signed `EventEnvelope` from a producer's
  outbox relay, and the **delivery signature is the whole of the authentication** — no bearer token
  is read. A MAC over the exact bytes is a shared-secret proof about the thing that actually matters
  here, the content of the row; a bearer would have proved only who opened the socket, and no relay
  can present one. A signed-in person still cannot reach this route, because a person does not hold
  the outbox signing secret. The signature is verified over the **raw request bytes** before anything
  parses them — which matters more now that it is the only thing in front of the parser, and a parser
  is an attack surface reachable by anyone who can open a socket. `contracts-events` registers no
  `analytics.*` topic and names this service as one that "is only ever a consumer"
  (`contracts/packages/events/src/index.ts`), so there is no outbox here — an outbox would come
  with a relay job, a signing secret in the deploy, and a permanently empty dashboard panel.
- **Deduped on the inbox**, primary key `(topic, event_id)`, claimed in the same transaction as the
  work — so a handler that throws leaves no inbox row and the redelivery is processed rather than
  swallowed. `events_source_uniq` is the second line behind it. `POST /ingest` is therefore the one
  mutating route **not** wrapped in `withIdempotency`; `routeidempotency.test.ts` records that
  exemption with its reason and fails the build on any other unwrapped mutating route.
- **No `setInterval`.** Rollups (5 min), retention (hourly) and the cohort recompute (hourly) are
  leased jobs claimed `FOR UPDATE SKIP LOCKED`, all keyed `global` because each contends on the same
  thing. `jobs.test.ts` runs two runners against one enqueued job and asserts it runs **once**.
  Gauges are sampled at scrape time, never on a timer.
- **`/livez` static, `/readyz` real.** Liveness answers "should this process be restarted", and a
  liveness probe that consults a dependency restarts a healthy process every time the database
  blinks. Postgres is the only **hard** probe; identity is soft, because a funnel that cannot be read
  for ten minutes is not a reason to take a replica out of the balancer, and `/metrics` falls back to
  its static token.
- **Versioned metric definitions.** Every metric states numerator, denominator and window
  (`13:608`), and the database holds a checksum over those three. Republishing `(id, version)` with
  different arithmetic **throws**, and a trigger refuses the UPDATE that would paper over it. A
  redefinition is a new version, never an edit.
- **Append-only.** A trigger refuses `UPDATE` on `events`. DELETE stays allowed, because retention
  removing a row is a different claim from rewriting one to say something else.
- **Strict TypeScript**, ESM, Node ≥22, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`.

---

## Reported, not fixed

This repository does not edit a sibling. Three things were found while building it:

1. **`contracts-events` registers no frontend topic.** AD-21 requires `page_viewed`, `cta_clicked`
   and `form_abandoned` (plus the `form_started` that metric 19's denominator needs) to arrive
   "through the same envelope" (`13-operational-model.md`), and `TOPICS` holds eighteen
   server-side topics and none of those four. They are **forward-declared** in `src/catalogue.ts` and
   accepted through a narrower validation path; they will be deleted from there the day `contracts`
   registers them. Until a producer emits them, metrics 1, 2, 19 and 20 report on the server-side
   half only.
2. **`03-repository-responsibilities.md` is not implementable as written.** It says analytics
   "must never RECEIVE a `user_id`", but `EventEnvelope.actor` is `user:<user_id>` and `key` is
   `user_id` on eleven of the eighteen topics, so every delivery this service is entitled to read
   carries one. `10-migration-strategy.md` says the opposite — that analytics must be *sent* a
   precomputed key — which would put the pepper in identity and in every other producer, contradicting
   the three documents that say it "lives only in the analytics service". Resolved the only way that
   is both implementable and stronger: receive it, convert it at the boundary, never store it, and
   have the database refuse a row that holds one.
3. **Seven metrics in `13 §12` name events that cannot be emitted.** Metrics 3, 4, 9, 11, 12, 13 and
   14 need `identity.email.verified`, `wallet.address.assigned`, `mint.order.created`,
   `trade.bot.started`, `worlds.session.started`, `membership.joined` and `proposal.voted`, none of
   which `contracts-events` registers. Definitions for them are deliberately **absent** rather than
   published: a definition whose input event cannot be emitted reports zero for ever, which is worse
   than its absence.

## One thing a product manager should read

**A subscription that does not exist misses the events it was not there for.** The estate's outbox
relay does not redeliver an event published while nothing was subscribed. This service's history
therefore begins the day its subscription does, and there is no backfill and cannot be one — the
producers' outboxes are pruned.

---

## Running it

```bash
pnpm install
cp .env.example .env          # then generate real values; boot refuses a placeholder

# migrations are a SEPARATE one-shot process, never run by the service
pnpm migrate
pnpm start

# tests — the database-backed suite runs only against a *_test database
ANALYTICS_TEST_DATABASE_URL=postgres://ci:ci@127.0.0.1:5432/analytics_test pnpm test
pnpm check                    # typecheck + test
```

The image needs two named build contexts until `@cloudsforge/*` is published (AD-02):

```bash
docker build -t analytics \
  --build-context runtimepkgs=../runtime \
  --build-context contractspkgs=../contracts .
```

---

## Provenance

The code in this repository was written by **Claude Opus 5** and **Claude Fable 5**, assets
generated with **FLUX 2 Pro**, under human direction and review.
