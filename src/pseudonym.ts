/**
 * Pseudonymisation. The reason this service is allowed to exist.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY A PLAIN HMAC(user_id, pepper) IS NOT PSEUDONYMISATION, AND WHAT IS HERE INSTEAD.**
 *
 * The estate specifies `subject_key = HMAC(user_id, analytics_pepper)` in four places
 * (02-target-architecture.md, 11-data-and-contract-strategy.md,
 * 13-operational-model.md, 10-migration-strategy.md). Taken literally it has a defect
 * that is fatal to the only privacy promise this service makes, and the defect is *erasure*:
 *
 *     subject_key = HMAC(pepper, user_id)   is a PURE FUNCTION of two things that both survive.
 *
 * Erasure of such a key is impossible by construction. Delete every row you like — anyone holding
 * the pepper and a candidate user id recomputes the key and finds that person's entire behavioural
 * history, for the four hundred days it is retained. That is not a pseudonym that can be erased,
 * it is an index into a person, and 10-migration-strategy.md ("Pseudonymised events —
 * `analytics` — Deleted by `subject_key`") assumes an erasure this construction cannot deliver.
 *
 * So the pseudonym here is salted per subject, and the salt is the only thing that can be
 * destroyed:
 *
 *     lookup_key  = HMAC(pepper, "cf.analytics.lookup.v1|"  || subject)
 *     subject_key = HMAC(pepper, "cf.analytics.subject.v1|" || subject || "|" || salt)
 *
 * `lookup_key` is deterministic, so the *same* person's second event finds their first pseudonym.
 * `subject_key` is not, because the salt is thirty-two random bytes minted once per subject and
 * stored beside the lookup key.
 *
 * **Erasure destroys the salt.** After it, `subject_key` is unreachable from `subject` — not
 * "hard", unreachable: recomputing it requires 2^256 guesses at a value that no longer exists
 * anywhere. The rows keep their pseudonym and become anonymous data about nobody, which is exactly
 * what 11-data-and-contract-strategy.md already claims of this service ("Nothing to do — it
 * never held a `user_id`") and what the plain construction could not have made true.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * ## Where the key lives, and where it does not
 *
 * The pepper is `ANALYTICS_PSEUDONYM_KEY`. It is read from the environment by `env.ts`, held in
 * process memory, and **never written to this service's database**. That separation is the second
 * half of the design: an attacker holding a database connection has, for every subject, two
 * unrelated 256-bit values and a random salt, and no way to test a guess at who any of them is.
 * 13-operational-model.md requires it to be absent from any backup that also contains the
 * identity database; keeping it out of this database is the strongest form of that available to
 * a service that owns exactly one database.
 *
 * ## An inherited claim that does not survive contact with the shipped contract
 *
 * 03-repository-responsibilities.md says `analytics` "must never RECEIVE a `user_id`". Against
 * the envelope that actually ships it is not implementable: `EventEnvelope.actor` is
 * `user:<user_id>` (`contracts/packages/events/src/index.ts,418`) and `key` is `user_id` on
 * eleven of the eighteen registered topics (`:234,242,249,256,318,325` and others), so every
 * delivery this service is entitled to read carries one. 10-migration-strategy.md says the
 * opposite of :204 outright — that analytics "cannot compute the key itself" and must be *sent*
 * one — which would put the pepper in identity, and in every other producer, contradicting the
 * three documents that say it "lives only in the analytics service".
 *
 * This service resolves it the only way that is both implementable and stronger: it receives a raw
 * subject at the ingest boundary, converts it here, and **never stores it**. `deriveSubject` is the
 * only function in the repository that takes a raw subject, its return type contains no path back
 * to one, and the database refuses a row that holds one (`migrations.ts`, `events_subject_shape`).
 * Pseudonymisation by construction rather than by the good behaviour of twenty producers.
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto'
import type { Db, Tx } from './store.ts'

/**
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **ROTATING THE PEPPER (#189), AND WHY THERE IS NO DRAIN.**
 *
 * `ANALYTICS_PSEUDONYM_KEY` was published in a public repository, so it has to be replaceable. It
 * is the hardest secret in the estate to replace, and it is worth being exact about why, because
 * the obvious fix and the estate's own proven fix are both wrong here.
 *
 * The estate's proven pattern is custody's: stamp each blob with the version that wrote it, hold
 * several secrets at once, then DRAIN — re-encrypt every stored blob under the new key, verify, and
 * only then drop the old one. `identity/src/rewrap.ts` does exactly this for the key-encryption key
 * and it is the right answer there.
 *
 * **IT CANNOT BE DONE HERE, AND THAT IS NOT AN OVERSIGHT — IT IS THE PRIVACY PROPERTY WORKING.**
 * A blob is ENCRYPTED, so anyone holding the old key can recover the plaintext and re-encrypt it. A
 * pseudonym is DERIVED:
 *
 *     lookup_key = HMAC(pepper, "cf.analytics.lookup.v1|" || subject)
 *
 * To write the v2 lookup key for an existing row you need `subject`. It is not in this database and
 * never has been: there is no `user_id` column (`migrations.ts`), `events_subject_shape` refuses a
 * row that holds one, `FORBIDDEN_COLUMNS` is asserted against the real migrated schema, and
 * `deriveSubject` is the only function in the repository that accepts a raw subject. HMAC is
 * one-way, so the stored value cannot be turned back into the input that produced it. A drain would
 * require re-introducing the raw identifiers this service exists not to hold — which is the same
 * property that makes erasure real, so it is not a trade worth making even if it were easy.
 *
 * **WHAT IS DONE INSTEAD, AND WHY ERASURE SURVIVES IT.** No drain is NEEDED, because nothing here
 * ever has to recover a subject from a stored value. Both operations that matter are HANDED the
 * raw subject by their caller — ingest gets it from the envelope, erasure gets it from
 * `identity.user.deleted`'s `payload.userId` (`ingest.ts`). So the pepper becomes a RING: the
 * newest pepper mints, and a lookup derives a candidate key under EVERY pepper held and matches on
 * any of them. A row minted under the old pepper is still found from the subject, so:
 *
 *   - a returning person still finds their existing pseudonym — linkability is preserved, and one
 *     person does not silently become two; and
 *   - **erasure still reaches pre-rotation rows**, which is the compliance requirement in #189 and
 *     the only one that is not merely a data-quality concern.
 *
 * `subject_key` is deliberately NOT recomputed. It is an opaque stored value that the events
 * reference; re-deriving it would mean rewriting every event row to no benefit, since nothing ever
 * recomputes it from a subject — the salt is what makes that impossible, on purpose.
 *
 * **THE HONEST COST, STATED PLAINLY.** The old pepper cannot be dropped the moment the new one is
 * in place. It stays load-bearing until no row references it — that is, until every pre-rotation
 * subject has been pruned by retention, up to `ANALYTICS_EVENT_RETENTION_DAYS`. `subjectsBelowVersion`
 * is the gauge that says when it is safe. So this is a rotation that AGES OUT rather than one that
 * drains, and a compromised pepper keeps some value to an attacker for that window. That is worse
 * than custody's clean cut-over and it is the best available: the alternatives are breaking erasure
 * for pre-rotation rows (a GDPR regression) or storing the identifiers that would make a drain
 * possible (destroying the property the service is for).
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

/**
 * The peppers this process holds, by version. The newest MINTS; all of them are tried on lookup.
 *
 * A class rather than a bare string threaded through `IngestDeps`, for the same reason custody's
 * `Keyring` is one: a rotation test has to hold two rings at once — the old one that minted the row
 * and the new one that must still find it — and a single string cannot be two values in one
 * process.
 */
export class PepperRing {
  readonly #peppers: ReadonlyMap<number, string>
  readonly #writeVersion: number

  constructor(peppers: ReadonlyMap<number, string>, writeVersion: number) {
    if (peppers.size === 0) throw new Error('a pepper ring needs at least one pepper')
    if (!peppers.has(writeVersion)) {
      throw new Error(`no pepper for the write version v${writeVersion}`)
    }
    this.#peppers = new Map(peppers)
    this.#writeVersion = writeVersion
  }

  /** The version new subjects are minted under. */
  get writeVersion(): number {
    return this.#writeVersion
  }

  /** Every version this process can LOOK UP under, newest first. Numbers only, never values. */
  get versions(): readonly number[] {
    return [...this.#peppers.keys()].sort((a, b) => b - a)
  }

  #pepperAt(version: number): string {
    const pepper = this.#peppers.get(version)
    if (pepper === undefined) {
      // Names the version, never the value. An operator seeing this has dropped a pepper that rows
      // still reference — the analytics equivalent of removing a key secret before the drain.
      throw new Error(
        `no pepper for version v${version}; this process holds v${this.versions.join(', v')}`,
      )
    }
    return pepper
  }

  lookupKeyFor(version: number, subject: RawSubject): string {
    return hmacHex(this.#pepperAt(version), `${LOOKUP_DOMAIN}${subject}`)
  }

  subjectKeyFor(version: number, subject: RawSubject, salt: string): string {
    return hmacHex(this.#pepperAt(version), `${SUBJECT_DOMAIN}${subject}|${salt}`)
  }

  /**
   * The session pseudonym, always under the WRITE version.
   *
   * Not under the subject's version, deliberately. A session may carry events that have no subject
   * at all, so keying it to a subject would give one browser session two different digests
   * depending on which events it produced. The cost of using the write version is that a session
   * open across the rotation instant splits into two — a bounded, one-off analytics-quality blip
   * affecting only sessions in flight at that moment.
   *
   * It costs erasure NOTHING, which is the part that matters: `eraseSubject` nulls sessions by
   * `subject_key`, not by recomputing this digest, so a session minted under any pepper is still
   * destroyed when its subject is erased.
   */
  sessionKeyFor(sessionId: string): string {
    return hmacHex(this.#pepperAt(this.#writeVersion), `cf.analytics.session.v1|${sessionId}`)
  }

  /**
   * One candidate lookup key per pepper held, newest first.
   *
   * This is the whole rotation mechanism: it is what lets a subject minted under the old pepper be
   * found from the raw subject after the new one is in place.
   */
  lookupCandidates(subject: RawSubject): readonly { version: number; lookupKey: string }[] {
    return this.versions.map((version) => ({ version, lookupKey: this.lookupKeyFor(version, subject) }))
  }
}

/** A 64-character lowercase hex digest. The only shape a pseudonym is ever allowed to have. */
export const DIGEST_PATTERN = /^[0-9a-f]{64}$/

/**
 * Domain separation strings, versioned.
 *
 * Two different HMACs under one key must not be able to collide into each other's namespace, and
 * the version is in the string so that a future construction change is a *different* pseudonym
 * rather than a silent reinterpretation of the old one.
 */
const LOOKUP_DOMAIN = 'cf.analytics.lookup.v1|'
const SUBJECT_DOMAIN = 'cf.analytics.subject.v1|'

/**
 * The subject a person is known by upstream: `user:<uuid>` or `operator:<id>`.
 *
 * A branded string, so a plain `string` cannot be passed where one is expected and the
 * type-checker marks every place a raw identifier enters the program. It leaves through
 * `deriveSubject` and nowhere else.
 */
export type RawSubject = string & { readonly __rawSubject: unique symbol }

export function rawSubject(actor: string): RawSubject {
  return actor as RawSubject
}

export function hmacHex(pepper: string, message: string): string {
  return createHmac('sha256', pepper).update(message, 'utf8').digest('hex')
}

/** Deterministic: the same subject always maps to the same lookup key under the same pepper. */
export function lookupKeyFor(pepper: string, subject: RawSubject): string {
  return hmacHex(pepper, `${LOOKUP_DOMAIN}${subject}`)
}

/** Not deterministic from the subject alone. The salt is the whole point — see the file header. */
export function subjectKeyFor(pepper: string, subject: RawSubject, salt: string): string {
  return hmacHex(pepper, `${SUBJECT_DOMAIN}${subject}|${salt}`)
}

/**
 * Thirty-two bytes from the CSPRNG.
 *
 * Not derived from anything, not a counter, not a timestamp. A salt that can be reconstructed is
 * a salt that erasure does not destroy, which is the entire failure this construction avoids.
 */
export function newSalt(): string {
  return randomBytes(32).toString('hex')
}

/** Constant-time equality for two digests. Used where a comparison result is observable. */
export function digestsEqual(a: string, b: string): boolean {
  if (!DIGEST_PATTERN.test(a) || !DIGEST_PATTERN.test(b)) return false
  return timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'))
}

/**
 * The result of pseudonymising one subject. Note what is not on it: the subject.
 *
 * `erased` means the person asked to be forgotten and their salt is gone. The correct response is
 * to discard the event, not to mint a fresh pseudonym: minting one would start a new behavioural
 * profile for somebody whose account no longer exists.
 */
export type Derived =
  | { readonly status: 'ok'; readonly subjectKey: string; readonly minted: boolean }
  | { readonly status: 'erased' }

/**
 * A pool or a transaction. Every function here takes either, because `deriveSubject` and
 * `eraseSubject` must be able to run inside the caller's transaction — the pseudonym upsert and
 * the event insert commit together or neither does — while `isAttributable` is a plain read.
 */
export type SubjectStore = Db | Tx

/**
 * Find or mint the pseudonym for one subject, inside the caller's transaction.
 *
 * The upsert is `on conflict do update` rather than `do nothing` so that the returning clause
 * always yields a row: with `do nothing` a concurrent insert of the same subject returns zero rows
 * and the caller has to issue a second read, which under `read committed` can still lose the race.
 * The `set last_seen` is real work — it is what lets retention prune a mapping whose events have
 * all expired — so nothing here is an update written to make a RETURNING clause behave.
 *
 * `salt` is generated by the caller's process before the statement runs and is thrown away when
 * the conflict path wins. That is correct and cheap: thirty-two unused random bytes cost nothing,
 * and the alternative — reading first, then inserting — has a race between the two.
 */
export async function deriveSubject(
  sql: SubjectStore,
  ring: PepperRing,
  subject: RawSubject,
  occurredAt: Date,
): Promise<Derived> {
  /*
   * ROTATION: look under every pepper before minting anything.
   *
   * Minting straight away — which is what a single-pepper upsert does — is precisely the #189
   * defect: after a rotation the newest pepper produces a lookup key that matches nothing, so a
   * returning person is minted a SECOND pseudonym and their entire history is orphaned from them.
   * One round trip covers every pepper held, so the common case (nothing to rotate, or already
   * minted under the current pepper) costs exactly what it did before.
   */
  const existing = await findAcross(sql, ring, subject)
  if (existing) {
    if (existing.erased_at !== null || existing.subject_key === null) return { status: 'erased' }
    await sql`
      update subject_keys
         set last_seen = greatest(last_seen, ${occurredAt})
       where lookup_key = ${existing.lookup_key}
    `
    return { status: 'ok', subjectKey: existing.subject_key, minted: false }
  }

  // Genuinely new under every pepper we hold, so mint under the newest.
  const version = ring.writeVersion
  const lookupKey = ring.lookupKeyFor(version, subject)
  const salt = newSalt()
  const candidate = ring.subjectKeyFor(version, subject, salt)

  const rows = await sql<{ subject_key: string | null; salt: string | null; erased_at: Date | null }[]>`
    insert into subject_keys (lookup_key, subject_key, salt, pepper_version, first_seen, last_seen)
    values (${lookupKey}, ${candidate}, ${salt}, ${version}, ${occurredAt}, ${occurredAt})
    on conflict (lookup_key) do update
      set last_seen = greatest(subject_keys.last_seen, excluded.last_seen)
    returning subject_key, salt, erased_at
  `

  const row = rows[0]
  if (!row) throw new Error('subject_keys upsert returned no row')
  if (row.erased_at !== null || row.subject_key === null) return { status: 'erased' }
  return { status: 'ok', subjectKey: row.subject_key, minted: row.subject_key === candidate }
}

/**
 * The row for this subject under ANY pepper held, or null.
 *
 * Ordering is load-bearing in two ways. An ERASED row wins over a live one, so that a subject who
 * was erased under the old pepper cannot be handed a fresh pseudonym under the new one — the
 * tombstone has to survive a rotation or erasure is undone by it. Failing that, the highest
 * `pepper_version` wins, so a subject that somehow exists under two peppers converges on the newer.
 *
 * That second case should not arise on this estate — every service runs a single replica
 * (`migrator.ts` records why), so there is no window in which one process mints under v1 while
 * another mints under v2 — but "should not arise" is not "cannot", and the cost of being definite
 * is one `order by`.
 */
async function findAcross(
  sql: SubjectStore,
  ring: PepperRing,
  subject: RawSubject,
): Promise<SubjectRow | null> {
  const keys = ring.lookupCandidates(subject).map((c) => c.lookupKey)
  const rows = await sql<SubjectRow[]>`
    select lookup_key, subject_key, salt, erased_at, pepper_version
      from subject_keys
     where lookup_key = any(${keys})
     order by (erased_at is not null) desc, pepper_version desc
     limit 1
  `
  return rows[0] ?? null
}

interface SubjectRow {
  readonly lookup_key: string
  readonly subject_key: string | null
  readonly salt: string | null
  readonly erased_at: Date | null
  readonly pepper_version: number
}

/**
 * Erase a subject. This is the whole of the GDPR path, and it is four columns.
 *
 * The salt and the pseudonym are set to NULL — *deleted*, not flagged. The `subject_keys_erased`
 * CHECK in `migrations.ts` refuses a row that claims `erased_at` while still holding either, so
 * a future code path cannot implement this as a soft delete that keeps the key.
 *
 * The row itself survives, holding only `lookup_key` and a timestamp, and that is deliberate: it
 * is the tombstone that stops a late-arriving event for an erased person minting a fresh pseudonym
 * and starting a new profile. The cost is that somebody holding the pepper AND a candidate user id
 * can learn whether that person was erased — a one-bit oracle, recorded in the README, and better
 * than the alternative, which is a forgotten user quietly accumulating a second history.
 *
 * The events keep their now-orphaned pseudonym. They are not deleted, for two reasons that agree:
 * after the salt is gone they identify nobody, and deleting them would retroactively rewrite every
 * historical funnel and cohort number — which 13-operational-model.md forbids in the strongest
 * terms it uses anywhere ("a retention number that changed definition in March is a chart that
 * lies about February").
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **AND `events.session`, WHICH THE SALT ARGUMENT DOES NOT COVER.**
 *
 * The paragraph above is only true of `subject_key`. `session` is a SECOND identifier on the same
 * rows, and it is derived on a completely different path: `hmacHex(pepper, 'cf.analytics.session
 * .v1|' + sessionId)` (`ingest.ts`). No per-subject salt goes into it, so destroying the salt does
 * nothing to it whatsoever.
 *
 * That leaves two live re-identification routes through a subject this service reports as erased:
 *
 *   1. **Recomputation.** The construction is deterministic under a pepper that is never destroyed
 *      — it cannot be, it keys every other subject in the table. Anyone holding the pepper and a
 *      candidate session id computes the digest and selects that person's rows directly. A browser
 *      session id is not a secret: it is in the client, in front-end logs, and in whatever other
 *      system minted it.
 *   2. **Linkage.** Rows sharing a session are one person's, so the orphaned events re-cluster into
 *      per-person groups even without the pepper — and a group joined to any dated external record
 *      is attributable again. "Unlinkable" is precisely the property GDPR Recital 26 asks for when
 *      deciding whether data is anonymous, and a surviving session id is a link.
 *
 * So erasure nulls it. The cost is one session-scoped metric losing an erased person's sessions,
 * which is the correct trade and much smaller than it sounds: the rows still count towards every
 * event total, and `subject_key` — not `session` — is what funnels and cohorts group by.
 *
 * `analytics_erasure_leaves_no_session` (migration 8) is the belt to this brace: a transaction that
 * sets `erased_at` and leaves a session behind is refused at commit, so this cannot be quietly
 * half-done by a future edit.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export async function eraseSubject(
  sql: SubjectStore,
  ring: PepperRing,
  subject: RawSubject,
  now: Date,
): Promise<{
  readonly erased: boolean
  readonly alreadyErased: boolean
  /** Rows whose surviving session identifier was destroyed. Counted, never logged with a value. */
  readonly sessionsCleared: number
}> {
  /*
   * `already` is read from the row as it stood BEFORE this statement, not inferred from the
   * timestamp afterwards.
   *
   * This used to return `(subject_keys.erased_at = ${now}) as was_live` — "if the surviving
   * `erased_at` is the one I just supplied, I am the caller who erased it". That reads as sound
   * and is not, because `coalesce` keeps the FIRST erasure's timestamp and `Date` resolves to the
   * millisecond: two erasures landing in the same millisecond carry the same `now`, so the
   * preserved value equals the second caller's timestamp and the second caller is told it erased
   * a live subject. Reproduced against Postgres — both calls returned true.
   *
   * That is a wrong answer about a right action. The erasure itself was always correct and
   * idempotent; what was wrong was the report, and this service's report is what the estate's
   * erasure register records as the acknowledgement. It surfaced as a flaky test because a
   * collision needs two statements inside one millisecond, which a warm connection manages and a
   * cold one does not.
   *
   * The CTE sees the pre-statement snapshot, so the answer no longer depends on clock resolution,
   * on how fast the database is, or on the caller passing distinct timestamps.
   */
  // ── THE SESSIONS GO FIRST, AND THE ORDER IS LOAD-BEARING ────────────────────────────────
  //
  // The pseudonym is the only handle on this person's rows, and the upsert below destroys it —
  // so the sessions have to be cleared while it can still be read. Doing it afterwards would
  // mean reading a value that no longer exists anywhere.
  //
  // It also makes this function correct when it is handed a POOL rather than a transaction.
  // `SubjectStore` is `Db | Tx` deliberately, and on a pool each statement commits on its own:
  // with the upsert first, `analytics_erasure_unlinked` fires at that commit, finds the sessions
  // still present, and refuses an erasure that was about to complete one statement later. In
  // this order the invariant is already satisfied whichever way the caller sequences it, and
  // inside a transaction — which is how `ingest` calls it — the deferred check still guarantees
  // the pair committed together.
  //
  // A re-erasure finds `subject_key` already null and clears nothing, which is the right
  // idempotent answer rather than a special case.
  /*
   * ROTATION (#189): EVERY pepper is tried, and this is where erasure is either preserved or lost.
   *
   * The raw subject is supplied by the caller — `identity.user.deleted` carries it — so a row
   * minted under a retired pepper is still reachable from it. That is the whole reason a rotation
   * here does not need a drain, and the whole reason it does not break erasure of pre-rotation
   * rows, which is the compliance point #189 turns on.
   *
   * Every match is erased, not just the newest. If a subject somehow exists under two peppers,
   * erasing one and leaving the other is a person who asked to be forgotten and was, partly.
   */
  const candidates = ring.lookupCandidates(subject).map((c) => c.lookupKey)
  const matches = await sql<{ lookup_key: string; subject_key: string | null; erased_at: Date | null }[]>`
    select lookup_key, subject_key, erased_at from subject_keys where lookup_key = any(${candidates})
  `

  let sessionsCleared = 0
  let alreadyErased = matches.length > 0 && matches.every((row) => row.erased_at !== null)

  for (const match of matches) {
    if (match.subject_key !== null) {
      const cleared = await sql<{ id: string }[]>`
        update events set session = null
         where subject_key = ${match.subject_key} and session is not null
        returning id
      `
      sessionsCleared += cleared.length
    }
    await sql`
      update subject_keys
         set subject_key = null,
             salt        = null,
             erased_at   = coalesce(erased_at, ${now})
       where lookup_key = ${match.lookup_key}
    `
  }

  if (matches.length === 0) {
    // An erasure for a subject this service never saw — an acknowledgement, and the tombstone that
    // keeps it that way if an event arrives afterwards. Written under the CURRENT pepper, because
    // that is what a future event for this subject will look up first.
    alreadyErased = false
    await sql`
      insert into subject_keys (lookup_key, subject_key, salt, pepper_version, first_seen, last_seen, erased_at)
      values (${ring.lookupKeyFor(ring.writeVersion, subject)}, null, null, ${ring.writeVersion}, ${now}, ${now}, ${now})
      on conflict (lookup_key) do update
        set subject_key = null,
            salt        = null,
            erased_at   = coalesce(subject_keys.erased_at, ${now})
    `
  }

  return { erased: true, alreadyErased, sessionsCleared }
}

/**
 * Does a live mapping exist for this subject?
 *
 * Exists for the erasure test and for nothing else: it is the question "can these events still be
 * traced back to this person", and after `eraseSubject` the answer must be no, permanently.
 */
export async function isAttributable(
  sql: SubjectStore,
  ring: PepperRing,
  subject: RawSubject,
): Promise<boolean> {
  // Across every pepper, for the same reason `eraseSubject` is: a subject that is still
  // attributable under a retired pepper is still attributable, and reporting otherwise would make
  // this function agree with a rotation rather than with the data.
  const candidates = ring.lookupCandidates(subject).map((c) => c.lookupKey)
  const rows = await sql<{ subject_key: string | null }[]>`
    select subject_key from subject_keys
     where lookup_key = any(${candidates}) and erased_at is null and subject_key is not null
     limit 1
  `
  return rows[0]?.subject_key != null
}

/**
 * How many mappings still reference a pepper older than `version`.
 *
 * The gauge that says when an old `ANALYTICS_PSEUDONYM_KEY` may finally be dropped from the
 * environment, and the analytics counterpart of identity's `remainingCount`. The difference is that
 * identity's number is driven to zero by a drain that can be RUN, and this one falls only as
 * retention prunes pre-rotation subjects — see the rotation note at the top of this file. An
 * operator removing a pepper while this is non-zero silently breaks erasure for exactly those rows,
 * which is the #189 regression arriving by the back door.
 */
export async function subjectsBelowVersion(sql: SubjectStore, version: number): Promise<number> {
  const rows = await sql<{ n: number }[]>`
    select count(*) as n from subject_keys where pepper_version < ${version} and erased_at is null
  `
  return Number(rows[0]?.n ?? 0)
}

/**
 * Prune mappings that no longer map anything.
 *
 * A mapping row that outlives every event it names is a pseudonym kept for no purpose, and this
 * service's whole argument is that it holds nothing it does not need. Only rows whose last event
 * has expired are eligible, and a tombstone is kept a full retention period so that a very late
 * redelivery for an erased subject still meets the tombstone rather than minting a pseudonym.
 */
export async function pruneSubjects(sql: Db, cutoff: Date): Promise<number> {
  const result = (await sql`
    delete from subject_keys
     where last_seen < ${cutoff}
       and not exists (
         select 1 from events where events.subject_key = subject_keys.subject_key
       )
  `) as unknown as { count?: number }
  return typeof result.count === 'number' ? result.count : 0
}
