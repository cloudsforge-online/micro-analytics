/**
 * Pseudonymisation. The reason this service is allowed to exist.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY A PLAIN HMAC(user_id, pepper) IS NOT PSEUDONYMISATION, AND WHAT IS HERE INSTEAD.**
 *
 * The estate specifies `subject_key = HMAC(user_id, analytics_pepper)` in four places
 * (02-target-architecture.md:596-597, 11-data-and-contract-strategy.md:509-510,
 * 13-operational-model.md:596-597, 10-migration-strategy.md:509). Taken literally it has a defect
 * that is fatal to the only privacy promise this service makes, and the defect is *erasure*:
 *
 *     subject_key = HMAC(pepper, user_id)   is a PURE FUNCTION of two things that both survive.
 *
 * Erasure of such a key is impossible by construction. Delete every row you like — anyone holding
 * the pepper and a candidate user id recomputes the key and finds that person's entire behavioural
 * history, for the four hundred days it is retained. That is not a pseudonym that can be erased,
 * it is an index into a person, and 10-migration-strategy.md:492 ("Pseudonymised events —
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
 * what 11-data-and-contract-strategy.md:468 already claims of this service ("Nothing to do — it
 * never held a `user_id`") and what the plain construction could not have made true.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * ## Where the key lives, and where it does not
 *
 * The pepper is `ANALYTICS_PSEUDONYM_KEY`. It is read from the environment by `env.ts`, held in
 * process memory, and **never written to this service's database**. That separation is the second
 * half of the design: an attacker holding a database connection has, for every subject, two
 * unrelated 256-bit values and a random salt, and no way to test a guess at who any of them is.
 * 13-operational-model.md:597 requires it to be absent from any backup that also contains the
 * identity database; keeping it out of this database is the strongest form of that available to
 * a service that owns exactly one database.
 *
 * ## An inherited claim that does not survive contact with the shipped contract
 *
 * 03-repository-responsibilities.md:204 says `analytics` "must never RECEIVE a `user_id`". Against
 * the envelope that actually ships it is not implementable: `EventEnvelope.actor` is
 * `user:<user_id>` (`contracts/packages/events/src/index.ts:61,418`) and `key` is `user_id` on
 * eleven of the eighteen registered topics (`:234,242,249,256,318,325` and others), so every
 * delivery this service is entitled to read carries one. 10-migration-strategy.md:509 says the
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
  pepper: string,
  subject: RawSubject,
  occurredAt: Date,
): Promise<Derived> {
  const lookupKey = lookupKeyFor(pepper, subject)
  const salt = newSalt()
  const candidate = subjectKeyFor(pepper, subject, salt)

  const rows = await sql<{ subject_key: string | null; salt: string | null; erased_at: Date | null }[]>`
    insert into subject_keys (lookup_key, subject_key, salt, first_seen, last_seen)
    values (${lookupKey}, ${candidate}, ${salt}, ${occurredAt}, ${occurredAt})
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
 * historical funnel and cohort number — which 13-operational-model.md:637 forbids in the strongest
 * terms it uses anywhere ("a retention number that changed definition in March is a chart that
 * lies about February").
 */
export async function eraseSubject(
  sql: SubjectStore,
  pepper: string,
  subject: RawSubject,
  now: Date,
): Promise<{ readonly erased: boolean; readonly alreadyErased: boolean }> {
  const lookupKey = lookupKeyFor(pepper, subject)

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
  const rows = await sql<{ already: boolean }[]>`
    with prior as (
      select erased_at from subject_keys where lookup_key = ${lookupKey}
    ), upserted as (
      insert into subject_keys (lookup_key, subject_key, salt, first_seen, last_seen, erased_at)
      values (${lookupKey}, null, null, ${now}, ${now}, ${now})
      on conflict (lookup_key) do update
        set subject_key = null,
            salt        = null,
            erased_at   = coalesce(subject_keys.erased_at, ${now})
      returning 1
    )
    select coalesce((select erased_at from prior) is not null, false) as already from upserted
  `
  const row = rows[0]
  // The INSERT path is an erasure for a subject this service never saw — an acknowledgement, and
  // the tombstone that keeps it that way if an event arrives afterwards.
  if (!row) return { erased: true, alreadyErased: false }
  return { erased: true, alreadyErased: row.already }
}

/**
 * Does a live mapping exist for this subject?
 *
 * Exists for the erasure test and for nothing else: it is the question "can these events still be
 * traced back to this person", and after `eraseSubject` the answer must be no, permanently.
 */
export async function isAttributable(
  sql: SubjectStore,
  pepper: string,
  subject: RawSubject,
): Promise<boolean> {
  const lookupKey = lookupKeyFor(pepper, subject)
  const rows = await sql<{ subject_key: string | null }[]>`
    select subject_key from subject_keys where lookup_key = ${lookupKey} and erased_at is null
  `
  return rows[0]?.subject_key != null
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
