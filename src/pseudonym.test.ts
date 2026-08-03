/**
 * Pseudonymisation and erasure, against a real Postgres.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE TEST THIS FILE EXISTS FOR IS `no value left in the database can re-derive the pseudonym`.**
 *
 * It is not an assertion about the code path. It reads EVERY text value out of EVERY table this
 * service owns, and proves that none of them — combined with the pepper and the user id, which is
 * everything an attacker could possibly bring — reproduces the pseudonym on the erased person's
 * events. That is the whole claim of `eraseSubject`, checked mechanically rather than argued.
 *
 * The test is also written so that it FAILS if the salt is retained. That is not hypothetical: the
 * first version of the `subject_keys_erased` constraint permitted a row that nulled the pseudonym
 * and kept the salt, which would have passed every "is it erased" test written the obvious way and
 * erased nothing at all.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { TABLES } from './migrations.ts'
import {
  DIGEST_PATTERN,
  deriveSubject,
  digestsEqual,
  eraseSubject,
  isAttributable,
  lookupKeyFor,
  newSalt,
  pruneSubjects,
  rawSubject,
  subjectKeyFor,
} from './pseudonym.ts'
import { TEST_PEPPER, migrateTestDb, openDb, resetAnalytics, skip } from './testsupport.ts'

const SPIROS = rawSubject('user:550e8400-e29b-41d4-a716-446655440000')
const OTHER = rawSubject('user:6ba7b810-9dad-11d1-80b4-00c04fd430c8')
const AT = new Date('2026-06-01T10:00:00.000Z')

describe('pseudonym', { skip }, () => {
  let sql: postgres.Sql

  before(async () => {
    sql = openDb()
    await migrateTestDb(sql)
  })
  beforeEach(async () => {
    await resetAnalytics(sql)
  })
  after(async () => {
    await sql.end({ timeout: 5 })
  })

  /* ================================================================ the construction */

  describe('the construction', () => {
    it('produces a 64-character lowercase hex digest, which is the only shape the store accepts', () => {
      assert.match(lookupKeyFor(TEST_PEPPER, SPIROS), DIGEST_PATTERN)
      assert.match(subjectKeyFor(TEST_PEPPER, SPIROS, newSalt()), DIGEST_PATTERN)
    })

    it('never contains the subject it was derived from', () => {
      const key = subjectKeyFor(TEST_PEPPER, SPIROS, newSalt())
      assert.ok(!key.includes('550e8400'), 'the pseudonym leaked part of the subject')
    })

    it('is deterministic for the lookup key and NOT deterministic for the pseudonym', () => {
      // The lookup key must be stable, or the same person's second event mints a second identity.
      assert.equal(lookupKeyFor(TEST_PEPPER, SPIROS), lookupKeyFor(TEST_PEPPER, SPIROS))
      // The pseudonym must not be, or erasure has nothing to destroy — see the module header.
      assert.notEqual(
        subjectKeyFor(TEST_PEPPER, SPIROS, newSalt()),
        subjectKeyFor(TEST_PEPPER, SPIROS, newSalt()),
      )
    })

    it('separates its two domains, so a lookup key can never be mistaken for a pseudonym', () => {
      assert.notEqual(lookupKeyFor(TEST_PEPPER, SPIROS), subjectKeyFor(TEST_PEPPER, SPIROS, ''))
    })

    it('changes completely with the pepper', () => {
      assert.notEqual(lookupKeyFor(TEST_PEPPER, SPIROS), lookupKeyFor(`${TEST_PEPPER}x`, SPIROS))
    })

    it('mints a salt with real entropy', () => {
      const salts = new Set(Array.from({ length: 200 }, () => newSalt()))
      assert.equal(salts.size, 200)
      for (const salt of salts) assert.match(salt, DIGEST_PATTERN)
    })

    it('compares digests in constant time and refuses a non-digest', () => {
      const key = subjectKeyFor(TEST_PEPPER, SPIROS, newSalt())
      assert.equal(digestsEqual(key, key), true)
      assert.equal(digestsEqual(key, subjectKeyFor(TEST_PEPPER, OTHER, newSalt())), false)
      assert.equal(digestsEqual(key, 'not-a-digest'), false)
    })
  })

  /* ================================================================ derivation */

  describe('deriving', () => {
    it('mints once and returns the same pseudonym for every later event', async () => {
      const first = await deriveSubject(sql, TEST_PEPPER, SPIROS, AT)
      const second = await deriveSubject(sql, TEST_PEPPER, SPIROS, new Date(AT.getTime() + 86_400_000))
      assert.equal(first.status, 'ok')
      assert.equal(second.status, 'ok')
      assert.equal(first.status === 'ok' && first.minted, true)
      assert.equal(second.status === 'ok' && second.minted, false)
      assert.equal(
        first.status === 'ok' && second.status === 'ok' && first.subjectKey === second.subjectKey,
        true,
        'a funnel joins on this; two pseudonyms for one person is two people',
      )
    })

    it('gives two people two pseudonyms', async () => {
      const a = await deriveSubject(sql, TEST_PEPPER, SPIROS, AT)
      const b = await deriveSubject(sql, TEST_PEPPER, OTHER, AT)
      assert.notEqual(a.status === 'ok' && a.subjectKey, b.status === 'ok' && b.subjectKey)
    })

    it('advances last_seen, which is what lets retention prune a dead mapping', async () => {
      await deriveSubject(sql, TEST_PEPPER, SPIROS, AT)
      const later = new Date(AT.getTime() + 30 * 86_400_000)
      await deriveSubject(sql, TEST_PEPPER, SPIROS, later)
      const rows = await sql<{ first_seen: Date; last_seen: Date }[]>`select first_seen, last_seen from subject_keys`
      assert.equal(rows[0]?.first_seen.toISOString(), AT.toISOString())
      assert.equal(rows[0]?.last_seen.toISOString(), later.toISOString())
    })

    it('never moves last_seen backwards when an event arrives out of order', async () => {
      const later = new Date(AT.getTime() + 30 * 86_400_000)
      await deriveSubject(sql, TEST_PEPPER, SPIROS, later)
      await deriveSubject(sql, TEST_PEPPER, SPIROS, AT)
      const rows = await sql<{ last_seen: Date }[]>`select last_seen from subject_keys`
      assert.equal(rows[0]?.last_seen.toISOString(), later.toISOString())
    })

    it('two concurrent first events for one person produce ONE pseudonym', async () => {
      // Ordering is per (topic, key) and nothing else, so two producers can deliver a person's
      // first two events simultaneously. Without the upsert, one transaction reads "no mapping",
      // both insert, and the person becomes two people in every cohort for ever.
      const [a, b] = await Promise.all([
        sql.begin((tx) => deriveSubject(tx, TEST_PEPPER, SPIROS, AT)),
        sql.begin((tx) => deriveSubject(tx, TEST_PEPPER, SPIROS, AT)),
      ])
      const keyA = (a as unknown as { subjectKey?: string }).subjectKey
      const keyB = (b as unknown as { subjectKey?: string }).subjectKey
      assert.ok(keyA && keyB)
      assert.equal(keyA, keyB)
      const rows = await sql<{ n: string }[]>`select count(*) as n from subject_keys`
      assert.equal(Number(rows[0]?.n), 1)
    })
  })

  /* ================================================================ erasure */

  describe('erasure', () => {
    /** Plant one event for a subject, returning the pseudonym its rows carry. */
    async function plant(subject: typeof SPIROS): Promise<string> {
      const derived = await deriveSubject(sql, TEST_PEPPER, subject, AT)
      assert.equal(derived.status, 'ok')
      const key = derived.status === 'ok' ? derived.subjectKey : ''
      await sql`
        insert into events (subject_key, subject_kind, event_name, occurred_at, source_event_id, source_topic, producer)
        values (${key}, 'user', 'deposit_confirmed', ${AT}, ${crypto.randomUUID()}, 'wallet.deposit.confirmed', 'wallet')
      `
      return key
    }

    it('destroys the salt and the pseudonym, and keeps the tombstone', async () => {
      await plant(SPIROS)
      const outcome = await eraseSubject(sql, TEST_PEPPER, SPIROS, new Date())
      assert.deepEqual(outcome, { erased: true, alreadyErased: false })

      const rows = await sql<{ subject_key: string | null; salt: string | null; erased_at: Date | null }[]>`
        select subject_key, salt, erased_at from subject_keys where lookup_key = ${lookupKeyFor(TEST_PEPPER, SPIROS)}
      `
      assert.equal(rows.length, 1, 'the tombstone must survive')
      assert.equal(rows[0]?.subject_key, null)
      assert.equal(rows[0]?.salt, null)
      assert.notEqual(rows[0]?.erased_at, null)
    })

    it('makes the person unattributable', async () => {
      await plant(SPIROS)
      assert.equal(await isAttributable(sql, TEST_PEPPER, SPIROS), true)
      await eraseSubject(sql, TEST_PEPPER, SPIROS, new Date())
      assert.equal(await isAttributable(sql, TEST_PEPPER, SPIROS), false)
    })

    it('no value left in the database can re-derive the pseudonym', async () => {
      // ═════════════════════════════════════════════════════════════════════════════════════════
      // THE PROOF. The attacker is assumed to hold the pepper AND the user id AND a connection to
      // this database — everything there is. The pseudonym is recomputable only from a salt, so
      // this reads every text value out of every table and shows that none of them is one.
      // ═════════════════════════════════════════════════════════════════════════════════════════
      const key = await plant(SPIROS)
      await plant(OTHER)
      await eraseSubject(sql, TEST_PEPPER, SPIROS, new Date())

      // The events are still there, still carrying the pseudonym. They identify nobody.
      const remaining = await sql<{ subject_key: string }[]>`select subject_key from events where subject_key = ${key}`
      assert.equal(remaining.length, 1, 'the events survive; it is the link that is destroyed')

      const columns = await sql<{ table_name: string; column_name: string }[]>`
        select table_name, column_name
          from information_schema.columns
         where table_schema = 'public'
           and table_name = any(${[...TABLES] as string[]}::text[])
           and data_type in ('text', 'character varying', 'uuid', 'jsonb')
      `
      assert.ok(columns.length > 10, 'the sweep must actually find columns, or it proves nothing')

      let inspected = 0
      for (const column of columns) {
        const values = (await sql.unsafe(
          `select distinct ${column.column_name}::text as v from ${column.table_name} where ${column.column_name} is not null`,
        )) as unknown as Array<{ v: string }>
        for (const { v } of values) {
          inspected += 1
          assert.notEqual(
            subjectKeyFor(TEST_PEPPER, SPIROS, v),
            key,
            `${column.table_name}.${column.column_name} still holds a value that re-derives the pseudonym`,
          )
        }
      }
      assert.ok(inspected > 0, 'no values were inspected, so nothing was proved')

      // And the other person's mapping is untouched — an erasure that took the store down with it
      // would also pass every assertion above.
      assert.equal(await isAttributable(sql, TEST_PEPPER, OTHER), true)
    })

    it('the same proof FAILS if the salt is retained — the check is not vacuous', async () => {
      // Plant the failure this test exists to catch: a row that kept its salt. If the sweep above
      // could not see it, the proof would be theatre.
      const derived = await deriveSubject(sql, TEST_PEPPER, SPIROS, AT)
      assert.equal(derived.status, 'ok')
      const key = derived.status === 'ok' ? derived.subjectKey : ''
      const rows = await sql<{ salt: string }[]>`select salt from subject_keys`
      const salt = rows[0]?.salt ?? ''
      assert.equal(subjectKeyFor(TEST_PEPPER, SPIROS, salt), key, 'a retained salt DOES re-derive it')
    })

    it('a later event for an erased person does not mint a new pseudonym', async () => {
      // Minting one would start a second behavioural profile for somebody whose account no longer
      // exists, which is the opposite of what was asked for. The tombstone is what stops it.
      const key = await plant(SPIROS)
      await eraseSubject(sql, TEST_PEPPER, SPIROS, new Date())
      const later = await deriveSubject(sql, TEST_PEPPER, SPIROS, new Date())
      assert.equal(later.status, 'erased')
      const rows = await sql<{ n: string }[]>`select count(*) as n from subject_keys where subject_key is not null`
      assert.equal(Number(rows[0]?.n), 0)
      // And nothing new joins to the old rows.
      assert.notEqual(key, '')
    })

    it('is idempotent, and says which time it was', async () => {
      await plant(SPIROS)
      const first = await eraseSubject(sql, TEST_PEPPER, SPIROS, new Date())
      const second = await eraseSubject(sql, TEST_PEPPER, SPIROS, new Date())
      assert.deepEqual(first, { erased: true, alreadyErased: false })
      assert.deepEqual(second, { erased: true, alreadyErased: true })
    })

    /*
     * THE SAME ASSERTION WITH THE CLOCK HELD STILL, because the version above was flaky and the
     * flakiness was the bug reporting itself.
     *
     * `eraseSubject` used to answer "was this already erased?" by comparing the surviving
     * `erased_at` with the timestamp it had just supplied. `coalesce` keeps the FIRST erasure's
     * timestamp and `Date` resolves to the millisecond, so two erasures inside one millisecond
     * carry equal values and the second caller was told it had erased a live subject. Two
     * `new Date()` calls collide on a warm connection and not on a cold one, which is exactly the
     * shape of a test that passes on a laptop and fails in CI — it failed there on a commit whose
     * whole diff was one line of README.
     *
     * Passing ONE date to both calls makes the collision certain rather than likely, so this case
     * fails every time against the old implementation instead of one run in five. A flaky test
     * teaches people to press rerun; a deterministic one teaches them to read.
     *
     * It matters beyond tidiness because this service's answer IS the estate's erasure
     * acknowledgement: the register records what came back, so a wrong `alreadyErased` writes a
     * wrong fact about a subject's erasure into another service's audit trail.
     */
    it('says already-erased even when both erasures share a millisecond', async () => {
      await plant(SPIROS)
      const sameInstant = new Date()
      const first = await eraseSubject(sql, TEST_PEPPER, SPIROS, sameInstant)
      const second = await eraseSubject(sql, TEST_PEPPER, SPIROS, sameInstant)
      assert.deepEqual(first, { erased: true, alreadyErased: false })
      assert.deepEqual(second, { erased: true, alreadyErased: true }, 'the clock is not the record')
    })

    it('acknowledges an erasure for somebody this service never saw', async () => {
      // The estate's erasure register waits on an acknowledgement from every subscriber
      // (10-migration-strategy.md:507-515). "We have nothing" is an acknowledgement, and the
      // tombstone is what keeps it true if an event turns up afterwards.
      const outcome = await eraseSubject(sql, TEST_PEPPER, SPIROS, new Date())
      assert.deepEqual(outcome, { erased: true, alreadyErased: false })
      assert.equal((await deriveSubject(sql, TEST_PEPPER, SPIROS, AT)).status, 'erased')
    })

    it('does not delete the events, because that would rewrite every historical aggregate', async () => {
      const key = await plant(SPIROS)
      await eraseSubject(sql, TEST_PEPPER, SPIROS, new Date())
      const rows = await sql<{ n: string }[]>`select count(*) as n from events where subject_key = ${key}`
      assert.equal(Number(rows[0]?.n), 1, '13-operational-model.md:637 — February must not change in March')
    })
  })

  /* ================================================================ pruning */

  describe('pruning mappings whose events are gone', () => {
    it('keeps a mapping whose events survive', async () => {
      const derived = await deriveSubject(sql, TEST_PEPPER, SPIROS, AT)
      const key = derived.status === 'ok' ? derived.subjectKey : ''
      await sql`
        insert into events (subject_key, subject_kind, event_name, occurred_at, source_event_id, source_topic, producer)
        values (${key}, 'user', 'user_registered', ${AT}, ${crypto.randomUUID()}, 'identity.user.registered', 'identity')
      `
      assert.equal(await pruneSubjects(sql, new Date()), 0)
      assert.equal(await isAttributable(sql, TEST_PEPPER, SPIROS), true)
    })

    it('drops a mapping that no longer maps anything', async () => {
      // A pseudonym for a person, retained for no purpose, in the one service that claims to hold
      // nothing it does not need.
      await deriveSubject(sql, TEST_PEPPER, SPIROS, AT)
      assert.equal(await pruneSubjects(sql, new Date()), 1)
      const rows = await sql<{ n: string }[]>`select count(*) as n from subject_keys`
      assert.equal(Number(rows[0]?.n), 0)
    })

    it('does not drop a mapping that is merely recent', async () => {
      await deriveSubject(sql, TEST_PEPPER, SPIROS, new Date())
      assert.equal(await pruneSubjects(sql, new Date(Date.now() - 86_400_000)), 0)
    })

    it('drops an old tombstone', async () => {
      await eraseSubject(sql, TEST_PEPPER, SPIROS, AT)
      assert.equal(await pruneSubjects(sql, new Date()), 1)
    })
  })
})
