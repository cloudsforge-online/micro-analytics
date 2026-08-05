/**
 * The rehearsal for #189: rotating `ANALYTICS_PSEUDONYM_KEY` without breaking erasure.
 *
 * **WHAT THIS FILE HAS TO PROVE, AND WHY IT IS NOT THE SAME AS IDENTITY'S.**
 *
 * `identity/src/rewrap.test.ts` proves a DRAIN: every blob is re-encrypted under the new key, and
 * afterwards the old key can be deleted. There is no equivalent here and there cannot be. A
 * pseudonym is derived, not encrypted:
 *
 *     lookup_key = HMAC(pepper, "cf.analytics.lookup.v1|" || subject)
 *
 * and the raw subject is never stored, by design and by constraint. So a stored `lookup_key` can
 * never be rewritten under a new pepper — the input that produced it does not exist anywhere in
 * this database. `no drain is possible, and it must not be faked` below asserts exactly that, so
 * that nobody later "fixes" this file by inventing a migration that silently loses the mapping.
 *
 * What replaces the drain is a RING: the newest pepper mints, and every pepper held is tried on
 * lookup. The subject is supplied by the caller in both directions — ingest has it from the
 * envelope, erasure has it from `identity.user.deleted` — so an old mapping is still reachable.
 *
 * The negative controls, in both directions the brief demands:
 *
 *   1. **A WRONG PEPPER MUST FAIL** — a subject derived under an unrelated pepper must not find a
 *      mapping minted under the real one, or the pepper is doing nothing.
 *   2. **A NEW PEPPER WITHOUT THE OLD ONE MUST FAIL** — the analytics analogue of skipping the
 *      drain. Dropping the old pepper from the ring while rows still reference it must ORPHAN
 *      those rows and must BREAK erasure for them. That is the #189 regression, reproduced
 *      deliberately, so the ring can never be quietly reduced to one value again.
 *
 * No pepper, subject or digest value is ever printed. Counts and booleans only.
 */

import { TEST_PEPPER_V1, TEST_PEPPER_V2, migrateTestDb, openDb, resetAnalytics, skip } from './testsupport.ts'
import { TABLES } from './migrations.ts'
import { before, after, beforeEach, describe, it } from 'node:test'
import assert from 'node:assert/strict'
import type postgres from 'postgres'
import {
  PepperRing,
  deriveSubject,
  eraseSubject,
  isAttributable,
  rawSubject,
  subjectsBelowVersion,
} from './pseudonym.ts'

let sql: postgres.Sql

/** Before the rotation: one pepper. */
const ringV1 = new PepperRing(new Map([[1, TEST_PEPPER_V1]]), 1)
/** During and after: both peppers held, the NEW one mints. This is how the service runs. */
const ringBoth = new PepperRing(
  new Map([
    [1, TEST_PEPPER_V1],
    [2, TEST_PEPPER_V2],
  ]),
  2,
)
/** The mistake: the old pepper dropped while rows still reference it. */
const ringV2Only = new PepperRing(new Map([[2, TEST_PEPPER_V2]]), 2)
/** An unrelated pepper, for the "is this doing anything at all" control. */
const ringWrong = new PepperRing(new Map([[1, 'an-entirely-unrelated-pepper-0011223344']]), 1)

const SPIROS = rawSubject('user:550e8400-e29b-41d4-a716-446655440000')
const OTHER = rawSubject('user:6ba7b810-9dad-11d1-80b4-00c04fd430c8')

before(async () => {
  if (!skip) {
    sql = openDb()
    await migrateTestDb(sql)
  }
})

after(async () => {
  if (!skip) await sql.end({ timeout: 5 })
})

beforeEach(async () => {
  if (!skip) await resetAnalytics(sql)
})

describe('rotating the pepper', { skip }, () => {
  /* ─────────────────────────────────────────────────────── the negative controls ───────────── */

  it('NEGATIVE CONTROL: a wrong pepper does not find a mapping', async () => {
    await deriveSubject(sql, ringV1, SPIROS, new Date())

    // Same subject, same code path, unrelated pepper. If this were attributable the pepper would be
    // decorative and every other assertion in this file would be vacuous.
    assert.equal(await isAttributable(sql, ringWrong, SPIROS), false)
    assert.equal(await isAttributable(sql, ringV1, SPIROS), true)
  })

  it('NEGATIVE CONTROL: dropping the old pepper orphans its rows and breaks their erasure', async () => {
    const before = await deriveSubject(sql, ringV1, SPIROS, new Date())
    assert.equal(before.status, 'ok')

    // The #189 regression, performed on purpose: the old pepper is gone while its row remains.
    //
    // The person is no longer findable, so they are no longer ERASABLE — an erasure request now
    // writes a fresh tombstone under the new pepper and leaves the real mapping live and fully
    // attributable. That is the compliance failure, and this asserts it happens, so that the ring
    // can never be silently reduced back to a single value.
    assert.equal(await isAttributable(sql, ringV2Only, SPIROS), false)

    await eraseSubject(sql, ringV2Only, SPIROS, new Date())

    // Still attributable under the pepper that minted it: the erasure did not reach the row.
    assert.equal(await isAttributable(sql, ringV1, SPIROS), true)
    const live = await sql<{ n: number }[]>`select count(*) as n from subject_keys where erased_at is null`
    assert.equal(Number(live[0]?.n), 1, 'the real mapping survived an erasure that should have destroyed it')
  })

  it('a ring refuses a write version it holds no pepper for', () => {
    assert.throws(() => new PepperRing(new Map([[1, TEST_PEPPER_V1]]), 2), /no pepper for the write version v2/)
    assert.throws(() => new PepperRing(new Map(), 1), /at least one pepper/)
  })

  /* ─────────────────────────────────────────── what the rotation must preserve ─────────────── */

  it('a returning subject keeps ONE pseudonym across the rotation', async () => {
    const before = await deriveSubject(sql, ringV1, SPIROS, new Date())
    assert.equal(before.status, 'ok')
    assert.ok(before.status === 'ok' && before.minted, 'the first sighting mints')

    // The rotation: the new pepper mints from here on, the old one is still held.
    const after = await deriveSubject(sql, ringBoth, SPIROS, new Date())
    assert.ok(after.status === 'ok')
    assert.equal(after.minted, false, 'a returning subject must NOT be minted a second pseudonym')
    assert.equal(
      after.subjectKey,
      before.status === 'ok' ? before.subjectKey : '',
      'the pseudonym must be the same one, or the history is orphaned',
    )

    // And exactly one mapping exists — the failure in #189 is that this becomes two.
    const rows = await sql<{ n: number }[]>`select count(*) as n from subject_keys`
    assert.equal(Number(rows[0]?.n), 1)
  })

  it('ERASURE STILL REACHES A PRE-ROTATION SUBJECT — the point of #189', async () => {
    // Minted under the OLD pepper, before the rotation.
    const before = await deriveSubject(sql, ringV1, SPIROS, new Date())
    assert.ok(before.status === 'ok')
    assert.equal(await isAttributable(sql, ringBoth, SPIROS), true)

    // The erasure arrives AFTER the rotation, carrying the raw subject as it always does.
    const outcome = await eraseSubject(sql, ringBoth, SPIROS, new Date())
    assert.equal(outcome.erased, true)
    assert.equal(outcome.alreadyErased, false)

    // Unattributable under every pepper — which is what erasure has to mean.
    assert.equal(await isAttributable(sql, ringBoth, SPIROS), false)
    assert.equal(await isAttributable(sql, ringV1, SPIROS), false)

    // And the row is a real tombstone: the salt and the pseudonym are GONE, not flagged.
    const rows = await sql<{ subject_key: string | null; salt: string | null; erased_at: Date | null }[]>`
      select subject_key, salt, erased_at from subject_keys
    `
    assert.equal(rows.length, 1)
    assert.equal(rows[0]?.subject_key, null)
    assert.equal(rows[0]?.salt, null)
    assert.notEqual(rows[0]?.erased_at, null)
  })

  it('an erased pre-rotation subject is not re-minted under the new pepper', async () => {
    await deriveSubject(sql, ringV1, SPIROS, new Date())
    await eraseSubject(sql, ringBoth, SPIROS, new Date())

    // A late event for somebody who asked to be forgotten. The tombstone was written under the old
    // pepper, and the ring has to find it or the person quietly starts a second behavioural profile
    // — erasure undone by a rotation, which is the subtlest form of the #189 defect.
    const late = await deriveSubject(sql, ringBoth, SPIROS, new Date())
    assert.equal(late.status, 'erased')

    const live = await sql<{ n: number }[]>`select count(*) as n from subject_keys where erased_at is null`
    assert.equal(Number(live[0]?.n), 0)
  })

  it('a subject first seen AFTER the rotation is minted under the new pepper', async () => {
    const minted = await deriveSubject(sql, ringBoth, OTHER, new Date())
    assert.ok(minted.status === 'ok' && minted.minted)

    const rows = await sql<{ pepper_version: number }[]>`select pepper_version from subject_keys`
    assert.equal(rows[0]?.pepper_version, 2)

    // It is NOT findable under the old pepper alone, which is what makes the new pepper a real
    // replacement rather than a second name for the old one.
    assert.equal(await isAttributable(sql, ringV1, OTHER), false)
  })

  /* ──────────────────────────── the gauge that says when the old pepper may go ─────────────── */

  it('the gauge counts live mappings still tied to an older pepper', async () => {
    await deriveSubject(sql, ringV1, SPIROS, new Date())
    await deriveSubject(sql, ringBoth, OTHER, new Date())

    // One pre-rotation subject is still live, so the old pepper is still load-bearing.
    assert.equal(await subjectsBelowVersion(sql, 2), 1)

    // Erasure is one of the two things that retires a row; retention pruning is the other.
    await eraseSubject(sql, ringBoth, SPIROS, new Date())
    assert.equal(await subjectsBelowVersion(sql, 2), 0, 'now the old pepper may be dropped')
  })

  /* ──────────────────────────────────────────────── the constraint that shapes all of it ───── */

  it('no drain is possible, and it must not be faked', async () => {
    await deriveSubject(sql, ringV1, SPIROS, new Date())

    // THE REASON THERE IS NO DRAIN, ASSERTED RATHER THAN ASSUMED.
    //
    // A drain would have to recompute `lookup_key` under the new pepper, which needs the raw
    // subject. Nothing in this database holds one: there is no column whose value equals the
    // subject, and the stored digests are one-way. This check is what stops a future edit
    // "fixing" the rotation by adding a column that makes a drain possible — because such a
    // column is exactly the identifier this service promises never to keep.
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
        // Not merely "no column equals the subject" — no column CONTAINS it, so a composite value
        // that embedded it would be caught too.
        assert.ok(
          !v.includes(String(SPIROS)) && !v.includes('550e8400'),
          `${column.table_name}.${column.column_name} holds the raw subject, which would make a drain possible and this service's promise false`,
        )
      }
    }
    assert.ok(inspected > 0, 'no values were inspected, so nothing was proved')
  })
})
