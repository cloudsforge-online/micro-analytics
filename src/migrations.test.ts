/**
 * The schema, against a real Postgres — because a CHECK constraint is exactly the thing a fake
 * cannot prove, and the four in this schema are the whole privacy argument of the service.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **EVERY CASE HERE ATTACKS THE DATABASE DIRECTLY, WITH THE SERVICE BYPASSED.**
 *
 * There is no ingest path in this file, no sanitiser and no pseudonymiser. Each case is a bare
 * `INSERT` issued on a connection, which is precisely the position of an attacker who has reached
 * the database, or of a code path nobody has written yet. If the constraint is the guarantee, it
 * has to hold against a caller who is not asking politely.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { EVENT_NAMES, PROPERTY_NAMES } from './catalogue.ts'
import { FORBIDDEN_COLUMNS, SCHEMA_VERSION, TABLES } from './migrations.ts'
import { migrateTestDb, openDb, resetAnalytics, skip } from './testsupport.ts'

const HEX64 = 'a'.repeat(64)
const OTHER_HEX64 = 'b'.repeat(64)

describe('migrations', { skip }, () => {
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

  /** Insert an event with these overrides, bypassing everything. Returns the driver's error, if any. */
  async function insertEvent(overrides: Record<string, unknown> = {}): Promise<string | null> {
    const row = {
      subject_key: HEX64,
      subject_kind: 'user',
      event_name: 'user_registered',
      occurred_at: new Date().toISOString(),
      session: null,
      props: '{}',
      source_event_id: crypto.randomUUID(),
      source_topic: 'identity.user.registered',
      producer: 'identity',
      ...overrides,
    }
    try {
      await sql.unsafe(
        `insert into events (subject_key, subject_kind, event_name, occurred_at, session, props,
                             source_event_id, source_topic, producer)
         values ($1, $2, $3, $4, $5, $6::text::jsonb, $7, $8, $9)`,
        [
          row.subject_key, row.subject_kind, row.event_name, row.occurred_at, row.session,
          row.props, row.source_event_id, row.source_topic, row.producer,
        ] as (string | null)[],
      )
      return null
    } catch (err) {
      return (err as { constraint_name?: string; message: string }).constraint_name ?? (err as Error).message
    }
  }

  /* ================================================================ the raw subject */

  describe('a raw subject cannot reach the event store, even with the service bypassed', () => {
    const rawSubjects: ReadonlyArray<readonly [string, string]> = [
      ['a bare user id', '550e8400-e29b-41d4-a716-446655440000'],
      ['an actor', 'user:550e8400-e29b-41d4-a716-446655440000'],
      ['an operator actor', 'operator:ops-14'],
      ['an email', 'savvanisspiros@gmail.com'],
      ['a handle', 'spiros'],
      ['a wallet address', '0x71c7656ec7ab88b098defb751b7401b5f6d8976f'],
      ['a display name', 'Spiros Savvanis'],
      ['an uppercase digest', 'A'.repeat(64)],
      ['a digest one character short', 'a'.repeat(63)],
      ['a digest one character long', 'a'.repeat(65)],
      ['a digest with a non-hex character', `${'a'.repeat(63)}g`],
      ['an empty string', ''],
    ]

    for (const [what, value] of rawSubjects) {
      it(`refuses ${what}`, async () => {
        assert.equal(
          await insertEvent({ subject_key: value }),
          'events_subject_shape',
          `the database accepted ${what} as a subject_key`,
        )
      })
    }

    it('accepts a 64-character lowercase hex digest, so the guard is not vacuous', async () => {
      assert.equal(await insertEvent({ subject_key: HEX64 }), null)
    })

    it('refuses a raw subject in subject_keys too', async () => {
      // The mapping table is the other place a raw identifier could be stored, and it is the one
      // an attacker would reach for: it is where the lookup happens.
      await assert.rejects(
        sql`insert into subject_keys (lookup_key, subject_key, salt)
            values ('user:550e8400-e29b-41d4-a716-446655440000', ${HEX64}, ${OTHER_HEX64})`,
        /subject_keys_lookup_shape/,
      )
      await assert.rejects(
        sql`insert into subject_keys (lookup_key, subject_key, salt)
            values (${HEX64}, 'savvanisspiros@gmail.com', ${OTHER_HEX64})`,
        /subject_keys_subject_shape/,
      )
    })

    it('refuses a raw session identifier', async () => {
      // A browser session id that also appears in a log or a support ticket would be a join key
      // straight back to a person, so the column holds a pseudonym or nothing.
      assert.equal(await insertEvent({ session: 'sess_9f3a-user-spiros' }), 'events_session_shape')
      assert.equal(await insertEvent({ session: OTHER_HEX64 }), null)
    })
  })

  /* ================================================================ person <-> pseudonym */

  describe('a person has a pseudonym and a machine has none — in both directions', () => {
    it('refuses a user event with no pseudonym', async () => {
      // Without this half, a bug that dropped the pseudonym would write an unattributable row into
      // a funnel and quietly shrink every cohort.
      assert.equal(await insertEvent({ subject_kind: 'user', subject_key: null }), 'events_person_has_pseudonym')
    })

    it('refuses an operator event with no pseudonym', async () => {
      assert.equal(await insertEvent({ subject_kind: 'operator', subject_key: null }), 'events_person_has_pseudonym')
    })

    it('refuses a system event that carries one', async () => {
      // Without this half, a machine event could be given a synthetic subject, which is how
      // "distinct users" becomes a number nobody can explain.
      assert.equal(await insertEvent({ subject_kind: 'system', subject_key: HEX64 }), 'events_person_has_pseudonym')
    })

    it('refuses a service event that carries one', async () => {
      assert.equal(await insertEvent({ subject_kind: 'service', subject_key: HEX64 }), 'events_person_has_pseudonym')
    })

    it('accepts the two legal shapes', async () => {
      assert.equal(await insertEvent({ subject_kind: 'user', subject_key: HEX64 }), null)
      assert.equal(
        await insertEvent({
          subject_kind: 'system',
          subject_key: null,
          event_name: 'reconciliation_completed',
        }),
        null,
      )
    })

    it('refuses an unknown subject kind', async () => {
      // With no pseudonym, so `events_person_has_pseudonym` is satisfied and this case can only
      // fail on the vocabulary — otherwise the test would pass without `events_subject_kind`
      // existing at all.
      assert.equal(await insertEvent({ subject_kind: 'robot', subject_key: null }), 'events_subject_kind')
    })
  })

  /* ================================================================ properties */

  describe('free text cannot be written into a property, even by hand', () => {
    const hostile: ReadonlyArray<readonly [string, string]> = [
      ['a display name under an unknown key', '{"display_name":"Spiros Savvanis"}'],
      ['a display name under an allowed key', '{"surface":"Spiros Savvanis"}'],
      ['a listing title', '{"surface":"1994 Corolla - must go!"}'],
      ['an email', '{"surface":"savvanisspiros@gmail.com"}'],
      ['a capitalised value', '{"surface":"Register"}'],
      ['a value with a space', '{"surface":"my page"}'],
      ['a nested object', '{"surface":{"deep":"Spiros"}}'],
      ['an array', '{"surface":["Spiros"]}'],
      ['a json null', '{"surface":null}'],
      ['a value past the length cap', `{"surface":"${'a'.repeat(33)}"}`],
      ['an unknown key with a harmless value', '{"page_title":"home"}'],
      ['a jsonb array as the whole props', '[]'],
      ['a jsonb string as the whole props', '"nope"'],
    ]

    for (const [what, props] of hostile) {
      it(`refuses ${what}`, async () => {
        assert.equal(await insertEvent({ props }), 'events_props_allowed', `the database accepted ${what}`)
      })
    }

    it('accepts an allowlisted slug, a number and a boolean, so the guard is not vacuous', async () => {
      assert.equal(await insertEvent({ props: '{"surface":"register","attempt":2,"is_first":true}'}), null)
    })

    it('refuses more properties than the cap', async () => {
      const wide = Object.fromEntries(PROPERTY_NAMES.slice(0, 14).map((name) => [name, 1]))
      assert.equal(await insertEvent({ props: JSON.stringify(wide) }), 'events_props_allowed')
    })

    it('refuses an event name outside the catalogue', async () => {
      assert.equal(await insertEvent({ event_name: 'page_title_viewed' }), 'events_name_known')
    })

    it('the CHECK list and the TypeScript catalogue agree', async () => {
      // Rendered from the same constant, so this proves the render rather than the list. A name
      // added to the catalogue without a migration would be accepted by ingest and refused here.
      for (const name of EVENT_NAMES) {
        assert.equal(await insertEvent({ event_name: name }), null, `${name} is in the catalogue but not the CHECK`)
      }
    })
  })

  /* ================================================================ erasure cannot be faked */

  describe('erasure cannot be faked', () => {
    it('refuses a row that claims to be erased while keeping its key', async () => {
      // THE LINE. Erasure here is the destruction of a salt; a "soft delete" that flagged the row
      // and kept the salt would look identical from the application and would erase nothing.
      await assert.rejects(
        sql`insert into subject_keys (lookup_key, subject_key, salt, erased_at)
            values (${HEX64}, ${OTHER_HEX64}, ${OTHER_HEX64}, now())`,
        /subject_keys_erased/,
      )
    })

    it('refuses a row that claims to be erased while keeping only its SALT', async () => {
      // The subtle half, and the one that caught a real defect in the first version of this
      // constraint. A kept salt plus the pepper plus a candidate user id recomputes the pseudonym,
      // so an "erasure" that nulls only `subject_key` erases nothing at all.
      await assert.rejects(
        sql`insert into subject_keys (lookup_key, subject_key, salt, erased_at)
            values (${HEX64}, null, ${OTHER_HEX64}, now())`,
        /subject_keys_erased/,
      )
    })

    it('refuses a row that claims to be erased while keeping only its pseudonym', async () => {
      await assert.rejects(
        sql`insert into subject_keys (lookup_key, subject_key, salt, erased_at)
            values (${HEX64}, ${OTHER_HEX64}, null, now())`,
        /subject_keys_erased/,
      )
    })

    it('refuses a live row with no pseudonym', async () => {
      await assert.rejects(
        sql`insert into subject_keys (lookup_key, subject_key, salt) values (${HEX64}, null, ${OTHER_HEX64})`,
        /subject_keys_erased/,
      )
    })

    it('refuses a live row with no salt', async () => {
      await assert.rejects(
        sql`insert into subject_keys (lookup_key, subject_key, salt) values (${HEX64}, ${OTHER_HEX64}, null)`,
        /subject_keys_erased/,
      )
    })

    it('accepts the two legal states', async () => {
      await sql`insert into subject_keys (lookup_key, subject_key, salt) values (${HEX64}, ${OTHER_HEX64}, ${OTHER_HEX64})`
      await sql`insert into subject_keys (lookup_key, subject_key, salt, erased_at)
                values (${'c'.repeat(64)}, null, null, now())`
      const rows = await sql<{ n: string }[]>`select count(*) as n from subject_keys`
      assert.equal(Number(rows[0]?.n), 2)
    })

    it('refuses two subjects sharing one pseudonym', async () => {
      // A collision would merge two people into one behavioural profile, and erasing one of them
      // would leave the other's events unattributable. Unique, so it cannot happen quietly.
      await sql`insert into subject_keys (lookup_key, subject_key, salt) values (${HEX64}, ${OTHER_HEX64}, ${OTHER_HEX64})`
      await assert.rejects(
        sql`insert into subject_keys (lookup_key, subject_key, salt)
            values (${'c'.repeat(64)}, ${OTHER_HEX64}, ${OTHER_HEX64})`,
        /subject_keys_subject_key_key|duplicate key/,
      )
    })
  })

  /* ================================================================ append-only */

  describe('the event store is append-only', () => {
    it('refuses an UPDATE', async () => {
      await insertEvent({ subject_key: HEX64 })
      await assert.rejects(sql`update events set event_name = 'session_started'`, /append-only/)
    })

    it('allows a DELETE, because retention is a deletion and not a rewrite', async () => {
      await insertEvent({ subject_key: HEX64 })
      const result = await sql`delete from events`
      assert.equal(result.count, 1)
    })

    it('refuses a duplicate source_event_id', async () => {
      const id = crypto.randomUUID()
      assert.equal(await insertEvent({ source_event_id: id }), null)
      const second = await insertEvent({ source_event_id: id })
      assert.match(String(second), /events_source_uniq|duplicate key/)
    })
  })

  /* ================================================================ the schema check */

  describe('the column names 11-data-and-contract-strategy.md:512 forbids', () => {
    it('appear in no table this service owns', async () => {
      // The CI check that document specifies, run where it can actually see the schema. A grep
      // over migrations.ts would miss a column added by a migration written next month.
      const rows = await sql<{ table_name: string; column_name: string }[]>`
        select table_name, column_name
          from information_schema.columns
         where table_schema = 'public'
           and table_name = any(${[...TABLES] as string[]}::text[])
           and column_name = any(${[...FORBIDDEN_COLUMNS] as string[]}::text[])
      `
      assert.deepEqual(
        rows.map((row) => `${row.table_name}.${row.column_name}`),
        [],
        'a forbidden column exists — AD-21, and 11-data-and-contract-strategy.md:512',
      )
    })

    it('the check is not vacuous — every table it names really exists', async () => {
      const rows = await sql<{ table_name: string }[]>`
        select table_name from information_schema.tables
         where table_schema = 'public' and table_name = any(${[...TABLES] as string[]}::text[])
      `
      assert.deepEqual(rows.map((row) => row.table_name).sort(), [...TABLES].sort())
    })
  })

  it('records the version index.ts asserts', async () => {
    const rows = await sql<{ v: string }[]>`select coalesce(max(version), 0)::bigint as v from schema_migrations`
    assert.equal(Number(rows[0]?.v), SCHEMA_VERSION)
  })
})
