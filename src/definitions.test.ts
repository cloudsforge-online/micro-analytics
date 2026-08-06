/**
 * The metric catalogue, and the one thing it must never do.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A RETENTION NUMBER THAT CHANGED DEFINITION IN MARCH IS A CHART THAT LIES ABOUT FEBRUARY.**
 *
 * 13-operational-model.md, and it is the whole of this file. `publish()` is not an upsert:
 * republishing `(id, version)` with different arithmetic THROWS, and the `metric_definitions`
 * trigger refuses the UPDATE that would paper over it. Both are asserted, and the second matters
 * independently of the first — a future code path that reached for `on conflict do update` would
 * pass a test of `publish()` alone and still be stopped by the database.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import {
  DEFINITIONS,
  DefinitionChangedError,
  checksumOf,
  listDefinitions,
  publish,
  type MetricDefinition,
} from './definitions.ts'
import { migrateTestDb, openDb, resetAnalytics, skip } from './testsupport.ts'

const BASE: MetricDefinition = {
  id: 'test.metric',
  version: 1,
  metric: 99,
  title: 'A metric',
  numerator: 'distinct subject_key with at least one thing',
  denominator: 'distinct active subject_key',
  window: '30d',
}

describe('metric definitions', { skip }, () => {
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

  /* ================================================================ the catalogue itself */

  describe('the catalogue this build carries', () => {
    it('states numerator, denominator and window for every metric', () => {
      // 13-operational-model.md. A metric that does not is a number two people read differently.
      for (const definition of DEFINITIONS) {
        assert.ok(definition.numerator.length > 0, `${definition.id} has no numerator`)
        assert.ok(definition.denominator.length > 0, `${definition.id} has no denominator`)
        assert.ok(definition.window.length > 0, `${definition.id} has no window`)
      }
    })

    it('has no duplicate (id, version)', () => {
      const keys = DEFINITIONS.map((definition) => `${definition.id}@${definition.version}`)
      assert.equal(new Set(keys).size, keys.length)
    })

    it('says outright that revenue comes from the ledger', () => {
      // 13-operational-model.md. This service holds amount_bucket and no amount, so a revenue
      // number computed here would be a range dressed up as a total.
      const revenue = DEFINITIONS.find((definition) => definition.id === 'revenue.shape')
      assert.ok(revenue)
      assert.match(revenue.window, /LEDGER/)
      assert.match(revenue.numerator, /never summed/)
    })
  })

  /* ================================================================ the checksum */

  describe('the checksum is over what the number MEANS', () => {
    it('changes when the numerator, denominator or window changes', () => {
      for (const field of ['numerator', 'denominator', 'window'] as const) {
        assert.notEqual(
          checksumOf(BASE),
          checksumOf({ ...BASE, [field]: 'something else' }),
          `${field} decides what the number means and must be pinned`,
        )
      }
    })

    it('does NOT change when the title is reworded', () => {
      // A title may be corrected without breaking a live series; the arithmetic may not change at
      // all. Pinning the title would make every copy-edit a fake redefinition, which is how a real
      // one stops being noticed.
      assert.equal(checksumOf(BASE), checksumOf({ ...BASE, title: 'A metric, reworded' }))
    })
  })

  /* ================================================================ publishing */

  describe('publishing', () => {
    it('is idempotent for text that has not changed', async () => {
      const first = await publish(sql, [BASE])
      assert.deepEqual(first, { published: ['test.metric@1'], alreadyPublished: [] })

      const second = await publish(sql, [BASE])
      assert.deepEqual(second, { published: [], alreadyPublished: ['test.metric@1'] })
    })

    it('THROWS rather than rewriting a released definition', async () => {
      await publish(sql, [BASE])
      await assert.rejects(
        () => publish(sql, [{ ...BASE, numerator: 'distinct subject_key with at least two things' }]),
        (err: unknown) =>
          err instanceof DefinitionChangedError && err.id === 'test.metric' && err.version === 1,
      )
    })

    it('leaves the released text intact after the refusal', async () => {
      await publish(sql, [BASE])
      await assert.rejects(() => publish(sql, [{ ...BASE, window: '90d' }]))
      const rows = await sql<{ window_spec: string }[]>`
        select window_spec from metric_definitions where id = ${BASE.id} and version = 1
      `
      assert.equal(rows[0]?.window_spec, '30d')
    })

    it('accepts a NEW VERSION with different arithmetic, which is the supported path', async () => {
      await publish(sql, [BASE])
      const result = await publish(sql, [{ ...BASE, version: 2, numerator: 'a different rule' }])
      assert.deepEqual(result.published, ['test.metric@2'])

      // Both survive, so February's chart still names the definition it was computed under.
      const stored = await listDefinitions(sql)
      assert.deepEqual(
        stored.map((definition) => `${definition.id}@${definition.version}`),
        ['test.metric@2', 'test.metric@1'],
      )
    })

    it('publishes this build’s whole catalogue at boot without complaint', async () => {
      const first = await publish(sql)
      assert.equal(first.published.length, DEFINITIONS.length)
      const second = await publish(sql)
      assert.equal(second.alreadyPublished.length, DEFINITIONS.length)
      assert.equal(second.published.length, 0)
    })
  })

  /* ================================================================ the database's own refusal */

  describe('the database refuses an UPDATE, independently of publish()', () => {
    it('a released definition cannot be edited by hand', async () => {
      await publish(sql, [BASE])
      // With the service bypassed entirely: a code path that reached for `on conflict do update`
      // would pass every test of publish() above and still be stopped here.
      await assert.rejects(
        () => sql`update metric_definitions set numerator = 'rewritten' where id = ${BASE.id}`,
        (err: unknown) => /immutable/.test((err as Error).message),
      )
    })

    it('refuses a checksum that is not a digest', async () => {
      await assert.rejects(
        () => sql`
          insert into metric_definitions (id, version, title, numerator, denominator, window_spec, checksum)
          values ('bad', 1, 't', 'n', 'd', 'w', 'not-a-digest')
        `,
        (err: unknown) => (err as { constraint_name?: string }).constraint_name === 'metric_definitions_checksum_shape',
      )
    })

    it('refuses version zero', async () => {
      await assert.rejects(
        () => sql`
          insert into metric_definitions (id, version, title, numerator, denominator, window_spec, checksum)
          values ('bad', 0, 't', 'n', 'd', 'w', ${'a'.repeat(64).replace(/a/g, '0')})
        `,
        (err: unknown) => (err as { constraint_name?: string }).constraint_name === 'metric_definitions_version',
      )
    })
  })

  /* ================================================================ the changelog */

  describe('the changelog', () => {
    it('returns every version ever published, newest first per id', async () => {
      await publish(sql, [BASE, { ...BASE, version: 2, window: '90d' }])
      const stored = await listDefinitions(sql)
      assert.deepEqual(stored.map((definition) => definition.version), [2, 1])
      assert.equal(stored[0]?.window, '90d')
      assert.equal(stored[1]?.window, '30d')
      assert.match(stored[0]!.publishedAt, /^\d{4}-\d{2}-\d{2}T/)
    })
  })
})
