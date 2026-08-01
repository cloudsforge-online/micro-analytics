/**
 * At most once per key, against a real Postgres.
 *
 * The shape is `market/src/idempotency.ts`'s, which took it from the ledger. Inheriting the code
 * without inheriting its tests would inherit the *appearance* of the four properties and none of
 * the proof, so each is asserted here:
 *
 *   1. the claim and the work share one transaction — a rolled-back run leaves no claim;
 *   2. a retry replays the stored response and does NOT run the work again;
 *   3. the same key with a different body is refused, never replayed;
 *   4. a claim with no response yet is "in flight", not "done".
 *
 * And the ledger's recorded defect, pinned in both directions: `correlationId` is EXCLUDED from the
 * fingerprint. A correlation id is supposed to change between attempts — it is what distinguishes a
 * retry in a trace — so fingerprinting it made every honest retry look like key reuse.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import {
  IdempotencyInFlightError,
  IdempotencyKeyReuseError,
  namespacedKey,
  requestFingerprint,
  withIdempotency,
} from './idempotency.ts'
import { migrateTestDb, openDb, resetAnalytics, skip } from './testsupport.ts'

const ROUTE = 'POST /cohorts/recompute'
const PRINCIPAL = 'service:admin-api'

describe('idempotency', { skip }, () => {
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

  /* ================================================================ the fingerprint */

  describe('the request fingerprint', () => {
    it('is stable under key order, because a legitimate retry may serialise differently', () => {
      assert.equal(
        requestFingerprint({ a: 1, b: { c: 2, d: 3 } }),
        requestFingerprint({ b: { d: 3, c: 2 }, a: 1 }),
      )
    })

    it('changes when the request changes', () => {
      assert.notEqual(requestFingerprint({ weeks: 12 }), requestFingerprint({ weeks: 13 }))
    })

    it('EXCLUDES correlationId, requestId and idempotencyKey — the ledger’s recorded defect', () => {
      const first = { kind: 'cohort.recompute', correlationId: 'corr-1', requestId: 'r-1', idempotencyKey: 'k-1' }
      const second = { kind: 'cohort.recompute', correlationId: 'corr-2', requestId: 'r-2', idempotencyKey: 'k-1' }
      assert.equal(
        requestFingerprint(first),
        requestFingerprint(second),
        'a retry carries a new correlation id by design; fingerprinting it rejects every honest retry',
      )
    })

    it('still distinguishes two different operations that share a correlation id', () => {
      // The exclusion must not become a hole: dropping the per-attempt fields cannot make two
      // genuinely different bodies fingerprint the same.
      assert.notEqual(
        requestFingerprint({ kind: 'a', correlationId: 'c' }),
        requestFingerprint({ kind: 'b', correlationId: 'c' }),
      )
    })
  })

  /* ================================================================ the namespace */

  describe('the stored key is namespaced', () => {
    it('separates two callers who chose the same client key', () => {
      assert.notEqual(
        namespacedKey('service:a', ROUTE, 'recompute-2026-08-01'),
        namespacedKey('service:b', ROUTE, 'recompute-2026-08-01'),
      )
    })

    it('separates one caller’s key across two routes, which are two operations', () => {
      assert.notEqual(
        namespacedKey(PRINCIPAL, 'POST /definitions', 'k'),
        namespacedKey(PRINCIPAL, 'POST /cohorts/recompute', 'k'),
      )
    })
  })

  /* ================================================================ replay */

  describe('a retry replays rather than re-running', () => {
    it('runs the work once and returns the stored response the second time', async () => {
      let runs = 0
      const call = (): Promise<{ result: { queued: number }; replayed: boolean }> =>
        withIdempotency(sql, {
          principal: PRINCIPAL,
          route: ROUTE,
          clientKey: 'recompute-0001',
          requestHash: requestFingerprint({ kind: 'cohort.recompute' }),
          run: async () => {
            runs += 1
            return { response: { queued: runs }, artefactId: null }
          },
        })

      const first = await call()
      assert.equal(first.replayed, false)
      assert.deepEqual(first.result, { queued: 1 })

      const second = await call()
      assert.equal(second.replayed, true, 'the second call must be a replay')
      assert.deepEqual(second.result, { queued: 1 }, 'and it must return the FIRST run’s answer')
      assert.equal(runs, 1, 'the work must not have run twice')
    })

    it('replays across a different correlation id, which is what a retry actually looks like', async () => {
      let runs = 0
      const call = (correlationId: string) =>
        withIdempotency(sql, {
          principal: PRINCIPAL,
          route: ROUTE,
          clientKey: 'recompute-0002',
          requestHash: requestFingerprint({ kind: 'cohort.recompute', correlationId }),
          run: async () => {
            runs += 1
            return { response: { ok: true }, artefactId: null }
          },
        })

      await call('corr-1')
      const retry = await call('corr-2')
      assert.equal(retry.replayed, true)
      assert.equal(runs, 1)
    })

    it('does not replay a different key', async () => {
      let runs = 0
      const call = (clientKey: string) =>
        withIdempotency(sql, {
          principal: PRINCIPAL,
          route: ROUTE,
          clientKey,
          requestHash: requestFingerprint({ kind: 'cohort.recompute' }),
          run: async () => {
            runs += 1
            return { response: { run: runs }, artefactId: null }
          },
        })
      await call('recompute-aaaa')
      await call('recompute-bbbb')
      assert.equal(runs, 2)
    })
  })

  /* ================================================================ reuse */

  describe('a reused key with a different body is refused, never replayed', () => {
    it('throws IdempotencyKeyReuseError', async () => {
      const call = (weeks: number) =>
        withIdempotency(sql, {
          principal: PRINCIPAL,
          route: ROUTE,
          clientKey: 'recompute-0003',
          requestHash: requestFingerprint({ weeks }),
          run: async () => ({ response: { weeks }, artefactId: null }),
        })

      await call(12)
      // Returning the first request's answer to a second, DIFFERENT request is worse than an
      // error: the caller believes the thing it asked for happened.
      await assert.rejects(() => call(24), IdempotencyKeyReuseError)

      // And the refusal leaves the first claim exactly as it was. Asserted in the same case rather
      // than the next one because `beforeEach` truncates between cases — a second `it` reading this
      // row would read an empty table and pass against nothing.
      const rows = await sql<{ response: { weeks: number } | null }[]>`
        select response from idempotency_keys where key = ${namespacedKey(PRINCIPAL, ROUTE, 'recompute-0003')}
      `
      assert.deepEqual(rows[0]?.response, { weeks: 12 })
    })
  })

  /* ================================================================ atomicity */

  describe('the claim and the work are one transaction', () => {
    it('leaves NO claim behind when the work throws, so a real retry can proceed', async () => {
      const clientKey = 'recompute-0004'
      await assert.rejects(() =>
        withIdempotency(sql, {
          principal: PRINCIPAL,
          route: ROUTE,
          clientKey,
          requestHash: requestFingerprint({ kind: 'x' }),
          run: async () => {
            throw new Error('the work failed')
          },
        }),
      )

      const rows = await sql`select 1 from idempotency_keys where key = ${namespacedKey(PRINCIPAL, ROUTE, clientKey)}`
      assert.equal(rows.length, 0, 'a claim that outlived its rolled-back work would wedge the key for ever')

      // And the retry succeeds, which is the observable consequence of the line above.
      const retry = await withIdempotency(sql, {
        principal: PRINCIPAL,
        route: ROUTE,
        clientKey,
        requestHash: requestFingerprint({ kind: 'x' }),
        run: async () => ({ response: { ok: true }, artefactId: null }),
      })
      assert.equal(retry.replayed, false)
    })

    it('the stored response is what committed, never what was merely computed', async () => {
      // The work writes a row; the response names it. Both are in one transaction, so a replay
      // cannot describe an artefact that does not exist.
      const clientKey = 'recompute-0005'
      const outcome = await withIdempotency(sql, {
        principal: PRINCIPAL,
        route: ROUTE,
        clientKey,
        requestHash: requestFingerprint({ kind: 'y' }),
        run: async (tx) => {
          const rows = await tx<{ day: Date }[]>`
            insert into ingest_rejections (day, reason, source_topic, rejections)
            values (current_date, 'unknown_topic', 'test.topic', 1)
            returning day
          `
          return { response: { rows: rows.length }, artefactId: 'test.topic' }
        },
      })
      assert.deepEqual(outcome.result, { rows: 1 })

      const stored = await sql<{ artefact_id: string | null }[]>`
        select artefact_id from idempotency_keys where key = ${namespacedKey(PRINCIPAL, ROUTE, clientKey)}
      `
      assert.equal(stored[0]?.artefact_id, 'test.topic')
      const rejections = await sql`select 1 from ingest_rejections where source_topic = 'test.topic'`
      assert.equal(rejections.length, 1)
    })
  })

  /* ================================================================ in flight */

  describe('a claim with no response yet is in flight, not done', () => {
    it('throws IdempotencyInFlightError rather than replaying an empty response', async () => {
      const clientKey = 'recompute-0006'
      const key = namespacedKey(PRINCIPAL, ROUTE, clientKey)
      // A committed claim whose response column is still null: what a caller sees between another
      // request's INSERT and its UPDATE. Replaying `null` here would tell the caller the operation
      // succeeded with an empty body.
      await sql`
        insert into idempotency_keys (key, route, request_hash)
        values (${key}, ${ROUTE}, ${requestFingerprint({ kind: 'z' })})
      `
      await assert.rejects(
        () =>
          withIdempotency(sql, {
            principal: PRINCIPAL,
            route: ROUTE,
            clientKey,
            requestHash: requestFingerprint({ kind: 'z' }),
            run: async () => ({ response: { ok: true }, artefactId: null }),
          }),
        IdempotencyInFlightError,
      )
    })
  })

  /* ================================================================ concurrency */

  describe('two concurrent requests with one key', () => {
    it('run the work once; the loser blocks and then replays', async () => {
      let runs = 0
      const call = () =>
        withIdempotency(sql, {
          principal: PRINCIPAL,
          route: ROUTE,
          clientKey: 'recompute-0007',
          requestHash: requestFingerprint({ kind: 'concurrent' }),
          run: async () => {
            runs += 1
            // Hold the transaction open long enough that the second claim is genuinely concurrent.
            await sql`select pg_sleep(0.15)`
            return { response: { run: runs }, artefactId: null }
          },
        })

      const [a, b] = await Promise.all([call(), call()])
      assert.equal(runs, 1, 'a duplicate must block on the uncommitted row, not run alongside it')
      assert.deepEqual([a.result, b.result], [{ run: 1 }, { run: 1 }])
      assert.deepEqual([a.replayed, b.replayed].sort(), [false, true])
    })
  })
})
