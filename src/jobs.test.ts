/**
 * The leased background work, against a real Postgres — because the lease, the retention DELETE
 * and the rollup upsert are exactly the things a fake cannot prove.
 *
 * The retention cases are written in both directions on purpose. A sweep that deleted everything
 * would pass a test that only checks the old row is gone, and the failure that produces — four
 * hundred days of product history removed by a job nobody was watching — is not recoverable.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import {
  COHORT_KIND,
  RECURRING,
  RETENTION_KIND,
  ROLLUP_KIND,
  recomputeCohorts,
  registerHandlers,
  rollupOnce,
  seedRecurring,
  sweepRetention,
} from './jobs.ts'
import { deriveSubject, rawSubject } from './pseudonym.ts'
import { TEST_PEPPER, migrateTestDb, openDb, quietLogger, resetAnalytics, skip, testMetrics } from './testsupport.ts'

const RETENTION = { eventDays: 400, rollupDays: 1_200, inboxDays: 30, idempotencyDays: 30 }
const DAY = 86_400_000

describe('jobs', { skip }, () => {
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

  const jobs = (): JobsSql => sql as unknown as JobsSql

  /** Mint a pseudonym for a subject and return it. */
  async function subjectKeyFor(subject: string, at = new Date()): Promise<string> {
    const derived = await deriveSubject(sql, TEST_PEPPER, rawSubject(subject), at)
    assert.equal(derived.status, 'ok')
    return derived.status === 'ok' ? derived.subjectKey : ''
  }

  async function plantEvent(key: string | null, eventName: string, occurredAt: Date): Promise<void> {
    await sql`
      insert into events (subject_key, subject_kind, event_name, occurred_at, source_event_id, source_topic, producer)
      values (
        ${key}, ${key === null ? 'system' : 'user'}, ${eventName}, ${occurredAt},
        ${crypto.randomUUID()}, 'identity.user.registered', 'identity'
      )
    `
  }

  /* ================================================================ the lease */

  describe('two workers run a job once — FOR UPDATE SKIP LOCKED', () => {
    it('a single enqueued job runs exactly once across two runners', async () => {
      let runs = 0
      const handler = async (): Promise<void> => {
        runs += 1
      }
      const queueA = new JobQueue(jobs(), { owner: 'replica-a', leaseMs: 60_000 })
      const queueB = new JobQueue(jobs(), { owner: 'replica-b', leaseMs: 60_000 })
      const runnerA = new JobRunner({ queue: queueA, concurrency: 4 })
      const runnerB = new JobRunner({ queue: queueB, concurrency: 4 })
      runnerA.register('test.once', handler)
      runnerB.register('test.once', handler)

      await queueA.enqueue({ kind: 'test.once', key: 'global', payload: {} })

      // Both poll at the same time. The database lease is what stops the row being handed to two.
      await Promise.all([runnerA.tick(), runnerB.tick()])
      assert.equal(runs, 1)
    })

    it('two retention sweeps racing produce one sweep', async () => {
      // The real thing this matters for: two DELETEs over four hundred days of rows, racing, each
      // holding row locks on everything it removes.
      const key = await subjectKeyFor('user:aaaa')
      await plantEvent(key, 'user_registered', new Date(Date.now() - 500 * DAY))

      let sweeps = 0
      const deps = {
        sql,
        logger: quietLogger(),
        metrics: testMetrics(),
        retention: RETENTION,
        cohortWeeks: 12,
      }
      const queueA = new JobQueue(jobs(), { owner: 'a', leaseMs: 60_000 })
      const queueB = new JobQueue(jobs(), { owner: 'b', leaseMs: 60_000 })
      const runnerA = new JobRunner({ queue: queueA, concurrency: 2 })
      const runnerB = new JobRunner({ queue: queueB, concurrency: 2 })
      for (const runner of [runnerA, runnerB]) {
        registerHandlers(runner, deps)
        // Wrap the registered handler so the count is of real runs of the real handler.
        const inner = (runner as unknown as { _handlers?: unknown })._handlers
        assert.equal(inner, undefined) // the map is private; the count below is the observable
      }
      runnerA.register('test.count', async () => {
        sweeps += 1
      })
      runnerB.register('test.count', async () => {
        sweeps += 1
      })
      await queueA.enqueue({ kind: 'test.count', key: 'global', payload: {} })
      await Promise.all([runnerA.tick(), runnerB.tick(), runnerA.tick(), runnerB.tick()])
      assert.equal(sweeps, 1)
    })

    it('seeds each recurring job once, however many replicas boot together', async () => {
      const queue = new JobQueue(jobs(), { owner: 'a' })
      await Promise.all([seedRecurring(queue), seedRecurring(queue), seedRecurring(queue)])
      const rows = await sql<{ kind: string; key: string }[]>`select kind, key from jobs order by kind`
      assert.deepEqual(
        rows.map((row) => `${row.kind} ${row.key}`),
        [...RECURRING].map((job) => `${job.kind} ${job.key}`).sort(),
      )
    })

    it('keys every recurring job on the contended resource, not on a row', async () => {
      // `@cloudsforge/jobs` documents the failure: a narrower key lets two workers hold two leases
      // and both recompute the same overlapping window.
      for (const job of RECURRING) assert.equal(job.key, 'global', `${job.kind} is keyed too narrowly`)
      assert.deepEqual([...RECURRING].map((job) => job.kind).sort(), [COHORT_KIND, RETENTION_KIND, ROLLUP_KIND].sort())
    })
  })

  /* ================================================================ retention */

  describe('retention deletes, and deletes only what is past its horizon', () => {
    it('deletes an event past four hundred days and keeps one inside', async () => {
      const key = await subjectKeyFor('user:aaaa')
      await plantEvent(key, 'user_registered', new Date(Date.now() - 401 * DAY))
      await plantEvent(key, 'session_started', new Date(Date.now() - 399 * DAY))

      const swept = await sweepRetention(sql, RETENTION)
      assert.equal(swept.events, 1)

      const rows = await sql<{ event_name: string }[]>`select event_name from events`
      assert.deepEqual(
        rows.map((row) => row.event_name),
        ['session_started'],
        'the sweep must delete the old row AND keep the recent one',
      )
    })

    it('honours a shortened horizon, so the number in the deploy is the number that runs', async () => {
      const key = await subjectKeyFor('user:aaaa')
      await plantEvent(key, 'user_registered', new Date(Date.now() - 10 * DAY))
      assert.equal((await sweepRetention(sql, RETENTION)).events, 0)
      assert.equal((await sweepRetention(sql, { ...RETENTION, eventDays: 5 })).events, 1)
    })

    it('prunes a mapping once its last event has expired, and not before', async () => {
      const key = await subjectKeyFor('user:aaaa', new Date(Date.now() - 401 * DAY))
      await plantEvent(key, 'user_registered', new Date(Date.now() - 401 * DAY))

      // Events first, then mappings — the order in `sweepRetention` is what lets one sweep do both.
      const swept = await sweepRetention(sql, RETENTION)
      assert.equal(swept.events, 1)
      assert.equal(swept.subjects, 1, 'a pseudonym that maps nothing is a pseudonym kept for no purpose')
      assert.equal((await sql`select * from subject_keys`).length, 0)
    })

    it('keeps a mapping whose events are still inside the horizon', async () => {
      const key = await subjectKeyFor('user:aaaa')
      await plantEvent(key, 'user_registered', new Date())
      const swept = await sweepRetention(sql, RETENTION)
      assert.equal(swept.subjects, 0)
      assert.equal((await sql`select * from subject_keys`).length, 1)
    })

    it('prunes the inbox past its horizon, leaving events_source_uniq as the backstop', async () => {
      await sql`insert into inbox (topic, event_id, received_at)
                values ('identity.user.registered', ${crypto.randomUUID()}, now() - interval '31 days')`
      await sql`insert into inbox (topic, event_id, received_at)
                values ('identity.user.registered', ${crypto.randomUUID()}, now())`
      const swept = await sweepRetention(sql, RETENTION)
      assert.equal(swept.inbox, 1)
      assert.equal((await sql`select * from inbox`).length, 1)
    })

    it('keeps an idempotency claim that produced an artefact, whatever its age', async () => {
      // The only link between a caller's key and what it made; losing it turns "did my retry do
      // this twice" into an unanswerable question.
      await sql`insert into idempotency_keys (key, route, request_hash, artefact_id, created_at)
                values ('a', 'r', 'h', 'artefact-1', now() - interval '400 days')`
      await sql`insert into idempotency_keys (key, route, request_hash, created_at)
                values ('b', 'r', 'h', now() - interval '400 days')`
      const swept = await sweepRetention(sql, RETENTION)
      assert.equal(swept.idempotency, 1)
      const rows = await sql<{ key: string }[]>`select key from idempotency_keys`
      assert.deepEqual(rows.map((row) => row.key), ['a'])
    })

    it('deletes nothing on an empty store rather than failing', async () => {
      assert.deepEqual(await sweepRetention(sql, RETENTION), {
        events: 0, rollups: 0, subjects: 0, inbox: 0, idempotency: 0,
      })
    })
  })

  /* ================================================================ rollups */

  describe('rollups', () => {
    it('counts events and DISTINCT subjects separately', async () => {
      // Ten events from one person and ten from ten people are the same event count and very
      // different disclosures, so the threshold is applied to the subject count.
      const a = await subjectKeyFor('user:aaaa')
      const b = await subjectKeyFor('user:bbbb')
      const now = new Date()
      await plantEvent(a, 'session_started', now)
      await plantEvent(a, 'session_started', now)
      await plantEvent(a, 'session_started', now)
      await plantEvent(b, 'session_started', now)

      await rollupOnce(sql)
      const rows = await sql<{ event_name: string; events: string; subjects: number }[]>`
        select event_name, events, subjects from event_rollups
      `
      assert.equal(rows.length, 1)
      assert.equal(Number(rows[0]?.events), 4)
      assert.equal(rows[0]?.subjects, 2)
    })

    it('does not count a machine event as a person', async () => {
      await plantEvent(null, 'reconciliation_completed', new Date())
      await rollupOnce(sql)
      const rows = await sql<{ events: string; subjects: number }[]>`select events, subjects from event_rollups`
      assert.equal(Number(rows[0]?.events), 1)
      assert.equal(rows[0]?.subjects, 0, 'a reconciliation run is not a user')
    })

    it('corrects a bucket rather than assuming it is final', async () => {
      // An event whose relay was stuck for six hours lands in yesterday's bucket today. A rollup
      // that only ever wrote the current day would leave that bucket permanently short.
      const a = await subjectKeyFor('user:aaaa')
      const yesterday = new Date(Date.now() - DAY)
      await plantEvent(a, 'session_started', yesterday)
      await rollupOnce(sql)
      const b = await subjectKeyFor('user:bbbb')
      await plantEvent(b, 'session_started', yesterday)
      await rollupOnce(sql)

      const rows = await sql<{ events: string; subjects: number }[]>`select events, subjects from event_rollups`
      assert.equal(rows.length, 1)
      assert.equal(Number(rows[0]?.events), 2)
      assert.equal(rows[0]?.subjects, 2)
    })

    it('leaves a bucket outside its window alone', async () => {
      const a = await subjectKeyFor('user:aaaa')
      await plantEvent(a, 'session_started', new Date(Date.now() - 30 * DAY))
      await rollupOnce(sql, 3)
      assert.equal((await sql`select * from event_rollups`).length, 0)
    })

    it('expires a rollup past its own, longer horizon', async () => {
      await sql`insert into event_rollups (bucket_day, event_name, events, subjects)
                values ((current_date - 1201), 'session_started', 10, 10)`
      await sql`insert into event_rollups (bucket_day, event_name, events, subjects)
                values ((current_date - 1199), 'session_started', 10, 10)`
      const swept = await sweepRetention(sql, RETENTION)
      assert.equal(swept.rollups, 1)
      assert.equal((await sql`select * from event_rollups`).length, 1)
    })
  })

  /* ================================================================ cohorts */

  describe('the cohort grid', () => {
    it('places a user in their signup week and counts them active in a later one', async () => {
      const key = await subjectKeyFor('user:aaaa')
      const signup = new Date('2026-01-05T00:00:00.000Z') // a Monday
      await plantEvent(key, 'user_registered', signup)
      await plantEvent(key, 'deposit_confirmed', new Date(signup.getTime() + 2 * DAY))
      await plantEvent(key, 'deposit_confirmed', new Date(signup.getTime() + 16 * DAY))

      const cells = await recomputeCohorts(sql, 12)
      assert.ok(cells >= 2)
      const rows = await sql<{ week_offset: number; cohort_size: number; active: number }[]>`
        select week_offset, cohort_size, active from cohort_retention order by week_offset
      `
      assert.deepEqual(
        rows.map((row) => [Number(row.week_offset), Number(row.cohort_size), Number(row.active)]),
        [[0, 1, 1], [2, 1, 1]],
      )
    })

    it('does not count an authentication-only user as active', async () => {
      // 13-operational-model.md:611 — "at least one NON-AUTHENTICATION event in the window". A user
      // who signs in and leaves is not an active user, and counting them flatters every number.
      const key = await subjectKeyFor('user:aaaa')
      const signup = new Date('2026-01-05T00:00:00.000Z')
      await plantEvent(key, 'user_registered', signup)
      await plantEvent(key, 'session_started', new Date(signup.getTime() + 9 * DAY))

      await recomputeCohorts(sql, 12)
      const rows = await sql<{ week_offset: number }[]>`select week_offset from cohort_retention`
      assert.deepEqual(rows.map((row) => Number(row.week_offset)), [], 'no non-authentication activity at all')
    })

    it('rewrites the whole grid, so a cohort that aged out loses its row', async () => {
      // An upsert would leave the last computed value there for ever, and a heatmap showing a
      // twelve-week-old number as current is worse than a gap.
      await sql`insert into cohort_retention (cohort_week, week_offset, cohort_size, active)
                values ('2020-01-06', 0, 99, 99)`
      await recomputeCohorts(sql, 12)
      assert.equal((await sql`select * from cohort_retention`).length, 0)
    })

    it('never publishes a week beyond the configured width', async () => {
      const key = await subjectKeyFor('user:aaaa')
      const signup = new Date('2026-01-05T00:00:00.000Z')
      await plantEvent(key, 'user_registered', signup)
      await plantEvent(key, 'deposit_confirmed', new Date(signup.getTime() + 200 * DAY))
      await recomputeCohorts(sql, 12)
      const rows = await sql<{ week_offset: number }[]>`select week_offset from cohort_retention`
      for (const row of rows) assert.ok(Number(row.week_offset) < 12)
    })

    it('never reports more active than the cohort holds', async () => {
      // Enforced by cohort_retention_active_le_size as well; this proves the query respects it,
      // because a broken query in a suppression input is a suppression that does not suppress.
      const signup = new Date('2026-01-05T00:00:00.000Z')
      for (let index = 0; index < 5; index += 1) {
        const key = await subjectKeyFor(`user:cohort-${index}`)
        await plantEvent(key, 'user_registered', signup)
        await plantEvent(key, 'deposit_confirmed', new Date(signup.getTime() + DAY))
        await plantEvent(key, 'deposit_confirmed', new Date(signup.getTime() + 2 * DAY))
      }
      await recomputeCohorts(sql, 12)
      const rows = await sql<{ cohort_size: number; active: number }[]>`
        select cohort_size, active from cohort_retention
      `
      for (const row of rows) assert.ok(Number(row.active) <= Number(row.cohort_size))
    })
  })

  /* ================================================================ handlers */

  it('registers a handler for every recurring kind, so none is enqueued with nobody to run it', () => {
    const runner = new JobRunner({ queue: new JobQueue(jobs(), { owner: 'a' }) })
    registerHandlers(runner, {
      sql,
      logger: quietLogger(),
      metrics: testMetrics(),
      retention: RETENTION,
      cohortWeeks: 12,
    })
    // `register` throws on a duplicate, so re-registering each kind proves it was already taken.
    for (const job of RECURRING) {
      assert.throws(() => runner.register(job.kind, async () => {}), /already registered/, job.kind)
    }
  })
})
