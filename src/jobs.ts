/**
 * Background work.
 *
 * Rule 8 of docs/ecosystem/03 §2: every background timer is a leased job. There is no `setInterval`
 * in this repository doing domain work, and CI greps for one
 * (`org/.github/workflows/service-ci.yml:443-463`).
 *
 * Each job is claimed `FOR UPDATE SKIP LOCKED` under a lease keyed `global`, so with N replicas
 * each tick runs exactly once. That matters more here than the rule alone suggests:
 *
 *   - **Retention deletes.** Two sweeps racing is survivable; two sweeps racing while a third
 *     replica is inserting is a long transaction holding row locks across the whole store.
 *   - **The rollup is an upsert on `(bucket_day, event_name)`.** Two workers recomputing the same
 *     day both write, and the loser's `count(distinct subject_key)` was taken at a different
 *     instant — so the published number depends on which transaction committed second.
 *   - **The cohort grid is a full recompute.** It is the most expensive query this service runs,
 *     and running it twice is the cheapest possible way to make the database the bottleneck.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **RETENTION IS A JOB THAT RUNS, NOT A DOCUMENTED INTENTION.**
 *
 * 11-data-and-contract-strategy.md:434 gives analytics events four hundred days, and a retention
 * policy that lives only in a table in a document is a policy that has never deleted a row.
 * `jobs.test.ts` plants a row past the horizon, runs `sweepRetention`, and asserts the row is gone
 * — and asserts a row inside the horizon is still there, because a sweep that deletes everything
 * also passes a test that only checks the first half.
 *
 * The sweep also prunes `subject_keys`. A mapping row that outlives every event it names is a
 * pseudonym kept for no purpose, and this service's whole argument is that it holds nothing it
 * does not need.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import { type JobQueue, type JobRunner, type RunnerEvent } from '@cloudsforge/jobs'
import type { Logger, Metrics } from '@cloudsforge/telemetry'
import { AUTHENTICATION_EVENTS } from './reads.ts'
import { pruneSubjects } from './pseudonym.ts'
import type { Db } from './store.ts'

export const ROLLUP_KIND = 'rollup'
export const RETENTION_KIND = 'retention'
export const COHORT_KIND = 'cohort.recompute'

export interface Recurring {
  readonly kind: string
  readonly key: string
  readonly everyMs: number
}

/**
 * Every recurring job. The key is `global` for all three because each contends on the same thing:
 * the rollup table, the deletions, or the cohort grid. Keying on anything narrower — a day, an
 * event name — would let two workers hold two leases and both recompute the same overlapping
 * window, which is the mistake `@cloudsforge/jobs` documents at `runtime/packages/jobs:16-27`.
 */
export const RECURRING: readonly Recurring[] = Object.freeze([
  { kind: ROLLUP_KIND, key: 'global', everyMs: 300_000 },
  { kind: RETENTION_KIND, key: 'global', everyMs: 3_600_000 },
  // Hourly. The grid is a twelve-week window over the whole store, and it moves slowly enough that
  // recomputing it more often would be work nobody reads.
  { kind: COHORT_KIND, key: 'global', everyMs: 3_600_000 },
])

/** Enqueue the recurring set at boot. `keep` means N replicas booting together produce one row. */
export async function seedRecurring(queue: JobQueue): Promise<void> {
  for (const job of RECURRING) {
    await queue.enqueue({ kind: job.kind, key: job.key, onConflict: 'keep', payload: {} })
  }
}

/**
 * Re-arm a recurring job from its completion event — the only moment the row is gone. A
 * dead-lettered recurring job is deliberately NOT re-armed: the row stays, `jobs_dead_total`
 * climbs, and that is how an operator learns that retention has stopped running.
 */
export function rescheduleRecurring(queue: JobQueue, logger: Logger): (event: RunnerEvent) => void {
  const byKey = new Map(RECURRING.map((job) => [`${job.kind} ${job.key}`, job]))
  return (event) => {
    if (event.type !== 'completed' || !event.kind || !event.key) return
    const job = byKey.get(`${event.kind} ${event.key}`)
    if (!job) return
    void queue
      .enqueue({
        kind: job.kind,
        key: job.key,
        runAt: new Date(Date.now() + job.everyMs),
        onConflict: 'earliest',
        payload: {},
      })
      .catch((err: unknown) => logger.error('failed to re-arm recurring job', { kind: job.kind, err }))
  }
}

export interface Retention {
  readonly eventDays: number
  readonly rollupDays: number
  readonly inboxDays: number
  readonly idempotencyDays: number
}

export interface JobDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly metrics: Metrics
  readonly retention: Retention
  readonly cohortWeeks: number
}

export function registerHandlers(runner: JobRunner, deps: JobDeps): JobRunner {
  runner.register(ROLLUP_KIND, async () => {
    await rollupOnce(deps.sql)
  })

  runner.register(RETENTION_KIND, async () => {
    const swept = await sweepRetention(deps.sql, deps.retention)
    deps.logger.info('retention sweep', { ...swept })
    deps.metrics.increment('analytics_retention_deleted_total', { table: 'events' }, swept.events)
    deps.metrics.increment('analytics_retention_deleted_total', { table: 'subject_keys' }, swept.subjects)
  })

  runner.register(COHORT_KIND, async () => {
    const cells = await recomputeCohorts(deps.sql, deps.cohortWeeks)
    deps.logger.info('cohort grid recomputed', { cells })
  })

  return runner
}

/* ------------------------------------------------------------------ rollup */

/**
 * Upsert daily rollups over the last few days.
 *
 * Re-runs over a window rather than only the current day, on purpose: `occurred_at` is when the
 * fact happened, and an event whose relay was stuck for six hours lands in yesterday's bucket
 * today. A rollup that only ever wrote the current day would leave that bucket permanently short.
 *
 * `subjects` is `count(distinct subject_key)`, which is the number every metric in 13 §12 is about
 * and the number the suppression threshold is applied to. `filter (where subject_key is not null)`
 * matters: a machine event has no subject, and counting it as a person would make a reconciliation
 * run look like a user.
 */
export async function rollupOnce(sql: Db, days = 3): Promise<void> {
  await sql`
    insert into event_rollups (bucket_day, event_name, events, subjects, computed_at)
    select date_trunc('day', occurred_at)::date                              as bucket_day,
           event_name,
           count(*)::bigint                                                  as events,
           count(distinct subject_key) filter (where subject_key is not null)::int as subjects,
           now()
      from events
     where occurred_at >= date_trunc('day', now() - make_interval(days => ${days}))
     group by bucket_day, event_name
    on conflict (bucket_day, event_name) do update set
      events = excluded.events, subjects = excluded.subjects, computed_at = now()
  `
}

/* ------------------------------------------------------------------ retention */

export interface SweepResult {
  readonly events: number
  readonly rollups: number
  readonly subjects: number
  readonly inbox: number
  readonly idempotency: number
}

/**
 * Delete everything past its horizon, and prune the mappings that no longer map anything.
 *
 * ORDER MATTERS. Events go first, so `pruneSubjects` sees the store as it will be and can drop a
 * mapping whose last event has just expired. Doing it the other way round keeps every mapping one
 * sweep longer than it needs to exist — which is a pseudonym for a person, retained for no reason,
 * in the one service that claims to hold nothing it does not need.
 */
export async function sweepRetention(sql: Db, retention: Retention): Promise<SweepResult> {
  const events = await deleted(sql`
    delete from events where occurred_at < now() - make_interval(days => ${retention.eventDays})
  `)
  const rollups = await deleted(sql`
    delete from event_rollups where bucket_day < (current_date - make_interval(days => ${retention.rollupDays}))
  `)

  const cutoff = new Date(Date.now() - retention.eventDays * 86_400_000)
  const subjects = await pruneSubjects(sql, cutoff)

  // The inbox is a redelivery horizon, not an archive: past it, `events_source_uniq` is still
  // there and still refuses a duplicate, so the row has stopped earning its storage.
  const inbox = await deleted(sql`
    delete from inbox where received_at < now() - make_interval(days => ${retention.inboxDays})
  `)
  // A claim that produced an artefact is kept regardless of age — it is the only link between a
  // caller's key and what it made. Same rule as market/src/idempotency.ts:198.
  const idempotency = await deleted(sql`
    delete from idempotency_keys
     where created_at < now() - make_interval(days => ${retention.idempotencyDays})
       and artefact_id is null
  `)

  return { events, rollups, subjects, inbox, idempotency }
}

/* ------------------------------------------------------------------ cohorts */

/**
 * Recompute the retention grid. Metric 18.
 *
 * A cohort is the ISO week of a subject's FIRST `user_registered`, and a subject is active in week
 * N if they emitted a non-authentication event in it — 13-operational-model.md:610 defines "active"
 * in exactly those words.
 *
 * The whole grid is rewritten inside one transaction rather than upserted cell by cell. A cohort
 * whose subjects have all aged out of retention must lose its row; an upsert would leave the last
 * computed value there for ever, and a heatmap showing a twelve-week-old number as current is
 * worse than a gap.
 */
export async function recomputeCohorts(sql: Db, weeks: number): Promise<number> {
  const outcome = await sql.begin(async (tx) => {
    await tx`delete from cohort_retention`
    const rows = await tx<{ inserted: string }[]>`
      with cohorts as (
        select subject_key, date_trunc('week', min(occurred_at))::date as cohort_week
          from events
         where event_name = 'user_registered' and subject_key is not null
         group by subject_key
      ),
      sizes as (
        select cohort_week, count(*)::int as cohort_size from cohorts group by cohort_week
      ),
      activity as (
        select c.cohort_week,
               ((date_trunc('week', e.occurred_at)::date - c.cohort_week) / 7)::int as week_offset,
               count(distinct e.subject_key)::int as active
          from cohorts c
          join events e on e.subject_key = c.subject_key
         where e.event_name <> all(${AUTHENTICATION_EVENTS as string[]}::text[])
         group by c.cohort_week, week_offset
      ),
      inserted as (
        insert into cohort_retention (cohort_week, week_offset, cohort_size, active)
        select s.cohort_week, a.week_offset, s.cohort_size, a.active
          from sizes s
          join activity a on a.cohort_week = s.cohort_week
         where a.week_offset >= 0 and a.week_offset < ${weeks}
        returning 1
      )
      select count(*) as inserted from inserted
    `
    return { value: Number(rows[0]?.inserted ?? 0) }
  })
  return outcome.value
}

/* ------------------------------------------------------------------ gauges */

/** Refresh the queue-depth gauges. Called at scrape time, never on a timer. */
export async function sampleQueue(queue: JobQueue, metrics: Metrics): Promise<void> {
  const stats = await queue.stats()
  metrics.set('jobs_pending', stats.pending)
  metrics.set('jobs_overdue', stats.overdue)
}

/** postgres.js returns a result whose `count` is the affected-row count for a write. */
async function deleted(promise: Promise<unknown>): Promise<number> {
  const result = (await promise) as unknown as { count?: number }
  return typeof result.count === 'number' ? result.count : 0
}
