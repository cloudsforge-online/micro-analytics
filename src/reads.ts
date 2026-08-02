/**
 * The analysis surface, and the threshold that stands in front of all of it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **AN AGGREGATE OVER FEW PEOPLE IS A DISCLOSURE. A COHORT OF ONE IS THAT PERSON.**
 *
 * The pepper, the salt and the property allowlist all protect the *store*. None of them protects
 * the *answers*: "seven users in the 1k–10k bucket deposited on Tuesday" is a statement about
 * seven people, and "one user did" is a statement about one, whatever the subject column holds.
 * Anyone who knows one person registered on Tuesday reads that row and learns what they did.
 *
 * So every count this file returns passes `suppress()`, and every count below `minCohort` distinct
 * subjects comes back as `{ suppressed: true }` carrying **no number at all** — not a rounded one,
 * not a range, not "fewer than five". A rounded small count is still a small count, and "1–4"
 * combined with a second query is arithmetic.
 *
 * The threshold is five, and the reasoning is in the README. `env.ts` will let a deploy raise it
 * and refuses to let one lower it.
 *
 * **What this does not defend against, stated plainly:** differencing. An analyst who can run two
 * overlapping queries whose subject sets differ by one person can compute a suppressed cell from
 * two unsuppressed ones. Closing that needs a per-principal query budget, which is a bigger piece
 * of machinery than this service has, and it is recorded in the README rather than implied away.
 * What is closed here is the direct read — which is the one an operator reaches for by accident.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * ## Every count is of DISTINCT SUBJECTS, not of events
 *
 * Every metric in 13-operational-model.md §12 is phrased "users with at least one …", and the
 * distinction is load-bearing for suppression as well as for correctness: ten events from one
 * person and ten events from ten people are the same number of events and very different
 * disclosures. `events` is reported alongside, but the threshold is always applied to `subjects`.
 */

import { funnelFor, type FunnelSpec } from './catalogue.ts'
import type { Db } from './store.ts'

/**
 * A count that has passed the threshold, or the fact that it has not.
 *
 * A discriminated union rather than a nullable number, so a caller cannot render `null` as zero —
 * which is the bug that turns "we are not telling you" into "nobody did this".
 */
export type Count =
  | { readonly suppressed: false; readonly subjects: number; readonly events: number }
  | { readonly suppressed: true; readonly threshold: number }

/**
 * The one place a count becomes publishable.
 *
 * Zero is deliberately NOT suppressed: "nobody did this" discloses nothing about anybody, and
 * suppressing it would make an empty funnel indistinguishable from a busy one, which is how an
 * operator ends up disabling the threshold to find out. Everything from one up to the threshold is
 * suppressed.
 */
export function suppress(subjects: number, events: number, minCohort: number): Count {
  if (subjects === 0) return { suppressed: false, subjects: 0, events }
  if (subjects < minCohort) return { suppressed: true, threshold: minCohort }
  return { suppressed: false, subjects, events }
}

export interface Window {
  readonly from: Date
  readonly to: Date
}

/* ------------------------------------------------------------------ time, as a parameter */

/**
 * **Wall-clock time is an argument here, never an ambient fact.**
 *
 * Most of this file already took its window as a parameter — `dailySeries`, `activeSubjects` and
 * `funnel` are all handed a `Window` — and the one place that did not (`retentionGrid`, which
 * anchored its cutoff on SQL `now()`) produced a test whose result depended on the day it ran.
 *
 * The failure is worth stating precisely, because the shape recurs. `date_trunc('week', …)` cuts on
 * a **Monday, in the session's timezone**. A fixture written as "three weeks ago, plus a day" keeps
 * the weekday of whatever day the suite runs on, so on one weekday the two timestamps share an ISO
 * week and on another they straddle the Monday boundary and land in different `week_offset`s. The
 * suite was green for three weeks and red on a Sunday — and, worse, green for the wrong reason in
 * between, since nothing in it ever checked that the offset was computed rather than assumed.
 *
 * A test cannot pin an instant it is not allowed to supply. So the instant is supplied. Production
 * passes nothing and gets the real clock; a test passes a fixed one and derives its fixture from
 * the same value, which is the only arrangement in which the fixture and the window it is asserted
 * against cannot drift apart.
 *
 * The type is `() => Date` rather than `() => number` to match the estate's prevailing seam —
 * `notify/src/pipeline.ts:83`, `runtime/packages/jobs/src/index.ts:121`, `foresight/src/jobs.ts:98`
 * — and because every use of it here crosses into SQL as a `timestamptz` parameter.
 */
export type Now = () => Date

/** The real clock. The default for every function below, so production wires up nothing. */
export const systemNow: Now = () => new Date()

/* ------------------------------------------------------------------ daily series */

export interface DailyPoint {
  readonly day: string
  readonly event: string
  readonly count: Count
}

/**
 * The daily series for one event, from the rollup table.
 *
 * From `event_rollups` rather than from `events`, because the rollup already holds
 * `count(distinct subject_key)` per day — and a dashboard that recomputed that over four hundred
 * days of raw rows on every page load is a dashboard that takes the database down at the exact
 * moment somebody is watching a launch.
 *
 * Suppression is applied per day, not to the series: a day with four active users is suppressed
 * even when its neighbours are not, because that day is the disclosure.
 */
export async function dailySeries(
  sql: Db,
  event: string,
  window: Window,
  minCohort: number,
): Promise<readonly DailyPoint[]> {
  const rows = await sql<{ bucket_day: Date; event_name: string; events: string; subjects: number }[]>`
    select bucket_day, event_name, events, subjects
      from event_rollups
     where event_name = ${event}
       and bucket_day >= ${window.from.toISOString().slice(0, 10)}::date
       and bucket_day <  ${window.to.toISOString().slice(0, 10)}::date
     order by bucket_day
  `
  return rows.map((row) => ({
    day: row.bucket_day.toISOString().slice(0, 10),
    event: row.event_name,
    count: suppress(row.subjects, Number(row.events), minCohort),
  }))
}

/* ------------------------------------------------------------------ active users */

/**
 * Distinct subjects with at least one **non-authentication** event in the window.
 *
 * 13-operational-model.md:611 defines "active" in exactly those words, and the exclusion is the
 * whole substance of the definition: a user whose only activity is signing in and leaving is not
 * an active user, and counting them makes every engagement number look better than it is.
 */
export const AUTHENTICATION_EVENTS: readonly string[] = Object.freeze([
  'session_started',
  'user_registered',
  'device_added',
  'mfa_removed',
])

export async function activeSubjects(sql: Db, window: Window, minCohort: number): Promise<Count> {
  const rows = await sql<{ subjects: string; events: string }[]>`
    select count(distinct subject_key) as subjects, count(*) as events
      from events
     where subject_key is not null
       and occurred_at >= ${window.from}
       and occurred_at <  ${window.to}
       and event_name <> all(${AUTHENTICATION_EVENTS as string[]}::text[])
  `
  const row = rows[0]
  return suppress(Number(row?.subjects ?? 0), Number(row?.events ?? 0), minCohort)
}

/* ------------------------------------------------------------------ funnels */

export interface FunnelStep {
  readonly step: number
  readonly event: string
  readonly count: Count
}

export interface FunnelResult {
  readonly id: string
  readonly steps: readonly FunnelStep[]
}

/**
 * An ordinal funnel. Metrics 9 and 17.
 *
 * **Ordered, not merely "did all of these".** A subject reaches step *n* only if their first
 * step-*n* event happened at or after their first step-(*n*−1) event. Without that, a user who
 * deployed a token in March and registered in April counts as a completed onboarding funnel, and
 * the conversion rate is a number about nothing.
 *
 * The SQL is a chain of CTEs, one per step, built from `FUNNELS` — a **closed catalogue**, never
 * a caller-supplied step list. That is a privacy decision as much as an injection one: an
 * arbitrary sequence of events is a query language, and a query language over a behavioural store
 * is how "which three things did this one person do" gets asked. The event names still cross as
 * bound parameters.
 *
 * Every step is suppressed independently. A funnel whose fourth step has three people publishes
 * its first three steps and withholds the fourth, which is the honest answer: the shape of the
 * drop-off is the product question, and the identity of the three is not available at any price.
 */
export async function funnel(
  sql: Db,
  spec: FunnelSpec,
  window: Window,
  minCohort: number,
): Promise<FunnelResult> {
  const ctes: string[] = []
  const selects: string[] = []
  // $1 and $2 are the window; step event names start at $3.
  const params: string[] = [window.from.toISOString(), window.to.toISOString()]

  spec.steps.forEach((event, index) => {
    const placeholder = `$${params.length + 1}`
    params.push(event)
    if (index === 0) {
      ctes.push(`s0 as (
        select subject_key, min(occurred_at) as at
          from events
         where event_name = ${placeholder}
           and subject_key is not null
           and occurred_at >= $1::timestamptz and occurred_at < $2::timestamptz
         group by subject_key
      )`)
    } else {
      const previous = `s${index - 1}`
      ctes.push(`s${index} as (
        select e.subject_key, min(e.occurred_at) as at
          from events e
          join ${previous} p on p.subject_key = e.subject_key
         where e.event_name = ${placeholder}
           and e.occurred_at >= p.at
           and e.occurred_at < $2::timestamptz
         group by e.subject_key
      )`)
    }
    selects.push(`select ${index} as step, count(*)::int as subjects from s${index}`)
  })

  const rows = (await sql.unsafe(
    `with ${ctes.join(',\n')}\n${selects.join('\nunion all\n')}\norder by step`,
    params,
  )) as unknown as Array<{ step: number; subjects: number }>

  const bySteps = new Map(rows.map((row) => [Number(row.step), Number(row.subjects)]))
  return {
    id: spec.id,
    steps: spec.steps.map((event, index) => {
      const subjects = bySteps.get(index) ?? 0
      // `events` equals `subjects` here by construction: each CTE takes one row per subject, so a
      // funnel step counts people and never repetitions. Reporting the same number twice would
      // invite a reader to treat one of them as a volume, so the volume is simply the same number.
      return { step: index, event, count: suppress(subjects, subjects, minCohort) }
    }),
  }
}

export async function funnelById(
  sql: Db,
  id: string,
  window: Window,
  minCohort: number,
): Promise<FunnelResult | null> {
  const spec = funnelFor(id)
  if (!spec) return null
  return funnel(sql, spec, window, minCohort)
}

/* ------------------------------------------------------------------ cohort retention */

export interface RetentionCell {
  readonly cohortWeek: string
  readonly weekOffset: number
  readonly cohortSize: Count
  readonly active: Count
}

/**
 * Metric 18: the twelve-week retention heatmap, from the precomputed grid.
 *
 * **Both numbers are suppressed, and the cohort size is the one people forget.** A cell showing
 * "3 of 40 active" discloses three people; a cell showing "8 of 3" discloses the whole cohort. The
 * threshold is applied to each, so a small cohort publishes neither its size nor its activity —
 * and a cell whose cohort is suppressed cannot have a rate computed from it, which is the point.
 *
 * `now` is the cutoff's anchor and is a parameter for the reason in `Now` above: this was SQL
 * `now()`, and a windowed query that reads the wall clock is a query no test can pin.
 */
export async function retentionGrid(
  sql: Db,
  sinceWeeks: number,
  minCohort: number,
  now: Now = systemNow,
): Promise<readonly RetentionCell[]> {
  const rows = await sql<
    { cohort_week: Date; week_offset: number; cohort_size: number; active: number }[]
  >`
    select cohort_week, week_offset, cohort_size, active
      from cohort_retention
     where cohort_week >= (date_trunc('week', ${now()}::timestamptz)::date
                           - make_interval(weeks => ${sinceWeeks}))
     order by cohort_week desc, week_offset
  `
  return rows.map((row) => ({
    cohortWeek: row.cohort_week.toISOString().slice(0, 10),
    weekOffset: Number(row.week_offset),
    cohortSize: suppress(Number(row.cohort_size), Number(row.cohort_size), minCohort),
    active: suppress(Number(row.active), Number(row.active), minCohort),
  }))
}

/* ------------------------------------------------------------------ operational reads */

export interface StoreSummary {
  readonly events: number
  readonly subjects: number
  readonly erasedSubjects: number
  readonly oldestEvent: string | null
}

/**
 * Volumes for `/metrics`. Not suppressed, and it does not need to be: these are totals over the
 * whole store, and a total over everybody is a statement about nobody in particular. The one
 * number here that could be small — `erasedSubjects` — is a count of erasure *requests honoured*,
 * which is an operational fact about this service rather than an attribute of a person.
 */
export async function storeSummary(sql: Db): Promise<StoreSummary> {
  const rows = await sql<
    { events: string; subjects: string; erased: string; oldest: Date | null }[]
  >`
    select
      (select count(*) from events)                                   as events,
      (select count(*) from subject_keys where erased_at is null)     as subjects,
      (select count(*) from subject_keys where erased_at is not null) as erased,
      (select min(occurred_at) from events)                           as oldest
  `
  const row = rows[0]
  return {
    events: Number(row?.events ?? 0),
    subjects: Number(row?.subjects ?? 0),
    erasedSubjects: Number(row?.erased ?? 0),
    oldestEvent: row?.oldest ? row.oldest.toISOString() : null,
  }
}
