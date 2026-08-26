/**
 * The HTTP surface: what this service depends on, and the one line that mounts it.
 *
 * Plain `node:http`, following the service template. The parts that matter — request ids, RED
 * metrics, the child logger, the error shape, the auth-fault mapping — are framework-independent.
 *
 * This file used to be all three of those things at once. It is now the composition point:
 *
 *   - `kernel.ts` owns the request listener — the plumbing this service and `micro-lantern` had
 *     each written for themselves, line for line the same.
 *   - `routes.ts` owns the route table, the error classes and the failure mapping, built by a
 *     factory over `ServerDeps` so every handler CLOSES OVER its dependencies instead of being
 *     handed them. That is the seam wave M1 of `deploy/docs/service-merge-plan.md` needs, and the
 *     reason is written out in that file's header: it is what keeps this service's pseudonymisation
 *     pepper out of scope for a route set mounted beside it.
 *   - This file keeps the dependency contract (`ServerDeps`, `PrincipalVerifier`), the scope
 *     vocabulary, the metric declarations, and `createServer`.
 *
 * `createServer(deps)` is unchanged in signature, in export and in behaviour.
 *
 * ---------------------------------------------------------------------------------------------
 * **THERE IS NO ROUTE THAT WRITES AN EVENT FROM A BROWSER.**
 *
 * AD-21: analytics is fed by the event bus, not by a page tag. `POST /ingest` takes a signed event
 * envelope from a producer's outbox relay, and that is the only write path for an event. A
 * collector endpoint a browser could reach would bypass the delivery signature and — because a
 * browser has no way to know a pepper — the pseudonymisation as well. The frontend events AD-21
 * names (`page_viewed`, `cta_clicked`, `form_abandoned`) reach this service the same way every
 * other event does: through their own service's outbox.
 *
 * `/ingest` authenticates with the delivery MAC and reads no bearer token; the route in `routes.ts`
 * records why at length, and why that is not a weakening. Every OTHER route on this service demands
 * a bearer, and the scope matcher for those is the exact one described below.
 * ---------------------------------------------------------------------------------------------
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE SCOPE MATCHER: EXACT, DELIBERATELY, AND NEITHER PACKAGE IS CHANGED.**
 *
 * 18-build-status.md §3.3h records that the estate ships two scope matchers that disagree:
 * `contracts/packages/auth/src/index.ts` is `granted.includes(required)` — exact only — and
 * `runtime/packages/auth/src/index.ts` honours one wildcard level, so `analytics:*` grants
 * `analytics:read`. Both are shipped, both are CI-green, and §3.3h leaves the disagreement open on
 * purpose because changing an authorisation matcher is the highest-blast-radius edit in this
 * estate.
 *
 * This service therefore changes neither package and matches **exactly**, in `hasExactScope` below
 * — the same choice `micro-devplatform` and `micro-admin-api` made, and made for a reason that
 * applies here with more force. A wildcard grants scopes that did not exist when the credential
 * was issued. In a service that holds four hundred days of behaviour, that means a token minted to
 * read a funnel silently acquires whatever read is added next — and the next one might be the
 * cohort export. `hasScope` from `@cloudsforge/auth` is deliberately not imported, and
 * `server.test.ts` asserts that about THIS FILE — which is why the matcher stays here rather than
 * moving to `routes.ts` with its callers.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import type { Server } from 'node:http'
import { type Principal } from '@cloudsforge/auth'
import type { JobQueue } from '@cloudsforge/jobs'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import type { Network } from '@cloudsforge/http'
import type { NetworkSql } from '@cloudsforge/db'
import type { Logger, Metrics } from '@cloudsforge/telemetry'
import type { IngestDeps } from './ingest.ts'
import { storeSummary, type Now } from './reads.ts'
import type { Db } from './store.ts'
import { mountRoutes } from './kernel.ts'
import { createRoutes } from './routes.ts'

/**
 * Re-exported, not moved back: `parseWindow` belongs beside the routes that call it, and this
 * export is part of the module's published surface.
 */
export { parseWindow } from './routes.ts'

/** The verifier as this file needs it. An interface, so a test does not need a JWKS. */
export interface PrincipalVerifier {
  principal(token: string): Promise<Principal>
}

export interface ServerDeps {
  readonly lifecycle: Lifecycle
  readonly logger: Logger
  readonly metrics: Metrics
  readonly verifier: PrincipalVerifier
  /**
   * The per-network SELECTOR, not a handle. Routes use `ctx.sql`; `NetworkSql` has no query
   * methods, so reaching for the process-wide handle does not compile.
   */
  readonly sql: NetworkSql
  /**
   * The network to assume when no `CF-Network` arrives, or `undefined` to refuse. `CF_NETWORK_SINGLE`,
   * for `pnpm dev`, which has no gateway in front of it. Never set in production.
   */
  readonly singleNetwork?: Network
  readonly ingest: IngestDeps
  /** Gates `/metrics`. Compared in constant time; see `presentsToken`. */
  readonly token: string
  readonly minCohort: number
  readonly queue: JobQueue
  readonly beforeScrape?: () => Promise<void>
  /**
   * Test seam. Production passes nothing and gets the real clock.
   *
   * Every read route defaults its window from an instant, and `/cohorts/retention` anchors its
   * cutoff on one. Reading that instant from the wall clock deep inside a query is what made
   * `reads.test.ts` depend on the weekday it ran on — see `reads.ts`'s `Now`.
   */
  readonly now?: Now
}

/* ------------------------------------------------------------------ scopes */

/**
 * There is deliberately no `SCOPE_INGEST` here any more.
 *
 * `POST /ingest` is MAC-only — see the route for the argument — so `analytics:ingest` was a scope
 * no route checked and no producer could present. It is deleted rather than left as an
 * unreferenced constant, following `micro-notify`, which deleted its `notify:ingest` for the same
 * reason rather than registering it.
 *
 * Two orphans outside this repository follow from that and are REPORTED, not edited here:
 * `contracts/packages/auth/src/index.ts` still registers `analytics:ingest` in the estate's
 * scope vocabulary, and `deploy/compose/docker-compose.estate.yml` still mints it into the
 * analytics service token. Neither is harmful — an unused scope grants nothing — and neither
 * repository is this one's to change.
 */
export const SCOPE_READ = 'analytics:read'
export const SCOPE_ADMIN = 'analytics:admin'

/**
 * Exact scope matching. See the file header for why, and for why neither auth package is touched.
 *
 * `granted === required`, and nothing else. `analytics:*` grants nothing here, and a test asserts
 * that in both directions so the choice cannot drift into a wildcard by accident.
 */
export function hasExactScope(principal: Principal, required: string): boolean {
  return principal.kind === 'service' && principal.scopes.includes(required)
}

/* ------------------------------------------------------------------ metrics */

/**
 * Domain metrics, declared rather than inferred from a log line — AD-20.
 *
 * `analytics_rejections_total` is the one to watch. A climbing `disallowed_property` rate means a
 * producer is trying to send this service something it will not store, and every one of those is a
 * conversation worth having before it becomes a pull request that widens the allowlist.
 */
export function registerServiceMetrics(metrics: Metrics): Metrics {
  return metrics
    .register({
      name: 'analytics_events_total',
      help: 'Product events stored, by event name',
      kind: 'counter',
      labels: ['event'],
    })
    .register({
      name: 'analytics_rejections_total',
      help: 'Events and properties refused at ingest, by reason. A climbing rate is a producer to talk to.',
      kind: 'counter',
      labels: ['reason'],
    })
    .register({
      name: 'analytics_duplicates_dropped_total',
      help: 'Redelivered events already in the inbox. Expected; a climbing rate is not.',
      kind: 'counter',
      labels: [],
    })
    .register({
      name: 'analytics_erasures_total',
      help: 'identity.user.deleted events honoured. Each one destroyed a salt.',
      kind: 'counter',
      labels: [],
    })
    .register({
      name: 'analytics_ingest_lag_seconds',
      help: 'Seconds between an event occurring and its row being written',
      kind: 'histogram',
      labels: ['producer'],
      // Seconds, not the millisecond default. A funnel a minute behind is fine and one an hour
      // behind is an incident, so the buckets have to span both.
      buckets: [0.5, 1, 2, 5, 10, 30, 60, 300, 900, 3_600],
    })
    .register({
      name: 'analytics_retention_deleted_total',
      help: 'Rows deleted by the retention sweep, by table. Zero for a week is a job that stopped.',
      kind: 'counter',
      labels: ['table'],
    })
    .register({
      name: 'analytics_events_stored',
      help: 'Rows currently in the event store',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'analytics_subjects_live',
      help: 'Subjects with a live pseudonym mapping',
      kind: 'gauge',
      labels: [],
    })
    .register({
      name: 'analytics_subjects_erased',
      help: 'Subjects whose salt has been destroyed. Only ever goes up until retention prunes it.',
      kind: 'gauge',
      labels: [],
    })
}

/** Sample the store gauges. Called at scrape time, never on a timer — rule 8. */
export function scrapeRefresh(deps: { sql: Db; metrics: Metrics }): () => Promise<void> {
  return async () => {
    // `deps.sql` here is this helper's OWN record, not the server's selector — it is called from
    // the scrape path, which has no request and therefore no network. Left alone deliberately.
    const summary = await storeSummary(deps.sql)
    deps.metrics.set('analytics_events_stored', summary.events)
    deps.metrics.set('analytics_subjects_live', summary.subjects)
    deps.metrics.set('analytics_subjects_erased', summary.erasedSubjects)
  }
}

/* ------------------------------------------------------------------ the server */

/**
 * Build this service's routes over `deps`, and mount them on the kernel's listener.
 *
 * The whole of what changed in wave M1a is visible in this one line: the route table is now a
 * value a factory produced, rather than a table the listener owned — so a second table, built by a
 * second module over a second `deps`, can be mounted on the same listener without either module
 * being able to see the other's dependencies.
 */
export function createServer(deps: ServerDeps): Server {
  return mountRoutes(createRoutes(deps), deps)
}
