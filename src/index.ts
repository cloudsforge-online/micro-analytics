/**
 * The composition root.
 *
 * Everything this service is made of is constructed here, once, in an order that is not arbitrary.
 * Each step carries the reason it must precede the next; the ordering is the substance of this file.
 *
 * What this file deliberately does **not** do: run migrations. That is `src/migrator.ts`, a separate
 * one-shot process — AD-17 and rule 7. Here it matters concretely: below `SCHEMA_VERSION` the four
 * constraints this service's privacy properties rest on — `events_subject_shape`,
 * `events_person_has_pseudonym`, `events_props_allowed` and `subject_keys_erased` — may not exist,
 * and a service that could create them at boot is a service that could start without them. It
 * asserts the version and refuses to serve below it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE PRODUCT ANALYTICS PLANE IS A LEAF.** Nothing here dials another service at boot and nothing
 * blocks on one. The only hard probe is Postgres: without it this service can answer `/livez` and
 * nothing else worth having, because every event, cohort and funnel is a row. Identity is a SOFT
 * probe — `/metrics` falls back to the static token, and a funnel that cannot be read for ten
 * minutes is not a reason to take a replica out of the balancer. 13-operational-model.md
 * classifies this plane as "durable but lossy by design", which is the same judgement.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **A subscription that does not exist misses the events it was not there for.** The estate's
 * outbox relay does not redeliver an event published while nothing was subscribed, so this
 * service's history begins the day its subscription does. There is no backfill and there cannot be
 * one — the producers' outboxes are pruned. The README says so where a product manager will read it.
 *
 * Traces are exported by the OpenTelemetry SDK loaded ahead of this module via `NODE_OPTIONS`,
 * which reads `OTEL_EXPORTER_OTLP_ENDPOINT` from the environment itself. That is why no `OTEL_*`
 * variable appears in `src/env.ts`.
 */

import postgres from 'postgres'
import { assertSchemaAtLeast, type Sql } from '@cloudsforge/db'
import { JobQueue, JobRunner, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Verifier } from '@cloudsforge/auth'
import { Lifecycle, installSignalHandlers, postgresProbe } from '@cloudsforge/lifecycle'
import { Logger, Metrics, registerHttpMetrics, registerJobMetrics } from '@cloudsforge/telemetry'
import { SERVICE, env } from './env.ts'
import { SCHEMA_VERSION } from './migrations.ts'
import { createServer, registerServiceMetrics, scrapeRefresh } from './server.ts'
import { registerHandlers, rescheduleRecurring, sampleQueue, seedRecurring } from './jobs.ts'
import { publish } from './definitions.ts'
import { PepperRing } from './pseudonym.ts'

// 1. Environment. Importing `./env.ts` validated it; a missing or placeholder pepper has already
//    exited with a structured line naming the variable and never its value.

// 2. Telemetry, before anything that can fail, so a pool failure is a structured line rather than a
//    bare V8 stack the collector drops.
const logger = new Logger({
  service: SERVICE,
  level: env.logLevel,
  version: env.version,
  env: env.env,
  // The pepper is never passed to a logger, but a redaction key costs nothing and closes the
  // accident where somebody logs the whole config object while debugging.
  redactKeys: ['pseudonymKey', 'pseudonymKeys', 'pepper', 'peppers', 'deliverySecrets'],
})
const metrics = registerServiceMetrics(registerJobMetrics(registerHttpMetrics(new Metrics())))
logger.info('starting', {
  version: env.version,
  schemaVersion: SCHEMA_VERSION,
  // Said at boot, because a threshold somebody raised in an incident and forgot to lower is
  // otherwise invisible until a dashboard is unexpectedly empty.
  minCohort: env.minCohort,
  eventRetentionDays: env.eventRetentionDays,
})

// 3. The database pool. Opened before the schema assertion (which is a query) and before the
//    Lifecycle (whose readiness probe closes over it).
const sql = postgres(env.databaseUrl, { max: env.databasePoolMax, onnotice: () => {} })
const db = sql as unknown as Sql

// 4. Assert the schema. This does NOT migrate. Failing here rather than serving is the point: see
//    the file header for which four constraints would otherwise be optional.
try {
  await assertSchemaAtLeast(db, SCHEMA_VERSION)
} catch (err) {
  logger.fatal('schema assertion failed', { err, required: SCHEMA_VERSION })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 5. Publish this build's metric definitions. Before serving, because a chart read against an
//    unpublished definition is a number nobody can explain afterwards — and because `publish`
//    THROWS if a released definition's text changed, which must stop the deploy rather than
//    surface as a 409 on an operator's first click.
try {
  const published = await publish(sql as unknown as never)
  logger.info('metric definitions published', { ...published })
} catch (err) {
  logger.fatal('a released metric definition was modified', { err })
  await sql.end({ timeout: 5 }).catch(() => {})
  process.exit(1)
}

// 6. The Lifecycle and its probes, before the routes, because `/readyz` is a route and it needs
//    something to report. Postgres is HARD; there are no soft probes because there are no
//    upstreams — this service calls nobody.
const lifecycle = new Lifecycle({
  drainDelayMs: 5_000,
  drainTimeoutMs: 25_000,
  onStateChange: (state) => logger.info('lifecycle state', { state }),
})
lifecycle.addProbe(
  postgresProbe('postgres', (signal) =>
    Promise.race([
      sql`select 1`,
      new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => reject(new Error('probe aborted')), { once: true })
      }),
    ]),
  ),
)

// 7. The queue and the runner's dependencies.
const queue = new JobQueue(sql as unknown as JobsSql, { owner: env.instanceId, leaseMs: 120_000 })

// 8. Routes. After the Lifecycle so the health handlers report real state.
const verifier = new Verifier({ jwksUrl: env.identityJwksUrl, issuer: env.identityIssuer })
const refresh = scrapeRefresh({ sql, metrics })
const server = createServer({
  lifecycle,
  logger,
  metrics,
  verifier,
  sql,
  token: env.token,
  minCohort: env.minCohort,
  queue,
  ingest: {
    sql,
    logger,
    metrics,
    secrets: env.deliverySecrets,
    peppers: new PepperRing(env.pseudonymKeys, env.pseudonymVersion),
  },
  // Gauges are sampled at scrape time rather than on a timer. There is no `setInterval` in this
  // repository and CI greps for one — rule 8.
  beforeScrape: async () => {
    await refresh()
    await sampleQueue(queue, metrics)
  },
})

// 9. The job runner, started before `listen()`. Background work is claimed under a lease, so a
//    replica that is draining stops claiming before it stops serving.
const reschedule = rescheduleRecurring(queue, logger)
const runner = new JobRunner({
  queue,
  concurrency: 2,
  pollMs: 1_000,
  shouldClaim: () => lifecycle.claimingJobs,
  onEvent: (event) => {
    if (event.kind) {
      if (event.type === 'claimed') metrics.increment('jobs_claimed_total', { kind: event.kind })
      if (event.type === 'completed') metrics.increment('jobs_completed_total', { kind: event.kind })
      if (event.type === 'failed') metrics.increment('jobs_failed_total', { kind: event.kind })
      if (event.type === 'dead') metrics.increment('jobs_dead_total', { kind: event.kind })
      if (event.durationMs !== undefined) {
        metrics.observe('jobs_duration_ms', event.durationMs, { kind: event.kind })
      }
    }
    if (event.type === 'failed' || event.type === 'dead' || event.type === 'error') {
      logger.error('job failure', { ...event })
    }
    reschedule(event)
  },
})
registerHandlers(runner, {
  sql,
  logger,
  metrics,
  retention: {
    eventDays: env.eventRetentionDays,
    rollupDays: env.rollupRetentionDays,
    inboxDays: env.inboxRetentionDays,
    idempotencyDays: env.idempotencyTtlDays,
  },
  cohortWeeks: env.cohortWeeks,
})
await seedRecurring(queue)
runner.start()

// 10. Listen. Last of the construction steps: a socket that accepts before its dependencies exist
//     is a socket that answers 500.
await new Promise<void>((resolve, reject) => {
  server.once('error', reject)
  server.listen(env.port, () => resolve())
})
logger.info('listening', { port: env.port })

// 11. Ready. Only now does `/readyz` start answering 200 and the balancer send traffic.
lifecycle.markReady()

// 12. Signal handlers, last of all. Hooks run in reverse registration order, so the server closes
//     first, then the runner stops claiming and DRAINS, then the pool closes with nothing left.
lifecycle.onShutdown(async () => {
  await sql.end({ timeout: 5 })
  logger.info('database pool closed')
})
lifecycle.onShutdown(async () => {
  const clean = await runner.stop(20_000)
  logger.info('job runner stopped', { clean })
})
lifecycle.onShutdown(
  () =>
    new Promise<void>((resolve) => {
      server.close(() => resolve())
      server.closeIdleConnections()
    }),
)

installSignalHandlers(lifecycle)
