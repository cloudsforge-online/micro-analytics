/**
 * The HTTP surface.
 *
 * Plain `node:http`, following the service template. The parts that matter — request ids, RED
 * metrics, the child logger, the error shape, the auth-fault mapping — are framework-independent.
 *
 * ---------------------------------------------------------------------------------------------
 * **THERE IS NO ROUTE HERE THAT WRITES AN EVENT FROM A BROWSER.**
 *
 * AD-21: analytics is fed by the event bus, not by a page tag. `POST /ingest` takes a signed event
 * envelope from a producer's outbox relay, and that is the only write path for an event. A
 * collector endpoint a browser could reach would bypass the delivery signature and — because a
 * browser has no way to know a pepper — the pseudonymisation as well. The frontend events AD-21
 * names (`page_viewed`, `cta_clicked`, `form_abandoned`) reach this service the same way every
 * other event does: through their own service's outbox.
 *
 * `/ingest` authenticates with the delivery MAC and reads no bearer token; the route below records
 * why at length, and why that is not a weakening. Every OTHER route on this service demands a
 * bearer, and the scope matcher for those is the exact one described below.
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
 * cohort export. `hasScope` from `@cloudsforge/auth` is deliberately not imported.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import { SIGNATURE_HEADER } from '@cloudsforge/contracts-events'
import { ForbiddenError, TokenError, bearerFrom, isAdmin, statusFor, type Principal } from '@cloudsforge/auth'
import type { JobQueue } from '@cloudsforge/jobs'
import type { Lifecycle } from '@cloudsforge/lifecycle'
import { NetworkUnknownError, requestNetwork, type Network } from '@cloudsforge/http'
import type { NetworkSql } from '@cloudsforge/db'
import { Metrics, newRequestId, type Logger } from '@cloudsforge/telemetry'
import { EVENT_NAMES, FUNNELS, PROPERTIES, PROPERTY_NAMES } from './catalogue.ts'
import { DEFINITIONS, DefinitionChangedError, listDefinitions, publish } from './definitions.ts'
import {
  DeliverySignatureError,
  MalformedEventError,
  ingest,
  parseDelivery,
  verifySignature,
  type IngestDeps,
} from './ingest.ts'
import {
  IdempotencyInFlightError,
  IdempotencyKeyReuseError,
  requestFingerprint,
  withIdempotency,
} from './idempotency.ts'
import { COHORT_KIND } from './jobs.ts'
import {
  activeSubjects,
  dailySeries,
  funnelById,
  retentionGrid,
  storeSummary,
  systemNow,
  type Now,
  type Window,
} from './reads.ts'
import { listRejections, type Db } from './store.ts'

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

const MAX_BODY_BYTES = 256 * 1024
const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/
const MAX_WINDOW_DAYS = 400
const SAFE_IDEMPOTENCY_KEY = /^[A-Za-z0-9_.:-]{8,128}$/

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

function requireExactScope(principal: Principal, required: string): void {
  if (!hasExactScope(principal, required)) throw new ForbiddenError(required)
}

/**
 * Who may read an aggregate.
 *
 * A scoped service token, or an operator. **Never an ordinary user token**, whatever it carries:
 * there is no per-user view of this data and there is not going to be one, because a per-user view
 * is the support question AD-21 exists to make unanswerable
 * (13-operational-model.md).
 */
function requireReader(principal: Principal): void {
  if (isAdmin(principal)) return
  requireExactScope(principal, SCOPE_READ)
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

/* ------------------------------------------------------------------ plumbing */

class BadRequestError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BadRequestError'
  }
}

class NotFoundError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'NotFoundError'
  }
}

class ConflictError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'ConflictError'
  }
}

interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
}

interface RequestContext {
  readonly req: IncomingMessage
  readonly url: URL
  readonly requestId: string
  readonly log: Logger
  readonly params: Readonly<Record<string, string>>
  /**
   * The network THIS REQUEST belongs to, from the `CF-Network` header the gateway stamped.
   *
   * Not a property of the process: one pod serves both estates since the network consolidation
   * (micro-deploy `docs/network-consolidation.md`), so "which network am I" has no answer.
   */
  readonly network: Network
  /**
   * The database handle for `network`, resolved ONCE, at the edge of the request.
   *
   * Every route uses this rather than reaching for the process-wide handle, because a wrong handle
   * is not an error — it is a query that SUCCEEDS against the other estate's rows and says nothing.
   * `deps.sql` is a `NetworkSql` with no query methods, so the mistake does not compile.
   */
  readonly sql: Db
}

/**
 * Routes that answer without belonging to a network.
 *
 * Kubelet probes the first two and Prometheus scrapes the third; none arrives through the gateway,
 * so none carries `CF-Network`. Refusing them makes every health probe a 500 and the pod never
 * becomes ready. Three literal paths rather than a prefix, because this is an exemption from a data
 * boundary; none of them queries the database.
 */
const OPERATIONAL_ROUTES: ReadonlySet<string> = new Set(['/livez', '/readyz', '/metrics'])

interface Route {
  readonly method: string
  /** `/funnels/:id`. Used verbatim as the metric label, so cardinality is bounded. */
  readonly path: string
  readonly pattern: RegExp
  readonly handle: (ctx: RequestContext, deps: ServerDeps) => Promise<Reply>
}

/**
 * Compile `/funnels/:id` into a matcher. The segment pattern excludes `/` so a parameter cannot
 * swallow the rest of the path and make one route answer for another.
 */
function compile(path: string): RegExp {
  const source = path
    .split('/')
    .map((segment) =>
      segment.startsWith(':') ? `(?<${segment.slice(1)}>[^/]+)` : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('/')
  return new RegExp(`^${source}$`)
}

export function createServer(deps: ServerDeps): Server {
  const routes = buildRoutes()
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()

    // Echoed before anything can fail, so even a 500 carries the id the user will quote.
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const method = req.method ?? 'GET'

    let matched: Route | undefined
    let params: Record<string, string> = {}
    for (const route of routes) {
      if (route.method !== method) continue
      const match = route.pattern.exec(url.pathname)
      if (match) {
        matched = route
        params = { ...match.groups }
        break
      }
    }

    // Unmatched paths collapse to one label. Using the raw path would let any caller mint
    // unbounded time series and take the scrape target down with cardinality.
    const routeLabel = matched ? matched.path : 'unmatched'
    const log = deps.logger.child({ requestId, method, route: routeLabel })

    inFlight += 1
    deps.metrics.set('http_requests_in_flight', inFlight)

    const finish = (status: number, metricNetwork: string) => {
      inFlight -= 1
      deps.metrics.set('http_requests_in_flight', inFlight)
      const durationMs = Number(process.hrtime.bigint() - startedAt) / 1e6
      deps.metrics.increment('http_requests_total', {
        method,
        route: routeLabel,
        status: String(status),
        // One target now serves both estates, so the network has to be on the SERIES. Labelled
        // per target it would say nothing — micro-org#398 in a form nothing could recover.
        network: metricNetwork,
      })
      deps.metrics.observe('http_request_duration_ms', durationMs, {
        method,
        route: routeLabel,
        network: metricNetwork,
      })
    }

    // ── THE NETWORK, THEN THE HANDLE, BEFORE ANY ROUTE RUNS ──────────────────────────────────
    //
    // `requestNetwork` REFUSES an unstamped request rather than assuming mainnet: a 500 is a
    // routing fault made loud, where a default is a cross-network write nothing would ever flag.
    //
    // The operational endpoints are exempt because kubelet and Prometheus do not come through the
    // gateway and never send the header. Refusing them makes the pod never become ready.
    const networkless = matched !== undefined && OPERATIONAL_ROUTES.has(matched.path)
    let network: Network
    try {
      network = networkless
        ? (deps.singleNetwork ?? deps.sql.networks[0] ?? 'mainnet')
        : requestNetwork(req.headers, deps.singleNetwork ? { fallback: deps.singleNetwork } : {})
    } catch (err) {
      log.error('request carries no usable network', {
        err: err instanceof NetworkUnknownError ? err.message : err,
      })
      send(
        res,
        errorReply(500, 'network_unknown', 'this request could not be attributed to a network', requestId),
        requestId,
      )
      finish(500, 'unknown')
      return
    }

    const sql = deps.sql.for(network) as unknown as Db
    void handle(matched, { req, url, requestId, log, params, network, sql }, deps)
      .then((reply) => {
        send(res, reply, requestId)
        finish(reply.status, network)
      })
      .catch((err: unknown) => {
        // Reaching here means the error mapping itself failed. Answer, then say so loudly.
        log.error('request handler threw after mapping', { err })
        send(res, errorReply(500, 'internal', 'the request could not be completed', requestId), requestId)
        finish(500, network)
      })
  })
}

async function handle(route: Route | undefined, ctx: RequestContext, deps: ServerDeps): Promise<Reply> {
  if (!route) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  try {
    return await route.handle(ctx, deps)
  } catch (err) {
    // `statusFor` is the whole point: it is the one place that decides what an auth failure means,
    // so five services cannot disagree about it again.
    const authStatus = statusFor(err)
    if (authStatus === 401) {
      // The reason is logged, never returned — "signature verification failed" versus "expired"
      // tells an attacker which half of a forged token to fix.
      ctx.log.info('unauthenticated request', { err })
      return errorReply(401, 'unauthenticated', 'a valid bearer token is required', ctx.requestId)
    }
    if (authStatus === 403) {
      const required = err instanceof ForbiddenError ? err.required : 'unknown'
      ctx.log.info('forbidden request', { required })
      return errorReply(403, 'forbidden', `missing required authority: ${required}`, ctx.requestId)
    }
    if (authStatus === 503) {
      // Answering 401 here would sign every caller in the estate out because identity is having a
      // bad minute.
      ctx.log.error('token verifier unavailable', { err })
      return errorReply(503, 'verifier_unavailable', 'authentication is temporarily unavailable', ctx.requestId)
    }
    if (err instanceof DeliverySignatureError) {
      ctx.log.warn('ingest refused: signature', { reason: err.reason })
      return errorReply(401, 'bad_signature', 'the delivery signature was refused', ctx.requestId)
    }
    if (err instanceof MalformedEventError) {
      // 400 with the errors, deliberately: this caller is another service in the estate, and the
      // whole point of contracts-events reporting every problem at once is that its producer needs
      // one round trip to fix them.
      ctx.log.warn('ingest refused: malformed envelope', { errors: err.errors })
      return errorReply(400, 'malformed_event', err.errors.join('; '), ctx.requestId)
    }
    if (err instanceof IdempotencyKeyReuseError) {
      return errorReply(409, 'idempotency_key_reuse', err.message, ctx.requestId)
    }
    if (err instanceof IdempotencyInFlightError) {
      return errorReply(409, 'in_flight', err.message, ctx.requestId)
    }
    if (err instanceof DefinitionChangedError) {
      return errorReply(409, 'definition_changed', err.message, ctx.requestId)
    }
    if (err instanceof ConflictError) {
      return errorReply(409, 'conflict', err.message, ctx.requestId)
    }
    if (err instanceof BadRequestError) {
      return errorReply(400, 'bad_request', err.message, ctx.requestId)
    }
    if (err instanceof NotFoundError) {
      return errorReply(404, 'not_found', err.message, ctx.requestId)
    }
    ctx.log.error('unhandled request failure', { err })
    return errorReply(500, 'internal', 'the request could not be completed', ctx.requestId)
  }
}

/* ------------------------------------------------------------------ routes */

function buildRoutes(): Route[] {
  const routes: Array<Omit<Route, 'pattern'>> = [
    {
      method: 'GET',
      path: '/livez',
      /**
       * Static, deliberately. Liveness answers one question — should this process be killed and
       * restarted — and a liveness probe that consults a dependency restarts a healthy process
       * every time the database blinks. Readiness is where dependencies belong.
       */
      handle: async (_ctx, deps) => ({ status: 200, body: deps.lifecycle.livez() }),
    },
    {
      method: 'GET',
      path: '/readyz',
      handle: async (_ctx, deps) => {
        const report = await deps.lifecycle.readyz()
        return { status: report.ready ? 200 : 503, body: report }
      },
    },
    {
      method: 'GET',
      path: '/metrics',
      /**
       * Authenticated, with the same reasoning `micro-lantern` records for its own: this surface
       * publishes which producers are being refused and at what rate, which is a map of where the
       * estate's privacy discipline is weakest. A static token rather than a JWT, because Prometheus
       * cannot mint one and identity being down is exactly when somebody wants this page.
       */
      handle: async (ctx, deps) => {
        if (!presentsToken(ctx.req, deps.token)) {
          throw new TokenError('x-analytics-token is missing or wrong', 'bad_token')
        }
        try {
          await deps.beforeScrape?.()
        } catch (err) {
          // A gauge that could not be sampled is a stale gauge. Failing the scrape instead would
          // lose every other metric too, and blind the dashboard at the moment it is needed.
          ctx.log.warn('gauge refresh failed; serving the previous values', { err })
        }
        return {
          status: 200,
          text: deps.metrics.render(),
          contentType: 'text/plain; version=0.0.4; charset=utf-8',
        }
      },
    },

    {
      method: 'POST',
      path: '/ingest',
      /**
       * The only way a row is created.
       *
       * ════════════════════════════════════════════════════════════════════════════════════════
       * **THE SIGNATURE IS THE AUTHENTICATION. NO BEARER TOKEN IS READ HERE, DELIBERATELY.**
       *
       * This handler used to call `authenticate()` and demand an `analytics:ingest` scope before
       * it read a byte. **No producer in this estate could ever satisfy it.** Every outbox relay
       * sends exactly two headers — the delivery signature and the event id — and nothing else;
       * `identity/src/outbox.ts` is the canonical one, and all twenty-one relays in the estate
       * were checked, not assumed. A relay is a background job woken by a Postgres poll: it has no
       * session, no user, and no way to mint a token. So every event bound for this service died
       * 401 at this line, always, and the onboarding denominator every funnel metric divides by
       * stayed empty while the service reported itself healthy.
       *
       * That was measured against the running estate before it was changed: a correctly signed
       * `POST /ingest` carrying no `Authorization` header answered
       * `401 {"code":"unauthenticated"}`.
       *
       * **Why removing it does not weaken anything.** The two checks were never redundant, but
       * they were also never both obtainable. A bearer proves *who* opened the socket and proves
       * nothing about the bytes; the MAC proves the bytes were produced by something holding the
       * estate's outbox signing secret, which is a strictly stronger statement about the thing
       * that actually matters here — the content of the row. A signed-in person still cannot reach
       * this route, because a person does not hold that secret. `micro-notify` (`server.ts`)
       * and `micro-activity` made this exact repair for this exact reason; `trade` and `worlds`
       * shaped their inboxes this way from the start.
       *
       * The `analytics:ingest` scope constant was DELETED rather than left unreferenced — a scope
       * that no route checks is a capability the vocabulary claims and does not have.
       * ════════════════════════════════════════════════════════════════════════════════════════
       *
       * The order below is the security property: read the raw bytes, verify the signature over
       * exactly those bytes, and only then parse. Parsing first would put a parser in front of the
       * authentication, reachable by anyone who can open a socket.
       *
       * It is deliberately NOT wrapped in `withIdempotency`: the inbox, unique on
       * `(topic, event_id)`, is a stronger guarantee than a caller-supplied key, because it works
       * for a relay that has forgotten it already delivered. `routeidempotency.test.ts` records
       * that exemption with this reason.
       */
      handle: async (ctx, deps) => {
        const rawBody = await readRaw(ctx.req)
        verifySignature(deps.ingest, rawBody, headerOf(ctx.req, SIGNATURE_HEADER))
        const delivery = parseDelivery(rawBody)
        const outcome = await ingest(deps.ingest, delivery)

        switch (outcome.status) {
          case 'duplicate':
            // 200, not 409. A redelivery is the producer doing exactly what at-least-once delivery
            // requires of it, and an error would make the relay retry for ever.
            return { status: 200, body: { status: 'duplicate', eventId: delivery.envelope.id } }
          case 'erased':
            return { status: 200, body: { status: 'erased', alreadyErased: outcome.alreadyErased } }
          case 'refused':
            // Also 200. The event was DECIDED about, not dropped on the floor, and the producer
            // needs to stop sending it rather than retry it.
            return { status: 200, body: { status: 'refused', reason: outcome.reason } }
          case 'recorded':
            return {
              status: 201,
              body: {
                status: 'recorded',
                event: outcome.eventName,
                // The producer chose these names and already knows them, so returning them costs
                // nothing and is the only way it learns to stop. They are never persisted.
                droppedProperties: outcome.dropped,
              },
            }
        }
      },
    },

    {
      method: 'GET',
      path: '/reports/daily',
      handle: async (ctx, deps) => {
        requireReader(await authenticate(ctx, deps))
        const event = ctx.url.searchParams.get('event') ?? ''
        if (!EVENT_NAMES.includes(event)) {
          throw new BadRequestError(`event must be one of: ${EVENT_NAMES.join(', ')}`)
        }
        const window = parseWindow(ctx.url, deps.now)
        const points = await dailySeries(ctx.sql, event, window, deps.minCohort)
        return { status: 200, body: { event, minCohort: deps.minCohort, points } }
      },
    },
    {
      method: 'GET',
      path: '/reports/active',
      handle: async (ctx, deps) => {
        requireReader(await authenticate(ctx, deps))
        const window = parseWindow(ctx.url, deps.now)
        const count = await activeSubjects(ctx.sql, window, deps.minCohort)
        return { status: 200, body: { minCohort: deps.minCohort, count } }
      },
    },
    {
      method: 'GET',
      path: '/funnels',
      handle: async (ctx, deps) => {
        requireReader(await authenticate(ctx, deps))
        return { status: 200, body: { funnels: FUNNELS } }
      },
    },
    {
      method: 'GET',
      path: '/funnels/:id',
      handle: async (ctx, deps) => {
        requireReader(await authenticate(ctx, deps))
        const id = ctx.params['id'] ?? ''
        const window = parseWindow(ctx.url, deps.now)
        const result = await funnelById(ctx.sql, id, window, deps.minCohort)
        if (!result) throw new NotFoundError(`no funnel ${id}; the catalogue is closed`)
        return { status: 200, body: { minCohort: deps.minCohort, ...result } }
      },
    },
    {
      method: 'GET',
      path: '/cohorts/retention',
      handle: async (ctx, deps) => {
        requireReader(await authenticate(ctx, deps))
        const weeks = parseInteger(ctx.url.searchParams.get('weeks'), 'weeks', 12, 2, 52)
        const cells = await retentionGrid(ctx.sql, weeks, deps.minCohort, deps.now)
        return { status: 200, body: { minCohort: deps.minCohort, weeks, cells } }
      },
    },
    {
      method: 'GET',
      path: '/definitions',
      handle: async (ctx, deps) => {
        requireReader(await authenticate(ctx, deps))
        return { status: 200, body: { definitions: await listDefinitions(ctx.sql) } }
      },
    },
    {
      method: 'GET',
      path: '/catalogue',
      /**
       * What this service will and will not store, as data.
       *
       * A producer building an analytics envelope needs the allowlist, and the alternative to
       * publishing it is every producer discovering it by having properties refused.
       */
      handle: async (ctx, deps) => {
        requireReader(await authenticate(ctx, deps))
        return {
          status: 200,
          body: { events: EVENT_NAMES, properties: PROPERTY_NAMES, specs: PROPERTIES },
        }
      },
    },
    {
      method: 'GET',
      path: '/rejections',
      handle: async (ctx, deps) => {
        requireReader(await authenticate(ctx, deps))
        const days = parseInteger(ctx.url.searchParams.get('days'), 'days', 7, 1, 400)
        return { status: 200, body: { days, rejections: await listRejections(ctx.sql, days) } }
      },
    },

    {
      method: 'POST',
      path: '/definitions',
      /**
       * Publish the catalogue this build carries. Idempotent by `Idempotency-Key`, and idempotent
       * again underneath by `publish()` — which refuses rather than replays if a version's text
       * changed. Both layers are wanted: the key stops a double-click doing the work twice, and
       * the checksum stops a *different* build quietly redefining a live series.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireExactScope(principal, SCOPE_ADMIN)
        const clientKey = idempotencyKeyOf(ctx.req)
        const outcome = await withIdempotency(ctx.sql, {
          principal: principalName(principal),
          route: 'POST /definitions',
          clientKey,
          requestHash: requestFingerprint({ definitions: DEFINITIONS.length }),
          run: async (tx) => {
            const result = await publish(tx, DEFINITIONS)
            return { response: result, artefactId: null }
          },
        })
        return { status: 200, body: { ...outcome.result, replayed: outcome.replayed } }
      },
    },
    {
      method: 'POST',
      path: '/cohorts/recompute',
      /**
       * Ask for the retention grid to be recomputed. Enqueues a job; it does not run one.
       *
       * A route that ran the recompute inline would hold an HTTP request open across the most
       * expensive query this service issues, and two operators clicking it would run it twice —
       * which is exactly the contention the `global` lease exists to prevent. The job queue is the
       * mechanism; this route is a request to it.
       */
      handle: async (ctx, deps) => {
        const principal = await authenticate(ctx, deps)
        requireExactScope(principal, SCOPE_ADMIN)
        const clientKey = idempotencyKeyOf(ctx.req)
        const outcome = await withIdempotency(ctx.sql, {
          principal: principalName(principal),
          route: 'POST /cohorts/recompute',
          clientKey,
          requestHash: requestFingerprint({ kind: COHORT_KIND }),
          run: async () => {
            // `earliest` rather than `keep`: an operator asking for a recompute wants it now, not
            // at the next hourly tick, and pulling the schedule forward still collapses two
            // requests into one run.
            await deps.queue.enqueue({ kind: COHORT_KIND, key: 'global', onConflict: 'earliest', payload: {} })
            return { response: { status: 'queued' as const }, artefactId: null }
          },
        })
        return { status: 202, body: { ...outcome.result, replayed: outcome.replayed } }
      },
    },
  ]

  return routes.map((route) => ({ ...route, pattern: compile(route.path) }))
}

/* ------------------------------------------------------------------ authorisation */

async function authenticate(ctx: RequestContext, deps: ServerDeps): Promise<Principal> {
  const token = bearerFrom(headerOf(ctx.req, 'authorization'))
  // A missing token is a token fault, so it takes the same 401 path as a bad one rather than being
  // a separate branch that can drift away from it.
  if (!token) throw new TokenError('no bearer token presented', 'missing')
  return deps.verifier.principal(token)
}

function principalName(principal: Principal): string {
  return principal.kind === 'service' ? `service:${principal.service}` : `user:${principal.userId}`
}

/**
 * Constant-time comparison of the `/metrics` token.
 *
 * `===` on a secret leaks its prefix through timing. The length is compared first because
 * `timingSafeEqual` throws on a mismatch, and a token's length is not the secret.
 */
function presentsToken(req: IncomingMessage, expected: string): boolean {
  const presented = headerOf(req, 'x-analytics-token')
  if (!presented) return false
  const a = Buffer.from(presented)
  const b = Buffer.from(expected)
  return a.length === b.length && timingSafeEqual(a, b)
}

/* ------------------------------------------------------------------ parsing */

function idempotencyKeyOf(req: IncomingMessage): string {
  const key = headerOf(req, 'idempotency-key')
  if (!key || !SAFE_IDEMPOTENCY_KEY.test(key)) {
    throw new BadRequestError('Idempotency-Key is required, 8–128 characters of [A-Za-z0-9_.:-]')
  }
  return key
}

/**
 * The reporting window.
 *
 * Bounded at four hundred days, which is the retention horizon: a wider window can only return
 * rows that have been deleted, and an unbounded one is a full scan any reader can request.
 */
export function parseWindow(url: URL, now: Now = systemNow): Window {
  const to = parseInstant(url.searchParams.get('to'), 'to') ?? now()
  const from = parseInstant(url.searchParams.get('from'), 'from') ?? new Date(to.getTime() - 30 * 86_400_000)
  if (from >= to) throw new BadRequestError('from must be before to')
  if (to.getTime() - from.getTime() > MAX_WINDOW_DAYS * 86_400_000) {
    throw new BadRequestError(`the window may not exceed ${MAX_WINDOW_DAYS} days`)
  }
  return { from, to }
}

function parseInstant(raw: string | null, name: string): Date | null {
  if (raw === null) return null
  const value = new Date(raw)
  if (Number.isNaN(value.getTime())) throw new BadRequestError(`${name} must be an ISO-8601 instant`)
  return value
}

function parseInteger(raw: string | null, name: string, fallback: number, min: number, max: number): number {
  if (raw === null) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new BadRequestError(`${name} must be a whole number between ${min} and ${max}`)
  }
  return value
}

/* ------------------------------------------------------------------ transport */

/**
 * The exact bytes that arrived, as a string.
 *
 * Not parsed and re-serialised. The signature is over these bytes, and a re-serialisation differs
 * on key order, whitespace and number formatting — so verifying anything else would be verifying
 * something other than what the handler acts on.
 */
async function readRaw(req: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = []
  let size = 0
  for await (const chunk of req) {
    const buffer = chunk as Buffer
    size += buffer.length
    // Capped before buffering, not after: an unbounded body is a memory exhaustion primitive that
    // any caller who can open a socket can reach.
    if (size > MAX_BODY_BYTES) throw new BadRequestError('request body too large')
    chunks.push(buffer)
  }
  return Buffer.concat(chunks).toString('utf8')
}

function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

function send(res: ServerResponse, reply: Reply, requestId: string): void {
  if (res.writableEnded) return
  const payload = reply.text ?? `${JSON.stringify(reply.body ?? {})}\n`
  res.writeHead(reply.status, {
    'content-type': reply.contentType ?? 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(payload),
    'x-request-id': requestId,
    // An aggregate is a point-in-time answer, and a cached one is a dashboard that stops updating.
    // It is also a privacy answer: a suppressed cell must not be served from a cache written
    // before the threshold was raised.
    'cache-control': 'no-store',
  })
  res.end(payload)
}

function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}
