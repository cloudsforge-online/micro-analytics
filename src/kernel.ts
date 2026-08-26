/**
 * The HTTP kernel — the plumbing, and nothing this service is about.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY THIS FILE EXISTS: IT IS THE HALF THAT IS ALREADY WRITTEN TWICE.**
 *
 * `micro-lantern/src/server.ts` and this service's `server.ts` grew the same request listener
 * independently, and today they agree line for line: the request id echoed before anything can
 * fail, the route table compiled from `/funnels/:id` shapes, the `unmatched` metric label that
 * stops a caller minting unbounded time series, the RED metrics with the network on the SERIES,
 * `requestNetwork` refusing an unstamped request, `deps.sql.for()` resolved INSIDE a try, and the
 * `send`/`errorReply`/`headerOf` trio. Wave M1 of `deploy/docs/service-merge-plan.md` puts those
 * two services in one process; this file is the seam that lets one listener serve both route sets
 * instead of a third copy being written.
 *
 * Nothing here knows what analytics is. There is no pepper, no cohort floor, no catalogue and no
 * scope constant in this file, and that is load-bearing rather than tidy — see `routes.ts`.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **The `sql` type is a parameter, not a decision.** lantern's `RequestContext.sql` is
 * `@cloudsforge/db`'s minimal `Sql`; this service's is `postgres`'s, because its reads use tagged
 * templates the minimal interface does not publish. That is the ONLY way the two contexts differed,
 * so it is expressed as a type parameter rather than by picking a winner and casting at every read.
 */

import {
  createServer as createHttpServer,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from 'node:http'
import { NetworkUnknownError, requestNetwork, type Network } from '@cloudsforge/http'
import type { NetworkSql, Sql } from '@cloudsforge/db'
import { newRequestId, type Logger, type Metrics } from '@cloudsforge/telemetry'

const SAFE_REQUEST_ID = /^[A-Za-z0-9_-]{1,64}$/

export interface Reply {
  readonly status: number
  readonly body?: unknown
  readonly text?: string
  readonly contentType?: string
  /**
   * Extra response headers, merged over the defaults `send` writes.
   *
   * No route in this service sets one, and the field is here for the merge rather than for
   * speculation: lantern's browser-facing ingest MUST attach `access-control-allow-origin` to every
   * refusal, because a 4xx a page cannot read is indistinguishable from the host being down. Its
   * `send` already takes `Reply & { headers?: … }`; hoisting the field onto `Reply` is what lets one
   * `send` serve both without lantern's CORS replies needing an intersection type at every call.
   */
  readonly headers?: Record<string, string>
}

export interface RequestContext<TSql = Sql> {
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
  readonly sql: TSql
}

/**
 * Routes that answer without belonging to a network.
 *
 * Kubelet probes the first two and Prometheus scrapes the third; none arrives through the gateway,
 * so none carries `CF-Network`. Refusing them makes every health probe a 500 and the pod never
 * becomes ready. Three literal paths rather than a prefix, because this is an exemption from a data
 * boundary; none of them queries the database.
 */
export const OPERATIONAL_ROUTES: ReadonlySet<string> = new Set(['/livez', '/readyz', '/metrics'])

/**
 * One route, as a module declares it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **`handle` TAKES ONLY `ctx`. THE DEPENDENCIES ARE CLOSED OVER, NOT PASSED.**
 *
 * The old shape was `handle(ctx, deps)`, which reads as harmless currying and is not. `deps` there
 * is the WHOLE service's dependency record — for analytics that includes the pseudonymisation
 * pepper ring — and a route table typed that way hands it to every handler mounted on the same
 * listener. The moment lantern's routes and these routes share one process, `handle(ctx, deps)`
 * means lantern's OTLP handler is one property access away from the pepper that makes this
 * service's subjects unattributable.
 *
 * Taking only `ctx` makes the reach impossible rather than merely impolite: each module builds its
 * own specs in its own factory, over its own deps, and what a handler cannot name it cannot leak.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */
export interface RouteSpec<TSql = Sql> {
  readonly method: string
  /** `/funnels/:id`. Used verbatim as the metric label, so cardinality is bounded. */
  readonly path: string
  readonly handle: (ctx: RequestContext<TSql>) => Promise<Reply>
}

/** A `RouteSpec` with its path compiled. Built by `mountRoutes`; modules never construct one. */
export interface Route<TSql = Sql> extends RouteSpec<TSql> {
  readonly pattern: RegExp
}

/**
 * Compile `/funnels/:id` into a matcher. The segment pattern excludes `/` so a parameter cannot
 * swallow the rest of the path and make one route answer for another.
 */
export function compile(path: string): RegExp {
  const source = path
    .split('/')
    .map((segment) =>
      segment.startsWith(':') ? `(?<${segment.slice(1)}>[^/]+)` : segment.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'),
    )
    .join('/')
  return new RegExp(`^${source}$`)
}

/**
 * What the listener itself needs, and deliberately nothing else.
 *
 * A service's full dependency record satisfies this structurally, so `createServer` passes its own
 * `deps` straight through — but the kernel's TYPE names only the four things it reads. That is the
 * boundary written down: anything a route needs beyond these is the route module's business.
 */
export interface KernelDeps {
  readonly logger: Logger
  readonly metrics: Metrics
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
}

/**
 * Mount a route table on a `node:http` server.
 *
 * This is the body that used to sit inside `createServer`, unchanged: same order, same metrics,
 * same two 500s, same `void`-with-`.catch` dispatch.
 */
export function mountRoutes<TSql>(specs: readonly RouteSpec<TSql>[], deps: KernelDeps): Server {
  const routes: readonly Route<TSql>[] = specs.map((spec) => ({ ...spec, pattern: compile(spec.path) }))
  let inFlight = 0

  return createHttpServer((req, res) => {
    const startedAt = process.hrtime.bigint()
    const presented = headerOf(req, 'x-request-id')
    const requestId = presented && SAFE_REQUEST_ID.test(presented) ? presented : newRequestId()

    // Echoed before anything can fail, so even a 500 carries the id the user will quote.
    res.setHeader('x-request-id', requestId)

    const url = new URL(req.url ?? '/', `http://${headerOf(req, 'host') ?? 'localhost'}`)
    const method = req.method ?? 'GET'

    let matched: Route<TSql> | undefined
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

    // ── RESOLVED INSIDE A TRY, AND THAT IS NOT DEFENSIVE PADDING ───────────────────────────────
    //
    // `deps.sql.for()` THROWS when this deployment holds no handle for that network, and that
    // refusal is the safety property the consolidation rests on — better a loud 500 than a query
    // answered out of the other estate's rows.
    //
    // It runs BEFORE `dispatch` returns a promise, so an uncaught throw escapes the `void`
    // expression past a `.catch` that is not attached yet, and the listener returns having sent
    // NOTHING. The connection then hangs until the client gives up: the one path the design most
    // depends on being loud was the one path that was silent.
    let sql: TSql
    try {
      sql = deps.sql.for(network) as unknown as TSql
    } catch (err) {
      log.error('no usable database handle for this request', { err, network })
      send(
        res,
        errorReply(500, 'network_unavailable', 'this deployment cannot serve that network', requestId),
        requestId,
      )
      finish(500, network)
      return
    }
    void dispatch(matched, { req, url, requestId, log, params, network, sql })
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

/**
 * The one decision the kernel makes about a request: whether a route claimed it.
 *
 * Mapping a THROWN failure to a status is deliberately not here. What a `ConflictError` means is a
 * fact about a module's domain, not about HTTP, and a kernel that owned the mapping would have to
 * import every module's error classes — which is the coupling this seam exists to remove. Each
 * module wraps its own handlers; see `mapFailure` in `routes.ts`.
 */
async function dispatch<TSql>(route: Route<TSql> | undefined, ctx: RequestContext<TSql>): Promise<Reply> {
  if (!route) {
    return errorReply(404, 'not_found', `no route for ${ctx.req.method} ${ctx.url.pathname}`, ctx.requestId)
  }
  return route.handle(ctx)
}

export function errorReply(status: number, code: string, message: string, requestId: string): Reply {
  return { status, body: { error: { code, message, requestId } } }
}

export function send(res: ServerResponse, reply: Reply, requestId: string): void {
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
    // Last, so a route that must override one of the above can. Nothing in this service does.
    ...(reply.headers ?? {}),
  })
  res.end(payload)
}

export function headerOf(req: IncomingMessage, name: string): string | undefined {
  const value = req.headers[name]
  return Array.isArray(value) ? value[0] : value
}
