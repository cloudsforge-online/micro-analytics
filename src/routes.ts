/**
 * The analytics route table, and everything only these routes may see.
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
 * why at length, and why that is not a weakening. Every OTHER route here demands a bearer, and the
 * scope matcher for those is `hasExactScope` in `server.ts` — exact, deliberately, for the reason
 * that file's header records at length.
 * ---------------------------------------------------------------------------------------------
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **WHY `createRoutes(deps)` IS A FACTORY, AND WHY `handle` LOST ITS `deps` PARAMETER.**
 *
 * Every handler below CLOSES OVER `deps`. None receives it. The shape it replaces —
 * `handle: (ctx, deps) => …` — put the whole service's dependency record in the signature of the
 * route type, which is fine while one process serves one service and stops being fine in wave M1
 * of `deploy/docs/service-merge-plan.md`: lantern and analytics become one process mounting both
 * route tables on one listener. Under `handle(ctx, deps)` the listener must hand every handler the
 * same `deps`, so lantern's OTLP handler would be one property access from
 * `deps.ingest.peppers` — the pseudonymisation pepper ring that is the whole reason a subject in
 * this store cannot be re-identified, including by us.
 *
 * The plan promises that the privacy boundary "survives as a module boundary instead of a process
 * boundary". This factory is that boundary, made out of scope rather than out of a convention: the
 * pepper is reachable only from inside this function, and what another module cannot name it
 * cannot pass to a logger, a metric label or an error body by accident.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import type { IncomingMessage } from 'node:http'
import { timingSafeEqual } from 'node:crypto'
import { SIGNATURE_HEADER } from '@cloudsforge/contracts-events'
import { ForbiddenError, TokenError, bearerFrom, isAdmin, statusFor, type Principal } from '@cloudsforge/auth'
import { EVENT_NAMES, FUNNELS, PROPERTIES, PROPERTY_NAMES } from './catalogue.ts'
import { DEFINITIONS, DefinitionChangedError, listDefinitions, publish } from './definitions.ts'
import { DeliverySignatureError, MalformedEventError, ingest, parseDelivery, verifySignature } from './ingest.ts'
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
  systemNow,
  type Now,
  type Window,
} from './reads.ts'
import { listRejections, type Db } from './store.ts'
import { errorReply, headerOf, type Reply, type RequestContext, type RouteSpec } from './kernel.ts'
/*
 * The scope vocabulary and the exact matcher stay in `server.ts` and are imported here rather than
 * moved, because `server.test.ts` pins them there — both by importing them from that module and by
 * asserting that THAT FILE never imports `hasScope`. Moving them would leave the guard reading a
 * file the matcher had left, which is a guard that passes and protects nothing.
 *
 * That makes `server.ts` ⇄ `routes.ts` a cycle. It is safe by construction: every binding below is
 * read from inside a handler, never while either module is still evaluating.
 */
import { SCOPE_ADMIN, SCOPE_READ, hasExactScope, type ServerDeps } from './server.ts'

const MAX_BODY_BYTES = 256 * 1024
const MAX_WINDOW_DAYS = 400
const SAFE_IDEMPOTENCY_KEY = /^[A-Za-z0-9_.:-]{8,128}$/

/** The context every handler in this module gets. `Db` is `postgres`'s handle; see `kernel.ts`. */
type Ctx = RequestContext<Db>

/* ------------------------------------------------------------------ failures */

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

/**
 * What a thrown failure means over HTTP.
 *
 * Owned by this module, not by the kernel: the kernel would have to import every module's error
 * classes to do it, which is exactly the coupling the seam removes. `createRoutes` wraps every
 * handler in it, so the mapping runs in the same place it always did — around one route's body.
 */
function mapFailure(err: unknown, ctx: Ctx): Reply {
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

/* ------------------------------------------------------------------ routes */

export function createRoutes(deps: ServerDeps): readonly RouteSpec<Db>[] {
  const routes: readonly RouteSpec<Db>[] = [
    {
      method: 'GET',
      path: '/livez',
      /**
       * Static, deliberately. Liveness answers one question — should this process be killed and
       * restarted — and a liveness probe that consults a dependency restarts a healthy process
       * every time the database blinks. Readiness is where dependencies belong.
       */
      handle: async () => ({ status: 200, body: deps.lifecycle.livez() }),
    },
    {
      method: 'GET',
      path: '/readyz',
      handle: async () => {
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
      handle: async (ctx) => {
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
      handle: async (ctx) => {
        const rawBody = await readRaw(ctx.req)
        verifySignature(deps.ingest, rawBody, headerOf(ctx.req, SIGNATURE_HEADER))
        const delivery = parseDelivery(rawBody)
        // ── `ctx.sql`, NOT `deps.ingest.sql` ────────────────────────────────
        //
        // `deps.ingest.sql` is the process-wide PRIMARY handle, fixed at boot
        // (`index.ts` builds `ingest: { sql, … }` from the primary pool). Every
        // other route in this file reads `ctx.sql`, which `networkSql` resolves
        // once per request from `CF-Network`.
        //
        // So this route — and only this route — ignored the header and wrote
        // every delivery into the mainnet database, whatever network it was
        // stamped for. It is the exact failure `@cloudsforge/db` calls the
        // single most important line in that file, and the one `network.test.ts`
        // asserts against for every route it covers. This route was not covered.
        //
        // Caught before it ever fired: both `events` tables were empty on
        // 2026-08-26, because analytics' only subscription is
        // `identity.user.deleted` and no user has been deleted. There is
        // therefore nothing to migrate — which is why this is a one-line fix
        // now and would have been a data-repair later.
        const outcome = await ingest({ ...deps.ingest, sql: ctx.sql as unknown as Db }, delivery)

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
      handle: async (ctx) => {
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
      handle: async (ctx) => {
        requireReader(await authenticate(ctx, deps))
        const window = parseWindow(ctx.url, deps.now)
        const count = await activeSubjects(ctx.sql, window, deps.minCohort)
        return { status: 200, body: { minCohort: deps.minCohort, count } }
      },
    },
    {
      method: 'GET',
      path: '/funnels',
      handle: async (ctx) => {
        requireReader(await authenticate(ctx, deps))
        return { status: 200, body: { funnels: FUNNELS } }
      },
    },
    {
      method: 'GET',
      path: '/funnels/:id',
      handle: async (ctx) => {
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
      handle: async (ctx) => {
        requireReader(await authenticate(ctx, deps))
        const weeks = parseInteger(ctx.url.searchParams.get('weeks'), 'weeks', 12, 2, 52)
        const cells = await retentionGrid(ctx.sql, weeks, deps.minCohort, deps.now)
        return { status: 200, body: { minCohort: deps.minCohort, weeks, cells } }
      },
    },
    {
      method: 'GET',
      path: '/definitions',
      handle: async (ctx) => {
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
      handle: async (ctx) => {
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
      handle: async (ctx) => {
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
      handle: async (ctx) => {
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
      handle: async (ctx) => {
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

  // The failure mapping wraps each handler here rather than sitting in the kernel, so that a route
  // set mounted beside this one maps its own failures with its own vocabulary.
  return routes.map((route) => ({
    ...route,
    handle: async (ctx: Ctx): Promise<Reply> => {
      try {
        return await route.handle(ctx)
      } catch (err) {
        return mapFailure(err, ctx)
      }
    },
  }))
}

/* ------------------------------------------------------------------ authorisation */

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

async function authenticate(ctx: Ctx, deps: ServerDeps): Promise<Principal> {
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
