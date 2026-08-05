/**
 * The HTTP surface, driven over a real socket against a real Postgres.
 *
 * The verifier is a fake — a plain object implementing `principal` — so no JWKS is needed to prove
 * the 401 path, the exact scope matcher and the static-token door on `/metrics`.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE TWO THINGS THIS FILE IS FOR THAT NOTHING ELSE COVERS.**
 *
 *   1. **The scope matcher is EXACT, and `analytics:*` grants nothing.** The estate ships two
 *      matchers that disagree — `contracts/packages/auth:209` is exact,
 *      `runtime/packages/auth:178` honours one wildcard level — and this service chose exact and
 *      changed neither package. A choice recorded only in a comment is a choice that drifts back;
 *      the cases below assert it in both directions, so a future edit that imports `hasScope`
 *      fails here rather than silently widening every credential ever issued against a store
 *      holding four hundred days of behaviour.
 *
 *   2. **Suppression survives the round trip.** `reads.test.ts` proves `suppress()` withholds a
 *      four-person cohort. This proves the JSON that actually leaves the process carries no number
 *      — because a threshold that is applied and then serialised alongside the raw count is not a
 *      threshold, and that is a mistake you cannot see from inside the function.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type { AddressInfo } from 'node:net'
import type { Server } from 'node:http'
import type postgres from 'postgres'
import { SIGNATURE_HEADER, makeEvent, serialiseEvent, signDelivery, type Actor, type EventEnvelope } from '@cloudsforge/contracts-events'
import { TokenError, type Principal } from '@cloudsforge/auth'
import { JobQueue, type Sql as JobsSql } from '@cloudsforge/jobs'
import { Lifecycle, postgresProbe } from '@cloudsforge/lifecycle'
import { COHORT_KIND } from './jobs.ts'
import { deriveSubject, rawSubject } from './pseudonym.ts'
import { SCOPE_ADMIN, SCOPE_READ, createServer, hasExactScope, scrapeRefresh, type PrincipalVerifier, type ServerDeps } from './server.ts'
import {
  TEST_PEPPER,
  migrateTestDb,
  openDb,
  quietLogger,
  resetAnalytics,
  skip,
  testMetrics,
} from './testsupport.ts'

const TOKEN = 'a-real-looking-static-token-000000000'
const SECRET = 'a-delivery-secret-of-sufficient-length'
const SPIROS = 'user:550e8400-e29b-41d4-a716-446655440000'
const DAY = 86_400_000

/**
 * Tokens, and what each one is.
 *
 * `wildcard` is the important one: a service holding `analytics:*` and nothing else. Under
 * `runtime/packages/auth`'s matcher it would read every report; here it reads nothing.
 */
const PRINCIPALS: Readonly<Record<string, Principal>> = {
  reader: { kind: 'service', service: 'admin-api', scopes: [SCOPE_READ] },
  admin: { kind: 'service', service: 'admin-api', scopes: [SCOPE_ADMIN] },
  wildcard: { kind: 'service', service: 'legacy', scopes: ['analytics:*'] },
  star: { kind: 'service', service: 'legacy', scopes: ['*'] },
  operator: { kind: 'user', userId: 'u-1', handle: 'ops', roles: ['admin'] },
  person: { kind: 'user', userId: 'u-2', handle: 'spiros', roles: [] },
}

const verifier: PrincipalVerifier = {
  async principal(token: string): Promise<Principal> {
    const principal = PRINCIPALS[token]
    if (!principal) throw new TokenError('unknown test token', 'invalid')
    return principal
  },
}

interface Running {
  readonly url: string
  close(): Promise<void>
}

describe('the HTTP surface', { skip }, () => {
  let sql: postgres.Sql
  let app: Running
  let queue: JobQueue

  async function start(): Promise<Running> {
    const lifecycle = new Lifecycle({ drainDelayMs: 0, drainTimeoutMs: 100 })
    lifecycle.addProbe(postgresProbe('postgres', () => sql`select 1`))
    const metrics = testMetrics()
    queue = new JobQueue(sql as unknown as JobsSql, { owner: 'test', leaseMs: 60_000 })
    const deps: ServerDeps = {
      lifecycle,
      logger: quietLogger(),
      metrics,
      verifier,
      sql,
      token: TOKEN,
      minCohort: 5,
      queue,
      ingest: { sql, logger: quietLogger(), metrics, secrets: [SECRET], peppers: TEST_PEPPER },
      beforeScrape: scrapeRefresh({ sql, metrics }),
    }
    const server: Server = createServer(deps)
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', () => resolve()))
    lifecycle.markReady()
    const port = (server.address() as AddressInfo).port
    return {
      url: `http://127.0.0.1:${port}`,
      close: () => new Promise<void>((resolve) => server.close(() => resolve())),
    }
  }

  before(async () => {
    sql = openDb()
    await migrateTestDb(sql)
    app = await start()
  })
  beforeEach(async () => {
    await resetAnalytics(sql)
  })
  after(async () => {
    await app.close()
    await sql.end({ timeout: 5 })
  })

  function get(path: string, token?: string): Promise<Response> {
    return fetch(`${app.url}${path}`, token ? { headers: { authorization: `Bearer ${token}` } } : {})
  }

  async function subjectKey(subject: string): Promise<string> {
    const derived = await deriveSubject(sql, TEST_PEPPER, rawSubject(subject), new Date())
    assert.equal(derived.status, 'ok')
    return derived.status === 'ok' ? derived.subjectKey : ''
  }

  async function plant(key: string, eventName: string, occurredAt: Date): Promise<void> {
    await sql`
      insert into events (subject_key, subject_kind, event_name, occurred_at, source_event_id, source_topic, producer)
      values (${key}, 'user', ${eventName}, ${occurredAt}, ${crypto.randomUUID()}, 'identity.user.registered', 'identity')
    `
  }

  /* ================================================================ health */

  describe('the three health endpoints', () => {
    it('/livez is static and answers 200', async () => {
      const res = await get('/livez')
      assert.equal(res.status, 200)
    })

    it('/readyz probes Postgres and reports ready', async () => {
      const res = await get('/readyz')
      assert.equal(res.status, 200)
      const body = (await res.json()) as { ready: boolean }
      assert.equal(body.ready, true)
    })

    it('/metrics costs a credential', async () => {
      assert.equal((await get('/metrics')).status, 401)
      const res = await fetch(`${app.url}/metrics`, { headers: { 'x-analytics-token': TOKEN } })
      assert.equal(res.status, 200)
      const text = await res.text()
      // The gauges are sampled at scrape time, never on a timer — rule 8.
      assert.match(text, /analytics_events_stored/)
      assert.match(text, /analytics_subjects_erased/)
    })

    it('/metrics refuses a token of the right length but the wrong bytes', async () => {
      const wrong = `${TOKEN.slice(0, -1)}X`
      const res = await fetch(`${app.url}/metrics`, { headers: { 'x-analytics-token': wrong } })
      assert.equal(res.status, 401)
    })
  })

  /* ================================================================ the scope matcher */

  describe('the scope matcher is exact, and neither auth package is changed', () => {
    it('grants the scope it names', () => {
      assert.equal(hasExactScope(PRINCIPALS['reader']!, SCOPE_READ), true)
    })

    it('a wildcard grants NOTHING — the whole point of choosing exact', () => {
      // Under runtime/packages/auth:178 this principal reads every report. Here it reads none.
      // A token minted to read a funnel must not silently acquire whatever read is added next.
      assert.equal(hasExactScope(PRINCIPALS['wildcard']!, SCOPE_READ), false)
      assert.equal(hasExactScope(PRINCIPALS['wildcard']!, SCOPE_ADMIN), false)
      assert.equal(hasExactScope(PRINCIPALS['star']!, SCOPE_READ), false)
    })

    it('answers 403 to the wildcard over HTTP, not merely in the predicate', async () => {
      const res = await get('/reports/active', 'wildcard')
      assert.equal(res.status, 403)
      const body = (await res.json()) as { error: { code: string; message: string } }
      assert.equal(body.error.code, 'forbidden')
      assert.match(body.error.message, /analytics:read/)
    })

    it('does not import hasScope from @cloudsforge/auth', async () => {
      // The choice must survive a future edit that reaches for the convenient import.
      const { readFileSync } = await import('node:fs')
      const { fileURLToPath } = await import('node:url')
      const source = readFileSync(fileURLToPath(new URL('./server.ts', import.meta.url)), 'utf8')
      const imports = /import \{([^}]*)\} from '@cloudsforge\/auth'/.exec(source)?.[1] ?? ''
      assert.equal(imports.includes('hasScope'), false, 'importing hasScope would widen every credential')
    })

    it('a read scope does not grant admin, and an admin scope does not grant read', async () => {
      assert.equal((await get('/reports/active', 'admin')).status, 403)
      const res = await fetch(`${app.url}/cohorts/recompute`, {
        method: 'POST',
        headers: { authorization: 'Bearer reader', 'idempotency-key': 'recompute-scope-01' },
      })
      assert.equal(res.status, 403)
    })
  })

  /* ================================================================ who may read */

  describe('who may read an aggregate', () => {
    it('nobody, without a token', async () => {
      assert.equal((await get('/reports/active')).status, 401)
      assert.equal((await get('/funnels')).status, 401)
    })

    it('an operator may', async () => {
      assert.equal((await get('/reports/active', 'operator')).status, 200)
    })

    it('an ordinary user may NOT, whatever they carry', async () => {
      // There is no per-user view of this data and there is not going to be one: a per-user view is
      // the support question AD-21 exists to make unanswerable (13-operational-model.md:603-608).
      const res = await get('/reports/active', 'person')
      assert.equal(res.status, 403)
    })

    it('an unknown token is a 401 that says nothing about why', async () => {
      const res = await get('/reports/active', 'not-a-token')
      assert.equal(res.status, 401)
      const body = (await res.json()) as { error: { message: string } }
      // "expired" versus "bad signature" tells an attacker which half of a forged token to fix.
      assert.equal(body.error.message, 'a valid bearer token is required')
    })
  })

  /* ================================================================ suppression over the wire */

  describe('suppression survives the round trip', () => {
    it('a four-person cohort leaves the process with no number in the body', async () => {
      for (let i = 0; i < 4; i += 1) {
        await plant(await subjectKey(`user:s-${i}`), 'listing_sold', new Date(Date.now() - DAY))
      }
      const res = await get('/reports/active', 'reader')
      assert.equal(res.status, 200)
      const text = await res.text()
      const body = JSON.parse(text) as { minCohort: number; count: { suppressed: boolean } }
      assert.equal(body.count.suppressed, true)
      assert.equal(body.minCohort, 5)
      assert.equal(/\b4\b/.test(text.replace(/"minCohort":\d+/, '')), false, 'the withheld count must not be in the bytes')
    })

    it('a five-person cohort is published', async () => {
      for (let i = 0; i < 5; i += 1) {
        await plant(await subjectKey(`user:t-${i}`), 'listing_sold', new Date(Date.now() - DAY))
      }
      const body = (await (await get('/reports/active', 'reader')).json()) as {
        count: { suppressed: boolean; subjects?: number }
      }
      assert.equal(body.count.suppressed, false)
      assert.equal(body.count.subjects, 5)
    })

    it('a suppressed answer is never served from a cache', async () => {
      const res = await get('/reports/active', 'reader')
      assert.equal(res.headers.get('cache-control'), 'no-store')
    })
  })

  /* ================================================================ the read routes */

  describe('the read routes', () => {
    it('publishes the catalogue so a producer need not discover it by refusal', async () => {
      const body = (await (await get('/catalogue', 'reader')).json()) as {
        events: string[]
        properties: string[]
      }
      assert.ok(body.events.includes('user_registered'))
      assert.ok(body.properties.includes('amount_bucket'))
      // No free-text property type exists to publish.
      assert.equal(body.properties.includes('display_name'), false)
    })

    it('refuses an event name that is not in the catalogue', async () => {
      const res = await get('/reports/daily?event=whatever', 'reader')
      assert.equal(res.status, 400)
    })

    it('refuses a window wider than the retention horizon', async () => {
      const from = new Date(Date.now() - 500 * DAY).toISOString()
      const res = await get(`/reports/daily?event=user_registered&from=${from}`, 'reader')
      assert.equal(res.status, 400)
      const body = (await res.json()) as { error: { message: string } }
      assert.match(body.error.message, /400 days/)
    })

    it('refuses a backwards window', async () => {
      const to = new Date(Date.now() - 10 * DAY).toISOString()
      const from = new Date().toISOString()
      assert.equal((await get(`/reports/daily?event=user_registered&from=${from}&to=${to}`, 'reader')).status, 400)
    })

    it('404s a funnel that is not in the closed catalogue', async () => {
      assert.equal((await get('/funnels/anything-i-like', 'reader')).status, 404)
    })

    it('serves a funnel that is', async () => {
      const body = (await (await get('/funnels/onboarding', 'reader')).json()) as {
        id: string
        steps: unknown[]
      }
      assert.equal(body.id, 'onboarding')
      assert.equal(body.steps.length, 4)
    })
  })

  /* ================================================================ ingest */

  describe('POST /ingest is the only write path for an event', () => {
    function body(payload: unknown, actor: Actor = SPIROS as Actor): string {
      return serialiseEvent(
        makeEvent({
          topic: 'identity.user.registered',
          key: 'k-1',
          actor,
          payload,
          occurredAt: new Date(),
        }) as EventEnvelope,
      )
    }

    function post(raw: string, options: { token?: string; signature?: string } = {}): Promise<Response> {
      const headers: Record<string, string> = { 'content-type': 'application/json' }
      if (options.token !== undefined) headers['authorization'] = `Bearer ${options.token}`
      if (options.signature !== undefined) headers[SIGNATURE_HEADER] = options.signature
      return fetch(`${app.url}/ingest`, { method: 'POST', headers, body: raw })
    }

    // ══════════════════════════════════════════════════════════════════════════════════════════
    // THE DEFECT THESE THREE EXIST FOR.
    //
    // Every test below used to pass `token: 'ingester'`, so the suite only ever exercised a caller
    // that does not exist. No outbox relay in this estate sends an `Authorization` header — all
    // twenty-one were read, `identity/src/outbox.ts:320` among them — so the shape exercised here
    // is now the shape actually on the wire: signature, event id, nothing else.
    // ══════════════════════════════════════════════════════════════════════════════════════════

    it('RECORDS A RELAY DELIVERY THAT CARRIES NO AUTHORIZATION HEADER AT ALL', async () => {
      // Against the previous build this answered 401 `unauthenticated` — measured against the
      // running estate as well as here — and the onboarding denominator stayed empty for ever.
      const raw = body({ analytics: { subject: SPIROS, surface: 'register' } })
      const res = await post(raw, { signature: signDelivery(raw, SECRET) })
      assert.equal(res.status, 201, 'a correctly signed delivery with no bearer must be recorded')
      const parsed = (await res.json()) as { status: string; event: string; droppedProperties: string[] }
      assert.deepEqual(parsed, { status: 'recorded', event: 'user_registered', droppedProperties: [] })
      assert.equal((await sql`select 1 from events`).length, 1)
    })

    it('THE MAC IS THE WHOLE AUTHENTICATION: a valid bearer does not substitute for it', async () => {
      // The other direction, and the one that would catch a future edit that "restores" the token
      // check by making the signature optional when a bearer is present. An admin token is the
      // strongest credential this service knows and it buys nothing here.
      const raw = body({ analytics: { subject: SPIROS } })
      const res = await post(raw, { token: 'admin' })
      assert.equal(res.status, 401)
      assert.equal(((await res.json()) as { error: { code: string } }).error.code, 'bad_signature')
      assert.equal((await sql`select 1 from events`).length, 0)
    })

    it('and a bearer that would have been REFUSED before is now simply irrelevant', async () => {
      // This case used to assert 403: `reader` holds `analytics:read`, never `analytics:ingest`.
      // The scope is gone, so what decides the outcome is the signature and only the signature.
      const raw = body({ analytics: { subject: SPIROS } })
      const res = await post(raw, { token: 'reader', signature: signDelivery(raw, SECRET) })
      assert.equal(res.status, 201)
    })

    it('stores a pseudonym and not the subject', async () => {
      const raw = body({ analytics: { subject: SPIROS } })
      await post(raw, { signature: signDelivery(raw, SECRET) })
      const rows = await sql<{ subject_key: string }[]>`select subject_key from events`
      assert.equal(rows.length, 1)
      assert.match(rows[0]!.subject_key, /^[0-9a-f]{64}$/)
      assert.equal(rows[0]!.subject_key.includes('550e8400'), false)
    })

    it('refuses an unsigned body with 401, before parsing it', async () => {
      // The body is not valid JSON. A 401 rather than a 400 proves the parser was never reached —
      // which matters more now that the MAC is the only thing standing in front of it.
      const res = await post('{"not":"even an envelope"')
      assert.equal(res.status, 401)
      const parsed = (await res.json()) as { error: { code: string } }
      assert.equal(parsed.error.code, 'bad_signature')
    })

    it('refuses a body signed with the wrong secret', async () => {
      const raw = body({ analytics: { subject: SPIROS } })
      const res = await post(raw, { signature: signDelivery(raw, 'a-different-secret-of-length') })
      assert.equal(res.status, 401)
    })

    it('THE SIGNATURE IS OVER THE EXACT BYTES: one altered byte is refused', async () => {
      // Signed over `raw`, delivered as `tampered`. The two parse to objects that differ in one
      // property value, so anything that verified a re-serialisation, or verified after parsing,
      // would let this through.
      const raw = body({ analytics: { subject: SPIROS, surface: 'register' } })
      const signature = signDelivery(raw, SECRET)
      const tampered = raw.replace('"surface":"register"', '"surface":"registeR"')
      assert.notEqual(tampered, raw, 'the fixture must actually differ or this asserts nothing')
      const res = await fetch(`${app.url}/ingest`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', [SIGNATURE_HEADER]: signature },
        body: tampered,
      })
      assert.equal(res.status, 401)
      assert.equal((await sql`select 1 from events`).length, 0)
    })

    it('answers 200 to a redelivery rather than an error that makes the relay retry for ever', async () => {
      const raw = body({ analytics: { subject: SPIROS } })
      const signature = signDelivery(raw, SECRET)
      assert.equal((await post(raw, { signature })).status, 201)
      const second = await post(raw, { signature })
      assert.equal(second.status, 200)
      assert.deepEqual((await second.json() as { status: string }).status, 'duplicate')
      const rows = await sql`select 1 from events`
      assert.equal(rows.length, 1)
    })

    it('tells the producer which properties were refused, and stores neither', async () => {
      const raw = body({ analytics: { subject: SPIROS, display_name: 'Spiros Savvanis', surface: 'register' } })
      const res = await post(raw, { signature: signDelivery(raw, SECRET) })
      assert.equal(res.status, 201)
      const parsed = (await res.json()) as { droppedProperties: string[] }
      assert.deepEqual(parsed.droppedProperties, ['display_name'])
      const rows = await sql<{ props: Record<string, unknown> }[]>`select props from events`
      assert.deepEqual(rows[0]?.props, { surface: 'register' })
      // The offending NAME is counted, never stored: a key can be the personal data.
      const counts = await sql<{ reason: string }[]>`select reason from ingest_rejections`
      assert.deepEqual(counts.map((row) => row.reason), ['disallowed_property'])
    })
  })

  /* ================================================================ the mutating routes */

  describe('POST /cohorts/recompute enqueues, and a retry replays', () => {
    it('requires an Idempotency-Key', async () => {
      const res = await fetch(`${app.url}/cohorts/recompute`, {
        method: 'POST',
        headers: { authorization: 'Bearer admin' },
      })
      assert.equal(res.status, 400)
      assert.match(((await res.json()) as { error: { message: string } }).error.message, /Idempotency-Key/)
    })

    it('enqueues once and replays the second time', async () => {
      const send = () =>
        fetch(`${app.url}/cohorts/recompute`, {
          method: 'POST',
          headers: { authorization: 'Bearer admin', 'idempotency-key': 'recompute-2026-08-01' },
        })

      const first = await send()
      assert.equal(first.status, 202)
      assert.deepEqual(await first.json(), { status: 'queued', replayed: false })

      const second = await send()
      assert.equal(second.status, 202)
      assert.deepEqual(await second.json(), { status: 'queued', replayed: true })

      const rows = await sql<{ n: number }[]>`select count(*)::int as n from jobs where kind = ${COHORT_KIND}`
      assert.equal(rows[0]?.n, 1, 'two clicks must not run the most expensive query twice')
    })

    it('publishes the definition catalogue idempotently', async () => {
      const send = () =>
        fetch(`${app.url}/definitions`, {
          method: 'POST',
          headers: { authorization: 'Bearer admin', 'idempotency-key': 'publish-definitions-1' },
        })
      const first = (await (await send()).json()) as { published: string[]; replayed: boolean }
      assert.ok(first.published.length > 0)
      assert.equal(first.replayed, false)
      const second = (await (await send()).json()) as { replayed: boolean }
      assert.equal(second.replayed, true)
    })
  })

  /* ================================================================ plumbing */

  describe('request plumbing', () => {
    it('echoes a safe request id and mints one otherwise', async () => {
      const mine = await fetch(`${app.url}/livez`, { headers: { 'x-request-id': 'abc-123' } })
      assert.equal(mine.headers.get('x-request-id'), 'abc-123')
      // A presented id is echoed into every log line and into the response header, so it is
      // constrained rather than trusted. `undici` refuses to send a newline at all, so the case
      // that can actually be driven over a socket is a value with spaces and one that is too long.
      for (const hostile of ['a b c', 'x'.repeat(65)]) {
        const res = await fetch(`${app.url}/livez`, { headers: { 'x-request-id': hostile } })
        assert.notEqual(res.headers.get('x-request-id'), hostile)
        assert.ok(res.headers.get('x-request-id'))
      }
    })

    it('404s an unknown path without leaking a route', async () => {
      const res = await get('/nope')
      assert.equal(res.status, 404)
    })
  })
})
