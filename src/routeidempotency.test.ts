/**
 * Every mutating route either replays a retry or has a documented reason not to.
 *
 * **WHY THIS IS A SOURCE-LEVEL TEST**, copied from `market/src/routeidempotency.test.ts` along with
 * the defect it was written for. In `market`, `POST /v1/orders/:id/disputes` was a plain INSERT with
 * no natural key and no route wrapper, so a double-clicked button opened TWO disputes on one order
 * and froze the listing twice. It sat beside four sibling routes that wrapped correctly and nothing
 * noticed, because the domain tests called `openDispute` directly and never traversed the route.
 *
 * The defect is an OMISSION, and an omission has no behaviour to test. So this asserts the shape of
 * the file: a mutating route added tomorrow without a wrapper fails here, and its author must either
 * wrap it or write down why it does not need one.
 *
 * The check is by ENUMERATION rather than by a list of routes somebody remembered to update — the
 * list is derived from `server.ts` itself, and the last three cases exist so that a detector which
 * has stopped seeing routes fails loudly instead of passing vacuously.
 */

import assert from 'node:assert/strict'
import { test } from 'node:test'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'

const RAW = readFileSync(fileURLToPath(new URL('./server.ts', import.meta.url)), 'utf8')

/**
 * The server with its comments removed.
 *
 * Not cosmetic. `POST /ingest` carries a doc comment reading "deliberately NOT wrapped in
 * `withIdempotency`", and a detector that greps the raw file reports that route as WRAPPED — the
 * exact inversion of what the comment says, and a false pass for any route whose prose happens to
 * name the wrapper. The first version of this file did precisely that. Only whole-line `//`
 * comments are stripped, so the `http://` inside a template literal survives.
 */
const SERVER = RAW.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '')

/**
 * Mutating routes that are safe WITHOUT the wrapper, each with the reason.
 *
 * A route is only exempt if retrying it a second time cannot produce a second artefact.
 */
const EXEMPT: Readonly<Record<string, string>> = {
  'POST /ingest':
    'the inbox, unique on (topic, event_id) — a STRONGER guarantee than a caller-supplied key, ' +
    'because it holds for a relay that has forgotten it already delivered. events_source_uniq is ' +
    'the second line behind it. A caller-supplied Idempotency-Key here would be a weaker claim ' +
    'layered over a stronger one, and a producer that omitted it would be unprotected.',
}

interface RouteRef {
  readonly key: string
  /** The handler's source, comments removed. */
  readonly body: string
  readonly wrapped: boolean
}

/** Every route in `buildRoutes()`, with whether its handler reaches `withIdempotency`. */
function routes(): readonly RouteRef[] {
  const pattern = /method:\s*'([A-Z]+)',\s*path:\s*'([^']+)'/g
  const found: Array<{ key: string; at: number }> = []
  for (let match = pattern.exec(SERVER); match !== null; match = pattern.exec(SERVER)) {
    found.push({ key: `${match[1]} ${match[2]}`, at: match.index })
  }
  return found.map((route, index) => {
    const body = SERVER.slice(route.at, found[index + 1]?.at ?? SERVER.length)
    return { key: route.key, body, wrapped: body.includes('withIdempotency(') }
  })
}

const MUTATING = new Set(['POST', 'PUT', 'PATCH', 'DELETE'])

function mutatingRoutes(): readonly RouteRef[] {
  return routes().filter((route) => MUTATING.has(route.key.split(' ')[0] ?? ''))
}

test('every mutating route replays a retry, or says why it need not', () => {
  const unexplained = mutatingRoutes()
    .filter((route) => !route.wrapped && !(route.key in EXEMPT))
    .map((route) => route.key)
  assert.deepEqual(
    unexplained,
    [],
    `these mutating routes neither wrap withIdempotency nor appear in EXEMPT:\n  ${unexplained.join('\n  ')}\n` +
      'A retried request must not create a second artefact. Wrap it, or add it to EXEMPT with the reason.',
  )
})

test('the two routes that enqueue or publish are wrapped', () => {
  const byKey = new Map(mutatingRoutes().map((route) => [route.key, route.wrapped]))
  assert.equal(
    byKey.get('POST /cohorts/recompute'),
    true,
    'two operators clicking recompute must not run the estate’s most expensive query twice',
  )
  assert.equal(
    byKey.get('POST /definitions'),
    true,
    'a double-click must not attempt to republish a released definition and 409 on the second',
  )
})

test('every wrapped route also demands the header, rather than defaulting one', () => {
  // A route that invented a key when the caller sent none would be idempotent against nothing:
  // two attempts would carry two generated keys and both would run.
  for (const route of mutatingRoutes()) {
    if (!route.wrapped) continue
    assert.ok(route.body.includes('idempotencyKeyOf'), `${route.key} must read the caller's Idempotency-Key`)
  }
})

test('the detector reads code, not prose', () => {
  // `POST /ingest` documents that it is deliberately NOT wrapped, and the first version of this
  // file reported it as wrapped because the sentence names the function. Comments are stripped
  // before anything is matched; this is the case that fails if that stops happening.
  assert.ok(RAW.includes('NOT wrapped in `withIdempotency`'), 'the prose this guards against is gone; update the case')
  const byKey = new Map(mutatingRoutes().map((route) => [route.key, route.wrapped]))
  assert.equal(byKey.get('POST /ingest'), false, 'a route that says it is unwrapped must be detected as unwrapped')
})

test('the detector sees the routes at all', () => {
  // An empty list passes the first test vacuously. This is the line that stops that.
  const all = routes()
  assert.ok(all.length >= 12, `expected the server to declare many routes, found ${all.length}`)
  assert.ok(mutatingRoutes().length >= 3, 'expected at least three mutating routes')
  assert.ok(mutatingRoutes().some((route) => route.wrapped), 'no route was detected as wrapped — the detector is broken')
  assert.ok(all.some((route) => route.key === 'GET /livez'), 'the health routes should be visible to the detector')
})

test('no exemption is stale', () => {
  // An exemption for a route that no longer exists is a claim nobody is checking, and it hides the
  // day that route comes back without a wrapper.
  const keys = new Set(mutatingRoutes().map((route) => route.key))
  for (const key of Object.keys(EXEMPT)) {
    assert.ok(keys.has(key), `EXEMPT names ${key}, which is not a mutating route on this server any more`)
  }
})

test('there is no browser-reachable collector route — AD-21', () => {
  // The rule `org/.github/workflows/web-ci.yml` enforces on every frontend (no Google, Segment,
  // Hotjar or Mixpanel tag) is only defensible because this service replaces them. A collector
  // endpoint here would bypass the delivery signature, the service token and — because a browser
  // cannot hold a pepper — the pseudonymisation as well.
  const paths = routes().map((route) => route.key)
  for (const forbidden of ['POST /collect', 'POST /events', 'POST /t', 'POST /track', 'GET /pixel.gif']) {
    assert.equal(paths.includes(forbidden), false, `${forbidden} is a page-tag collector; AD-21 forbids one`)
  }
})
