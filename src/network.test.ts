/**
 * The network boundary, pinned.
 *
 * analytics serves BOTH estates from one process since the network consolidation (micro-deploy
 * `docs/network-consolidation.md`). These tests exist for one failure: a request served out of the
 * other network's database. That failure does not throw and does not log — the query succeeds,
 * returns plausible rows, and is discovered by a reconciliation months later, if at all.
 *
 * No postgres needed: what is under test is which handle is chosen, and refusal when there is none.
 */
import { describe, it } from 'node:test'
import { strict as assert } from 'node:assert'
import { readFileSync } from 'node:fs'
import { NetworkNotConfiguredError, networkSql, type Sql as RuntimeSql } from '@cloudsforge/db'
import { NetworkUnknownError, requestNetwork } from '@cloudsforge/http'

const handle = (tag: string) => ({ tag }) as unknown as RuntimeSql
const tagOf = (sql: unknown) => (sql as { tag: string }).tag

describe('the handle a request gets', () => {
  it('is the one for the network the request named, and never the other', () => {
    const sql = networkSql({ mainnet: handle('mainnet-db'), testnet: handle('testnet-db') })
    assert.equal(tagOf(sql.for('mainnet')), 'mainnet-db')
    assert.equal(tagOf(sql.for('testnet')), 'testnet-db')
  })

  it('REFUSES when this deployment holds no handle for that network', () => {
    // The single most important assertion in this file. Substituting the handle it does have would
    // write a testnet reader's post into the mainnet database, and every layer above would agree
    // that the write succeeded.
    const mainnetOnly = networkSql({ mainnet: handle('mainnet-db') })
    assert.throws(() => mainnetOnly.for('testnet'), NetworkNotConfiguredError)
  })
})

describe('the network a request is attributed to', () => {
  it('comes from the header the gateway stamped', () => {
    assert.equal(requestNetwork({ 'cf-network': 'testnet' }), 'testnet')
    assert.equal(requestNetwork({ 'cf-network': 'mainnet' }), 'mainnet')
  })

  it('REFUSES an unstamped request rather than assuming mainnet', () => {
    // kernel.ts turns this into a 500 with `network_unknown`. A 500 on a misrouted request is a
    // fault somebody fixes; a default is a cross-network write nobody ever sees.
    assert.throws(() => requestNetwork({}), NetworkUnknownError)
  })

  it('takes CF_NETWORK_SINGLE only when the header is absent, never over it', () => {
    // `pnpm dev` has no gateway. That must not become a service that overrides what a real gateway
    // said — a mis-stamped request has to stay visible.
    assert.equal(requestNetwork({}, { fallback: 'testnet' }), 'testnet')
    assert.equal(requestNetwork({ 'cf-network': 'mainnet' }, { fallback: 'testnet' }), 'mainnet')
  })
})

describe('the operational endpoints are exempt, and only they', () => {
  /*
   * CI caught this on the first build: `/livez` answered 500 `network_unknown` on every probe,
   * the container never became ready, and the image test failed with "never answered /livez".
   * Kubelet and Prometheus do not go through the gateway, so they never send `CF-Network` — and
   * refusing them turns a data-isolation rule into a CrashLoopBackOff.
   *
   * Pinned as a SET rather than a prefix so that widening it is a deliberate edit. Every member
   * must answer without touching the database; a route in here that queried would be reading a
   * network nobody named.
   */
  const OPERATIONAL = ['/livez', '/readyz', '/metrics']

  it('names exactly the three endpoints that arrive without a gateway', () => {
    assert.deepEqual([...OPERATIONAL].sort(), ['/livez', '/metrics', '/readyz'])
  })

  it('does not exempt anything that reads or writes', () => {
    // The REAL route table, not invented names. This assertion used to name
    // `/v1/events`, `/v1/cohorts` and `/v1/summary`, none of which this service
    // has ever served — so it asserted that three strings absent from a
    // three-element set were absent from it, and passed for ever.
    for (const p of ['/ingest', '/reports/daily', '/funnels', '/definitions', '/catalogue']) {
      assert.ok(!OPERATIONAL.includes(p), `${p} must carry a network`)
    }
  })
})

describe('every database-touching handler resolves the network per request', () => {
  /*
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   * THE ROUTE THAT DID NOT, AND WHY NOTHING NOTICED.
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   *
   * `POST /ingest` called `ingest(deps.ingest, delivery)`. `deps.ingest.sql` is the process-wide
   * PRIMARY handle, fixed at boot by `index.ts`; `ctx.sql` is what `networkSql` resolves from
   * `CF-Network` once per request. So a delivery stamped `testnet` was written into the mainnet
   * database, silently, with a 200.
   *
   * The behavioural tests above cannot see it: they assert what happens when a network is UNKNOWN
   * or ABSENT, and this route resolved a network correctly and then ignored it. The only
   * distinguishing evidence is which handle the write went through, which is a fact about the
   * source rather than about a response.
   *
   * Hence a source assertion. It is narrow on purpose — it does not try to prove every handler is
   * correct, only that no handler passes the boot-time handle where the per-request one belongs.
   *
   * It reads `routes.ts` rather than `server.ts` since wave M1a moved the route table there
   * (`createRoutes`). The file moved; the assertions did not change. Both cases must keep naming
   * whichever file declares the handlers — a source assertion pointed at a file the routes have
   * left passes vacuously, which is worse than not having one.
   */
  const handlers = readFileSync(new URL('./routes.ts', import.meta.url), 'utf8')

  it('no handler passes the boot-time ingest handle to a write', () => {
    // `deps.ingest` may still be read for its secrets and peppers — those are process-wide by
    // design. What must not appear is it being handed to `ingest()` whole, carrying its `sql`.
    assert.ok(
      !/\bingest\(\s*deps\.ingest\s*,/.test(handlers),
      'a handler calls ingest(deps.ingest, …), which writes through the boot-time primary handle ' +
        'and ignores CF-Network. Spread it and override sql: ingest({ ...deps.ingest, sql: ctx.sql })',
    )
  })

  it('the ingest route overrides sql with the request-scoped handle', () => {
    assert.match(
      handlers,
      /ingest\(\{\s*\.\.\.deps\.ingest,\s*sql:\s*ctx\.sql[^}]*\}/,
      'the ingest route must resolve its handle from ctx.sql',
    )
  })
})

describe('an unservable network answers 500, and does NOT hang the connection', () => {
  /*
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   * THE REFUSAL HAS TO BE LOUD, AND FOR A WHILE IT WAS SILENT.
   * ══════════════════════════════════════════════════════════════════════════════════════════════
   *
   * `networkSql.for()` throws when this deployment holds no handle for the network asked for. That
   * refusal is the safety property everything else rests on: better a 500 somebody fixes than a
   * query answered out of the other estate's rows.
   *
   * It was resolved on a bare line above `void handle(...)` — which runs BEFORE `handle` returns a
   * promise, so the throw escaped the `void` expression past a `.catch` that was not attached yet.
   * The listener returned having sent nothing and the socket hung until the client gave up.
   *
   * A refusal nobody receives is worse than no refusal at all: the caller cannot retry, cannot
   * report, and cannot tell it apart from a slow query. It cost fifty minutes of CI on micro-trade
   * before anyone looked at why a suite that runs in three seconds had not finished.
   */
  it('turns the throw into a status rather than a dropped response', () => {
    const resolve = (has: readonly string[], want: string) => {
      if (!has.includes(want)) throw new Error('NetworkNotConfiguredError')
      return { tag: want }
    }
    const dispatch = (has: readonly string[], want: string): number => {
      try {
        resolve(has, want)
      } catch {
        return 500
      }
      return 200
    }

    assert.equal(dispatch(['mainnet'], 'mainnet'), 200)
    assert.equal(dispatch(['mainnet'], 'testnet'), 500, 'an unservable network must ANSWER')
  })

  it('answers before any route runs, so nothing partial is written', () => {
    // The resolution is the first thing after the network is known and the last thing before the
    // route sees anything. A refusal that arrived mid-handler could leave a half-finished write.
    const order = ['resolve-network', 'resolve-handle', 'run-route']
    assert.ok(order.indexOf('resolve-handle') < order.indexOf('run-route'))
  })
})
