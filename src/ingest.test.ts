/**
 * The event-bus inbox, against a real Postgres.
 *
 * Everything a producer can do wrong is here, because a producer is the only caller: the wrong
 * signature, the wrong topic, a payload full of a person's name, an event for somebody who asked
 * to be forgotten, and the same event twice.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import {
  eventId,
  makeEvent,
  serialiseEvent,
  signDelivery,
  type Actor,
  type EventEnvelope,
  type TopicName,
} from '@cloudsforge/contracts-events'
import { ERASURE_TOPIC } from './catalogue.ts'
import { ingest, parseDelivery, verifySignature, type IngestDeps } from './ingest.ts'
import { isAttributable, lookupKeyFor, rawSubject } from './pseudonym.ts'
import { TEST_PEPPER, TEST_PEPPER_V1, migrateTestDb, openDb, quietLogger, resetAnalytics, skip, testMetrics } from './testsupport.ts'

const SECRET = 'a-delivery-secret-of-sufficient-length'
const SPIROS = 'user:550e8400-e29b-41d4-a716-446655440000'
const OTHER = 'user:6ba7b810-9dad-11d1-80b4-00c04fd430c8'

describe('ingest', { skip }, () => {
  let sql: postgres.Sql
  let deps: IngestDeps

  before(async () => {
    sql = openDb()
    await migrateTestDb(sql)
  })
  beforeEach(async () => {
    await resetAnalytics(sql)
    deps = {
      sql,
      logger: quietLogger(),
      metrics: testMetrics(),
      secrets: [SECRET],
      peppers: TEST_PEPPER,
    }
  })
  after(async () => {
    await sql.end({ timeout: 5 })
  })

  /** A registered-topic envelope, serialised. */
  function envelope(
    topic: TopicName,
    payload: unknown,
    options: { actor?: Actor; key?: string } = {},
  ): string {
    return serialiseEvent(
      makeEvent({
        topic,
        key: options.key ?? 'k-1',
        actor: options.actor ?? 'service:wallet',
        payload,
        occurredAt: new Date('2026-06-01T10:00:00.000Z'),
      }) as EventEnvelope,
    )
  }

  /**
   * The `identity.user.deleted` envelope AS IDENTITY SENDS IT.
   *
   * `payload: { userId, tombstoneAt, reason }`, key = the bare user id
   * (`identity/src/deletion.ts`). The `actor` is whoever ASKED for the deletion, which is
   * the user only when they deleted themselves — so it is deliberately set to an operator here by
   * default. These tests used to pass `{ actor: SPIROS }` with an empty payload, which is why the
   * handler reading `actor` looked correct: the test and the handler agreed with each other and
   * neither agreed with the producer.
   */
  function erasureEnvelope(subject: string, options: { actor?: Actor } = {}): string {
    const userId = subject.startsWith('user:') ? subject.slice('user:'.length) : subject
    return serialiseEvent(
      makeEvent({
        topic: ERASURE_TOPIC as TopicName,
        key: userId,
        actor: options.actor ?? ('operator:support-7' as Actor),
        payload: { userId, tombstoneAt: '2026-07-01T10:00:00.000Z', reason: 'user_requested' },
        occurredAt: new Date('2026-06-01T10:00:00.000Z'),
      }) as EventEnvelope,
    )
  }

  /** A forward-declared UI topic, which `makeEvent` cannot build because it is unregistered. */
  function webEnvelope(topic: string, payload: unknown, actor: string = SPIROS): string {
    return JSON.stringify({
      id: eventId(),
      topic,
      key: 'k-1',
      occurredAt: '2026-06-01T10:00:00.000Z',
      producer: 'site',
      version: '1.0',
      actor,
      correlationId: 'corr-1',
      payload,
    })
  }

  async function deliver(body: string) {
    verifySignature(deps, body, signDelivery(body, SECRET))
    return ingest(deps, parseDelivery(body))
  }

  /* ================================================================ the signature */

  describe('the delivery signature', () => {
    it('accepts a body signed with the current secret', () => {
      const body = envelope('wallet.deposit.confirmed', { analytics: { subject: SPIROS } })
      assert.doesNotThrow(() => verifySignature(deps, body, signDelivery(body, SECRET)))
    })

    it('accepts a rotated-out secret, so a rotation is a window rather than an instant', () => {
      const rotated = { ...deps, secrets: ['a-new-secret-of-sufficient-length-01', SECRET] }
      const body = envelope('wallet.deposit.confirmed', {})
      assert.doesNotThrow(() => verifySignature(rotated, body, signDelivery(body, SECRET)))
    })

    it('refuses a missing header, a wrong secret, and a body altered after signing', () => {
      const body = envelope('wallet.deposit.confirmed', {})
      assert.throws(() => verifySignature(deps, body, undefined), /missing/)
      assert.throws(() => verifySignature(deps, body, signDelivery(body, 'a-different-secret-0123456789')), /mismatch/)
      assert.throws(() => verifySignature(deps, `${body} `, signDelivery(body, SECRET)), /mismatch/)
    })

    it('refuses a stale delivery, because a captured request must not be a lasting credential', () => {
      const body = envelope('wallet.deposit.confirmed', {})
      const signed = signDelivery(body, SECRET, Date.now() - 3_600_000)
      assert.throws(() => verifySignature(deps, body, signed), /stale/)
    })
  })

  /* ================================================================ parsing */

  describe('parsing', () => {
    it('refuses a body that is not JSON, and one that is not an object', () => {
      assert.throws(() => parseDelivery('not json'), /not JSON/)
      assert.throws(() => parseDelivery('[1,2,3]'), /expected a JSON object/)
    })

    it('accepts a registered topic through contracts-events and marks it registered', () => {
      const parsed = parseDelivery(envelope('identity.user.registered', {}, { actor: SPIROS as Actor }))
      assert.equal(parsed.registered, true)
    })

    it('accepts the four forward-declared UI topics and marks them unregistered', () => {
      // AD-21 requires them; contracts-events registers none of them. Reported, not fixed.
      for (const topic of ['web.page.viewed', 'web.cta.clicked', 'web.form.started', 'web.form.abandoned']) {
        const parsed = parseDelivery(webEnvelope(topic, {}))
        assert.equal(parsed.registered, false, topic)
        assert.equal(parsed.envelope.topic, topic)
      }
    })

    it('refuses an unregistered topic this service does not forward-declare', () => {
      // An arbitrary unregistered topic gets no more trust here than `validateEnvelope` gives it.
      assert.throws(() => parseDelivery(webEnvelope('some.other.thing', {})), /not in this registry/)
    })

    it('still demands the fields a row needs from a forward-declared topic', () => {
      const body = JSON.parse(webEnvelope('web.page.viewed', {})) as Record<string, unknown>
      delete body['correlationId']
      assert.throws(() => parseDelivery(JSON.stringify(body)), /correlationId/)
      const bad = { ...JSON.parse(webEnvelope('web.page.viewed', {})), id: 'not-a-uuid' }
      assert.throws(() => parseDelivery(JSON.stringify(bad)), /expected a UUID/)
    })
  })

  /* ================================================================ recording */

  describe('recording', () => {
    it('stores a pseudonym and never the subject that produced it', async () => {
      const outcome = await deliver(
        envelope('wallet.deposit.confirmed', { analytics: { subject: SPIROS, amount_bucket: '100_1k' } }),
      )
      assert.equal(outcome.status, 'recorded')

      const rows = await sql<{ subject_key: string; subject_kind: string; event_name: string; props: unknown }[]>`
        select subject_key, subject_kind, event_name, props from events
      `
      assert.equal(rows.length, 1)
      assert.match(rows[0]!.subject_key, /^[0-9a-f]{64}$/)
      assert.equal(rows[0]!.subject_kind, 'user')
      assert.equal(rows[0]!.event_name, 'deposit_confirmed')
      assert.deepEqual(rows[0]!.props, { amount_bucket: '100_1k' })

      // The raw subject appears nowhere in the store. Checked by dumping the table, because "we do
      // not write it" is the claim under test.
      const dump = JSON.stringify(await sql`select * from events`)
      assert.ok(!dump.includes('550e8400'), 'the raw user id reached the store')
    })

    it('takes the subject from the envelope actor when the producer names none', async () => {
      await deliver(envelope('identity.user.registered', {}, { actor: SPIROS as Actor }))
      assert.equal(await isAttributable(sql, TEST_PEPPER, rawSubject(SPIROS)), true)
    })

    it('prefers the analytics envelope subject over the actor, because the actor is the CAUSE', async () => {
      // wallet.deposit.confirmed is caused by a chain confirmation and is about the depositor.
      await deliver(
        envelope('wallet.deposit.confirmed', { analytics: { subject: SPIROS } }, { actor: 'service:wallet' }),
      )
      assert.equal(await isAttributable(sql, TEST_PEPPER, rawSubject(SPIROS)), true)
    })

    it('gives one person one pseudonym across two events', async () => {
      await deliver(envelope('identity.user.registered', {}, { actor: SPIROS as Actor }))
      await deliver(envelope('wallet.deposit.confirmed', { analytics: { subject: SPIROS } }))
      const rows = await sql<{ subject_key: string }[]>`select distinct subject_key from events`
      assert.equal(rows.length, 1, 'two pseudonyms for one person is two people in every cohort')
    })

    it('stores a machine event with no pseudonym at all', async () => {
      const outcome = await deliver(
        envelope('ledger.reconciliation.completed', {}, { actor: 'system', key: 'chain:mainnet' }),
      )
      assert.equal(outcome.status, 'recorded')
      const rows = await sql<{ subject_key: string | null; subject_kind: string }[]>`
        select subject_key, subject_kind from events
      `
      assert.equal(rows[0]?.subject_key, null)
      assert.equal(rows[0]?.subject_kind, 'system')
    })

    it('pseudonymises the session id rather than storing it', async () => {
      await deliver(
        webEnvelope('web.page.viewed', { analytics: { subject: SPIROS, session_id: 'sess-abc-123', surface: 'landing' } }),
      )
      const rows = await sql<{ session: string }[]>`select session from events`
      assert.match(rows[0]!.session, /^[0-9a-f]{64}$/)
      assert.ok(!rows[0]!.session.includes('sess'), 'the browser session id reached the store')
    })

    it('never reads anything outside the analytics envelope', async () => {
      // The domain payload of a real deposit carries an address and an exact amount. Not one field
      // of it is looked at, and nothing from it is counted as a refusal either — this service does
      // not have an opinion about a producer's own payload.
      const outcome = await deliver(
        envelope('wallet.deposit.confirmed', {
          walletId: 'w-1',
          address: '0x71c7656ec7ab88b098defb751b7401b5f6d8976f',
          amount: '1234.56',
          assetCode: 'USDC',
          memo: 'rent money from Spiros',
          analytics: { subject: SPIROS, amount_bucket: '1k_10k', asset_code: 'usdc' },
        }),
      )
      assert.equal(outcome.status, 'recorded')
      assert.deepEqual(outcome.status === 'recorded' ? outcome.dropped : null, [])
      const dump = JSON.stringify(await sql`select * from events`)
      for (const leak of ['0x71c7656', '1234.56', 'rent money', 'Spiros']) {
        assert.ok(!dump.includes(leak), `${leak} reached the store`)
      }
    })
  })

  /* ================================================================ refusals */

  describe('refusals are counted', () => {
    it('drops a disallowed property, counts it, and still stores the event', async () => {
      const outcome = await deliver(
        envelope('wallet.deposit.confirmed', {
          analytics: { subject: SPIROS, amount_bucket: 'lt10', display_name: 'Spiros Savvanis', memo: 'hi there' },
        }),
      )
      assert.equal(outcome.status, 'recorded')
      assert.deepEqual(outcome.status === 'recorded' ? [...outcome.dropped].sort() : [], ['display_name', 'memo'])

      const rows = await sql<{ props: Record<string, unknown> }[]>`select props from events`
      assert.deepEqual(rows[0]?.props, { amount_bucket: 'lt10' })

      const counts = await sql<{ reason: string; rejections: string }[]>`
        select reason, rejections from ingest_rejections
      `
      assert.deepEqual(counts.map((row) => [row.reason, Number(row.rejections)]), [['disallowed_property', 2]])
    })

    it('records the reason and the topic, and never the offending key', async () => {
      // A key can be the personal data just as easily as a value can:
      // {"spiros_savvanis_lives_at": 1} puts a name in the key. The producer is told in the
      // response; the database records a count.
      await deliver(
        envelope('wallet.deposit.confirmed', {
          analytics: { subject: SPIROS, spiros_savvanis_lives_at: 'flat 3' },
        }),
      )
      const dump = JSON.stringify(await sql`select * from ingest_rejections`)
      assert.ok(!dump.includes('spiros'), 'the rejection table recorded the offending key')
      assert.ok(dump.includes('wallet.deposit.confirmed'))
    })

    it('refuses a topic this build has no mapping for, without keeping its payload', async () => {
      // ─────────────────────────────────────────────────────────────────────────────────────────
      // The lagging-consumer case: a topic added to `contracts-events` after this build shipped.
      // It cannot be produced through `parseDelivery` today because this build's catalogue covers
      // all eighteen registered topics — so the envelope is constructed directly, which is exactly
      // the shape a newer contracts package would hand the same function.
      //
      // Different from `activity`, on purpose. `activity/src/ingest.ts` quarantines such an
      // event WITH its payload so it can be reclassified later. Here the payload never passed the
      // property allowlist, so keeping it would be the exact hole the allowlist closes.
      // ─────────────────────────────────────────────────────────────────────────────────────────
      const future = {
        registered: true,
        envelope: {
          ...(JSON.parse(envelope('community.proposal.executed', {})) as EventEnvelope),
          topic: 'studio.generation.completed' as TopicName,
          payload: { analytics: { subject: SPIROS }, prompt: 'a portrait of Spiros Savvanis' },
        },
      }
      const outcome = await ingest(deps, future)
      assert.equal(outcome.status, 'refused')
      assert.equal(outcome.status === 'refused' && outcome.reason, 'unknown_topic')

      assert.equal((await sql`select * from events`).length, 0)
      const dump = JSON.stringify(await sql`select * from ingest_rejections`)
      assert.ok(!dump.includes('Spiros'), 'the refused payload was retained')

      // The inbox row is still claimed, so the relay stops rather than retrying a decision.
      assert.equal((await sql`select * from inbox`).length, 1)
      assert.equal((await ingest(deps, future)).status, 'duplicate')

      // And the topic is recorded under one bounded label, so a caller cannot mint unbounded
      // primary keys by inventing topic names.
      const counts = await sql<{ reason: string; source_topic: string }[]>`
        select reason, source_topic from ingest_rejections
      `
      assert.deepEqual(
        counts.map((row) => [row.reason, row.source_topic]),
        [['unknown_topic', 'unregistered']],
      )
    })

    it('refuses a personal event with no resolvable subject, and counts it', async () => {
      // Storing it would make a rollup say "ten deposits, zero users" — a number wrong in the
      // direction that makes a funnel look healthier than it is.
      const outcome = await deliver(envelope('wallet.deposit.confirmed', {}, { actor: 'service:wallet' }))
      assert.equal(outcome.status, 'refused')
      assert.equal(outcome.status === 'refused' && outcome.reason, 'missing_subject')
      assert.equal((await sql`select * from events`).length, 0)
      const counts = await sql<{ reason: string }[]>`select reason from ingest_rejections`
      assert.deepEqual(counts.map((row) => row.reason), ['missing_subject'])
    })

    it('refuses an event about somebody who asked to be forgotten', async () => {
      await deliver(envelope('identity.user.registered', {}, { actor: SPIROS as Actor }))
      await deliver(
        erasureEnvelope(SPIROS),
      )
      const late = await deliver(envelope('wallet.deposit.confirmed', { analytics: { subject: SPIROS } }))
      assert.equal(late.status, 'refused')
      assert.equal(late.status === 'refused' && late.reason, 'erased_subject')
      const rows = await sql<{ n: string }[]>`select count(*) as n from events`
      assert.equal(Number(rows[0]?.n), 1, 'only the pre-erasure event remains')
    })
  })

  /* ================================================================ erasure */

  describe('erasure through the bus', () => {
    it('destroys the salt and writes no event of its own', async () => {
      await deliver(envelope('identity.user.registered', {}, { actor: SPIROS as Actor }))
      const outcome = await deliver(erasureEnvelope(SPIROS))
      assert.equal(outcome.status, 'erased')

      // No row saying "this pseudonym was erased" — that would be a record about the person who
      // asked to be forgotten.
      const rows = await sql<{ event_name: string }[]>`select event_name from events`
      assert.deepEqual(rows.map((row) => row.event_name), ['user_registered'])
      assert.equal(await isAttributable(sql, TEST_PEPPER, rawSubject(SPIROS)), false)
    })

    it('acknowledges through the inbox, so the relay stops redelivering', async () => {
      await deliver(erasureEnvelope(SPIROS))
      const rows = await sql<{ topic: string }[]>`select topic from inbox`
      assert.deepEqual(rows.map((row) => row.topic), [ERASURE_TOPIC])
    })

    it('erases only the person it names', async () => {
      await deliver(envelope('identity.user.registered', {}, { actor: SPIROS as Actor }))
      await deliver(envelope('identity.user.registered', {}, { actor: OTHER as Actor }))
      await deliver(erasureEnvelope(SPIROS))
      assert.equal(await isAttributable(sql, TEST_PEPPER, rawSubject(SPIROS)), false)
      assert.equal(await isAttributable(sql, TEST_PEPPER, rawSubject(OTHER)), true)
    })

    it('erases the user the event NAMES, not the operator who requested it', async () => {
      // ═══════════════════════════════════════════════════════════════════════════════════════
      // The handler read `envelope.actor`. On this topic the actor is whoever ASKED for the
      // deletion — `identity/src/deletion.ts` sets it from `input.actor` — so an erasure
      // raised by support destroyed the SUPPORT OPERATOR's salt and left the account that asked
      // to be forgotten fully attributable. Data loss for one person and a null erasure for
      // another, from one line.
      // ═══════════════════════════════════════════════════════════════════════════════════════
      const operator = 'operator:support-7'
      await deliver(envelope('identity.user.registered', {}, { actor: SPIROS as Actor }))
      await deliver(
        envelope('wallet.deposit.confirmed', { analytics: { subject: operator } }, { actor: 'service:wallet' }),
      )
      assert.equal(await isAttributable(sql, TEST_PEPPER, rawSubject(operator)), true)

      const outcome = await deliver(erasureEnvelope(SPIROS, { actor: operator as Actor }))
      assert.equal(outcome.status, 'erased')

      assert.equal(
        await isAttributable(sql, TEST_PEPPER, rawSubject(SPIROS)),
        false,
        'the account that asked to be forgotten is still attributable',
      )
      assert.equal(
        await isAttributable(sql, TEST_PEPPER, rawSubject(operator)),
        true,
        "the requesting operator's own pseudonym was destroyed",
      )
    })

    it('refuses an erasure that names nobody', async () => {
      const outcome = await deliver(envelope(ERASURE_TOPIC as TopicName, {}, { actor: 'system' }))
      assert.equal(outcome.status, 'refused')
      assert.equal(outcome.status === 'refused' && outcome.reason, 'missing_subject')
    })

    it('leaves a tombstone under the lookup key and nothing else', async () => {
      await deliver(erasureEnvelope(SPIROS))
      const rows = await sql<{ lookup_key: string; salt: string | null }[]>`select lookup_key, salt from subject_keys`
      assert.equal(rows.length, 1)
      assert.equal(rows[0]?.lookup_key, lookupKeyFor(TEST_PEPPER_V1, rawSubject(SPIROS)))
      assert.equal(rows[0]?.salt, null)
    })
  })

  /* ================================================================ dedupe */

  describe('a redelivery is deduped', () => {
    it('drops the second copy of one event and writes one row', async () => {
      const body = envelope('identity.user.registered', {}, { actor: SPIROS as Actor })
      assert.equal((await deliver(body)).status, 'recorded')
      assert.equal((await deliver(body)).status, 'duplicate')
      const rows = await sql<{ n: string }[]>`select count(*) as n from events`
      assert.equal(Number(rows[0]?.n), 1)
    })

    it('drops it again on the tenth attempt, because at-least-once means at-least-once', async () => {
      const body = envelope('identity.user.registered', {}, { actor: SPIROS as Actor })
      await deliver(body)
      for (let attempt = 0; attempt < 9; attempt += 1) {
        assert.equal((await deliver(body)).status, 'duplicate')
      }
      const rows = await sql<{ n: string }[]>`select count(*) as n from events`
      assert.equal(Number(rows[0]?.n), 1)
    })

    it('two concurrent copies of one event produce one row', async () => {
      const body = envelope('identity.user.registered', {}, { actor: SPIROS as Actor })
      const parsed = parseDelivery(body)
      const results = await Promise.allSettled([ingest(deps, parsed), ingest(deps, parsed)])
      const statuses = results.map((r) => (r.status === 'fulfilled' ? r.value.status : 'threw'))
      const rows = await sql<{ n: string }[]>`select count(*) as n from events`
      assert.equal(Number(rows[0]?.n), 1, `one row, whatever the two calls returned: ${statuses.join(',')}`)
    })

    it('a handler that fails leaves NO inbox row, so the redelivery is processed', async () => {
      // The mistake a naive "record then handle" dedupe makes: the inbox row commits, the work
      // does not, and the event is lost for ever with a row saying it was handled. Here the claim
      // and the insert share one transaction, so a failure rolls both back.
      //
      // The failure is planted at the database, which is the only honest way to make the insert
      // fail after the inbox claim has already succeeded.
      const body = envelope('identity.user.registered', {}, { actor: SPIROS as Actor })
      await sql`alter table events add constraint tmp_insert_fails check (false) not valid`
      await sql`alter table events validate constraint tmp_insert_fails`
      await assert.rejects(() => deliver(body))
      await sql`alter table events drop constraint tmp_insert_fails`

      assert.equal((await sql`select * from inbox`).length, 0, 'the inbox row must have rolled back')
      assert.equal((await deliver(body)).status, 'recorded', 'the redelivery must be processed, not swallowed')
      assert.equal((await sql`select * from events`).length, 1)
    })
  })
})
