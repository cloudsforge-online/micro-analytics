/**
 * The two allowlists, checked for the properties that make them worth having.
 *
 * The most important test in this file is `there is no free-text property type`. Every other guard
 * in this service — the database CHECK, the ingest sanitiser, the erasure path — is downstream of
 * the catalogue admitting only closed types. The day somebody adds `{ type: 'string' }` for a
 * "just the page title, it is harmless" property, this fails.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import {
  AMOUNT_BUCKETS,
  CODE_PATTERN,
  EVENTS,
  EVENT_NAMES,
  ERASURE_TOPIC,
  FUNNELS,
  MAX_PROPERTIES,
  PROPERTIES,
  PROPERTY_NAMES,
  VALUE_PATTERN,
  bucketAmount,
  eventFor,
} from './catalogue.ts'

describe('catalogue', () => {
  /* ---------------------------------------------------------------- property types */

  describe('the property types are closed', () => {
    it('there is no free-text property type', () => {
      // THE GUARD. A `string` type would accept "Spiros Savvanis" and a length cap would not save
      // it. Four closed types, and the day a fifth appears this test is the conversation.
      const kinds = new Set(Object.values(PROPERTIES).map((spec) => spec.type))
      assert.deepEqual([...kinds].sort(), ['bool', 'code', 'enum', 'int'])
    })

    it('every enum member is storable — it matches the database value pattern', () => {
      // The database CHECK is rendered from VALUE_PATTERN. An enum member that does not match it
      // would be accepted by ingest and refused by the insert, which is a 500 on a valid event.
      const pattern = new RegExp(VALUE_PATTERN)
      for (const [name, spec] of Object.entries(PROPERTIES)) {
        if (spec.type !== 'enum') continue
        for (const value of spec.values) {
          assert.ok(pattern.test(value), `${name}=${value} would be refused by events_props_allowed`)
        }
      }
    })

    it('every code value the pattern admits is also storable', () => {
      const value = new RegExp(VALUE_PATTERN)
      for (const candidate of ['usdc', 'ember', 'mainnet', 'pro', 'a', 'x1-y_2']) {
        assert.ok(CODE_PATTERN.test(candidate), `${candidate} should be a valid code`)
        assert.ok(value.test(candidate), `${candidate} should be storable`)
      }
    })

    it('a code cannot hold a name, an email or a chain address', () => {
      for (const hostile of [
        'Spiros Savvanis',
        'spiros savvanis',
        'savvanisspiros@gmail.com',
        '0x71c7656ec7ab88b098defb751b7401b5f6d8976f',
        'spiros-savvanis',
        'a'.repeat(13),
      ]) {
        assert.equal(CODE_PATTERN.test(hostile), false, `a code must not admit ${hostile}`)
      }
    })

    it('the value pattern refuses anything with a space, a capital or an at-sign', () => {
      const pattern = new RegExp(VALUE_PATTERN)
      for (const hostile of [
        'Spiros Savvanis',
        'spiros savvanis',
        'a@b.com',
        '1994 Corolla',
        'Register',
        '',
        'a'.repeat(33),
      ]) {
        assert.equal(pattern.test(hostile), false, `the store must refuse ${JSON.stringify(hostile)}`)
      }
    })

    it('every property says which metric needs it', () => {
      // A property with no metric behind it is a property collected because it was available,
      // which is the habit AD-21 exists to prevent.
      for (const [name, spec] of Object.entries(PROPERTIES)) {
        assert.ok(spec.why.length > 20, `${name} has no stated reason to exist`)
      }
    })

    it('no property is named after something the estate forbids', () => {
      // 11-data-and-contract-strategy.md:512, applied to the property namespace as well as to
      // columns: the schema check would not see a jsonb key called `email`.
      for (const forbidden of ['user_id', 'email', 'handle', 'address', 'amount', 'name', 'title', 'ip']) {
        assert.ok(!PROPERTY_NAMES.includes(forbidden), `${forbidden} may not be an allowed property`)
      }
    })

    it('caps the number of properties, because a wide event is a fingerprint', () => {
      assert.ok(MAX_PROPERTIES > 0 && MAX_PROPERTIES <= 16)
    })
  })

  /* ---------------------------------------------------------------- amount buckets */

  describe('amounts are bucketed exactly as 13-operational-model.md:598 states', () => {
    it('places the boundaries where the document places them', () => {
      assert.equal(bucketAmount('0'), 'lt10')
      assert.equal(bucketAmount('9.99'), 'lt10')
      assert.equal(bucketAmount('10'), '10_100')
      assert.equal(bucketAmount('99.999999'), '10_100')
      assert.equal(bucketAmount('100'), '100_1k')
      assert.equal(bucketAmount('999'), '100_1k')
      assert.equal(bucketAmount('1000'), '1k_10k')
      assert.equal(bucketAmount('9999'), '1k_10k')
      assert.equal(bucketAmount('10000'), 'gt10k')
      assert.equal(bucketAmount('123456789012345678901234567890'), 'gt10k')
    })

    it('buckets a refund by magnitude, because the direction is the event name', () => {
      assert.equal(bucketAmount('-50'), bucketAmount('50'))
    })

    it('ignores leading zeros', () => {
      assert.equal(bucketAmount('0009.99'), 'lt10')
    })

    it('refuses anything that is not a decimal', () => {
      for (const bad of ['', 'ten', '1e30', 'NaN', '1,000', '0x10']) {
        assert.equal(bucketAmount(bad), null, `${bad} is not an amount`)
      }
    })

    it('every bucket name is an allowed value of amount_bucket', () => {
      const spec = PROPERTIES['amount_bucket']
      assert.ok(spec && spec.type === 'enum')
      assert.deepEqual([...spec.values].sort(), [...AMOUNT_BUCKETS].sort())
    })
  })

  /* ---------------------------------------------------------------- events */

  describe('the event catalogue', () => {
    it('never maps the erasure topic to an event', () => {
      // A row saying "this pseudonym was erased" is a record about the person who asked to be
      // forgotten. `ingest.ts` handles the topic; the catalogue must not.
      assert.equal(eventFor(ERASURE_TOPIC), undefined)
    })

    it('EVENT_NAMES is exactly the distinct set the catalogue maps to', () => {
      const expected = [...new Set(Object.values(EVENTS).map((spec) => spec.name))].sort()
      assert.deepEqual([...EVENT_NAMES], expected)
    })

    it('names no two topics to one event', () => {
      // Two topics collapsing to one name would double-count a funnel step, silently.
      const names = Object.values(EVENTS).map((spec) => spec.name)
      assert.equal(new Set(names).size, names.length)
    })

    it('marks exactly the machine-subject events as impersonal', () => {
      const impersonal = Object.entries(EVENTS)
        .filter(([, spec]) => !spec.personal)
        .map(([topic]) => topic)
      assert.deepEqual(impersonal, ['ledger.reconciliation.completed'])
    })

    it('forward-declares only the four AD-21 UI topics, and marks them unregistered', () => {
      const unregistered = Object.entries(EVENTS)
        .filter(([, spec]) => !spec.registered)
        .map(([topic]) => topic)
        .sort()
      assert.deepEqual(unregistered, [
        'web.cta.clicked',
        'web.form.abandoned',
        'web.form.started',
        'web.page.viewed',
      ])
    })

    it('every event name is a storable slug', () => {
      // Rendered into the events_name_known CHECK, so a name with a quote in it would be a
      // migration that does not parse.
      for (const name of EVENT_NAMES) assert.match(name, /^[a-z][a-z0-9_]{1,40}$/)
    })
  })

  /* ---------------------------------------------------------------- funnels */

  describe('funnels', () => {
    it('every step names an event this service can actually store', () => {
      // A funnel step naming an event the catalogue does not produce reports zero for ever, which
      // reads as a product failure rather than as a missing topic.
      for (const funnel of FUNNELS) {
        for (const step of funnel.steps) {
          assert.ok(EVENT_NAMES.includes(step), `funnel ${funnel.id} names unknown step ${step}`)
        }
      }
    })

    it('has at least two steps per funnel and a unique id', () => {
      const ids = FUNNELS.map((funnel) => funnel.id)
      assert.equal(new Set(ids).size, ids.length)
      for (const funnel of FUNNELS) assert.ok(funnel.steps.length >= 2, `${funnel.id} is not a funnel`)
    })

    it('repeats no step within a funnel', () => {
      // The CTE chain in reads.ts joins each step to the previous one; a repeated event name would
      // make step n+1 the same set as step n and report a 100% conversion that is an artefact.
      for (const funnel of FUNNELS) {
        assert.equal(new Set(funnel.steps).size, funnel.steps.length, `${funnel.id} repeats a step`)
      }
    })
  })
})
