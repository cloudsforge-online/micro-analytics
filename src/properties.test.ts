/**
 * The property boundary.
 *
 * Half of these are hostile inputs shaped like the real thing: a display name, a listing title, an
 * email, a chat line. Each is a re-identification vector and a GDPR erasure problem, and each must
 * be refused *and counted* rather than dropped quietly —
 * 11-data-and-contract-strategy.md.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'
import { MAX_PROPERTIES } from './catalogue.ts'
import { sanitise, tally } from './properties.ts'

describe('properties', () => {
  /* ---------------------------------------------------------------- accepted */

  it('keeps an allowlisted property of the declared type', () => {
    const clean = sanitise({ surface: 'register', attempt: 2, is_first: true, asset_code: 'usdc' })
    assert.deepEqual(clean.props, { surface: 'register', attempt: 2, is_first: true, asset_code: 'usdc' })
    assert.deepEqual(clean.dropped, [])
  })

  it('treats a missing envelope as an event with no properties, not an error', () => {
    // Most registered bus topics are server-side facts whose producers have nothing to add, and
    // such an event still counts towards every "users with at least one …" metric.
    for (const empty of [undefined, null, {}]) {
      const clean = sanitise(empty)
      assert.deepEqual(clean.props, {})
      assert.deepEqual(clean.reasons, [])
    }
  })

  /* ---------------------------------------------------------------- refused */

  describe('free text a person typed is refused and counted', () => {
    const hostile: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
      ['a display name', { display_name: 'Spiros Savvanis' }],
      ['a listing title', { title: "Spiros's 1994 Corolla — must go!" }],
      ['a chat line', { message: 'hey, is this still available? call me on 07700 900000' }],
      ['an email', { email: 'savvanisspiros@gmail.com' }],
      ['a handle', { handle: 'spiros' }],
      ['a wallet address', { address: '0x71c7656ec7ab88b098defb751b7401b5f6d8976f' }],
      ['an exact amount', { amount: '1234.56' }],
      ['a user id', { user_id: '550e8400-e29b-41d4-a716-446655440000' }],
      ['a search query', { query: 'how do I withdraw' }],
      ['a full URL', { referrer: 'https://mail.google.com/mail/u/0/#inbox' }],
    ]

    for (const [what, envelope] of hostile) {
      it(`refuses ${what}`, () => {
        const clean = sanitise(envelope)
        assert.deepEqual(clean.props, {}, `${what} reached the store`)
        assert.deepEqual(clean.dropped, Object.keys(envelope))
        assert.deepEqual(clean.reasons, ['disallowed_property'])
      })
    }

    it('refuses every one of them in a single envelope, and counts every one', () => {
      const all = Object.assign({}, ...hostile.map(([, envelope]) => envelope)) as Record<string, unknown>
      const clean = sanitise(all)
      assert.deepEqual(clean.props, {})
      assert.equal(clean.dropped.length, Object.keys(all).length)
      assert.equal(tally(clean.reasons).get('disallowed_property'), Object.keys(all).length)
    })

    it('keeps the allowlisted properties of an envelope that also carries a name', () => {
      // The EVENT is still stored. Refusing the whole event would mean a producer that added one
      // field lost every funnel it feeds, which is the pressure that gets a guard turned off.
      const clean = sanitise({ surface: 'register', display_name: 'Spiros Savvanis' })
      assert.deepEqual(clean.props, { surface: 'register' })
      assert.deepEqual(clean.dropped, ['display_name'])
    })
  })

  describe('an allowlisted name with the wrong value is refused too', () => {
    const bad: ReadonlyArray<readonly [string, unknown]> = [
      ['an enum member that is not a member', { surface: 'my-secret-page' }],
      ['an enum given a free-text value', { surface: 'Spiros Savvanis' }],
      ['a code that is too long', { asset_code: 'this-is-not-a-code' }],
      ['a code with a capital', { asset_code: 'USDC' }],
      ['an int that is a float', { attempt: 1.5 }],
      ['an int out of range', { attempt: 10_000 }],
      ['an int that is NaN', { attempt: Number.NaN }],
      ['an int that is Infinity', { day_offset: Number.POSITIVE_INFINITY }],
      ['a bool that is a string', { is_first: 'true' }],
      ['an object smuggled into an enum', { surface: { toString: 'register' } }],
      ['an array smuggled into an enum', { surface: ['register'] }],
      ['a null', { surface: null }],
    ]

    for (const [what, envelope] of bad) {
      it(`refuses ${what}`, () => {
        const clean = sanitise(envelope)
        assert.deepEqual(clean.props, {})
        assert.deepEqual(clean.reasons, ['bad_property_value'])
      })
    }
  })

  it('refuses an envelope that is not an object at all', () => {
    for (const bad of ['a string', 42, ['a', 'b'], true]) {
      const clean = sanitise(bad)
      assert.deepEqual(clean.props, {})
      assert.deepEqual(clean.reasons, ['bad_property_value'])
    }
  })

  it('caps the property count and counts the overflow', () => {
    // Refused as a whole rather than accepted up to the cap and truncated in an order nobody chose.
    const wide: Record<string, unknown> = {}
    const names = [
      'surface', 'form_id', 'cta_id', 'product', 'step', 'outcome',
      'amount_bucket', 'duration_bucket', 'asset_code', 'chain', 'plan', 'attempt', 'day_offset', 'is_first',
    ]
    const values: Record<string, unknown> = {
      surface: 'register', form_id: 'register', cta_id: 'register', product: 'identity',
      step: 'registered', outcome: 'succeeded', amount_bucket: 'lt10', duration_bucket: 'lt1h',
      asset_code: 'usdc', chain: 'mainnet', plan: 'pro', attempt: 1, day_offset: 7, is_first: true,
    }
    for (const name of names) wide[name] = values[name]
    const clean = sanitise(wide)
    assert.equal(Object.keys(clean.props).length, MAX_PROPERTIES)
    assert.equal(tally(clean.reasons).get('too_many_properties'), names.length - MAX_PROPERTIES)
  })

  /* ---------------------------------------------------------------- reserved keys */

  describe('the reserved keys are identifiers, not properties', () => {
    it('extracts a session id without storing it as a property', () => {
      const clean = sanitise({ session_id: 'abc-123-session', surface: 'landing' })
      assert.equal(clean.sessionId, 'abc-123-session')
      assert.deepEqual(clean.props, { surface: 'landing' })
      assert.ok(!('session_id' in clean.props))
    })

    it('extracts an actor-shaped subject without storing it as a property', () => {
      const clean = sanitise({ subject: 'user:550e8400-e29b-41d4-a716-446655440000' })
      assert.equal(clean.subject, 'user:550e8400-e29b-41d4-a716-446655440000')
      assert.deepEqual(clean.props, {})
    })

    it('accepts an operator subject', () => {
      assert.equal(sanitise({ subject: 'operator:ops-14' }).subject, 'operator:ops-14')
    })

    it('refuses a subject that is not an actor — a bare handle is not an identity', () => {
      for (const bad of ['spiros', 'savvanisspiros@gmail.com', 'service:wallet', 'system', 'user:']) {
        const clean = sanitise({ subject: bad })
        assert.equal(clean.subject, null, `subject=${bad} must be refused`)
        assert.deepEqual(clean.reasons, ['bad_property_value'])
      }
    })

    it('refuses an oversized session id rather than truncating it', () => {
      const clean = sanitise({ session_id: 'x'.repeat(129) })
      assert.equal(clean.sessionId, null)
      assert.deepEqual(clean.reasons, ['bad_property_value'])
    })
  })

  /* ---------------------------------------------------------------- tally */

  it('tallies reasons into counts', () => {
    const counts = tally(['disallowed_property', 'disallowed_property', 'bad_property_value'])
    assert.equal(counts.get('disallowed_property'), 2)
    assert.equal(counts.get('bad_property_value'), 1)
    assert.equal(counts.get('unknown_topic'), undefined)
  })
})
