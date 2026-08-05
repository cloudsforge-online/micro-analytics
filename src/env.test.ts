/**
 * Configuration, and the two variables whose absence must stop the process.
 *
 * The DSN-variable assertion at the bottom is not decoration. `service-ci.yml:234-241` fails the
 * build if the database-backed suite skipped, and it detects that by grepping the output for the
 * skip message — which only appears if `testsupport.ts` read the variable the workflow exported. A
 * misspelling here would skip silently and turn the estate's false-green guard into the false green
 * it exists to prevent.
 */

import assert from 'node:assert/strict'
import { describe, it } from 'node:test'

/** A source that satisfies every required variable, so a case can vary exactly one thing. */
const BASE: Record<string, string> = {
  ANALYTICS_DATABASE_URL: 'postgres://u:p@localhost:5432/analytics',
  IDENTITY_JWKS_URL: 'http://localhost:4001/.well-known/jwks.json',
  IDENTITY_ISSUER: 'http://localhost:4001',
  ANALYTICS_PSEUDONYM_KEY: 'a-real-looking-pepper-0123456789abcdef',
  ANALYTICS_TOKEN: 'a-real-looking-token-0123456789',
  ANALYTICS_DELIVERY_SECRETS: 'a-real-looking-delivery-secret-01234',
}

// `env.ts` validates `process.env` at IMPORT and exits the process on a bad configuration — right
// for a service, fatal for a test runner. So populate a valid environment first, then import it
// dynamically. `loadEnv` itself is pure over its source, so every case below passes an explicit
// object and never touches `process.env`.
for (const [key, value] of Object.entries(BASE)) process.env[key] = value
const { EnvError, MIN_COHORT_FLOOR, loadEnv, parseSecrets } = await import('./env.ts')
const { TEST_DSN_VAR } = await import('./testsupport.ts')

describe('env', () => {
  it('loads with the required set and defaults the rest', () => {
    const env = loadEnv(BASE)
    assert.equal(env.port, 4023)
    assert.equal(env.minCohort, MIN_COHORT_FLOOR)
    assert.equal(env.eventRetentionDays, 400, '11-data-and-contract-strategy.md:434')
    assert.equal(env.cohortWeeks, 12, 'metric 18 is a twelve-week heatmap')
    assert.deepEqual(env.deliverySecrets, ['a-real-looking-delivery-secret-01234'])
  })

  /* ---------------------------------------------------------------- the pepper */

  describe('the pseudonym key', () => {
    it('is required — there is no development fallback', () => {
      const source = { ...BASE }
      delete (source as Record<string, string | undefined>)['ANALYTICS_PSEUDONYM_KEY']
      assert.throws(() => loadEnv(source), EnvError)
    })

    it('refuses a short one, because length is the only entropy proxy available', () => {
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY: 'short-pepper' }),
        (err: unknown) => err instanceof EnvError && /at least 32/.test(err.message),
      )
    })

    it('refuses a known placeholder', () => {
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY: 'CHANGE_ME_TO_32_RANDOM_CHARACTERS_OK' }),
        (err: unknown) => err instanceof EnvError && /placeholder/.test(err.message),
      )
    })

    it('accepts the unsuffixed name as v1, which every existing mapping depends on', () => {
      // LOAD-BEARING. Mappings minted before #189 derive from the value this variable held, and
      // there is no way to re-derive them under another name — the raw subject is not stored and
      // HMAC does not run backwards. Renaming the variable would orphan every existing pseudonym,
      // which is the exact damage the fix exists to prevent.
      const env = loadEnv(BASE)
      assert.deepEqual([...env.pseudonymKeys.keys()], [1])
      assert.equal(env.pseudonymVersion, 1)
    })

    it('mints under the highest pepper supplied', () => {
      const env = loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V2: 'a-second-real-looking-pepper-0123456789ab' })
      assert.deepEqual([...env.pseudonymKeys.keys()].sort((a, b) => a - b), [1, 2])
      assert.equal(env.pseudonymVersion, 2)
    })

    it('refuses a mint version it holds no pepper for', () => {
      // Minting under a pepper it cannot look up would orphan every subject it then created.
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_VERSION: '2' }),
        (err: unknown) => err instanceof EnvError && /ANALYTICS_PSEUDONYM_KEY_V2 is not set/.test(err.message),
      )
    })

    it('refuses two identical peppers — a rotation that did not rotate', () => {
      // Both versions would derive the same lookup key, so the old one could never be retired and
      // `subjectsBelowVersion` would report progress that had not happened.
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V2: BASE['ANALYTICS_PSEUDONYM_KEY']! }),
        (err: unknown) => err instanceof EnvError && /identical/.test(err.message),
      )
    })

    it('refuses two different values both claiming v1 rather than guessing', () => {
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V1: 'a-different-v1-pepper-0123456789abcdef' }),
        (err: unknown) => err instanceof EnvError && /both set and differ/.test(err.message),
      )
    })

    it('holds a versioned pepper to the same floor and placeholder rules', () => {
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V2: 'short' }),
        (err: unknown) => err instanceof EnvError && /at least 32/.test(err.message),
      )
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V2: 'CHANGE_ME_TO_32_RANDOM_CHARACTERS_OK' }),
        (err: unknown) => err instanceof EnvError && /placeholder/.test(err.message),
      )
    })

    it('never puts the value in the error message', () => {
      // The fatal handler writes `err.message` to stderr, where the collector picks it up. A
      // message carrying the pepper would put it in Loki, in every backup of Loki, and in the
      // one place 13-operational-model.md:597 says it must never be.
      const secret = 'aaaaaaaaaaaaaaaaaaaaaaaa'
      try {
        loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY: secret })
        assert.fail('expected a throw')
      } catch (err) {
        assert.ok(err instanceof EnvError)
        assert.ok(!err.message.includes(secret), `the message leaked the value: ${err.message}`)
      }
    })
  })

  /* ---------------------------------------------------------------- the threshold */

  describe('the minimum cohort is a floor, not a default', () => {
    it('may be raised', () => {
      assert.equal(loadEnv({ ...BASE, ANALYTICS_MIN_COHORT: '25' }).minCohort, 25)
    })

    it('may not be lowered below the floor', () => {
      for (const value of ['1', '2', '4']) {
        assert.throws(
          () => loadEnv({ ...BASE, ANALYTICS_MIN_COHORT: value }),
          (err: unknown) => err instanceof EnvError && /never lowered below 5/.test(err.message),
          `ANALYTICS_MIN_COHORT=${value} must be refused`,
        )
      }
    })

    it('accepts exactly the floor', () => {
      assert.equal(loadEnv({ ...BASE, ANALYTICS_MIN_COHORT: '5' }).minCohort, 5)
    })
  })

  /* ---------------------------------------------------------------- retention ordering */

  it('refuses a rollup horizon shorter than the event horizon', () => {
    assert.throws(
      () => loadEnv({ ...BASE, ANALYTICS_EVENT_RETENTION_DAYS: '400', ANALYTICS_ROLLUP_RETENTION_DAYS: '30' }),
      (err: unknown) => err instanceof EnvError && /outlives its events/.test(err.message),
    )
  })

  /* ---------------------------------------------------------------- delivery secrets */

  describe('delivery secrets', () => {
    it('parses a rotation window of two', () => {
      const secrets = parseSecrets('secret-one-0123456789abcdef, secret-two-0123456789abcdef', 'X')
      assert.deepEqual(secrets, ['secret-one-0123456789abcdef', 'secret-two-0123456789abcdef'])
    })

    it('refuses an empty list', () => {
      assert.throws(() => parseSecrets('  ,  ', 'X'), EnvError)
    })

    it('refuses a duplicate, because a rotation that did not rotate reports the wrong keyIndex', () => {
      const one = 'secret-one-0123456789abcdef'
      assert.throws(() => parseSecrets(`${one},${one}`, 'X'), (err: unknown) => err instanceof EnvError && /twice/.test(err.message))
    })

    it('refuses a short entry', () => {
      assert.throws(() => parseSecrets('short', 'X'), EnvError)
    })
  })

  /* ---------------------------------------------------------------- CI contract */

  it('reads its own test database variable, spelled exactly as service-ci.yml exports it', () => {
    // `<SERVICE>_DATABASE_URL` with `_DATABASE_URL` replaced by `_TEST_DATABASE_URL`, which is what
    // `service-ci.yml:223` does. Assembled rather than written, so this test agrees with the rule
    // rather than restating it — and so Rule 1's grep does not read it as a second database.
    const declared = 'ANALYTICS_DATABASE_URL'
    assert.equal(TEST_DSN_VAR, declared.replace('_DATABASE_URL', '_TEST_DATABASE_URL'))
  })
})
