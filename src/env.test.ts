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
import { randomBytes } from 'node:crypto'
import { describe, it } from 'node:test'

/**
 * GENERATED, NOT WRITTEN, AND THE LITERALS THEY REPLACE ARE WHY.
 *
 * Every case in this file used to be built on three hyphenated sentences describing themselves:
 * `'a-real-looking-pepper-0123456789abcdef'`, `'a-real-looking-token-0123456789'` and
 * `'a-real-looking-delivery-secret-01234'`. They are the same family as the values this estate
 * actually shipped — `estate-only-…` and `estate-placeholder-…` — and they cleared the old floors
 * for the same reason those did: the floor counted keystrokes. So this suite was asserting that a
 * hyphenated placeholder is an acceptable PEPPER, which is the variable this service's own header
 * calls the most consequential in the estate.
 *
 * Regenerated per run rather than replaced with better-looking literals, so a placeholder cannot
 * creep back in the next time somebody needs a fixture.
 */
const PEPPER = randomBytes(48).toString('base64')
const TOKEN = randomBytes(48).toString('base64')
const DELIVERY_SECRET = randomBytes(48).toString('base64')

/** A source that satisfies every required variable, so a case can vary exactly one thing. */
const BASE: Record<string, string> = {
  ANALYTICS_DATABASE_URL: 'postgres://u:p@localhost:5432/analytics',
  IDENTITY_JWKS_URL: 'http://localhost:4001/.well-known/jwks.json',
  IDENTITY_ISSUER: 'http://localhost:4001',
  ANALYTICS_PSEUDONYM_KEY: PEPPER,
  ANALYTICS_TOKEN: TOKEN,
  ANALYTICS_DELIVERY_SECRETS: DELIVERY_SECRET,
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
    assert.deepEqual(env.deliverySecrets, [DELIVERY_SECRET])
  })

  /* ---------------------------------------------------------------- the values the estate runs */

  /**
   * **THE TWO VALUES THIS SERVICE IS RUNNING ON TODAY, PINNED AS FAILURES.**
   *
   * Measured inside `cloudsforge-estate-analytics-1` on 2026-08-05, not read off a file:
   *
   *   ANALYTICS_TOKEN          `estate-placeholder-token-0000000000000000`, 41 characters
   *   ANALYTICS_PSEUDONYM_KEY  40 characters, hyphenated, containing `estate-only`
   *
   * The token cleared the 24-character floor and the pepper cleared the 32-character one, which is
   * micro-org #142 and #189 in one service, and is why both floors are gone. Quoted here because
   * the token is an already-public defect value with no secrecy left to protect, and because a test
   * that names the exact string the estate shipped is the only kind that cannot be satisfied by a
   * rule that happens to catch something else. The pepper's exact value is NOT quoted — a marker
   * fixture standing in for it proves the same property without moving a live secret into a
   * repository, even one this weak.
   */
  it('REFUSES BOTH VALUES THE ESTATE IS RUNNING, which is the whole of this change', () => {
    assert.throws(
      () => loadEnv({ ...BASE, ANALYTICS_TOKEN: 'estate-placeholder-token-0000000000000000' }),
      (err: unknown) => {
        assert.ok(err instanceof EnvError)
        assert.match(err.message, /ANALYTICS_TOKEN/)
        assert.match(err.message, /placeholder/)
        // The message names the marker it matched, never the value it matched it in: the fatal
        // handler writes this to stderr and the collector ships it onwards.
        assert.ok(!err.message.includes('estate-placeholder-token-0000000000000000'))
        return true
      },
    )
    assert.throws(
      () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY: 'estate-only-analytics-pepper-000000000000' }),
      (err: unknown) => {
        assert.ok(err instanceof EnvError)
        assert.match(err.message, /ANALYTICS_PSEUDONYM_KEY/)
        assert.match(err.message, /estateonly/)
        return true
      },
    )
  })

  /* ---------------------------------------------------------------- the pepper */

  describe('the pseudonym key', () => {
    it('is required — there is no development fallback', () => {
      const source = { ...BASE }
      delete (source as Record<string, string | undefined>)['ANALYTICS_PSEUDONYM_KEY']
      assert.throws(() => loadEnv(source), EnvError)
    })

    it('refuses a short one, and the unit is BYTES rather than keystrokes', () => {
      // This assertion used to demand the message say "at least 32" CHARACTERS — the keystroke
      // floor that let the estate's 40-character pepper through. Pinning that wording made the test
      // a DEFENCE of the defective rule: any fix that stopped counting characters would fail CI,
      // however much better the new rule was. What it asserts now is the property that matters.
      //
      // `shortpepper` is spelled in the base64 alphabet, so it is not the alphabet that catches it —
      // it decodes to 8 bytes. `short-pepper` would have failed on the hyphen instead, which is a
      // true refusal about the wrong property.
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY: 'shortpepper' }),
        (err: unknown) =>
          err instanceof EnvError &&
          /8 bytes of key material/.test(err.message) &&
          /at least 32/.test(err.message),
      )
    })

    it('refuses a hyphenated one — a generated key is not typed', () => {
      // The alphabet check is the one that catches every placeholder this estate has actually
      // written, because a human reaching for a memorable value reaches for a hyphen and neither
      // base64 nor hex contains one.
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY: 'a-real-looking-pepper-0123456789abcdef' }),
        (err: unknown) => err instanceof EnvError && /not base64 or hex/.test(err.message),
      )
    })

    it('refuses a long, well-formed, DEGENERATE one', () => {
      // 64 zeros: past any keystroke floor, spelled in both alphabets, and carrying no entropy at
      // all. A floor that counts characters cannot tell this apart from a key.
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY: '0'.repeat(64) }),
        (err: unknown) => err instanceof EnvError && /entropy/.test(err.message),
      )
    })

    it('accepts what the runbook tells an operator to generate', () => {
      // `runbook-analytics-pseudonym-key.md:68` is
      // `openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-48`. A guard that refused the
      // estate's own documented command would be a guard somebody removes, so this is pinned.
      const runbookShaped = randomBytes(64).toString('base64').replace(/[^A-Za-z0-9]/g, '').slice(0, 48)
      assert.equal(runbookShaped.length, 48)
      assert.equal(
        loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY: runbookShaped }).pseudonymKeys.get(1),
        runbookShaped,
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
      const env = loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V2: randomBytes(48).toString('base64') })
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
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V1: randomBytes(48).toString('base64') }),
        (err: unknown) => err instanceof EnvError && /both set and differ/.test(err.message),
      )
    })

    it('holds EVERY versioned pepper to the full rule, including one being rotated out', () => {
      // "Just until retention catches up" is exactly how a placeholder survives the rotation that
      // was meant to remove it, and here the outgoing pepper is the one whose disclosure undoes the
      // privacy property of four hundred days of data.
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V2: 'short' }),
        (err: unknown) => err instanceof EnvError && /bytes of key material/.test(err.message),
      )
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V2: 'CHANGE_ME_TO_32_RANDOM_CHARACTERS_OK' }),
        (err: unknown) => err instanceof EnvError && /placeholder/.test(err.message),
      )
      // And the message names WHICH version failed, because an operator holding a ring of three
      // needs to know which line to regenerate.
      assert.throws(
        () => loadEnv({ ...BASE, ANALYTICS_PSEUDONYM_KEY_V2: 'short' }),
        (err: unknown) => err instanceof EnvError && /ANALYTICS_PSEUDONYM_KEY_V2/.test(err.message),
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
    // Was `'secret-one-0123456789abcdef'` and its `-two-` twin: hyphenated, zero-padded and past
    // the old 24-character floor, which is the exact family that reached the estate as #142.
    const one = randomBytes(48).toString('base64')
    const two = randomBytes(48).toString('base64')

    it('parses a rotation window of two', () => {
      assert.deepEqual(parseSecrets(`${one}, ${two}`, 'X'), [one, two])
    })

    it('refuses an empty list', () => {
      assert.throws(() => parseSecrets('  ,  ', 'X'), EnvError)
      assert.throws(() => parseSecrets('', 'X'), EnvError)
    })

    it('refuses a duplicate, because a rotation that did not rotate reports the wrong keyIndex', () => {
      assert.throws(() => parseSecrets(`${one},${one}`, 'X'), (err: unknown) => err instanceof EnvError && /twice/.test(err.message))
    })

    it('holds EVERY entry to the full rule, and names WHICH one failed', () => {
      // The index is in the message and the entry is not: an operator with the file open counts
      // commas, and a log collector must not be handed the value.
      assert.throws(
        () => parseSecrets(`${one},short`, 'X'),
        (err: unknown) =>
          err instanceof EnvError && /X\[1\]/.test(err.message) && /at least 32/.test(err.message),
      )
      // The outgoing key faces the same rule as the incoming one. "Just for the drain" is how a
      // placeholder survives the rotation that was meant to remove it.
      assert.throws(
        () => parseSecrets(`${one},changeme`, 'X'),
        (err: unknown) => err instanceof EnvError && /placeholder/.test(err.message),
      )
    })

    it('accepts what the estate already mints, which is what this variable holds today', () => {
      // Measured live 2026-08-05: 64 characters of base64 carrying 48 bytes — `openssl rand
      // -base64 48` exactly. This is the one secret analytics reads that was never a placeholder,
      // and pinning it means a future tightening cannot silently start refusing it.
      assert.deepEqual(parseSecrets(one, 'X'), [one])
      assert.equal(one.length, 64)
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
