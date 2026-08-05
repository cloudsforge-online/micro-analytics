/**
 * Configuration, validated at import.
 *
 * Rule 9 of docs/ecosystem/03 §2 — "a repo declares the variables it needs; the deploy provides
 * exactly those" — is a property of this file. Every variable this service reads is named here and
 * nowhere else.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **`ANALYTICS_PSEUDONYM_KEY` IS THE MOST CONSEQUENTIAL VARIABLE IN THIS ESTATE, AND IT IS
 * REQUIRED, LONG, AND NEVER DEFAULTED.**
 *
 * Every other secret in the estate answers "can an attacker act as us". This one answers "was the
 * pseudonymisation ever real". With the pepper and a candidate user id, an attacker can compute a
 * lookup key and learn whether that person is in the store — and, while their salt still exists,
 * recover their entire four-hundred-day behavioural history. R-37 in
 * 16-risks-and-open-decisions.md:75 is exactly this risk and names it as the reason the boundary is
 * enforced in code.
 *
 * So there is no default, no development fallback, and no "unset means off" mode. A service that
 * started with a weak or absent pepper would produce a store that looks pseudonymised and is not,
 * which is worse than one that refuses to start.
 *
 * **THE CHECK IS NO LONGER ON LENGTH, AND THAT SENTENCE USED TO BE THIS FILE'S BIGGEST LIE.** It
 * said "the check is on length, which is the only proxy available here" and asked for 32
 * characters. Measured out of `cloudsforge-estate-analytics-1` on 2026-08-05, the pepper this
 * estate is running is 40 characters, hyphenated, and normalises to a string containing
 * `estateonly` — micro-org #142 and #189 in the same value, on the one variable this header calls
 * the most consequential in the estate, and the 32-character floor passed it without a word.
 * `@cloudsforge/secrets` asserts the SHAPE instead: base64 or hex, 32 decoded BYTES rather than 32
 * keystrokes, a measured entropy floor, and no placeholder marker anywhere in the value.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The minimum-cohort threshold has a FLOOR rather than a range. The deploy may raise it; it may
 * not lower it below five. A configurable suppression threshold that can be set to 1 is not a
 * suppression threshold, it is a suggestion, and the one number in this service that protects a
 * person from being the only member of a cohort should not be weakenable by an environment
 * variable somebody set while debugging a dashboard.
 *
 * Two behaviours are copied deliberately from the siblings:
 *
 *   1. **A missing variable names itself.** `undefined` propagating into a connection string
 *      surfaces four layers later as an unreadable driver error.
 *   2. **A known placeholder is refused outright.** A default secret in source is not convenient,
 *      it is catastrophic, and a placeholder that boots is a placeholder that reaches production.
 */

import { hostname } from 'node:os'
import {
  SecretError,
  assertGeneratedSecret,
  assertOpaqueSecret,
  parseSecretList as parseSharedSecretList,
} from '@cloudsforge/secrets'

/**
 * The service's own name. A constant rather than a variable: it is a property of the repository,
 * not of the deployment, and making it configurable is how two services end up sharing a migration
 * advisory lock.
 */
export const SERVICE = 'analytics'

/**
 * The smallest cohort, funnel step or bucket whose count may be returned.
 *
 * Five, and the reasoning is in the README. It is a floor, not a default: `loadEnv` refuses a
 * configured value below it.
 */
export const MIN_COHORT_FLOOR = 5

/** Raised by `loadEnv`. Distinct so a caller can tell configuration from every other failure. */
export class EnvError extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'EnvError'
  }
}

/**
 * THE `PLACEHOLDERS` SET THAT USED TO BE HERE IS GONE, AND ITS ABSENCE IS THE FIX.
 *
 * It held ten exact strings and was paired with a length floor — 24 characters for the token, 32
 * for the pepper. Neither could fail for either of the two values this estate is actually running.
 * Measured out of `cloudsforge-estate-analytics-1` on 2026-08-05:
 *
 *   ANALYTICS_TOKEN          41 characters, hyphenated, normalises to contain `placeholder`
 *   ANALYTICS_PSEUDONYM_KEY  40 characters, hyphenated, normalises to contain `estateonly`
 *
 * The token's compose line is `${ANALYTICS_TOKEN:-estate-placeholder-token-0000000000000000}`, so a
 * deploy CAN override it and has not, on either estate, on two lines each. The pepper arrives from
 * `secrets/analytics-pepper.<network>.env` and is the value #189 exists about.
 *
 * A check that cannot fail is worse than no check, because the absence of an alarm gets read as the
 * absence of a problem. Both floors were long enough to look like diligence and short enough to
 * pass every placeholder anybody wrote — 41 > 24 and 40 > 32.
 *
 * A deny-list of exact strings is structurally unable to work: the next placeholder somebody writes
 * is, by definition, not on it. `@cloudsforge/secrets` asserts the SHAPE of the value instead,
 * which is the property a placeholder cannot have. It is imported rather than copied so that this
 * service cannot drift from the other sixteen.
 */

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

/**
 * Re-wrap the shared guard's `SecretError` as this service's `EnvError`.
 *
 * `loadEnv` documents a single error class for every configuration failure, and the boot path
 * catches that one class. The message is preserved verbatim — it already names the variable and the
 * command that fixes it, and it never contains the value.
 */
function asEnvError<T>(run: () => T): T {
  try {
    return run()
  } catch (err) {
    if (err instanceof SecretError) throw new EnvError(err.message)
    throw err
  }
}

/**
 * A key THIS ESTATE GENERATES, held to the strictest of the three rules.
 *
 * Used for the peppers, and correctly: `runbooks/runbook-analytics-pseudonym-key.md:68` tells an
 * operator to mint one with `openssl rand -base64 48 | tr -dc 'A-Za-z0-9' | cut -c1-48`, which is
 * 48 characters of the base64 alphabet carrying 36 bytes. The estate chose that command, so the
 * estate may demand its alphabet — that argument does not transfer to a value somebody else issues,
 * which is why `ANALYTICS_TOKEN` below takes the opaque rule instead.
 *
 * `assertGeneratedSecret` asserts what a placeholder cannot have: base64 or hex (no hyphens — every
 * placeholder this estate wrote had one), 32 decoded BYTES rather than 32 keystrokes, and a
 * measured Shannon entropy floor. The old `minLength = 32` parameter is gone rather than kept in
 * front of it: it is a strict subset of the shape check, and running it first answers a
 * 40-character placeholder with "must be at least 32 characters" — true, useless, and about the
 * wrong property.
 *
 * **CONSEQUENCE, STATED PLAINLY, BECAUSE IT IS THE MOST EXPENSIVE ONE IN THIS CHANGE: the pepper
 * this estate is running is refused, so analytics will not boot until a real one is set — and the
 * placeholder CANNOT BE KEPT IN THE RING as `_V1` to preserve pre-rotation lookups, because the
 * guard refuses it under any version number.** That is the right answer even though it costs
 * something real. A pepper that was published in a compose file pseudonymises nothing: its lookup
 * keys are computable by anyone who can read the repository, so the rows derived under it were
 * never protected, and keeping it alive would buy erasure-reachability for data that has no privacy
 * property to protect. Retention prunes those rows; `subjectsBelowVersion` says when.
 */
function requiredGeneratedSecret(source: Source, name: string): string {
  const value = required(source, name)
  asEnvError(() => assertGeneratedSecret(name, value))
  return value
}

/**
 * A secret whose ALPHABET THIS ESTATE DOES NOT CONTROL.
 *
 * `ANALYTICS_TOKEN` is not minted by anything. The compose file's own note on the service-token
 * grants says it in passing and exactly: "`ledger` and `analytics` lost their entries entirely.
 * Neither makes a tokened outbound call; `ANALYTICS_TOKEN` is an inbound `/metrics` secret." It is
 * a static shared value written into a compose file and into Prometheus's `http_headers` block by
 * an operator — the case `@cloudsforge/secrets` documents `assertOpaqueSecret` for by name.
 *
 * The two rules differ on the alphabet and agree on everything that matters here: both refuse a
 * placeholder MARKER anywhere in the normalised value, so `estate-placeholder-token-0000000000000000`
 * is refused by either. The choice buys an operator a hand-set value that works; it does not buy the
 * defect a way through.
 */
function requiredOpaqueSecret(source: Source, name: string): string {
  const value = required(source, name)
  asEnvError(() => assertOpaqueSecret(name, value))
  return value
}

function optional(source: Source, name: string, fallback: string): string {
  const value = source[name]?.trim()
  return value && value.length > 0 ? value : fallback
}

const PEPPER_PREFIX = 'ANALYTICS_PSEUDONYM_KEY_V'
const LEGACY_PEPPER = 'ANALYTICS_PSEUDONYM_KEY'

/**
 * The pepper ring: every `ANALYTICS_PSEUDONYM_KEY_V<n>` present, plus the version that mints.
 *
 * **THE UNSUFFIXED NAME IS ACCEPTED AS V1, AND IT HAS TO BE.** Every mapping minted before this
 * existed was derived from the value `ANALYTICS_PSEUDONYM_KEY` held, and there is no way to
 * re-derive those rows under any other name — the raw subject is not stored and HMAC is one-way.
 * If shipping #189's fix required renaming the variable, the fix would itself orphan every existing
 * pseudonym, which is the exact damage it exists to prevent.
 *
 * Every version faces the FULL rule, including one being rotated out. "Just until retention catches
 * up" is exactly how a placeholder survives the rotation that was meant to remove it — and here the
 * outgoing pepper is the one whose disclosure retroactively undoes the privacy property of four
 * hundred days of data, so it is the last entry that should get a relaxed check.
 */
function parsePseudonymKeys(source: Source): {
  pseudonymKeys: ReadonlyMap<number, string>
  pseudonymVersion: number
} {
  const peppers = new Map<number, string>()

  for (const name of Object.keys(source)) {
    if (!name.startsWith(PEPPER_PREFIX)) continue
    const suffix = name.slice(PEPPER_PREFIX.length)
    if (!/^[0-9]{1,3}$/.test(suffix)) continue
    const version = Number(suffix)
    if (version < 1) throw new EnvError(`${name}: pepper versions start at 1`)
    if (!source[name]?.trim()) continue
    peppers.set(version, requiredGeneratedSecret(source, name))
  }

  const legacy = source[LEGACY_PEPPER]?.trim()
  if (legacy) {
    const explicit = peppers.get(1)
    if (explicit !== undefined && explicit !== legacy) {
      throw new EnvError(
        `${LEGACY_PEPPER} and ${PEPPER_PREFIX}1 are both set and differ — keep ${PEPPER_PREFIX}1 and remove the unsuffixed one`,
      )
    }
    if (explicit === undefined) peppers.set(1, requiredGeneratedSecret(source, LEGACY_PEPPER))
  }

  if (peppers.size === 0) {
    throw new EnvError(`${PEPPER_PREFIX}1 is required — ${SERVICE} refuses to start without a pepper`)
  }

  // Two peppers with the same value is a rotation that did not rotate: every subject would derive
  // to one lookup key under both versions, so the "old" one could never be retired and the gauge
  // would report progress that had not happened. `parseSecrets` refuses the same thing, for the
  // same reason.
  const distinct = new Set(peppers.values())
  if (distinct.size !== peppers.size) {
    throw new EnvError(`two ${PEPPER_PREFIX}<n> values are identical — that is a rotation that did not rotate`)
  }

  const highest = Math.max(...peppers.keys())
  const pseudonymVersion = integer(source, 'ANALYTICS_PSEUDONYM_VERSION', highest, 1, 999)
  if (!peppers.has(pseudonymVersion)) {
    throw new EnvError(
      `ANALYTICS_PSEUDONYM_VERSION is ${pseudonymVersion} but ${PEPPER_PREFIX}${pseudonymVersion} is not set — this process would mint pseudonyms it cannot look up`,
    )
  }
  return { pseudonymKeys: peppers, pseudonymVersion }
}

function integer(source: Source, name: string, fallback: number, min: number, max: number): number {
  const raw = source[name]?.trim()
  if (!raw) return fallback
  const value = Number(raw)
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new EnvError(`${name} must be a whole number between ${min} and ${max} (got ${raw})`)
  }
  return value
}

/**
 * The delivery-signature secrets, newest first.
 *
 * A LIST rather than one value, because `verifyDelivery` takes a list so that a rotation is a
 * window rather than an instant (`contracts/packages/events/src/index.ts:718-721`). An endpoint
 * publishes a new secret, accepts both for a window, then drops the old one. One value here would
 * make every rotation an estate-wide synchronised deploy.
 */
export function parseSecrets(raw: string, name: string): readonly string[] {
  // The `minLength = 24` parameter this used to take is GONE. It was the keystroke floor
  // `@cloudsforge/secrets` exists to replace: `estate-placeholder-token-0000000000000000` is 41
  // characters and cleared it, as would every other placeholder this estate has written. Removing
  // the parameter rather than defaulting it differently is deliberate — a caller cannot ask for a
  // weaker rule if there is no argument that expresses one.
  //
  // Argument order is flipped on the way through: this service's exported signature is
  // `(raw, name)` and the shared one is `(name, raw)`. Kept rather than changed because the
  // signature is this module's public surface, and a silent flip of two `string` parameters is a
  // change the type checker cannot catch.
  //
  // EVERY ENTRY FACES THE FULL RULE, INCLUDING THE OUTGOING ONE. In a rotation overlap window the
  // outgoing key is the one an attacker already holds if it leaked, and "just for the drain" is
  // exactly how a placeholder survives the rotation that was meant to remove it. The duplicate
  // check comes across too: two identical secrets is a rotation that did not rotate, and it would
  // make `keyIndex > 0` — the signal that an old key is still in use — report the wrong thing.
  //
  // These are GENERATED keys, not opaque ones: measured live on 2026-08-05,
  // `ANALYTICS_DELIVERY_SECRETS` holds 64 characters of the base64/hex alphabet carrying 48 bytes,
  // which is `openssl rand -base64 48` exactly. It is the one secret this service reads that the
  // estate already mints correctly, and it PASSES.
  return asEnvError(() => parseSharedSecretList(name, raw))
}

export interface Env {
  readonly port: number
  readonly env: string
  readonly version: string
  readonly logLevel: 'debug' | 'info' | 'warn' | 'error'
  /**
   * Rule 1: one database, named by this service's own variable. The CI check greps for any other
   * connection-string variable, so adding a second one here fails the build rather than review.
   */
  readonly databaseUrl: string
  readonly databasePoolMax: number
  readonly identityJwksUrl: string
  readonly identityIssuer: string
  readonly instanceId: string

  /**
   * The peppers, BY VERSION — `ANALYTICS_PSEUDONYM_KEY_V<n>`. See the file header, and
   * `src/pseudonym.ts` for what they are used for and for how a rotation works.
   *
   * They exist in this process's memory and in the deploy's secret store, and in no third place:
   * never written to this service's database, never logged, never returned by a route.
   *
   * A MAP rather than a string, and that is #189's fix. With one value, replacing it re-derived
   * every returning subject to a new lookup key — one person silently became two pseudonyms, their
   * history was orphaned, and **erasure stopped reaching pre-rotation rows**. Holding every pepper
   * at once means an old mapping is still found from the raw subject, which is what keeps erasure
   * whole across a rotation.
   */
  readonly pseudonymKeys: ReadonlyMap<number, string>
  /**
   * The version new subjects are MINTED under. Must be present in `pseudonymKeys`.
   *
   * Defaults to the highest supplied, so a deployment holding one pepper needs no new variable.
   * Unlike identity's key secret there is no drain to run afterwards — old mappings keep their old
   * lookup key for ever, because HMAC does not run backwards — so the old pepper stays in this map
   * until retention has pruned every row that predates the rotation. `subjectsBelowVersion` says
   * when that is.
   */
  readonly pseudonymVersion: number

  /** The credential Prometheus presents in `x-analytics-token` to reach `/metrics`. */
  readonly token: string

  /** Delivery-signature secrets for the event-bus inbox. Newest first; see `parseSecrets`. */
  readonly deliverySecrets: readonly string[]

  /**
   * The minimum cohort. No count derived from fewer distinct subjects than this is returned.
   * Floor `MIN_COHORT_FLOOR`; the deploy may raise it and may not lower it.
   */
  readonly minCohort: number

  /** Product events. 400 days — 11-data-and-contract-strategy.md:434. */
  readonly eventRetentionDays: number
  /** Daily rollups and the cohort grid. They outlive the events they were computed from. */
  readonly rollupRetentionDays: number
  /** Inbox rows. The redelivery horizon, not an archive; `events_source_uniq` is the backstop. */
  readonly inboxRetentionDays: number
  readonly idempotencyTtlDays: number
  /** How many weeks wide the retention grid is. Metric 18 says twelve. */
  readonly cohortWeeks: number
}

const LEVELS = new Set(['debug', 'info', 'warn', 'error'])

export function loadEnv(source: Source = process.env, host = ''): Env {
  const logLevel = optional(source, 'LOG_LEVEL', 'info')
  if (!LEVELS.has(logLevel)) {
    throw new EnvError(`LOG_LEVEL must be one of debug, info, warn, error (got ${logLevel})`)
  }

  const minCohort = integer(source, 'ANALYTICS_MIN_COHORT', MIN_COHORT_FLOOR, 1, 10_000)
  if (minCohort < MIN_COHORT_FLOOR) {
    // Refused rather than clamped. Clamping would let a deploy believe it had set 1 and get 5,
    // and the difference between those two numbers is whether a funnel of one person is published.
    throw new EnvError(
      `ANALYTICS_MIN_COHORT may be raised but never lowered below ${MIN_COHORT_FLOOR} (got ${minCohort}) — ` +
        'a suppression threshold that can be set to 1 is not a suppression threshold',
    )
  }

  const eventRetentionDays = integer(source, 'ANALYTICS_EVENT_RETENTION_DAYS', 400, 1, 3_650)
  const rollupRetentionDays = integer(source, 'ANALYTICS_ROLLUP_RETENTION_DAYS', 1_200, 1, 3_650)
  if (rollupRetentionDays < eventRetentionDays) {
    // A rollup that expires before the events behind it throws away the cheap summary while
    // keeping the expensive raw rows — the exact inversion of why the rollup table exists.
    throw new EnvError(
      `ANALYTICS_ROLLUP_RETENTION_DAYS (${rollupRetentionDays}) must be at least ` +
        `ANALYTICS_EVENT_RETENTION_DAYS (${eventRetentionDays}) — a rollup outlives its events`,
    )
  }

  return {
    port: integer(source, 'PORT', 4023, 1, 65_535),
    env: optional(source, 'NODE_ENV', 'development'),
    version: optional(source, 'CLOUDSFORGE_TAG', 'dev'),
    logLevel: logLevel as Env['logLevel'],
    databaseUrl: required(source, 'ANALYTICS_DATABASE_URL'),
    databasePoolMax: integer(source, 'ANALYTICS_DATABASE_POOL_MAX', 10, 1, 100),
    identityJwksUrl: required(source, 'IDENTITY_JWKS_URL'),
    identityIssuer: required(source, 'IDENTITY_ISSUER'),
    instanceId: optional(source, 'INSTANCE_ID', host || 'unknown'),

    ...parsePseudonymKeys(source),
    token: requiredOpaqueSecret(source, 'ANALYTICS_TOKEN'),
    deliverySecrets: parseSecrets(required(source, 'ANALYTICS_DELIVERY_SECRETS'), 'ANALYTICS_DELIVERY_SECRETS'),

    minCohort,
    eventRetentionDays,
    rollupRetentionDays,
    inboxRetentionDays: integer(source, 'ANALYTICS_INBOX_RETENTION_DAYS', 30, 1, 400),
    idempotencyTtlDays: integer(source, 'ANALYTICS_IDEMPOTENCY_TTL_DAYS', 30, 1, 400),
    cohortWeeks: integer(source, 'ANALYTICS_COHORT_WEEKS', 12, 2, 52),
  }
}

/**
 * The checks above run at import, before the logger exists, so an uncaught throw reaches the
 * container as a bare V8 stack: not JSON, no level, no service name. The collector drops it and
 * the only symptom an operator gets is a container that exits instantly.
 *
 * So emit one structured fatal line by hand. It is built from a literal rather than routed through
 * the telemetry package: nothing that can itself fail may sit between a configuration error and
 * the report of it. The message is `err.message`, which by construction above never contains the
 * value of the variable it is complaining about — only its name and, for a length failure, its
 * length.
 */
function fatalConfig(err: unknown): never {
  const message = err instanceof Error ? err.message : String(err)
  process.stderr.write(
    `${JSON.stringify({
      time: new Date().toISOString(),
      level: 'fatal',
      service: SERVICE,
      step: 'env',
      msg: `startup failed at: env — ${message}`,
    })}\n`,
  )
  process.exit(1)
}

export const env: Env = (() => {
  try {
    return loadEnv(process.env, hostname())
  } catch (err) {
    fatalConfig(err)
  }
})()
