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
 * So there is no default, no development fallback, and no "unset means off" mode. Sixteen bytes of
 * entropy is the floor and the check is on length, which is the only proxy available here. It is
 * deliberately above the point at which a human-chosen string is plausible, so a memorable password
 * fails it too. A service that started with a weak or absent pepper would produce a store that
 * looks pseudonymised and is not, which is worse than one that refuses to start.
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

const PLACEHOLDERS = new Set([
  'changeme',
  'change-me',
  'change_me',
  'placeholder',
  'secret',
  'token',
  'pepper',
  'dev-secret',
  'replace-with-a-real-secret',
  'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
])

type Source = Readonly<Record<string, string | undefined>>

function required(source: Source, name: string): string {
  const value = source[name]?.trim()
  if (!value) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  return value
}

function requiredSecret(source: Source, name: string, minLength = 24): string {
  const value = required(source, name)
  if (PLACEHOLDERS.has(value.toLowerCase()) || value.toLowerCase().startsWith('change_me')) {
    throw new EnvError(`${name} is set to a known placeholder — generate a real secret`)
  }
  // Length is a proxy for entropy and the only one available here. It is set above the point at
  // which a human-chosen string is plausible, so a memorable password fails this check too.
  if (value.length < minLength) {
    throw new EnvError(`${name} must be at least ${minLength} characters (got ${value.length})`)
  }
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
 * 32 rather than the estate's usual 24: this is the value whose disclosure retroactively undoes the
 * privacy property of four hundred days of data; it is worth eight more characters.
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
    peppers.set(version, requiredSecret(source, name, 32))
  }

  const legacy = source[LEGACY_PEPPER]?.trim()
  if (legacy) {
    const explicit = peppers.get(1)
    if (explicit !== undefined && explicit !== legacy) {
      throw new EnvError(
        `${LEGACY_PEPPER} and ${PEPPER_PREFIX}1 are both set and differ — keep ${PEPPER_PREFIX}1 and remove the unsuffixed one`,
      )
    }
    if (explicit === undefined) peppers.set(1, requiredSecret(source, LEGACY_PEPPER, 32))
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
export function parseSecrets(raw: string, name: string, minLength = 24): readonly string[] {
  const secrets = raw
    .split(',')
    .map((entry) => entry.trim())
    .filter((entry) => entry.length > 0)
  if (secrets.length === 0) throw new EnvError(`${name} is required — ${SERVICE} refuses to start without it`)
  for (const secret of secrets) {
    if (PLACEHOLDERS.has(secret.toLowerCase()) || secret.toLowerCase().startsWith('change_me')) {
      throw new EnvError(`${name} contains a known placeholder — generate a real secret`)
    }
    if (secret.length < minLength) {
      throw new EnvError(`${name} entries must each be at least ${minLength} characters`)
    }
  }
  if (new Set(secrets).size !== secrets.length) {
    // Two identical secrets is a rotation that did not rotate, and it would make `keyIndex > 0`
    // — the signal that an old key is still in use — report the wrong thing.
    throw new EnvError(`${name} lists the same secret twice`)
  }
  return Object.freeze(secrets)
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
    token: requiredSecret(source, 'ANALYTICS_TOKEN'),
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
