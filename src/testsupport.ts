/**
 * The database harness, and the small fakes.
 *
 * **A database test runs only against a database whose name says it is a test database.**
 *
 * Not a convenience: `resetAnalytics` truncates every table this service owns, and requiring
 * "test" in the name is the difference between a red build and an emptied environment.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE VARIABLE IS `ANALYTICS_TEST_DATABASE_URL`, SPELLED EXACTLY.**
 *
 * The reusable workflow at `cloudsforge-online/micro-org/.github/workflows/service-ci.yml` exports
 * the CI Postgres DSN under `<SERVICE>_TEST_DATABASE_URL` and then GREPS the test output for a skip
 * — if the database-backed suite skipped, the build FAILS rather than going green on nothing. A
 * different spelling here reads no DSN, skips silently, and turns that guard into the exact
 * false-green it exists to prevent. So the name is not negotiable and is asserted by `env.test.ts`.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 */

import postgres from 'postgres'
import { migrate, type Sql } from '@cloudsforge/db'
import { Logger, Metrics } from '@cloudsforge/telemetry'
import { MIGRATIONS, TABLES } from './migrations.ts'
import { registerServiceMetrics } from './server.ts'

// Named `TEST_DSN_VAR` rather than `..._DATABASE_URL_...` on purpose: the estate's Rule 1 CI check
// greps source for any `*_DATABASE_URL` token that is not this service's own, and a constant NAMED
// after the variable would trip it — the value is the honest spelling and is what everything reads.
export const TEST_DSN_VAR = 'ANALYTICS_TEST_DATABASE_URL'

const url = process.env[TEST_DSN_VAR]

export const enabled = Boolean(url && /test/i.test(url))

/** node:test's `{ skip }` option: a string reason disables the suite; `false` runs it. */
export const skip = enabled ? false : `set ${TEST_DSN_VAR} (name must contain "test")`

export function openDb(max = 8): postgres.Sql {
  if (!enabled) throw new Error('database tests are disabled')
  return postgres(url!, { max, onnotice: () => {} })
}

/** The `@cloudsforge/db` view of a postgres.js client, which every store function takes. */
export const db = (sql: postgres.Sql): Sql => sql as unknown as Sql

/**
 * Bring the schema up. Idempotent, so every test file may call it and only the first does work.
 *
 * Deliberately runs the real `MIGRATIONS` rather than a hand-written fixture schema. A fixture
 * would let the constraints drift out of the tests that are supposed to prove they fire — and
 * `events_subject_shape`, `events_person_has_pseudonym`, `events_props_allowed` and
 * `subject_keys_erased` are the four lines this whole service is built around. Every test that
 * plants a raw subject or a free-text property is asserting that the migrator created them.
 */
export async function migrateTestDb(sql: postgres.Sql): Promise<void> {
  await migrate(sql as unknown as Sql, MIGRATIONS, { service: 'analytics-test' })
}

/** Empty every table this service owns. `jobs` included, so a lease cannot leak between files. */
export async function resetAnalytics(sql: postgres.Sql): Promise<void> {
  await sql.unsafe(`truncate ${[...TABLES, 'jobs'].join(', ')} restart identity cascade`)
}

/** Logs are discarded rather than silenced, so a serialisation failure still throws. */
export function quietLogger(): Logger {
  return new Logger({ service: 'analytics-test', sink: () => {} })
}

export function testMetrics(): Metrics {
  return registerServiceMetrics(new Metrics())
}

/**
 * A pepper for tests. Long enough to satisfy `env.ts`, and constant so a test can assert that the
 * SAME subject derives the SAME pseudonym across calls — which is the property funnels rest on.
 */
export const TEST_PEPPER = 'test-pepper-not-a-real-one-0123456789abcdef'
