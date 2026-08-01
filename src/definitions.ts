/**
 * The metric catalogue: versioned, checksummed, and unable to change under a chart.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **A REDEFINITION CREATES A NEW ID. IT NEVER EDITS AN OLD ONE.**
 *
 * 13-operational-model.md:637 states the rule and the reason in one sentence: "a retention number
 * that changed definition in March is a chart that lies about February". Definitions are versioned
 * *in this repository*, which is what :636 asks for, and the database holds a checksum over the
 * numerator, the denominator and the window of every version ever published.
 *
 * `publish()` is therefore not an upsert. Publishing `(id, version)` whose checksum differs from
 * the one already stored **throws**, and the `metric_definitions` trigger refuses the UPDATE that
 * would paper over it. The only way to change what a metric means is to add a version — which
 * leaves the old series intact, with the definition it was computed under still readable beside it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Every entry carries numerator, denominator and window, because 13-operational-model.md:611 says
 * "every metric states numerator, denominator and window" and a metric that does not is a number
 * two people will read differently. The `metric` field cites the row in 13 §12 it implements.
 *
 * This is a SUBSET of the twenty in 13 §12, and the gap is honest rather than hidden: metrics 3,
 * 4, 9, 11, 12, 13 and 14 name events (`identity.email.verified`, `wallet.address.assigned`,
 * `mint.order.created`, `trade.bot.started`, `worlds.session.started`, `membership.joined`,
 * `proposal.voted`) that `contracts-events` does not register — eighteen topics, checked at
 * `contracts/packages/events/src/index.ts:222-349`. A definition for a metric whose input event
 * cannot be emitted would be a definition that silently reports zero for ever, which is worse than
 * its absence. They are listed in the README as the work this service is waiting on.
 */

import { createHash } from 'node:crypto'
import type { Db, Tx } from './store.ts'

export interface MetricDefinition {
  /** Stable. A redefinition is a new VERSION of this id, or a new id — never an edit. */
  readonly id: string
  readonly version: number
  readonly title: string
  /** The row in 13-operational-model.md §12 this implements. */
  readonly metric: number
  readonly numerator: string
  readonly denominator: string
  readonly window: string
  /** Set when this version replaces an earlier id entirely. */
  readonly supersedes?: string
}

export const DEFINITIONS: readonly MetricDefinition[] = Object.freeze([
  Object.freeze({
    id: 'acquisition.first_page_view',
    version: 1,
    metric: 1,
    title: 'Acquisition',
    numerator: 'distinct subject_key with a first-ever page_viewed, by referrer_class',
    denominator: 'none; this is a count',
    window: 'daily and weekly, suppressed below the minimum cohort',
  }),
  Object.freeze({
    id: 'registration.conversion',
    version: 1,
    metric: 2,
    title: 'Registration conversion',
    numerator: 'distinct subject_key with user_registered',
    denominator: 'distinct subject_key with page_viewed where surface = register',
    window: 'session, with 7-day attribution',
  }),
  Object.freeze({
    id: 'deposit.first',
    version: 1,
    metric: 5,
    title: 'First deposit',
    numerator: 'distinct subject_key with at least one deposit_confirmed',
    denominator: 'distinct subject_key in the signup-week cohort',
    window: '7d, 30d and 90d from registration',
  }),
  Object.freeze({
    id: 'transaction.first',
    version: 1,
    metric: 7,
    title: 'First transaction',
    numerator: 'distinct subject_key with at least one ledger_entry_posted',
    denominator: 'distinct subject_key with a first deposit',
    window: '30d',
  }),
  Object.freeze({
    id: 'token.creation',
    version: 1,
    metric: 8,
    title: 'Token creation',
    numerator: 'distinct subject_key with at least one token_deployed',
    denominator: 'distinct active subject_key (see active.definition)',
    window: '30d',
  }),
  Object.freeze({
    id: 'market.activity',
    version: 1,
    metric: 10,
    title: 'Marketplace activity',
    numerator: 'distinct subject_key with at least one listing_sold',
    denominator: 'distinct active subject_key (see active.definition)',
    window: '7d and 30d',
  }),
  Object.freeze({
    id: 'revenue.shape',
    version: 1,
    metric: 15,
    title: 'Revenue shape',
    numerator: 'ledger_entry_posted counted by amount_bucket, never summed',
    denominator: 'none; this is a distribution',
    window: 'daily. ACTUAL REVENUE COMES FROM THE LEDGER, NEVER FROM HERE (13:630)',
  }),
  Object.freeze({
    id: 'onboarding.funnel',
    version: 1,
    metric: 17,
    title: 'Onboarding funnel',
    numerator: 'subjects reaching each step at or after the previous step',
    denominator: 'subjects at the previous step',
    window: '30d cohort; every step suppressed independently',
  }),
  Object.freeze({
    id: 'cohort.retention',
    version: 1,
    metric: 18,
    title: 'Cohort retention',
    numerator: 'distinct subject_key with a non-authentication event in week N',
    denominator: 'distinct subject_key whose first user_registered fell in the cohort week',
    window: '12 weeks; both numerator and denominator suppressed',
  }),
  Object.freeze({
    id: 'form.abandonment',
    version: 1,
    metric: 19,
    title: 'Form abandonment',
    numerator: 'distinct subject_key with form_abandoned, by form_id',
    denominator: 'distinct subject_key with form_started, by the same form_id',
    window: 'session',
  }),
  Object.freeze({
    id: 'active.definition',
    version: 1,
    metric: 16,
    title: 'Active subject',
    numerator: 'distinct subject_key with at least one non-authentication event',
    denominator: 'none; this is the denominator others use',
    window: 'the caller’s window. Authentication events are session_started, user_registered, device_added, mfa_removed (13:610)',
  }),
])

/**
 * The checksum a published definition is pinned by.
 *
 * Over the three fields that decide what the number MEANS, and nothing else. The title may be
 * reworded and the citation corrected without breaking a series; the numerator, denominator or
 * window may not change at all without a new version, which is exactly the line 13:637 draws.
 */
export function checksumOf(definition: MetricDefinition): string {
  return createHash('sha256')
    .update(
      JSON.stringify({
        numerator: definition.numerator,
        denominator: definition.denominator,
        window: definition.window,
      }),
    )
    .digest('hex')
}

export class DefinitionChangedError extends Error {
  readonly id: string
  readonly version: number
  constructor(id: string, version: number) {
    super(
      `metric definition ${id} v${version} was published with different text — ` +
        'publish a new version; a redefinition never edits an existing series',
    )
    this.name = 'DefinitionChangedError'
    this.id = id
    this.version = version
  }
}

export interface PublishResult {
  readonly published: readonly string[]
  readonly alreadyPublished: readonly string[]
}

/**
 * Publish the catalogue. Idempotent, and loud about the one case that must never be idempotent.
 *
 * Run at boot and by `POST /definitions`. A version already stored with the same checksum is left
 * alone; a version already stored with a DIFFERENT checksum throws, because the alternative is a
 * chart whose February and March were computed by different arithmetic under one label.
 */
export async function publish(
  sql: Db | Tx,
  definitions: readonly MetricDefinition[] = DEFINITIONS,
): Promise<PublishResult> {
  const published: string[] = []
  const alreadyPublished: string[] = []

  for (const definition of definitions) {
    const checksum = checksumOf(definition)
    const rows = await sql<{ checksum: string; inserted: boolean }[]>`
      insert into metric_definitions (id, version, title, numerator, denominator, window_spec, supersedes, checksum)
      values (
        ${definition.id}, ${definition.version}, ${definition.title},
        ${definition.numerator}, ${definition.denominator}, ${definition.window},
        ${definition.supersedes ?? null}, ${checksum}
      )
      on conflict (id, version) do nothing
      returning checksum, true as inserted
    `
    if (rows.length > 0) {
      published.push(`${definition.id}@${definition.version}`)
      continue
    }
    // No row means the conflict path. Read what is actually stored and compare — an `on conflict
    // do update` here would have QUIETLY REWRITTEN the definition, which is the failure mode this
    // whole table exists to prevent.
    const existing = await sql<{ checksum: string }[]>`
      select checksum from metric_definitions where id = ${definition.id} and version = ${definition.version}
    `
    if (existing[0]?.checksum !== checksum) {
      throw new DefinitionChangedError(definition.id, definition.version)
    }
    alreadyPublished.push(`${definition.id}@${definition.version}`)
  }

  return { published, alreadyPublished }
}

export interface StoredDefinition {
  readonly id: string
  readonly version: number
  readonly title: string
  readonly numerator: string
  readonly denominator: string
  readonly window: string
  readonly supersedes: string | null
  readonly checksum: string
  readonly publishedAt: string
}

/** The changelog. Every version ever published, newest first — 13-operational-model.md:636. */
export async function listDefinitions(sql: Db): Promise<readonly StoredDefinition[]> {
  const rows = await sql<
    {
      id: string
      version: number
      title: string
      numerator: string
      denominator: string
      window_spec: string
      supersedes: string | null
      checksum: string
      published_at: Date
    }[]
  >`
    select id, version, title, numerator, denominator, window_spec, supersedes, checksum, published_at
      from metric_definitions
     order by id, version desc
  `
  return rows.map((row) => ({
    id: row.id,
    version: Number(row.version),
    title: row.title,
    numerator: row.numerator,
    denominator: row.denominator,
    window: row.window_spec,
    supersedes: row.supersedes,
    checksum: row.checksum,
    publishedAt: row.published_at.toISOString(),
  }))
}
