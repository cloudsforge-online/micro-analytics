/**
 * What this service is allowed to know.
 *
 * Two allowlists, and they are the whole privacy design at the ingest boundary:
 *
 *   1. **`EVENTS`** — which bus topics become which analytics event names. A topic that is not
 *      here produces no row at all.
 *   2. **`PROPERTIES`** — the only property names an event may carry, each with a *type*, and
 *      every type is closed. There is no `string` type. A property is an enum member, a short
 *      code, a bounded integer or a boolean, and nothing else.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THERE IS NO FREE-TEXT PROPERTY TYPE, AND THAT IS THE POINT.**
 *
 * A display name, a listing title, a search query or a chat line in an analytics payload is two
 * separate failures at once. It is a re-identification vector — "the user whose listing is called
 * *Spiros's 1994 Corolla*" is one person, whatever the subject column says — and it is a GDPR
 * erasure problem, because erasing the subject mapping does not erase a name written into a
 * property. 11-data-and-contract-strategy.md:509-515 requires the ingest path to REJECT such a
 * key "rather than dropping the key silently"; a producer that sends one is told, in the response
 * to its own signed delivery, exactly which properties were refused.
 *
 * Closing the type system is what makes that structural rather than a review habit. A `string`
 * type with a length cap would still accept `"Spiros Savvanis"`; an enum whose members are listed
 * below cannot. `code` exists for the genuinely bounded machine identifiers — an asset code, a
 * chain name — and its pattern is short enough and narrow enough that no name, email or chain
 * address fits through it.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Money is a special case, stated twice in the estate and enforced here: amounts arrive
 * **bucketed** (`amount_bucket`), never exact. 13-operational-model.md:598-600 fixes the buckets
 * at `<10, 10–100, 100–1k, 1k–10k, >10k` USD-equivalent, and 11:512 forbids an `amount` column
 * outright. Actual revenue comes from the ledger — 13-operational-model.md:630 — never from here.
 */

/* ------------------------------------------------------------------ property types */

export interface EnumProperty {
  readonly type: 'enum'
  readonly values: readonly string[]
  readonly why: string
}

export interface CodeProperty {
  readonly type: 'code'
  readonly why: string
}

export interface IntProperty {
  readonly type: 'int'
  readonly min: number
  readonly max: number
  readonly why: string
}

export interface BoolProperty {
  readonly type: 'bool'
  readonly why: string
}

export type PropertySpec = EnumProperty | CodeProperty | IntProperty | BoolProperty

/**
 * A machine identifier: lowercase, twelve characters at the outside.
 *
 * Deliberately too short for a name (`spirossavva` is already eleven and truncating a person's
 * name is not a defence), far too short for an email, and far too short for any chain address —
 * the shortest in the estate is a 42-character 0x address. It admits `usdc`, `ember`, `mainnet`,
 * `pro`, and nothing a person typed about themselves.
 */
export const CODE_PATTERN = /^[a-z0-9][a-z0-9_-]{0,11}$/

/**
 * The shape any string value must have once it is in the store.
 *
 * Rendered into a database CHECK by `migrations.ts`, so the guarantee survives a code path that
 * has not been written yet. A space, a capital letter, an `@` and every other character a human
 * sentence needs are all outside it: `"Spiros Savvanis"`, `"a@b.com"` and `"1994 Corolla — must
 * go!"` are each refused by the database itself.
 */
export const VALUE_PATTERN = '^[a-z0-9][a-z0-9_.:/-]{0,31}$'

/** At most this many properties on one event. A wide event is a fingerprint. */
export const MAX_PROPERTIES = 12

/**
 * The amount buckets, exactly as 13-operational-model.md:598-600 states them.
 *
 * USD-equivalent at event time, computed by the producer. This service never sees the number it
 * came from and could not reconstruct it: `100_1k` is nine hundred dollars wide.
 */
export const AMOUNT_BUCKETS = Object.freeze([
  'lt10',
  '10_100',
  '100_1k',
  '1k_10k',
  'gt10k',
] as const)

export type AmountBucket = (typeof AMOUNT_BUCKETS)[number]

/**
 * Bucket a USD-equivalent decimal string.
 *
 * Takes a **string**, and compares it as a decimal rather than as a float, because a producer
 * that has an exact decimal must not have to round-trip it through a double to ask which bucket
 * it is in. The answer is one of five words either way, so precision loss here would be invisible
 * and wrong rather than visible and wrong.
 */
export function bucketAmount(usd: string): AmountBucket | null {
  if (!/^-?\d+(\.\d+)?$/.test(usd)) return null
  const unsigned = usd.startsWith('-') ? usd.slice(1) : usd
  // Magnitude only: a refund of -50 lands in the same bucket as a payment of 50, because the
  // bucket describes size and the direction is the event name. Leading zeros are stripped so
  // "0009.99" is one digit wide, not four.
  const whole = (unsigned.split('.')[0] ?? '0').replace(/^0+(?=\d)/, '')
  switch (whole.length) {
    case 1:
      return 'lt10'
    case 2:
      return '10_100'
    case 3:
      return '100_1k'
    case 4:
      return '1k_10k'
    default:
      return 'gt10k'
  }
}

/* ------------------------------------------------------------------ the properties */

/**
 * Every property name an event may carry.
 *
 * Each entry states the metric in 13-operational-model.md §12 that needs it. A property with no
 * metric behind it is a property collected because it was available, which is the habit AD-21
 * exists to prevent.
 */
export const PROPERTIES: Readonly<Record<string, PropertySpec>> = Object.freeze({
  referrer_class: {
    type: 'enum',
    values: ['direct', 'search', 'social', 'referral', 'campaign', 'internal', 'unknown'],
    why: 'metric 1, acquisition by referrer class. A CLASS, never a URL: a referring URL carries the query a person typed.',
  },
  surface: {
    type: 'enum',
    values: [
      'landing',
      'register',
      'signin',
      'verify_email',
      'dashboard',
      'wallet',
      'deposit',
      'withdraw',
      'market',
      'listing',
      'mint',
      'trade',
      'worlds',
      'community',
      'devportal',
      'settings',
      'docs',
      'other',
    ],
    why: 'metrics 2 and 20. A NAMED surface, never a path: /u/spiros-savvanis is one person, and a path column is an unbounded re-identifier.',
  },
  form_id: {
    type: 'enum',
    values: ['register', 'signin', 'kyc', 'deposit', 'withdraw', 'listing_create', 'mint_order', 'bot_create'],
    why: 'metric 19, form abandonment — form_abandoned over form_started per form id.',
  },
  cta_id: {
    type: 'enum',
    values: ['register', 'signin', 'deposit', 'create_token', 'browse_market', 'start_bot', 'join_community', 'read_docs'],
    why: 'metric 2 and metric 20, the click that begins a funnel.',
  },
  product: {
    type: 'enum',
    values: [
      'identity',
      'wallet',
      'ledger',
      'billing',
      'market',
      'mint',
      'trade',
      'worlds',
      'nda',
      'community',
      'studio',
      'devplatform',
      'custody',
      'settlement',
    ],
    why: 'metric 16, cross-product usage — users active in two or more product groups.',
  },
  step: {
    type: 'enum',
    values: [
      'registered',
      'email_verified',
      'wallet_activated',
      'deposit_confirmed',
      'first_conversion',
      'first_product_action',
      'order_created',
      'deploy_submitted',
      'deploy_confirmed',
    ],
    why: 'metrics 9 and 17, the ordinal funnels. The step vocabulary is closed so a funnel cannot silently gain a step.',
  },
  outcome: {
    type: 'enum',
    values: ['succeeded', 'failed', 'cancelled', 'expired', 'refunded', 'stuck'],
    why: 'metric 9 and metric 15 — a funnel step that failed is not a step that did not happen.',
  },
  amount_bucket: {
    type: 'enum',
    values: [...AMOUNT_BUCKETS],
    why: 'metric 15, revenue SHAPE. 13-operational-model.md:598 — money appears only as a bucketed range, and the real number comes from the ledger.',
  },
  duration_bucket: {
    type: 'enum',
    values: ['lt1h', '1h_24h', '1d_7d', '7d_30d', 'gt30d'],
    why: 'metric 6, time to first deposit. A bucket rather than a duration, because an exact millisecond gap between two events is close to a unique key.',
  },
  asset_code: {
    type: 'code',
    why: 'metrics 5 and 15. Bounded by the pricing catalogue and personal to nobody; twelve characters admits EMBER and USDC and no address.',
  },
  chain: {
    type: 'code',
    why: 'metrics 5 and 15, deposits and settlements by network.',
  },
  plan: {
    type: 'code',
    why: 'metric 14 and 15, which paid tier an entitlement belongs to.',
  },
  attempt: {
    type: 'int',
    min: 1,
    max: 100,
    why: 'metric 9, per-attempt funnels — the second try at a token deploy is not the first.',
  },
  day_offset: {
    type: 'int',
    min: 0,
    max: 400,
    why: 'metric 12, D1/D7/D30 game retention, measured from the cohort day.',
  },
  is_first: {
    type: 'bool',
    why: 'metrics 3, 4, 5 and 8 — every one of them is "users with at least one", which needs the first occurrence marked.',
  },
} as const)

export type PropertyName = keyof typeof PROPERTIES

export const PROPERTY_NAMES: readonly string[] = Object.freeze(Object.keys(PROPERTIES).sort())

export function isAllowedProperty(name: string): name is PropertyName {
  return Object.hasOwn(PROPERTIES, name)
}

/* ------------------------------------------------------------------ the events */

export interface EventSpec {
  /** The analytics event name, as it appears in the store and in every metric definition. */
  readonly name: string
  /**
   * True when this event is ABOUT a person and is worthless without one.
   *
   * It is not the same question as "who caused it". `wallet.deposit.confirmed` is caused by a
   * chain confirmation and is very much about a user; `ledger.reconciliation.completed` is caused
   * by a job and is about the estate. A `personal` event that arrives with no resolvable subject
   * is refused and counted rather than stored, because storing it would make a rollup say "ten
   * deposits, zero users" — a number that is wrong in the direction that makes a funnel look
   * healthier than it is.
   */
  readonly personal: boolean
  /**
   * False when the topic is not in this build's `@cloudsforge/contracts-events` registry.
   *
   * Four of them are: AD-21 requires the three explicit UI events, and 13-operational-model.md:590
   * says frontends emit them "through the same envelope". `contracts-events` registers no topic
   * for any of them (`contracts/packages/events/src/index.ts:222-349` — eighteen topics, all
   * server-side), so they are forward-declared here rather than dropped. Reported, not fixed: this
   * repository does not edit a sibling's contract package.
   */
  readonly registered: boolean
  readonly why: string
}

/**
 * Bus topic → analytics event. The only mapping there is.
 *
 * A topic absent from this table is refused and counted, never quarantined with its payload the
 * way `activity` quarantines an unknown topic. The difference is deliberate and it is a privacy
 * difference: activity's quarantine keeps the payload so the record can be reclassified later,
 * and an unclassified payload here would be an arbitrary producer-controlled object that never
 * passed the property allowlist. Keeping it would be the exact hole the allowlist exists to close.
 */
export const EVENTS: Readonly<Record<string, EventSpec>> = Object.freeze({
  'identity.user.registered': { name: 'user_registered', personal: true, registered: true, why: 'metric 2, the denominator of every onboarding cohort' },
  'identity.session.created': { name: 'session_started', personal: true, registered: true, why: 'metric 1 and the "active" definition in 13 §12' },
  'identity.device.added': { name: 'device_added', personal: true, registered: true, why: 'metric 20, feature adoption of the security surface' },
  'identity.mfa.removed': { name: 'mfa_removed', personal: true, registered: true, why: 'metric 20, adoption and abandonment of a second factor' },
  'ledger.entry.posted': { name: 'ledger_entry_posted', personal: true, registered: true, why: 'metric 7, first transaction. SHAPE only — actual revenue is the ledger (13:630)' },
  'ledger.reconciliation.completed': { name: 'reconciliation_completed', personal: false, registered: true, why: 'has no subject; kept because a reconciliation freeze explains a hole in every funnel that week' },
  'wallet.deposit.confirmed': { name: 'deposit_confirmed', personal: true, registered: true, why: 'metrics 5 and 6, first deposit and time to it' },
  'wallet.withdrawal.requested': { name: 'withdrawal_requested', personal: true, registered: true, why: 'metric 16, and the leading indicator of churn' },
  'settlement.withdrawal.completed': { name: 'withdrawal_completed', personal: true, registered: true, why: 'metric 16' },
  'settlement.withdrawal.stuck': { name: 'withdrawal_stuck', personal: true, registered: true, why: 'metric 9 outcome=stuck; a funnel that drops here is an incident, not a product problem' },
  'billing.entitlement.granted': { name: 'entitlement_granted', personal: true, registered: true, why: 'metrics 14 and 15' },
  'billing.entitlement.revoked': { name: 'entitlement_revoked', personal: true, registered: true, why: 'metric 15 — a refund that is not counted makes every conversion number optimistic' },
  'custody.export.requested': { name: 'key_export_requested', personal: true, registered: true, why: 'metric 16; self-custody is a product outcome, not a failure' },
  'custody.key.exported': { name: 'key_exported', personal: true, registered: true, why: 'metric 16' },
  'mint.deploy.confirmed': { name: 'token_deployed', personal: true, registered: true, why: 'metrics 8 and 9, token creation and its funnel' },
  'market.listing.sold': { name: 'listing_sold', personal: true, registered: true, why: 'metric 10, marketplace activity' },
  'community.proposal.executed': { name: 'proposal_executed', personal: true, registered: true, why: 'metric 13, community participation' },

  // AD-21's three explicit UI events, plus the `form_started` that metric 19's denominator needs.
  // Forward-declared: see EventSpec.registered.
  'web.page.viewed': { name: 'page_viewed', personal: true, registered: false, why: 'AD-21 and metric 1. Not in contracts-events; forward-declared, reported' },
  'web.cta.clicked': { name: 'cta_clicked', personal: true, registered: false, why: 'AD-21 and metric 2. Not in contracts-events; forward-declared, reported' },
  'web.form.started': { name: 'form_started', personal: true, registered: false, why: "metric 19's denominator. Not in contracts-events; forward-declared, reported" },
  'web.form.abandoned': { name: 'form_abandoned', personal: true, registered: false, why: 'AD-21 and metric 19. Not in contracts-events; forward-declared, reported' },
} as const)

/**
 * `identity.user.deleted` is deliberately absent from `EVENTS`.
 *
 * It is not an analytics event and it must never become a row: a row saying "this pseudonym was
 * erased" is a record about the person who asked to be forgotten. It is handled by `ingest.ts`,
 * which destroys the subject's salt, and the inbox row is the acknowledgement — the same shape
 * `activity/src/ingest.ts:186-189` uses, for the same reason.
 */
export const ERASURE_TOPIC = 'identity.user.deleted'

export const EVENT_TOPICS: readonly string[] = Object.freeze(Object.keys(EVENTS).sort())

/** Every analytics event name, sorted. Rendered into the store's CHECK constraint. */
export const EVENT_NAMES: readonly string[] = Object.freeze(
  [...new Set(Object.values(EVENTS).map((spec) => spec.name))].sort(),
)

export function eventFor(topic: string): EventSpec | undefined {
  return Object.hasOwn(EVENTS, topic) ? EVENTS[topic] : undefined
}

/* ------------------------------------------------------------------ funnels */

export interface FunnelSpec {
  readonly id: string
  readonly steps: readonly string[]
  readonly why: string
}

/**
 * The named funnels. A funnel is a fixed, reviewed sequence of event names, never a sequence a
 * caller supplies: an arbitrary step list is a query language, and a query language over a
 * behavioural store is how a "which three events did this one person do" question gets asked.
 */
export const FUNNELS: readonly FunnelSpec[] = Object.freeze([
  Object.freeze({
    id: 'onboarding',
    steps: Object.freeze(['user_registered', 'session_started', 'deposit_confirmed', 'ledger_entry_posted']),
    why: 'metric 17, register → verify → wallet → deposit → first conversion, in the events this estate actually emits',
  }),
  Object.freeze({
    id: 'token_creation',
    steps: Object.freeze(['session_started', 'token_deployed']),
    why: 'metric 9. The order/submit steps arrive when mint gains those topics; see the README',
  }),
  Object.freeze({
    id: 'acquisition',
    steps: Object.freeze(['page_viewed', 'cta_clicked', 'user_registered']),
    why: 'metrics 1 and 2, the only funnel whose first step is a UI event',
  }),
])

export function funnelFor(id: string): FunnelSpec | undefined {
  return FUNNELS.find((funnel) => funnel.id === id)
}
