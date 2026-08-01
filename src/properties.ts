/**
 * The property boundary. Nothing a person typed gets past this file.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THIS SERVICE NEVER READS A PRODUCER'S DOMAIN PAYLOAD.**
 *
 * That is the single most important sentence in this repository after the one about the pepper.
 *
 * `wallet.deposit.confirmed` carries an address and an exact amount. `market.listing.sold` carries
 * a listing title a seller typed. `identity.user.registered` carries a handle. Every one of those
 * is in the envelope this service receives, and not one of them is ever looked at: `sanitise`
 * reads `payload.analytics` — the **analytics envelope**, the object a producer opts in to sending
 * — and nothing else in the payload exists as far as this service is concerned.
 *
 * The alternative design, mapping each topic's domain payload onto analytics properties, would put
 * a per-topic function in front of a listing title and rely on that function to be careful. Twenty
 * producers, eighteen topics and a changelog later, one of those functions passes a name through.
 * 16-risks-and-open-decisions.md:75 names the review trigger as "any PR adding a field to the
 * analytics envelope", which is a trigger that only means something if the envelope is a real,
 * separate, opt-in object — so it is one.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * Within the analytics envelope, every key must be in `PROPERTIES` and every value must satisfy
 * its declared type. A key that is not, or a value that does not, is **dropped and counted** —
 * 11-data-and-contract-strategy.md:515: "the ingest path rejects an event carrying any of those
 * keys rather than dropping the key silently". The producer is told which keys were refused in the
 * response to its own signed delivery; the database records a count by reason and topic and never
 * the key itself, because a key can be the personal data (`{"spiros_lives_at": 1}`) just as easily
 * as a value can.
 *
 * The event is still stored when a property is refused. Refusing the whole event would mean a
 * producer that added one field lost every funnel it feeds, which is the pressure that gets a
 * privacy guard turned off.
 */

import {
  CODE_PATTERN,
  MAX_PROPERTIES,
  PROPERTIES,
  isAllowedProperty,
  type PropertySpec,
} from './catalogue.ts'

/** The reasons a property or an event is refused. Must match `REJECTION_REASONS` in migrations. */
export type RejectionReason =
  | 'unknown_topic'
  | 'disallowed_property'
  | 'bad_property_value'
  | 'too_many_properties'
  | 'missing_subject'
  | 'erased_subject'

export type PropertyValue = string | number | boolean

export interface Sanitised {
  /** What will be stored. Every key allowlisted, every value type-checked. */
  readonly props: Readonly<Record<string, PropertyValue>>
  /**
   * The keys that were refused, in the order they appeared.
   *
   * Returned to the producer that sent them and **never persisted**. The producer already knows
   * these names — it chose them — so telling it costs nothing and is the only way it learns to
   * stop. See the header for why the database does not record them.
   */
  readonly dropped: readonly string[]
  /** One entry per refusal, for the counters. Same length as `dropped`. */
  readonly reasons: readonly RejectionReason[]
  /** The raw session identifier, if the producer sent one. Pseudonymised by the caller. */
  readonly sessionId: string | null
  /**
   * The raw subject this event is about — `user:<uuid>` or `operator:<id>` — if the producer named
   * one. **Pseudonymised by the caller and never stored.**
   *
   * It has to be here, and the reason is a gap in the shipped contract rather than a preference.
   * The envelope's `actor` is "who caused this" (`contracts/packages/events/src/index.ts:56-61`),
   * which for `wallet.deposit.confirmed` is a chain confirmation and not the depositor; and the
   * envelope's `key` is the ordering partition, which `TOPICS` sets to `wallet_id` for deposits,
   * `account_id` for ledger entries and `listing_id` for sales (`:276,262,338`). Neither field
   * identifies the person a funnel is about for eleven of the eighteen registered topics. The
   * producer knows, so it says — inside the analytics envelope, where it is reviewed.
   */
  readonly subject: string | null
}

/**
 * The keys of the analytics envelope that are not properties.
 *
 * Both are raw identifiers, and both are treated the same way: pseudonymised at the boundary, with
 * the raw value never reaching a column. Metrics 2 and 19 need to know that two events shared a
 * session; neither needs to know which session, and a browser session id that also appears in a
 * log or a support ticket would be a join key straight back to a person.
 */
const RESERVED_KEYS = new Set(['session_id', 'subject'])

function checkValue(spec: PropertySpec, value: unknown): value is PropertyValue {
  switch (spec.type) {
    case 'enum':
      return typeof value === 'string' && spec.values.includes(value)
    case 'code':
      return typeof value === 'string' && CODE_PATTERN.test(value)
    case 'int':
      // `Number.isInteger` rejects NaN, Infinity and 1.5 — all three of which a producer can send
      // and all three of which would otherwise reach a jsonb column as something no reader expects.
      return typeof value === 'number' && Number.isInteger(value) && value >= spec.min && value <= spec.max
    case 'bool':
      return typeof value === 'boolean'
  }
}

/**
 * Sanitise one analytics envelope.
 *
 * A missing or non-object envelope is not an error: most of the eighteen registered bus topics are
 * server-side facts whose producers have no analytics properties to add, and an event with no
 * properties still counts towards every "users with at least one …" metric in 13 §12.
 */
export function sanitise(analyticsEnvelope: unknown): Sanitised {
  const props: Record<string, PropertyValue> = {}
  const dropped: string[] = []
  const reasons: RejectionReason[] = []
  let sessionId: string | null = null
  let subject: string | null = null

  if (analyticsEnvelope === undefined || analyticsEnvelope === null) {
    return { props, dropped, reasons, sessionId, subject }
  }
  if (typeof analyticsEnvelope !== 'object' || Array.isArray(analyticsEnvelope)) {
    dropped.push('analytics')
    reasons.push('bad_property_value')
    return { props, dropped, reasons, sessionId, subject }
  }

  for (const [key, value] of Object.entries(analyticsEnvelope as Record<string, unknown>)) {
    if (RESERVED_KEYS.has(key)) {
      // Both are opaque to this service, so the only thing worth checking is that each is a
      // bounded string rather than an object with a name in it. `subject` is additionally required
      // to be an `Actor` — anything else is a producer sending a free-form identifier, which is
      // the shape a handle or an email arrives in.
      if (typeof value !== 'string' || value.length === 0 || value.length > 128) {
        dropped.push(key)
        reasons.push('bad_property_value')
      } else if (key === 'session_id') {
        sessionId = value
      } else if (/^(user|operator):.+$/.test(value)) {
        subject = value
      } else {
        dropped.push(key)
        reasons.push('bad_property_value')
      }
      continue
    }

    if (!isAllowedProperty(key)) {
      dropped.push(key)
      reasons.push('disallowed_property')
      continue
    }
    // Counted before the value is examined, so a twenty-property envelope is refused as a whole
    // rather than accepted up to twelve and then silently truncated in an order nobody chose.
    if (Object.keys(props).length >= MAX_PROPERTIES) {
      dropped.push(key)
      reasons.push('too_many_properties')
      continue
    }
    const spec = PROPERTIES[key]
    if (!spec || !checkValue(spec, value)) {
      dropped.push(key)
      reasons.push('bad_property_value')
      continue
    }
    props[key] = value
  }

  return { props, dropped, reasons, sessionId, subject }
}

/**
 * Fold a list of reasons into counts. What the rejection table is incremented by.
 *
 * Counts rather than rows: one malformed producer retrying a batch would otherwise write a row per
 * property per delivery, and a table that grows with an attacker's request rate is a table an
 * attacker controls.
 */
export function tally(reasons: readonly RejectionReason[]): ReadonlyMap<RejectionReason, number> {
  const counts = new Map<RejectionReason, number>()
  for (const reason of reasons) counts.set(reason, (counts.get(reason) ?? 0) + 1)
  return counts
}
