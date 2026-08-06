/**
 * Ingest: the only way a row is ever created, and the only place a raw identifier exists.
 *
 * AD-21: **product analytics is a service fed by the event bus, not a page tag.** There is no
 * `POST /events` on this service and there will not be one — a page tag is a write path that
 * bypasses the pepper, the allowlist and the signature at once, and
 * `org/.github/workflows/web-ci.yml` already fails any frontend that ships a Google, Segment,
 * Hotjar or Mixpanel tag. That rule is only defensible because this file exists.
 *
 * ## One check, and why it is the right one
 *
 * A service token would say **who is calling**. The delivery signature says **these exact bytes
 * were produced by something holding the estate's outbox signing secret**. Neither implies the
 * other — but only one of them is obtainable by the caller this route exists to serve.
 *
 * This route used to demand both. That made it undeliverable: an outbox relay is a background job
 * driven by a Postgres poll, it sends the signature and the event id and nothing else, and it has
 * no way to mint a bearer. Demanding one meant the event bus was refused by the route built to
 * receive it, and the funnel denominators stayed empty behind a healthy-looking service. The MAC
 * is now the whole of the authentication, which is the same repair `micro-notify` and
 * `micro-activity` made. `server.ts`'s `/ingest` route carries the full argument.
 *
 * The signature is verified over the raw request bytes before anything parses them — the ordering
 * is the point, since a parser is an attack surface reachable by anyone who can open a socket, and
 * with the bearer gone it is the ONLY thing in front of that parser.
 *
 * `verifyDelivery` comes from `@cloudsforge/contracts-events` and is not reimplemented here.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE RAW SUBJECT LIVES INSIDE ONE FUNCTION AND LEAVES AS A PSEUDONYM.**
 *
 * `record()` below is the only place in this repository that holds a `user:<uuid>`. It hands it to
 * `deriveSubject`, receives a 64-character digest, and everything downstream — the insert, the
 * rollups, the funnels, the response, the logs — sees only that. The database refuses a row that
 * holds anything else (`events_subject_shape`), so this is enforced twice: once by the shape of
 * the code and once by a constraint that does not care what the code does.
 *
 * Note the ORDER inside the transaction. The inbox claim comes first, so a redelivery is dropped
 * before any work; the pseudonym is resolved next, so an erased subject is refused before an event
 * about them is written; the insert is last. All three commit together, so a handler that throws
 * leaves no inbox row and the redelivery is processed rather than swallowed — the mistake that
 * makes a naive "record then handle" dedupe lose events. AD-10.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * ## An unknown topic is refused, not quarantined — and that differs from `activity` on purpose
 *
 * `activity/src/ingest.ts` quarantines an unregistered topic **with its payload**, so it can
 * be reclassified later from data that was never thrown away. That is right for a narrative feed
 * and wrong here: an unclassified payload is an arbitrary producer-controlled object that never
 * passed the property allowlist, and keeping it would be exactly the hole the allowlist closes. So
 * the topic name is counted, the payload is dropped, and the inbox row is the acknowledgement.
 */

import {
  DELIVERY_TOLERANCE_MS,
  isValidTopicName,
  parseActor,
  validateEnvelope,
  verifyDelivery,
  type DeliveryFailure,
  type EventEnvelope,
} from '@cloudsforge/contracts-events'
import type { Logger, Metrics } from '@cloudsforge/telemetry'
import { ERASURE_TOPIC, eventFor } from './catalogue.ts'
import { sanitise, tally, type RejectionReason } from './properties.ts'
import { deriveSubject, eraseSubject, rawSubject, type PepperRing } from './pseudonym.ts'
import { countRejections, insertEvent, type Db, type SubjectKind } from './store.ts'

export class DeliverySignatureError extends Error {
  readonly reason: DeliveryFailure | 'missing'
  constructor(reason: DeliveryFailure | 'missing') {
    super(`the delivery signature was refused: ${reason}`)
    this.name = 'DeliverySignatureError'
    this.reason = reason
  }
}

export class MalformedEventError extends Error {
  readonly errors: readonly string[]
  constructor(errors: readonly string[]) {
    super(`the delivered body is not an event envelope: ${errors.join('; ')}`)
    this.name = 'MalformedEventError'
    this.errors = errors
  }
}

export interface IngestDeps {
  readonly sql: Db
  readonly logger: Logger
  readonly metrics: Metrics
  /** Delivery-signature secrets, newest first. A list, so a rotation is a window. */
  readonly secrets: readonly string[]
  /**
   * The peppers, newest first on lookup. Never logged, never stored, never returned.
   *
   * A ring rather than one value since #189: a rotation must not orphan the mappings the old pepper
   * minted, because erasure reaches them through exactly this object.
   */
  readonly peppers: PepperRing
  readonly toleranceMs?: number
  /** A seam, so the lag histogram and the freshness window can both be tested. */
  readonly now?: () => number
}

/**
 * Verify the signature over the raw bytes.
 *
 * The body is passed as the exact string that arrived, not a re-serialisation of a parsed object:
 * `JSON.stringify(JSON.parse(body))` differs from `body` on key order, whitespace and number
 * formatting, and any of those would make a valid signature fail — or, far worse, make an
 * implementation drift towards verifying something other than what it acted on.
 */
export function verifySignature(deps: IngestDeps, rawBody: string, header: string | undefined): void {
  if (!header) throw new DeliverySignatureError('missing')
  const verification = verifyDelivery(rawBody, header, deps.secrets, {
    now: deps.now?.() ?? Date.now(),
    toleranceMs: deps.toleranceMs ?? DELIVERY_TOLERANCE_MS,
  })
  if (!verification.ok) throw new DeliverySignatureError(verification.reason)
  if (verification.keyIndex > 0) {
    // Non-zero means the endpoint is still accepting a rotated-out key. Worth knowing about: a
    // rotation that is never finished is a secret that is never actually retired.
    deps.logger.warn('delivery verified against a rotated-out secret', { keyIndex: verification.keyIndex })
  }
}

export interface ParsedDelivery {
  readonly envelope: EventEnvelope
  /** False when the topic is well-formed but this build's contracts registry has never heard of it. */
  readonly registered: boolean
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/

/**
 * Parse a delivered body into an envelope.
 *
 * For a registered topic this is `validateEnvelope` from contracts-events and nothing else — the
 * envelope contract is owned there and is never restated here.
 *
 * For an unregistered one, `validateEnvelope` would reject the whole event over the topic alone,
 * and four topics this service must read are unregistered by necessity rather than by mistake:
 * AD-21 requires `page_viewed`, `cta_clicked` and `form_abandoned` (plus the `form_started` that
 * metric 19's denominator needs) to arrive "through the same envelope", and `contracts-events`
 * registers no topic for any of them. Reported, not fixed: this repository does not edit a
 * sibling's contract package. The checks below are the minimum such a row needs, and the topic is
 * still required to be one this service's own catalogue names — an arbitrary unregistered topic
 * gets no more trust here than it would from `validateEnvelope`.
 */
export function parseDelivery(rawBody: string): ParsedDelivery {
  let parsed: unknown
  try {
    parsed = JSON.parse(rawBody)
  } catch (err) {
    throw new MalformedEventError([`not JSON (${err instanceof Error ? err.message : String(err)})`])
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new MalformedEventError(['expected a JSON object'])
  }
  const record = parsed as Record<string, unknown>
  const topic = record['topic']

  const validated = validateEnvelope(parsed)
  if (validated.ok) return { envelope: validated.value, registered: true }

  // Not registered. Accept it only if it is a topic this build's own catalogue forward-declares,
  // and only after the same structural checks contracts-events would have applied.
  if (typeof topic !== 'string' || !isValidTopicName(topic) || !eventFor(topic)) {
    throw new MalformedEventError(validated.errors)
  }

  const errors: string[] = []
  if (typeof record['id'] !== 'string' || !UUID.test(record['id'])) errors.push('id: expected a UUID')
  if (typeof record['key'] !== 'string' || record['key'] === '') errors.push('key: missing')
  const occurredAt = record['occurredAt']
  if (typeof occurredAt !== 'string' || Number.isNaN(Date.parse(occurredAt))) {
    errors.push('occurredAt: expected an ISO-8601 instant')
  }
  if (typeof record['producer'] !== 'string' || record['producer'] === '') errors.push('producer: missing')
  if (typeof record['actor'] !== 'string' || !parseActor(record['actor']).ok) errors.push('actor: missing or malformed')
  if (typeof record['correlationId'] !== 'string' || record['correlationId'] === '') {
    errors.push('correlationId: missing; a cross-service investigation stops here')
  }
  if (!('payload' in record)) errors.push('payload: missing')
  if (errors.length > 0) throw new MalformedEventError(errors)
  return { envelope: record as unknown as EventEnvelope, registered: false }
}

export type IngestOutcome =
  | {
      readonly status: 'recorded'
      readonly eventName: string
      /** Property keys the allowlist refused. Returned to the producer; never persisted. */
      readonly dropped: readonly string[]
      /** One per dropped key, for the counters. */
      readonly reasons: readonly RejectionReason[]
    }
  | { readonly status: 'duplicate' }
  | { readonly status: 'erased'; readonly alreadyErased: boolean }
  | { readonly status: 'refused'; readonly reason: RejectionReason }

/** Only the analytics envelope is ever read. See `properties.ts` for why. */
function analyticsEnvelopeOf(payload: unknown): unknown {
  if (typeof payload !== 'object' || payload === null || Array.isArray(payload)) return undefined
  return (payload as Record<string, unknown>)['analytics']
}

/**
 * The topic as it is allowed to appear in a primary key.
 *
 * A producer chooses its own topic string, and `ingest_rejections` is keyed on it — so an
 * unbounded topic is an unbounded number of rows that a caller controls. A topic this build knows
 * is bounded by the catalogue; anything else collapses to one label.
 */
function countableTopic(topic: string): string {
  return eventFor(topic) || topic === ERASURE_TOPIC ? topic : 'unregistered'
}

/**
 * Record one event, exactly once.
 *
 * Every branch that does not write an event still claims the inbox row, deliberately. A refusal is
 * a decision, not a failure: answering anything that makes the relay retry would turn one
 * misconfigured producer into an infinite redelivery loop against the service that is refusing it.
 */
export async function ingest(deps: IngestDeps, delivery: ParsedDelivery): Promise<IngestOutcome> {
  const { envelope } = delivery
  const receivedAt = deps.now?.() ?? Date.now()
  const day = new Date(receivedAt).toISOString().slice(0, 10)
  const topicLabel = countableTopic(envelope.topic)

  const outcome = await deps.sql.begin(async (tx) => {
    const claimed = await tx<{ event_id: string }[]>`
      insert into inbox (topic, event_id) values (${envelope.topic}, ${envelope.id})
      on conflict (topic, event_id) do nothing
      returning event_id
    `
    if (claimed.length === 0) return { result: { status: 'duplicate' } as IngestOutcome }

    /**
     * Erasure, and why it writes no event.
     *
     * The topic registry calls `identity.user.deleted` "FIRST. Erasure. Every service holding
     * user_id must acknowledge within the SLA". This service holds no user_id — but it holds a
     * mapping FROM one, and that mapping is the whole of what makes four hundred days of
     * behaviour attributable to a person. `eraseSubject` destroys the salt, which is the only
     * irreversible operation in this design; after it the events identify nobody, including to us.
     * Writing an "erased" event would leave a row about the person who asked to be forgotten,
     * which is the thing being asked for. The inbox row is the acknowledgement.
     */
    if (envelope.topic === ERASURE_TOPIC) {
      // ══════════════════════════════════════════════════════════════════════════════════════
      // **THE SUBJECT IS `payload.userId`. IT WAS `envelope.actor`, WHICH IS WHOEVER ASKED.**
      //
      // This read `subjectOf(envelope)`, and `subjectOf` returns `envelope.actor`. On every other
      // topic that is right — the actor is the person the event is about. On THIS topic it is the
      // principal who requested the deletion, and identity sets it from `input.actor`
      // (`identity/src/deletion.ts`), which is the deleted user only when the user deleted
      // themselves.
      //
      // So an operator-initiated or service-initiated deletion destroyed the OPERATOR's salt —
      // erasing a live colleague's four hundred days of behaviour — or, for a `service:` actor,
      // was refused as `missing_subject` while the account it named kept its pseudonym and stayed
      // fully attributable. Both are wrong, and one of them is data loss for somebody who never
      // asked for it.
      //
      // `payload.userId` is the authoritative statement of WHO WAS DELETED, and it is the only
      // field on this topic that means that. The `user:` prefix is added explicitly rather than
      // incidentally: `deriveSubject` keys every normal event on `envelope.actor`, which is spelled
      // `user:<uuid>`, so an erasure computed over a bare uuid would hash to a different lookup key
      // and tombstone a subject that has no events while leaving the real one untouched.
      // ══════════════════════════════════════════════════════════════════════════════════════
      const payload =
        typeof envelope.payload === 'object' && envelope.payload !== null
          ? (envelope.payload as Record<string, unknown>)
          : {}
      const named = typeof payload['userId'] === 'string' ? payload['userId'] : ''
      const userId = named.startsWith('user:') ? named.slice('user:'.length) : named
      if (!UUID.test(userId)) {
        await countRejections(tx, day, topicLabel, new Map([['missing_subject', 1] as const]))
        return { result: { status: 'refused', reason: 'missing_subject' } as IngestOutcome }
      }
      const erasure = await eraseSubject(tx, deps.peppers, rawSubject(`user:${userId}`), new Date(receivedAt))
      return { result: { status: 'erased', alreadyErased: erasure.alreadyErased } as IngestOutcome }
    }

    const spec = eventFor(envelope.topic)
    if (!spec) {
      await countRejections(tx, day, topicLabel, new Map([['unknown_topic', 1] as const]))
      return { result: { status: 'refused', reason: 'unknown_topic' } as IngestOutcome }
    }

    const clean = sanitise(analyticsEnvelopeOf(envelope.payload))
    const counts = new Map(tally(clean.reasons))

    // The subject the producer named, or failing that whoever caused the event. See
    // `Sanitised.subject` for why the envelope's own fields are not enough on their own.
    const named = clean.subject
      ? { subject: clean.subject, kind: clean.subject.startsWith('operator:') ? ('operator' as const) : ('user' as const) }
      : subjectOf(envelope)

    let subjectKey: string | null = null
    let subjectKind: SubjectKind = 'system'

    if (named) {
      const derived = await deriveSubject(tx, deps.peppers, rawSubject(named.subject), new Date(envelope.occurredAt))
      if (derived.status === 'erased') {
        // A late event for somebody who asked to be forgotten. Minting a fresh pseudonym would
        // start a second behavioural profile for them, which is the opposite of what was asked.
        counts.set('erased_subject', (counts.get('erased_subject') ?? 0) + 1)
        await countRejections(tx, day, topicLabel, counts)
        return { result: { status: 'refused', reason: 'erased_subject' } as IngestOutcome }
      }
      subjectKey = derived.subjectKey
      subjectKind = named.kind
    } else if (spec.personal) {
      counts.set('missing_subject', (counts.get('missing_subject') ?? 0) + 1)
      await countRejections(tx, day, topicLabel, counts)
      return { result: { status: 'refused', reason: 'missing_subject' } as IngestOutcome }
    } else {
      subjectKind = parseActorKind(envelope.actor)
    }

    if (counts.size > 0) await countRejections(tx, day, topicLabel, counts)

    const stored = await insertEvent(tx, {
      subjectKey,
      subjectKind,
      eventName: spec.name,
      occurredAt: envelope.occurredAt,
      // Pseudonymised with the same pepper under its own domain string, so a browser session id
      // that leaks anywhere else in the estate cannot be used to select rows here.
      session: clean.sessionId ? deps.peppers.sessionKeyFor(clean.sessionId) : null,
      props: clean.props,
      sourceEventId: envelope.id,
      sourceTopic: envelope.topic,
      producer: envelope.producer,
    })
    // Null means `events_source_uniq` refused it: the same event id under a different topic. A
    // producer bug, but the answer is still "we already have it".
    if (!stored) return { result: { status: 'duplicate' } as IngestOutcome }

    return {
      result: {
        status: 'recorded',
        eventName: spec.name,
        dropped: clean.dropped,
        reasons: clean.reasons,
      } as IngestOutcome,
    }
  })

  const result = outcome.result

  if (result.status === 'duplicate') {
    // Expected under at-least-once delivery, so it is counted rather than logged at a level that
    // wakes anybody. A rate that climbs means a producer is not marking deliveries as delivered.
    deps.metrics.increment('analytics_duplicates_dropped_total')
    return result
  }

  if (result.status === 'refused') {
    deps.metrics.increment('analytics_rejections_total', { reason: result.reason })
    // The topic, never the offending property name — see properties.ts. A producer learns the
    // names from the response to its own delivery.
    deps.logger.warn('an event was refused', { topic: envelope.topic, reason: result.reason })
    return result
  }

  if (result.status === 'erased') {
    deps.logger.info('a subject was erased', {
      alreadyErased: result.alreadyErased,
      correlationId: envelope.correlationId,
    })
    deps.metrics.increment('analytics_erasures_total')
    return result
  }

  // How far behind the fact this service is. Measured from `occurredAt` — when the thing
  // happened — rather than from when the relay sent it, because a relay stuck for an hour is
  // exactly the outage this metric exists to show.
  const lagSeconds = Math.max(0, (receivedAt - Date.parse(envelope.occurredAt)) / 1_000)
  deps.metrics.observe('analytics_ingest_lag_seconds', lagSeconds, { producer: envelope.producer })
  deps.metrics.increment('analytics_events_total', { event: result.eventName })
  for (const reason of result.reasons) deps.metrics.increment('analytics_rejections_total', { reason })

  return result
}

/** The envelope's own actor, when it names a person. */
function subjectOf(envelope: EventEnvelope): { subject: string; kind: 'user' | 'operator' } | null {
  const parsed = parseActor(envelope.actor)
  if (!parsed.ok) return null
  if (parsed.value.kind !== 'user' && parsed.value.kind !== 'operator') return null
  if (parsed.value.id === null) return null
  return { subject: envelope.actor, kind: parsed.value.kind }
}

function parseActorKind(actor: string): SubjectKind {
  const parsed = parseActor(actor)
  return parsed.ok ? parsed.value.kind : 'system'
}
