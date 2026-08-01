/**
 * Writing the event store, and counting what was refused.
 *
 * Small on purpose. Everything that decides *what* may be written lives in `catalogue.ts`,
 * `properties.ts` and `pseudonym.ts`; this file is the two statements that do it, and it takes a
 * transaction so the inbox claim, the pseudonym upsert and the event insert commit together.
 */

import type { Sql, TransactionSql } from 'postgres'
import type { PropertyValue, RejectionReason } from './properties.ts'

export type Db = Sql
export type Tx = TransactionSql

/** The kinds `events.subject_kind` accepts. Mirrors `Actor` in `@cloudsforge/contracts-events`. */
export type SubjectKind = 'user' | 'operator' | 'service' | 'system'

/** Which kinds are people, and therefore must carry a pseudonym. Mirrors `events_person_has_pseudonym`. */
export const PERSON_KINDS: ReadonlySet<SubjectKind> = new Set<SubjectKind>(['user', 'operator'])

export interface NewEvent {
  /** The pseudonym, or null for a machine subject. Never a raw subject — the column refuses one. */
  readonly subjectKey: string | null
  readonly subjectKind: SubjectKind
  readonly eventName: string
  readonly occurredAt: string
  /** Already pseudonymised by the caller. Null when the producer sent no session. */
  readonly session: string | null
  readonly props: Readonly<Record<string, PropertyValue>>
  readonly sourceEventId: string
  readonly sourceTopic: string
  readonly producer: string
}

export interface StoredEvent {
  readonly id: string
  readonly eventName: string
  readonly occurredAt: string
}

/**
 * Insert one event.
 *
 * `on conflict (source_event_id) do nothing` and a null return rather than a thrown 23505: the
 * only way to reach it is the same event id arriving under a different topic, which is a producer
 * bug — but the honest answer is still "we already have it", not a 500 that makes the relay retry
 * for ever. Same reasoning as `activity/src/ingest.ts:204-205`.
 */
export async function insertEvent(tx: Tx, event: NewEvent): Promise<StoredEvent | null> {
  const rows = await tx<{ id: string; event_name: string; occurred_at: Date }[]>`
    insert into events (
      subject_key, subject_kind, event_name, occurred_at, session, props,
      source_event_id, source_topic, producer
    ) values (
      ${event.subjectKey},
      ${event.subjectKind},
      ${event.eventName},
      ${event.occurredAt},
      ${event.session},
      ${tx.json(event.props as Record<string, never>)},
      ${event.sourceEventId},
      ${event.sourceTopic},
      ${event.producer}
    )
    on conflict (source_event_id) do nothing
    returning id, event_name, occurred_at
  `
  const row = rows[0]
  if (!row) return null
  return { id: String(row.id), eventName: row.event_name, occurredAt: row.occurred_at.toISOString() }
}

/**
 * Record refusals, by day, reason and topic.
 *
 * The topic is narrowed to `unregistered` by the caller when it is not one this build knows, so an
 * attacker cannot mint unbounded primary keys by inventing topic names. Counts, never the offending
 * property name — see `properties.ts`.
 */
export async function countRejections(
  tx: Tx,
  day: string,
  topic: string,
  counts: ReadonlyMap<RejectionReason, number>,
): Promise<void> {
  for (const [reason, count] of counts) {
    await tx`
      insert into ingest_rejections (day, reason, source_topic, rejections)
      values (${day}, ${reason}, ${topic}, ${count})
      on conflict (day, reason, source_topic)
        do update set rejections = ingest_rejections.rejections + ${count}
    `
  }
}

export interface RejectionRow {
  readonly day: string
  readonly reason: string
  readonly topic: string
  readonly rejections: number
}

/** The refusal backlog. Read by `/metrics` and by an operator asking which producer is misbehaving. */
export async function listRejections(sql: Db, sinceDays: number): Promise<readonly RejectionRow[]> {
  const rows = await sql<{ day: Date; reason: string; source_topic: string; rejections: string }[]>`
    select day, reason, source_topic, rejections
      from ingest_rejections
     where day >= (current_date - make_interval(days => ${sinceDays}))
     order by day desc, reason, source_topic
  `
  return rows.map((row) => ({
    day: row.day.toISOString().slice(0, 10),
    reason: row.reason,
    topic: row.source_topic,
    rejections: Number(row.rejections),
  }))
}
