/**
 * Run a mutating operation at most once per key.
 *
 * **The shape is `market/src/idempotency.ts`'s**, which took it from the ledger, which took it from
 * `repos/forge-pay/services/pay/src/store.ts`. It is not reinvented here; it is inherited,
 * because the four properties below are the whole of the correctness and each is easy to lose
 * while writing something that looks equivalent:
 *
 *   1. **The claim INSERT and the work share ONE transaction.** The stored response can therefore
 *      never disagree with what actually committed.
 *   2. **A concurrent duplicate blocks rather than races.** The second INSERT waits on the first
 *      transaction's uncommitted row, then reads the stored response and replays it.
 *   3. **A reused key with a different body is refused, not replayed.** Returning the first
 *      request's answer to a second, different request is worse than an error: the caller believes
 *      the thing it asked for happened.
 *   4. **A claim with no response yet is "in flight", not "done".**
 *
 * `correlationId`, `requestId` and `idempotencyKey` are excluded from the fingerprint. That is the
 * ledger's recorded defect, pinned here in both directions by `idempotency.test.ts`: a correlation
 * id is SUPPOSED to change between attempts — it is what distinguishes a retry in a trace — so
 * fingerprinting it made every honest retry look like key reuse.
 */

import { createHash } from 'node:crypto'
import type { Db, Tx } from './store.ts'

/** The claim exists but its transaction has not committed a response yet. The caller retries. */
export class IdempotencyInFlightError extends Error {
  constructor() {
    super('a request with this idempotency key is still in flight; retry shortly')
    this.name = 'IdempotencyInFlightError'
  }
}

/** The same key was presented with a different body. 409, always. */
export class IdempotencyKeyReuseError extends Error {
  constructor() {
    super('this idempotency key was already used with a different request body')
    this.name = 'IdempotencyKeyReuseError'
  }
}

/** Fields that legitimately differ between attempts at the *same* operation. See the header. */
const PER_ATTEMPT_FIELDS = new Set(['correlationId', 'idempotencyKey', 'requestId'])

/**
 * A stable fingerprint of a request body.
 *
 * Keys are sorted at every depth before hashing. `JSON.stringify` preserves insertion order, so
 * two semantically identical bodies that serialised their fields in a different order would
 * fingerprint differently and a legitimate retry would be rejected as reuse.
 */
export function requestFingerprint(value: unknown): string {
  const subject =
    value !== null && typeof value === 'object' && !Array.isArray(value)
      ? Object.fromEntries(
          Object.entries(value as Record<string, unknown>).filter(([key]) => !PER_ATTEMPT_FIELDS.has(key)),
        )
      : value
  return createHash('sha256').update(canonicalise(subject)).digest('hex')
}

function canonicalise(value: unknown): string {
  if (value === null || value === undefined) return 'null'
  if (typeof value === 'bigint') return `"${value.toString()}"`
  if (typeof value !== 'object') return JSON.stringify(value) ?? 'null'
  if (Array.isArray(value)) return `[${value.map(canonicalise).join(',')}]`
  const entries = Object.entries(value as Record<string, unknown>)
    .filter(([, v]) => v !== undefined)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
  return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonicalise(v)}`).join(',')}}`
}

/**
 * The stored key, namespaced by the calling principal and the route.
 *
 * Keys are chosen by callers, and two callers independently choosing `recompute-2026-08-01` must
 * not collide. The route is in it because the same client key presented to two different routes
 * describes two different operations.
 */
export function namespacedKey(principal: string, route: string, clientKey: string): string {
  return `${principal}:${route}:${clientKey}`
}

export interface IdempotentOutcome<T> {
  readonly result: T
  readonly replayed: boolean
}

export interface IdempotencyInput<T> {
  readonly principal: string
  readonly route: string
  readonly clientKey: string
  readonly requestHash: string
  readonly run: (tx: Tx, storedKey: string) => Promise<{ response: T; artefactId: string | null }>
}

export async function withIdempotency<T>(sql: Db, input: IdempotencyInput<T>): Promise<IdempotentOutcome<T>> {
  const key = namespacedKey(input.principal, input.route, input.clientKey)

  const outcome = await sql.begin(async (tx) => {
    const claimed = await tx<{ key: string }[]>`
      insert into idempotency_keys (key, route, request_hash)
      values (${key}, ${input.route}, ${input.requestHash})
      on conflict (key) do nothing
      returning key
    `

    if (claimed.length === 0) {
      // Someone else holds the key. By the time this read runs, their transaction has either
      // committed (so the response is here) or rolled back (so the row is gone).
      const rows = await tx<{ request_hash: string; response: unknown }[]>`
        select request_hash, response from idempotency_keys where key = ${key}
      `
      const existing = rows[0]
      if (!existing) throw new IdempotencyInFlightError()
      if (existing.request_hash !== input.requestHash) throw new IdempotencyKeyReuseError()
      if (existing.response === null || existing.response === undefined) throw new IdempotencyInFlightError()
      return { value: { result: existing.response as T, replayed: true } }
    }

    const { response, artefactId } = await input.run(tx, key)

    await tx`
      update idempotency_keys
         set response = ${tx.json(response as Record<string, never>)}, artefact_id = ${artefactId}
       where key = ${key}
    `

    return { value: { result: response, replayed: false } }
  })

  // Wrapped in an object above so postgres.js does not treat an array-shaped result as a list of
  // promises to unwrap, which would rewrite the caller's return type.
  return outcome.value
}
