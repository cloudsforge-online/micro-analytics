/**
 * The analysis surface, and the threshold in front of it.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE POINT OF THIS FILE IS THAT A COHORT OF ONE IS THAT PERSON.**
 *
 * Everything else in this repository protects the STORE: the pepper, the salt, the property
 * allowlist and the four CHECK constraints. None of them protects the ANSWERS. "One user in the
 * 1k–10k bucket deposited on Tuesday" is a statement about one person, whatever the subject column
 * holds, and anybody who knows who registered on Tuesday has just read their behaviour.
 *
 * So every count that leaves `reads.ts` passes `suppress()`, and this file proves it in both
 * directions on every path — the daily series, the active count, each funnel step independently,
 * and both halves of a retention cell. Testing only that a small count is withheld would pass
 * against a function that withheld everything, so each case also plants a cohort at the threshold
 * and asserts the number IS returned. A suppression that suppresses everything is an outage, and an
 * outage is what gets a privacy guard switched off.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * The numbers are deliberately chosen around `minCohort = 5`: four is withheld, five is published,
 * and zero is published as zero. Zero is not a disclosure — "nobody did this" says nothing about
 * anybody — and suppressing it would make an empty funnel indistinguishable from a busy one, which
 * is precisely how an operator ends up lowering the threshold to find out which it was.
 */

import assert from 'node:assert/strict'
import { after, before, beforeEach, describe, it } from 'node:test'
import type postgres from 'postgres'
import { funnelFor } from './catalogue.ts'
import { rollupOnce, recomputeCohorts } from './jobs.ts'
import { deriveSubject, rawSubject } from './pseudonym.ts'
import {
  activeSubjects,
  dailySeries,
  funnel,
  funnelById,
  retentionGrid,
  storeSummary,
  suppress,
  type Count,
  type Window,
} from './reads.ts'
import { TEST_PEPPER, migrateTestDb, openDb, resetAnalytics, skip } from './testsupport.ts'

const DAY = 86_400_000
const MIN_COHORT = 5

/** A window wide enough to contain everything these cases plant, and narrower than retention. */
const WINDOW: Window = { from: new Date(Date.now() - 90 * DAY), to: new Date(Date.now() + DAY) }

describe('reads', { skip }, () => {
  let sql: postgres.Sql

  before(async () => {
    sql = openDb()
    await migrateTestDb(sql)
  })
  beforeEach(async () => {
    await resetAnalytics(sql)
  })
  after(async () => {
    await sql.end({ timeout: 5 })
  })

  /** Mint a real pseudonym. Never a hand-written digest: the store's CHECK is part of the test. */
  async function subjectKey(subject: string): Promise<string> {
    const derived = await deriveSubject(sql, TEST_PEPPER, rawSubject(subject), new Date())
    assert.equal(derived.status, 'ok')
    return derived.status === 'ok' ? derived.subjectKey : ''
  }

  async function plant(key: string | null, eventName: string, occurredAt: Date): Promise<void> {
    await sql`
      insert into events (subject_key, subject_kind, event_name, occurred_at, source_event_id, source_topic, producer)
      values (
        ${key}, ${key === null ? 'system' : 'user'}, ${eventName}, ${occurredAt},
        ${crypto.randomUUID()}, 'identity.user.registered', 'identity'
      )
    `
  }

  /** `count` distinct people each emitting `eventName` once, at `occurredAt`. */
  async function plantPeople(count: number, eventName: string, occurredAt: Date, prefix = 'p'): Promise<string[]> {
    const keys: string[] = []
    for (let i = 0; i < count; i += 1) {
      const key = await subjectKey(`user:${prefix}-${eventName}-${i}`)
      await plant(key, eventName, occurredAt)
      keys.push(key)
    }
    return keys
  }

  function subjectsOf(count: Count): number | 'suppressed' {
    return count.suppressed ? 'suppressed' : count.subjects
  }

  /* ================================================================ the primitive */

  describe('suppress() is the one place a count becomes publishable', () => {
    it('withholds every count from one up to the threshold', () => {
      for (let subjects = 1; subjects < MIN_COHORT; subjects += 1) {
        const count = suppress(subjects, subjects * 3, MIN_COHORT)
        assert.equal(count.suppressed, true, `${subjects} distinct subjects must not be published`)
      }
    })

    it('publishes the threshold itself, and everything above it', () => {
      for (const subjects of [MIN_COHORT, MIN_COHORT + 1, 100]) {
        const count = suppress(subjects, subjects * 3, MIN_COHORT)
        assert.equal(count.suppressed, false)
        assert.equal(subjectsOf(count), subjects)
      }
    })

    it('publishes zero, because "nobody did this" discloses nobody', () => {
      const count = suppress(0, 0, MIN_COHORT)
      assert.equal(count.suppressed, false)
      assert.equal(subjectsOf(count), 0)
    })

    it('carries NO number when it suppresses — not a rounded one, not a range', () => {
      const count = suppress(3, 9, MIN_COHORT)
      assert.equal(count.suppressed, true)
      // A rounded small count is still a small count, and "1–4" plus a second query is arithmetic.
      // The only field on the suppressed branch is the threshold, which is not data about anybody.
      assert.deepEqual(Object.keys(count).sort(), ['suppressed', 'threshold'])
      assert.equal(JSON.stringify(count).includes('3'), false, 'the withheld count must not leak into the body')
    })

    it('a raised threshold withholds more, not less', () => {
      // The deploy may raise it (env.ts refuses to lower it), so raising must actually bite.
      assert.equal(suppress(7, 7, 5).suppressed, false)
      assert.equal(suppress(7, 7, 20).suppressed, true)
    })
  })

  /* ================================================================ the daily series */

  describe('the daily series is suppressed per day, not per series', () => {
    it('withholds a four-person day and publishes a five-person day beside it', async () => {
      const busy = new Date(Date.now() - 3 * DAY)
      const quiet = new Date(Date.now() - 2 * DAY)
      await plantPeople(5, 'listing_sold', busy, 'busy')
      await plantPeople(4, 'listing_sold', quiet, 'quiet')
      await rollupOnce(sql, 5)

      const points = await dailySeries(sql, 'listing_sold', WINDOW, MIN_COHORT)
      const byDay = new Map(points.map((point) => [point.day, point.count]))
      const busyDay = busy.toISOString().slice(0, 10)
      const quietDay = quiet.toISOString().slice(0, 10)

      assert.equal(subjectsOf(byDay.get(busyDay)!), 5, 'a day at the threshold is published')
      assert.equal(
        subjectsOf(byDay.get(quietDay)!),
        'suppressed',
        'the day BELOW the threshold is the disclosure, even when its neighbour is fine',
      )
    })

    it('does not let ten events from one person look like a cohort', async () => {
      // The reason `subjects` and not `events` is what the threshold is applied to: ten events from
      // one person and ten from ten people are the same number of events and very different
      // disclosures. A threshold on `events` would publish the first.
      const at = new Date(Date.now() - 4 * DAY)
      const key = await subjectKey('user:loud')
      for (let i = 0; i < 10; i += 1) await plant(key, 'listing_sold', at)
      await rollupOnce(sql, 6)

      const points = await dailySeries(sql, 'listing_sold', WINDOW, MIN_COHORT)
      assert.equal(points.length, 1)
      assert.equal(subjectsOf(points[0]!.count), 'suppressed')
    })
  })

  /* ================================================================ active subjects */

  describe('the active count', () => {
    it('withholds four active people and publishes five', async () => {
      await plantPeople(4, 'listing_sold', new Date(Date.now() - DAY), 'a')
      assert.equal(subjectsOf(await activeSubjects(sql, WINDOW, MIN_COHORT)), 'suppressed')

      await plantPeople(1, 'listing_sold', new Date(Date.now() - DAY), 'b')
      assert.equal(subjectsOf(await activeSubjects(sql, WINDOW, MIN_COHORT)), 5)
    })

    it('excludes authentication events, which is the whole substance of "active"', async () => {
      // 13-operational-model.md:611. A user whose only activity is signing in and leaving is not
      // an active user, and counting them makes every engagement number look better than it is.
      await plantPeople(9, 'session_started', new Date(Date.now() - DAY), 'auth')
      const count = await activeSubjects(sql, WINDOW, MIN_COHORT)
      assert.equal(count.suppressed, false)
      assert.equal(subjectsOf(count), 0, 'nine sign-ins are zero active users')
    })

    it('counts a machine event as nobody', async () => {
      await plant(null, 'reconciliation_completed', new Date(Date.now() - DAY))
      assert.equal(subjectsOf(await activeSubjects(sql, WINDOW, MIN_COHORT)), 0)
    })

    it('honours the window rather than counting the whole store', async () => {
      await plantPeople(6, 'listing_sold', new Date(Date.now() - 200 * DAY), 'old')
      const recent: Window = { from: new Date(Date.now() - 7 * DAY), to: new Date(Date.now() + DAY) }
      assert.equal(subjectsOf(await activeSubjects(sql, recent, MIN_COHORT)), 0)
      assert.equal(subjectsOf(await activeSubjects(sql, WINDOW, MIN_COHORT)), 0) // 200d > 90d window
    })
  })

  /* ================================================================ funnels */

  describe('funnels are ordered, and every step is suppressed on its own', () => {
    const spec = funnelFor('onboarding')!

    it('publishes the wide steps and withholds the narrow one', async () => {
      // Six people register, six start a session, three deposit. The third step is three people,
      // and the honest answer is the shape of the drop-off WITHOUT the three.
      const base = Date.now() - 30 * DAY
      const keys: string[] = []
      for (let i = 0; i < 6; i += 1) {
        const key = await subjectKey(`user:f-${i}`)
        keys.push(key)
        await plant(key, 'user_registered', new Date(base))
        await plant(key, 'session_started', new Date(base + 60_000))
      }
      for (const key of keys.slice(0, 3)) await plant(key, 'deposit_confirmed', new Date(base + 120_000))

      const result = await funnel(sql, spec, WINDOW, MIN_COHORT)
      assert.deepEqual(
        result.steps.map((step) => subjectsOf(step.count)),
        [6, 6, 'suppressed', 0],
        'step 3 has three people and must be withheld; step 4 has nobody and is published as zero',
      )
    })

    it('is ordinal: an event before the previous step does not count', async () => {
      // A user who deployed a token in March and registered in April is not a completed funnel.
      const key = await subjectKey('user:backwards')
      await plant(key, 'token_deployed', new Date(Date.now() - 40 * DAY))
      await plant(key, 'session_started', new Date(Date.now() - 10 * DAY))
      // Five more who did it in the right order, so the step is above the threshold if it counts.
      for (let i = 0; i < 5; i += 1) {
        const other = await subjectKey(`user:forwards-${i}`)
        await plant(other, 'session_started', new Date(Date.now() - 20 * DAY))
        await plant(other, 'token_deployed', new Date(Date.now() - 19 * DAY))
      }

      const result = await funnel(sql, funnelFor('token_creation')!, WINDOW, MIN_COHORT)
      assert.equal(subjectsOf(result.steps[0]!.count), 6, 'six people started a session')
      assert.equal(
        subjectsOf(result.steps[1]!.count),
        5,
        'the out-of-order deploy must not be counted as a conversion',
      )
    })

    it('has a closed catalogue: an unknown funnel is not a query somebody can compose', async () => {
      // An arbitrary step list is a query language, and a query language over a behavioural store is
      // how "which three things did this one person do" gets asked.
      assert.equal(await funnelById(sql, 'not-a-funnel', WINDOW, MIN_COHORT), null)
      assert.equal(await funnelById(sql, "'; drop table events; --", WINDOW, MIN_COHORT), null)
      const rows = await sql`select count(*)::int as n from events`
      assert.equal((rows[0] as { n: number }).n, 0)
    })
  })

  /* ================================================================ cohort retention */

  describe('a retention cell suppresses BOTH numbers', () => {
    it('withholds a small cohort entirely — its size as well as its activity', async () => {
      // A cell showing "8 of 3" discloses the whole cohort, which is the half people forget.
      const registeredAt = new Date(Date.now() - 21 * DAY)
      const keys = await plantPeople(3, 'user_registered', registeredAt, 'small')
      for (const key of keys) await plant(key, 'listing_sold', new Date(registeredAt.getTime() + DAY))
      await recomputeCohorts(sql, 12)

      const cells = await retentionGrid(sql, 12, MIN_COHORT)
      assert.ok(cells.length > 0, 'the grid must have been computed at all')
      for (const cell of cells) {
        assert.equal(cell.cohortSize.suppressed, true, 'a three-person cohort must not publish its size')
        assert.equal(cell.active.suppressed, true)
      }
    })

    it('publishes a cohort at the threshold', async () => {
      const registeredAt = new Date(Date.now() - 21 * DAY)
      const keys = await plantPeople(5, 'user_registered', registeredAt, 'big')
      for (const key of keys) await plant(key, 'listing_sold', new Date(registeredAt.getTime() + DAY))
      await recomputeCohorts(sql, 12)

      const cells = await retentionGrid(sql, 12, MIN_COHORT)
      const week0 = cells.find((cell) => cell.weekOffset === 0)
      assert.ok(week0, 'week 0 must exist')
      assert.equal(subjectsOf(week0.cohortSize), 5)
      assert.equal(subjectsOf(week0.active), 5)
    })
  })

  /* ================================================================ operational reads */

  describe('the operational summary is a total over everybody, so it is not suppressed', () => {
    it('reports volumes and the oldest event', async () => {
      const key = await subjectKey('user:summary')
      const oldest = new Date(Date.now() - 10 * DAY)
      await plant(key, 'user_registered', oldest)
      await plant(key, 'listing_sold', new Date())

      const summary = await storeSummary(sql)
      assert.equal(summary.events, 2)
      assert.equal(summary.subjects, 1)
      assert.equal(summary.erasedSubjects, 0)
      assert.equal(summary.oldestEvent, oldest.toISOString())
    })
  })
})
