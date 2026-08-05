/**
 * The versioned schema.
 *
 * Rule 7 of docs/ecosystem/03 §2: versioned files, run by a one-shot job under an advisory lock,
 * expand/contract only. Nothing here is executed by `index.ts` — `src/migrator.ts` is the only
 * caller, and the service asserts the version rather than reaching it.
 *
 * **A released migration is immutable.** `@cloudsforge/db` checksums each one and refuses a run
 * where the text changed after it was applied. The fix for a wrong migration is always a new one.
 *
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 * **THE FOUR CONSTRAINTS THIS FILE EXISTS FOR.**
 *
 * Every other service in the estate holds data about a user because it must. This one holds data
 * about *behaviour, at volume, for analysis*, which is the shape that becomes a re-identification
 * incident. The privacy properties are therefore written as constraints rather than as code, on
 * the same principle that made `micro-devplatform`'s database refuse a fast hash and
 * `micro-ledger`'s refuse an unbalanced journal: an attacker with a database connection, and a
 * future code path nobody has written yet, are both stopped by the same line.
 *
 *   `events_subject_shape`        A subject column value must be 64 lowercase hex characters. A
 *                                 raw `user:<uuid>`, a bare UUID, an email and a handle are each
 *                                 refused BY THE DATABASE, so `INSERT INTO events` with a real
 *                                 identifier fails whoever runs it and whatever code path they
 *                                 found. AD-21, and 03-repository-responsibilities.md:204.
 *
 *   `events_person_has_pseudonym` A row for a person has a pseudonym, and a row for a machine has
 *                                 none — `(subject_kind in ('user','operator')) = (subject_key
 *                                 is not null)`. Both halves matter. Without the first, a bug that
 *                                 dropped the pseudonym would write an unattributable row into a
 *                                 funnel and quietly shrink every cohort. Without the second, a
 *                                 system event could be given a synthetic subject, which is how
 *                                 "distinct users" becomes a number nobody can explain.
 *
 *   `events_props_allowed`        Every property key is in the catalogue, no value is a nested
 *                                 object or array, and every string value matches a slug pattern
 *                                 with no spaces and no capitals. `"Spiros Savvanis"`,
 *                                 `"a@b.com"` and `"1994 Corolla — must go!"` are each refused by
 *                                 the database. 11-data-and-contract-strategy.md:509-515.
 *
 *   `subject_keys_erased`         Two legal states and no third: live, holding both salt and
 *                                 pseudonym, or erased, holding NEITHER. The database refuses a
 *                                 soft delete that keeps either half — and keeping the salt is the
 *                                 subtle one, because a salt plus the pepper plus the user id
 *                                 recomputes the pseudonym, so an "erasure" that kept it would
 *                                 have erased nothing. See `pseudonym.ts`.
 * ══════════════════════════════════════════════════════════════════════════════════════════════
 *
 * **There is no `user_id`, `email`, `handle`, `address` or `amount` column, anywhere.**
 * 11-data-and-contract-strategy.md:512 specifies that as a CI check — "a schema check in
 * `analytics`'s CI fails the build if a column named `user_id`, `email`, `handle`, `address` or
 * `amount` appears in any table". The estate's reusable workflow has no such check and this
 * repository ships no bespoke CI (03 §5), so it is `migrations.test.ts` instead, run against the
 * real migrated schema through `information_schema.columns`. It fails the build in the same place
 * and for the same reason, and it can see a column a grep over this file would miss.
 *
 * **Not partitioned.** 13-operational-model.md:655 says "append-only, partitioned monthly", and
 * that is the right answer at volume: retention becomes `DROP PARTITION` rather than a DELETE over
 * four hundred days of rows. It is deliberately not done yet, because declarative partitioning
 * forces the partition key into every unique constraint — `source_event_id` is the inbox's second
 * line of defence and would become `(occurred_at, source_event_id)`, which no longer refuses a
 * redelivery whose producer restamped the time. The retention sweep proves it deletes; the day the
 * DELETE is too slow is the day this becomes a migration, not before.
 */

import { JOBS_SCHEMA_SQL } from '@cloudsforge/jobs'
import type { Migration } from '@cloudsforge/db'
import { EVENT_NAMES, MAX_PROPERTIES, PROPERTY_NAMES, VALUE_PATTERN } from './catalogue.ts'

/** Rendered into the CHECK constraints, so the columns and the TypeScript catalogue cannot drift. */
const EVENT_NAME_LIST = EVENT_NAMES.map((name) => `'${name}'`).join(', ')
const PROPERTY_NAME_LIST = PROPERTY_NAMES.map((name) => `'${name}'`).join(', ')

/** The reasons an ingest may refuse something. Bounded, because it is a primary key column. */
export const REJECTION_REASONS: readonly string[] = Object.freeze([
  'unknown_topic',
  'disallowed_property',
  'bad_property_value',
  'too_many_properties',
  'missing_subject',
  'erased_subject',
])

const REJECTION_REASON_LIST = REJECTION_REASONS.map((reason) => `'${reason}'`).join(', ')

export const MIGRATIONS: readonly Migration[] = [
  {
    version: 1,
    name: 'jobs',
    // Taken verbatim from the runtime package so the table the claim query assumes and the table
    // that exists cannot drift. Copying the DDL by hand is how a service ends up with a jobs table
    // missing the (kind, key) unique constraint, which silently turns every recurring enqueue into
    // a duplicate run.
    up: JOBS_SCHEMA_SQL,
  },

  {
    version: 2,
    name: 'inbox',
    up: `
      -- Delivery is at-least-once, so the consumer is what makes it effectively-once. The primary
      -- key is the dedupe: a redelivered event conflicts and the handler is never re-run — AD-10,
      -- and 04-domain-model §10.6 specifies the pair.
      --
      -- There is no outbox. \`contracts-events\` registers no \`analytics.*\` topic and names this
      -- service as one that "is only ever a consumer" (contracts/packages/events/src/index.ts:174),
      -- so there is nothing this service is entitled to publish. An outbox here would come with a
      -- relay job, a signing secret in the deploy and a permanently empty dashboard panel.
      create table if not exists inbox (
        topic       text        not null,
        event_id    uuid        not null,
        received_at timestamptz not null default now(),
        primary key (topic, event_id)
      );

      create index if not exists inbox_received_idx on inbox (received_at);
    `,
  },

  {
    version: 3,
    name: 'subject_keys',
    up: `
      -- The key mapping. Erasure is the deletion of a row's salt, and nothing else in this schema
      -- can accomplish it — see src/pseudonym.ts for why a plain HMAC(user_id, pepper) cannot be
      -- erased at all.
      --
      -- NOTE WHAT IS NOT HERE: there is no user_id column, and there is no pepper column. The
      -- pepper is process memory, supplied by the deploy, and 13-operational-model.md:597 requires
      -- it to be absent from any backup that also holds the identity database. Keeping it out of
      -- this database is the strongest form of that available to a service that owns exactly one.
      --
      -- An attacker with a connection to this database therefore has, per subject: one HMAC under
      -- an unknown key, one unrelated HMAC under the same unknown key, and thirty-two random
      -- bytes. There is nothing here to test a guess against.
      create table if not exists subject_keys (
        -- HMAC(pepper, "cf.analytics.lookup.v1|" || subject). Deterministic, so the same person's
        -- next event finds their existing pseudonym.
        lookup_key  text        primary key,
        -- HMAC(pepper, "cf.analytics.subject.v1|" || subject || "|" || salt). NULL once erased.
        subject_key text        unique,
        -- Thirty-two CSPRNG bytes. The only thing in this system whose destruction is irreversible,
        -- which is exactly why it is the thing erasure destroys.
        salt        text,
        first_seen  timestamptz not null default now(),
        last_seen   timestamptz not null default now(),
        erased_at   timestamptz,

        constraint subject_keys_lookup_shape  check (lookup_key  ~ '^[0-9a-f]{64}$'),
        constraint subject_keys_subject_shape check (subject_key is null or subject_key ~ '^[0-9a-f]{64}$'),
        constraint subject_keys_salt_shape    check (salt        is null or salt        ~ '^[0-9a-f]{64}$'),

        -- ══════════════════════════════════════════════════════════════════════════════════════
        -- ERASURE CANNOT BE FAKED.
        --
        -- A row is either live — salt and pseudonym present, erased_at null — or erased, holding
        -- NEITHER. There is no third state, so "mark it deleted but keep the key" is not a bug
        -- someone can introduce here: the database refuses the row. This is the line that makes
        -- "erasure makes the events unattributable" a property of the schema rather than a claim
        -- about the code that happens to write it today.
        -- ══════════════════════════════════════════════════════════════════════════════════════
        --
        -- Written as the two legal states rather than as an equivalence, and the difference is not
        -- stylistic. "(erased_at is null) = (salt is not null and subject_key is not null)" is
        -- satisfied by a row that is erased, has NULLED THE PSEUDONYM AND KEPT THE SALT — and a
        -- kept salt is a recomputable pseudonym for anyone holding the pepper and the user id,
        -- which is erasure that erases nothing. Caught by migrations.test.ts before it shipped.
        constraint subject_keys_erased
          check (
            (erased_at is     null and salt is not null and subject_key is not null) or
            (erased_at is not null and salt is     null and subject_key is     null)
          ),

        constraint subject_keys_seen_ordered check (last_seen >= first_seen)
      );

      -- The retention sweep's access path.
      create index if not exists subject_keys_last_seen_idx on subject_keys (last_seen);
    `,
  },

  {
    version: 4,
    name: 'events',
    up: `
      -- ══════════════════════════════════════════════════════════════════════════════════════
      -- The property guard, as a function so a CHECK can call it.
      --
      -- A CHECK expression may not contain a subquery, so "every key of this jsonb is in a list"
      -- has to be a function. IMMUTABLE because it depends on nothing but its argument — the
      -- allowlist is compiled into the body by the migration, which is what makes it immutable and
      -- what makes changing the allowlist a new migration rather than an edit.
      --
      -- It enforces three things, and the third is the one that stops a sentence:
      --   1. every key is in the catalogue                     (no unforeseen field)
      --   2. no value is an object, an array or null           (no smuggled structure)
      --   3. every string value is a slug: lowercase, no spaces (no free text a person typed)
      -- ══════════════════════════════════════════════════════════════════════════════════════
      create or replace function analytics_props_allowed(props jsonb) returns boolean as $fn$
      declare
        k text;
        v jsonb;
      begin
        if props is null or jsonb_typeof(props) <> 'object' then return false; end if;
        if (select count(*) from jsonb_object_keys(props)) > ${MAX_PROPERTIES} then return false; end if;
        for k, v in select key, value from jsonb_each(props) loop
          if k not in (${PROPERTY_NAME_LIST}) then return false; end if;
          if jsonb_typeof(v) in ('object', 'array', 'null') then return false; end if;
          if jsonb_typeof(v) = 'string' and (v #>> '{}') !~ '${VALUE_PATTERN}' then return false; end if;
        end loop;
        return true;
      end;
      $fn$ language plpgsql immutable;

      -- One product event. Append-only: there is no UPDATE path and the trigger below refuses one.
      create table if not exists events (
        id              bigserial   primary key,
        -- The pseudonym, and the ONLY thing here that refers to a person. 64 hex characters, and
        -- the CHECK is what makes that a guarantee rather than a habit — a raw user:<uuid>, a bare
        -- UUID, an email and a handle are all refused by the database itself.
        subject_key     text,
        -- Which kind of SUBJECT this event is about — deliberately not "who caused it". The
        -- envelope's \`actor\` answers the second question and is often \`service:wallet\`, for a
        -- deposit that is very much about a person. The pairing constraint below ties this to the
        -- presence of a pseudonym in both directions, so a machine event is never counted as a
        -- person and a person's event is never counted as a machine's.
        subject_kind    text        not null,
        -- The analytics event name from src/catalogue.ts. A closed vocabulary: an event this build
        -- has never heard of is refused at ingest and counted, never stored with its payload.
        event_name      text        not null,
        -- When the fact happened, from the envelope. NOT when it was relayed: a funnel ordered by
        -- arrival reorders itself whenever a producer retries.
        occurred_at     timestamptz not null,
        received_at     timestamptz not null default now(),
        -- A pseudonymised per-session identifier, so two events in one session join without the
        -- browser's own session id ever being stored. Metrics 2 and 19 need the session; neither
        -- needs to know which session.
        session         text,
        -- Allowlisted, typed, bucketed. See the function above and src/catalogue.ts.
        props           jsonb       not null default '{}'::jsonb,

        -- §10.1's invariant, in this service's terms: unique, so a redelivered event does not
        -- become a second row in a funnel. It holds even if a future code path writes by some
        -- other route than the inbox.
        source_event_id uuid        not null,
        source_topic    text        not null,
        producer        text        not null,

        constraint events_source_uniq unique (source_event_id),
        constraint events_subject_shape check (subject_key is null or subject_key ~ '^[0-9a-f]{64}$'),
        constraint events_session_shape check (session is null or session ~ '^[0-9a-f]{64}$'),
        constraint events_subject_kind check (subject_kind in ('user', 'operator', 'service', 'system')),
        -- Both directions. A person's event has a pseudonym; a machine's event has none.
        constraint events_person_has_pseudonym
          check ((subject_kind in ('user', 'operator')) = (subject_key is not null)),
        constraint events_name_known check (event_name in (${EVENT_NAME_LIST})),
        constraint events_props_allowed check (analytics_props_allowed(props))
      );

      -- The three access paths, and nothing speculative. Every analysis query in reads.ts is a
      -- prefix of one of them.
      create index if not exists events_name_time_idx    on events (event_name, occurred_at);
      create index if not exists events_subject_time_idx on events (subject_key, occurred_at) where subject_key is not null;
      create index if not exists events_time_idx         on events (occurred_at);

      -- Append-only. Not "we do not update it" — the database refuses.
      --
      -- An event store that can be edited after the fact is a record of what somebody last said
      -- happened. DELETE stays allowed: retention removes rows entirely, which is a different
      -- claim from rewriting one to say something else.
      create or replace function analytics_events_no_update() returns trigger as $$
      begin
        raise exception 'events is append-only; analytics computes, it does not correct';
      end;
      $$ language plpgsql;

      drop trigger if exists analytics_events_immutable on events;
      create trigger analytics_events_immutable
        before update on events
        for each row execute function analytics_events_no_update();
    `,
  },

  {
    version: 5,
    name: 'aggregates',
    up: `
      -- Daily counts by event name. \`subjects\` is a count of DISTINCT pseudonyms, which is the
      -- number every metric in 13 §12 is actually about ("users with at least one …"), and it is
      -- also what the minimum-cohort threshold is applied to. A rollup that stored only the event
      -- count could not be suppressed, because ten events from one person and ten from ten people
      -- are the same number.
      create table if not exists event_rollups (
        bucket_day  date        not null,
        event_name  text        not null,
        events      bigint      not null,
        subjects    integer     not null,
        computed_at timestamptz not null default now(),
        constraint event_rollups_pk primary key (bucket_day, event_name),
        constraint event_rollups_nonneg check (events >= 0 and subjects >= 0),
        -- Distinct people cannot exceed events. A rollup that violates this is a broken query, and
        -- a broken query in a suppression input is a suppression that does not suppress.
        constraint event_rollups_subjects_le_events check (subjects <= events)
      );

      create index if not exists event_rollups_day_idx on event_rollups (bucket_day desc);

      -- Metric 18: users active in week N, over the signup-week cohort, twelve weeks.
      -- Recomputed by a leased job rather than computed per request: the query is a self-join over
      -- four hundred days of events, and a dashboard that runs it on every page load is a dashboard
      -- that takes the database down at the exact moment somebody is watching a launch.
      create table if not exists cohort_retention (
        cohort_week date        not null,
        week_offset integer     not null,
        cohort_size integer     not null,
        active      integer     not null,
        computed_at timestamptz not null default now(),
        constraint cohort_retention_pk primary key (cohort_week, week_offset),
        constraint cohort_retention_offset check (week_offset >= 0 and week_offset <= 52),
        constraint cohort_retention_nonneg check (cohort_size >= 0 and active >= 0),
        constraint cohort_retention_active_le_size check (active <= cohort_size)
      );

      -- Refusals, counted and nothing more.
      --
      -- The offending property NAME is deliberately not stored. A producer that sends
      -- {"spiros_savvanis_lives_at": 1} has put the personal data in the key, and a rejection table
      -- that records keys is a table that collects exactly what the allowlist refused. The producer
      -- is told which of its properties were dropped in the synchronous response to its own signed
      -- delivery — where it already knew, and where nothing is retained.
      create table if not exists ingest_rejections (
        day          date   not null,
        reason       text   not null,
        source_topic text   not null,
        rejections   bigint not null default 0,
        constraint ingest_rejections_pk primary key (day, reason, source_topic),
        constraint ingest_rejections_reason check (reason in (${REJECTION_REASON_LIST})),
        constraint ingest_rejections_nonneg check (rejections >= 0)
      );
    `,
  },

  {
    version: 6,
    name: 'definitions',
    up: `
      -- The metric catalogue, versioned with a changelog. 13-operational-model.md:637:
      -- "A redefinition creates a new metric id and never silently changes an existing series: a
      -- retention number that changed definition in March is a chart that lies about February."
      --
      -- The primary key is (id, version) and the checksum is over numerator, denominator and
      -- window. Republishing the same (id, version) with different text is refused by the code AND
      -- by the trigger below, because "the definition changed but the series did not" is the
      -- failure this table exists to make impossible.
      create table if not exists metric_definitions (
        id            text        not null,
        version       integer     not null,
        title         text        not null,
        numerator     text        not null,
        denominator   text        not null,
        window_spec   text        not null,
        supersedes    text,
        checksum      text        not null,
        published_at  timestamptz not null default now(),
        constraint metric_definitions_pk primary key (id, version),
        constraint metric_definitions_version check (version >= 1),
        constraint metric_definitions_checksum_shape check (checksum ~ '^[0-9a-f]{64}$')
      );

      create or replace function analytics_definitions_no_update() returns trigger as $$
      begin
        raise exception 'a published metric definition is immutable; publish a new version';
      end;
      $$ language plpgsql;

      drop trigger if exists analytics_definitions_immutable on metric_definitions;
      create trigger analytics_definitions_immutable
        before update on metric_definitions
        for each row execute function analytics_definitions_no_update();
    `,
  },

  {
    version: 7,
    name: 'idempotency',
    up: `
      -- The shape is the ledger's, by way of market/src/idempotency.ts. The claim INSERT and the
      -- work share one transaction, so the stored response can never disagree with what committed.
      create table if not exists idempotency_keys (
        key          text        primary key,
        route        text        not null,
        request_hash text        not null,
        response     jsonb,
        artefact_id  text,
        created_at   timestamptz not null default now()
      );

      create index if not exists idempotency_keys_created_idx on idempotency_keys (created_at);
    `,
  },

  {
    version: 8,
    name: 'erasure-clears-the-session',
    up: `
      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- ERASURE HAS TO REACH \`events.session\`, AND APPEND-ONLY SAID IT COULD NOT.
      --
      -- \`subject_keys_erased\` (migration 3) makes the salt destruction real, and the argument
      -- attached to it — after the salt is gone the events identify nobody — is true of
      -- \`subject_key\` and ONLY of \`subject_key\`.
      --
      -- \`session\` is a second identifier on the same rows, derived on a different path:
      -- HMAC(pepper, 'cf.analytics.session.v1|' || session_id), with no per-subject salt in it at
      -- all. Destroying the salt therefore does nothing to it. It stays deterministic under a
      -- pepper that can never be destroyed — the pepper keys every other subject in the table —
      -- so anyone holding the pepper and a candidate session id recomputes the digest and selects
      -- an "erased" person's rows directly; and even without the pepper, rows sharing a session
      -- re-cluster into one person's history. Recital 26 asks whether the data can be linked back
      -- to an individual, and a surviving session identifier is exactly such a link.
      --
      -- ── WHY THIS RELAXES APPEND-ONLY, AND HOW FAR ─────────────────────────────────────────
      --
      -- \`analytics_events_immutable\` existed so that "analytics computes, it does not correct":
      -- an event store whose rows can be rewritten is a record of what somebody last SAID
      -- happened. That argument is about CORRECTING A FACT, and it is still enforced below.
      --
      -- Clearing an identifier is not correcting a fact. Nothing about what happened, when, to
      -- what kind of subject, or under which event name changes; a link is removed. The exception
      -- is therefore made as narrow as it can be expressed rather than by dropping the trigger:
      --
      --   * only \`session\` may differ,
      --   * only from non-null to NULL — never to another value, so no row can be re-keyed,
      --   * every other column must be byte-identical.
      --
      -- The comparison is \`to_jsonb(new) - 'session'\` against the same of \`old\` rather than a
      -- list of column names on purpose: a column added by a later migration is covered by this
      -- rule automatically, where an enumerated list would silently stop protecting it.
      --
      -- This is the same move \`micro-community\` made for the same reason — its
      -- \`community_refuse_vote_update\` permits \`subject\` and \`cast_by\` to be rewritten by the
      -- erasure handler and refuses \`choice\`, \`weight\` and \`proposal_id\` outright — because
      -- refusing the whole UPDATE does not make the record safer, it makes erasure impossible
      -- without a DELETE, which is strictly worse.
      -- ════════════════════════════════════════════════════════════════════════════════════════
      create or replace function analytics_events_no_update() returns trigger as $$
      begin
        if new.session is null
           and old.session is not null
           and (to_jsonb(new) - 'session') = (to_jsonb(old) - 'session') then
          return new;
        end if;
        raise exception
          'events is append-only; the only permitted update is GDPR erasure clearing session';
      end;
      $$ language plpgsql;

      -- ════════════════════════════════════════════════════════════════════════════════════════
      -- AN ERASURE THAT LEAVES A SESSION BEHIND DOES NOT COMMIT.
      --
      -- The handler in \`pseudonym.ts\` nulls the sessions in the same transaction that sets
      -- \`erased_at\`. This is the invariant underneath that, so it cannot be quietly half-done by
      -- a future edit, an exception on the wrong branch, or a hand-run UPDATE during an incident.
      --
      -- DEFERRED, and it has to be: the handler nulls \`subject_keys.subject_key\` and clears the
      -- sessions in one transaction, and an immediate trigger would fire between the two and
      -- refuse a write that is in the middle of being correct. Checked at commit, the question is
      -- "did this transaction, as a whole, finish the erasure" — which is the only version of the
      -- question worth asking. Same mechanism, and the same reason, as
      -- \`community_assert_spend_names_entry\` and \`ledger/src/migrations.ts:324\`.
      --
      -- It reads OLD.subject_key because NEW's is already null — the pseudonym being retired is
      -- the only handle on the rows that have to be checked.
      -- ════════════════════════════════════════════════════════════════════════════════════════
      create or replace function analytics_assert_erasure_unlinked() returns trigger as $$
      declare
        leaked bigint;
      begin
        if new.erased_at is null or old.subject_key is null then
          return null;
        end if;
        select count(*) into leaked
          from events where subject_key = old.subject_key and session is not null;
        if leaked > 0 then
          raise exception
            'erasure left a session identifier on % event row(s); the subject is still linkable', leaked
            using errcode = 'check_violation';
        end if;
        return null;
      end;
      $$ language plpgsql;

      drop trigger if exists analytics_erasure_unlinked on subject_keys;
      create constraint trigger analytics_erasure_unlinked
        after update on subject_keys
        deferrable initially deferred
        for each row execute function analytics_assert_erasure_unlinked();
    `,
  },
]

/** Every table this service owns. The truncate list for the test harness, and nothing else. */
export const TABLES: readonly string[] = Object.freeze([
  'events',
  'subject_keys',
  'inbox',
  'event_rollups',
  'cohort_retention',
  'ingest_rejections',
  'metric_definitions',
  'idempotency_keys',
])

/**
 * Column names that may not exist in any table this service owns.
 *
 * 11-data-and-contract-strategy.md:512, restated exactly. `migrations.test.ts` checks the real
 * migrated schema against this list, because a grep over source cannot see a column added by a
 * migration written next month.
 */
export const FORBIDDEN_COLUMNS: readonly string[] = Object.freeze([
  'user_id',
  'email',
  'handle',
  'address',
  'amount',
  'display_name',
  'wallet_address',
  'ip',
  'ip_address',
  'balance',
])

/**
 * The version `index.ts` asserts before it serves.
 *
 * Derived rather than written down, so adding a migration cannot leave the assertion behind — the
 * failure that produces is a service running happily against a schema missing the CHECK it depends
 * on, which is silent until the day it matters.
 */
export const SCHEMA_VERSION: number = MIGRATIONS.reduce(
  (highest, migration) => Math.max(highest, migration.version),
  0,
)

/**
 * No baseline. This service has never existed, so there is no hand-built schema to adopt; a
 * non-zero baseline would record migrations as applied without running them, and the four
 * constraints in the header would then not exist on the database that claims to be at version 7.
 */
export const BASELINE_VERSION = 0
