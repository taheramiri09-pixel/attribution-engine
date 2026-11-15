-- =====================================================================
-- Attribution engine ledger: Postgres schema
-- Target: Postgres 14+ (VERIFY version if using Supabase)
--
-- Conventions
--   * hashed_* columns: lowercase hex SHA-256 of the NORMALIZED value
--     (email: trimmed + lowercased; phone: E.164). Hashing happens in the
--     n8n sub-workflow hash_pii, never inside Meta/Google payload code.
--   * *_enc columns: raw PII, encrypted at the column level, e.g.
--       pgp_sym_encrypt(value, :key)::bytea
--     The key lives in n8n credentials / env vars, never in the database.
--     Also enable disk encryption at rest on the host (VERIFY on Supabase).
--   * events.event_id: lowercase hex SHA-256 built by build_event_id
--       revenue:        sha256(job_uuid || ':' || event_type || ':' || location_id)
--       qualification:  sha256(lead_id  || ':' || event_type || ':' || location_id)
--   * location_id is on every table that carries business data.
--   * Raw PII must never appear in jsonb payload columns: redact before insert.
-- =====================================================================

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ---------------------------------------------------------------------
-- Shared trigger helper
-- ---------------------------------------------------------------------
CREATE OR REPLACE FUNCTION set_updated_at() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.updated_at := now();
  RETURN NEW;
END $$;

-- ---------------------------------------------------------------------
-- 1. locations (config store, one row per hub)
-- ---------------------------------------------------------------------
CREATE TABLE locations (
  location_id                 text PRIMARY KEY
                              CHECK (location_id ~ '^[a-z0-9][a-z0-9_-]*$'),
  name                        text        NOT NULL,
  timezone                    text        NOT NULL DEFAULT 'UTC',
  currency                    char(3)     NOT NULL,
  servicem8_credential_ref    text        NOT NULL,  -- n8n credential name, not a secret
  servicem8_webhook_active    boolean     NOT NULL DEFAULT false,
  meta_dataset_id             text,                  -- pixel / dataset ID
  meta_credential_ref         text,
  google_customer_id          text,
  google_login_customer_id    text,                  -- manager (MCC) account, if used
  -- {"QualifiedLead": "customers/123/conversionActions/456", "JobPaid": "..."}
  google_conversion_actions   jsonb       NOT NULL DEFAULT '{}'::jsonb,
  slack_channel               text,
  service_types               text[]      NOT NULL DEFAULT '{}',
  service_area                jsonb       NOT NULL DEFAULT '{}'::jsonb,
  -- Maps a ServiceM8 status to an internal event type, e.g.
  -- {"Quote accepted": "QuoteAccepted", "Completed": "JobCompleted", "Paid": "JobPaid"}
  -- VERIFY exact ServiceM8 status names and how "paid" is derived (Job Payment object).
  status_event_map            jsonb       NOT NULL DEFAULT '{}'::jsonb,
  -- Platform age limits per event type / click ID, kept in config, NOT hardcoded.
  -- VERIFY against current Meta and Google docs before filling in, e.g.
  -- {"meta": {"revenue": {"max_age_days": null}}, "google": {"gclid_max_age_days": null}}
  platform_limits             jsonb       NOT NULL DEFAULT '{}'::jsonb,
  phone_match_window_hours    integer     NOT NULL DEFAULT 168
                              CHECK (phone_match_window_hours > 0),
  active                      boolean     NOT NULL DEFAULT true,
  created_at                  timestamptz NOT NULL DEFAULT now(),
  updated_at                  timestamptz NOT NULL DEFAULT now()
);

CREATE TRIGGER trg_locations_updated_at
  BEFORE UPDATE ON locations
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- 2. leads
--    One row per person per location. First-touch click IDs are stored
--    here and are immutable once set; later touches go to lead_touches.
--
--    Dedup note: a composite key on (hashed_phone, hashed_email, location_id)
--    does not dedupe when either column is NULL, and misses a lead who first
--    arrives by phone and later by email. This schema therefore uses one
--    partial unique index per identifier. If phone matches lead A and email
--    matches lead B, WF-01 merges them and sets merged_into on the loser.
-- ---------------------------------------------------------------------
CREATE TABLE leads (
  lead_id                 uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  location_id             text        NOT NULL REFERENCES locations(location_id),

  hashed_phone            char(64),
  hashed_email            char(64),
  phone_enc               bytea,
  email_enc               bytea,
  name_enc                bytea,

  -- first touch (write-once, enforced by trigger below)
  first_touch_at          timestamptz,
  first_channel           text
                          CHECK (first_channel IN ('form','calculator','chat','sms','whatsapp','phone')),
  first_gclid             text,
  first_gbraid            text,
  first_wbraid            text,
  first_fbclid            text,
  first_fbp               text,
  first_fbc               text,
  first_msclkid           text,
  first_utm               jsonb,
  first_landing_page      text,
  first_referrer          text,

  last_touch_at           timestamptz,
  attribution_status      text        NOT NULL DEFAULT 'pending'
                          CHECK (attribution_status IN ('pending','attributed','unattributed')),

  -- qualification state (written by WF-01 / WF-02; detail lives in grok_audit)
  status                  text        NOT NULL DEFAULT 'new'
                          CHECK (status IN ('new','qualifying','qualified','unqualified','spam','needs_review')),
  qualification_source    text
                          CHECK (qualification_source IN ('grok','grok_reprompt','rules_fallback','manual')),
  intent_score            smallint    CHECK (intent_score BETWEEN 0 AND 100),
  service_type            text,
  urgency                 text,
  qualified_at            timestamptz,

  -- ServiceM8 links (UUIDs stored as text to avoid assuming a format)
  servicem8_client_uuid   text,
  servicem8_job_uuid      text,

  merged_into             uuid        REFERENCES leads(lead_id),
  created_at              timestamptz NOT NULL DEFAULT now(),
  updated_at              timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT leads_has_identifier
    CHECK (hashed_phone IS NOT NULL OR hashed_email IS NOT NULL),
  CONSTRAINT leads_hash_format
    CHECK ((hashed_phone IS NULL OR hashed_phone ~ '^[0-9a-f]{64}$')
       AND (hashed_email IS NULL OR hashed_email ~ '^[0-9a-f]{64}$'))
);

CREATE UNIQUE INDEX leads_uq_phone
  ON leads (location_id, hashed_phone)
  WHERE hashed_phone IS NOT NULL AND merged_into IS NULL;

CREATE UNIQUE INDEX leads_uq_email
  ON leads (location_id, hashed_email)
  WHERE hashed_email IS NOT NULL AND merged_into IS NULL;

CREATE INDEX leads_servicem8_job_idx
  ON leads (servicem8_job_uuid) WHERE servicem8_job_uuid IS NOT NULL;
CREATE INDEX leads_servicem8_client_idx
  ON leads (servicem8_client_uuid) WHERE servicem8_client_uuid IS NOT NULL;
CREATE INDEX leads_review_idx
  ON leads (location_id, created_at) WHERE status = 'needs_review';
CREATE INDEX leads_status_idx
  ON leads (location_id, status, created_at);
CREATE INDEX leads_first_gclid_idx
  ON leads (first_gclid) WHERE first_gclid IS NOT NULL;
CREATE INDEX leads_first_fbclid_idx
  ON leads (first_fbclid) WHERE first_fbclid IS NOT NULL;

CREATE TRIGGER trg_leads_updated_at
  BEFORE UPDATE ON leads
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- First-touch protection: once a first_* column has a value it can never change.
CREATE OR REPLACE FUNCTION leads_protect_first_touch() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  NEW.first_touch_at     := COALESCE(OLD.first_touch_at,     NEW.first_touch_at);
  NEW.first_channel      := COALESCE(OLD.first_channel,      NEW.first_channel);
  NEW.first_gclid        := COALESCE(OLD.first_gclid,        NEW.first_gclid);
  NEW.first_gbraid       := COALESCE(OLD.first_gbraid,       NEW.first_gbraid);
  NEW.first_wbraid       := COALESCE(OLD.first_wbraid,       NEW.first_wbraid);
  NEW.first_fbclid       := COALESCE(OLD.first_fbclid,       NEW.first_fbclid);
  NEW.first_fbp          := COALESCE(OLD.first_fbp,          NEW.first_fbp);
  NEW.first_fbc          := COALESCE(OLD.first_fbc,          NEW.first_fbc);
  NEW.first_msclkid      := COALESCE(OLD.first_msclkid,      NEW.first_msclkid);
  NEW.first_utm          := COALESCE(OLD.first_utm,          NEW.first_utm);
  NEW.first_landing_page := COALESCE(OLD.first_landing_page, NEW.first_landing_page);
  NEW.first_referrer     := COALESCE(OLD.first_referrer,     NEW.first_referrer);
  RETURN NEW;
END $$;

CREATE TRIGGER trg_leads_protect_first_touch
  BEFORE UPDATE ON leads
  FOR EACH ROW EXECUTE FUNCTION leads_protect_first_touch();

-- ---------------------------------------------------------------------
-- 3. lead_touches (every touch, including phone calls; append-only)
-- ---------------------------------------------------------------------
CREATE TABLE lead_touches (
  touch_id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  lead_id         uuid        NOT NULL REFERENCES leads(lead_id) ON DELETE CASCADE,
  location_id     text        NOT NULL REFERENCES locations(location_id),
  is_first        boolean     NOT NULL DEFAULT false,
  channel         text        NOT NULL
                  CHECK (channel IN ('form','calculator','chat','sms','whatsapp','phone')),
  occurred_at     timestamptz NOT NULL,
  gclid           text,
  gbraid          text,
  wbraid          text,
  fbclid          text,
  fbp             text,
  fbc             text,
  msclkid         text,
  utm             jsonb       NOT NULL DEFAULT '{}'::jsonb,
  landing_page    text,
  referrer        text,
  raw_payload     jsonb,                 -- REDACTED payload only (no raw PII)
  payload_hash    char(64)    NOT NULL,  -- sha256 of the normalized inbound payload
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT lead_touches_uq_payload UNIQUE (lead_id, payload_hash)  -- webhook replay safe
);

CREATE INDEX lead_touches_lead_idx ON lead_touches (lead_id, occurred_at DESC);
CREATE INDEX lead_touches_loc_idx  ON lead_touches (location_id, occurred_at DESC);

-- ---------------------------------------------------------------------
-- 4. grok_audit (one row per Grok / fallback attempt; qualification only)
-- ---------------------------------------------------------------------
CREATE TABLE grok_audit (
  audit_id        uuid        PRIMARY KEY DEFAULT gen_random_uuid(),
  lead_id         uuid        NOT NULL REFERENCES leads(lead_id),
  location_id     text        NOT NULL REFERENCES locations(location_id),
  attempt_no      smallint    NOT NULL DEFAULT 1,
  stage           text        NOT NULL
                  CHECK (stage IN ('grok','grok_reprompt','rules_fallback')),
  model           text        NOT NULL,
  prompt_version  text        NOT NULL,
  schema_version  text        NOT NULL,
  input_hash      char(64),                -- hash of the prompt input, not the text
  http_status     integer,
  latency_ms      integer,
  error_type      text        NOT NULL DEFAULT 'none'
                  CHECK (error_type IN ('none','timeout','rate_limit','server_error','malformed','schema_invalid')),
  response_raw    text,                    -- VERIFY PII handling before storing raw output
  parsed          jsonb,
  is_spam         boolean,
  intent_score    smallint    CHECK (intent_score BETWEEN 0 AND 100),
  qualified       boolean,
  service_type    text,
  urgency         text,
  reason          text,
  confidence      numeric(3,2) CHECK (confidence BETWEEN 0 AND 1),
  decision        text        CHECK (decision IN ('qualified','unqualified','spam','needs_review')),
                                           -- set only on the final attempt row
  created_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT grok_audit_uq_attempt UNIQUE (lead_id, attempt_no, stage)
);

CREATE INDEX grok_audit_lead_idx ON grok_audit (lead_id, created_at DESC);
CREATE INDEX grok_audit_err_idx  ON grok_audit (location_id, created_at DESC)
  WHERE error_type <> 'none';

-- ---------------------------------------------------------------------
-- 5. outbox (write here BEFORE any external call; work queue + receipts)
--    dedupe_key examples:
--      lead intake:       'lead:' || location_id || ':' || payload_hash
--      ServiceM8 webhook: 'sm8:' || object || ':' || uuid || ':' || <time or edit_date>
--                         VERIFY which timestamp the webhook payload carries.
--    Claim rows with:
--      SELECT ... FROM outbox
--      WHERE status IN ('pending','failed') AND next_attempt_at <= now()
--      ORDER BY next_attempt_at
--      FOR UPDATE SKIP LOCKED LIMIT n;
-- ---------------------------------------------------------------------
CREATE TABLE outbox (
  outbox_id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  location_id      text        NOT NULL REFERENCES locations(location_id),
  kind             text        NOT NULL
                   CHECK (kind IN ('lead_intake','qualification','servicem8_event','dispatch','call_log')),
  dedupe_key       text        NOT NULL,
  payload          jsonb       NOT NULL,
  status           text        NOT NULL DEFAULT 'pending'
                   CHECK (status IN ('pending','processing','done','failed','dead')),
  attempt_count    integer     NOT NULL DEFAULT 0,
  max_attempts     integer     NOT NULL DEFAULT 5,
  next_attempt_at  timestamptz NOT NULL DEFAULT now(),
  locked_at        timestamptz,
  locked_by        text,
  last_error       text,
  created_at       timestamptz NOT NULL DEFAULT now(),
  processed_at     timestamptz,
  updated_at       timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT outbox_uq_dedupe UNIQUE (dedupe_key)
);

CREATE INDEX outbox_ready_idx
  ON outbox (next_attempt_at) WHERE status IN ('pending','failed');
CREATE INDEX outbox_stale_lock_idx
  ON outbox (locked_at) WHERE status = 'processing';
CREATE INDEX outbox_loc_status_idx
  ON outbox (location_id, status, created_at);

CREATE TRIGGER trg_outbox_updated_at
  BEFORE UPDATE ON outbox
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- 6. events (event ledger; the UNIQUE event_id is the dedup guarantee)
--    Write with: INSERT ... ON CONFLICT (event_id) DO NOTHING
--    If zero rows are inserted, the event already exists: stop.
-- ---------------------------------------------------------------------
CREATE TABLE events (
  event_pk          uuid         PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id          char(64)     NOT NULL,
  location_id       text         NOT NULL REFERENCES locations(location_id),
  lead_id           uuid         REFERENCES leads(lead_id),
  event_type        text         NOT NULL,     -- QualifiedLead, QuoteAccepted, JobCompleted, JobPaid ...
  event_class       text         NOT NULL
                    CHECK (event_class IN ('qualification','revenue')),
  grok_audit_id     uuid         REFERENCES grok_audit(audit_id),
  source_object     text         NOT NULL
                    CHECK (source_object IN ('lead','job','job_payment')),
  source_uuid       text,
  value             numeric(12,2) CHECK (value >= 0),
  currency          char(3),
  event_time        timestamptz  NOT NULL,     -- when the real event happened
  click_time        timestamptz,               -- original click, for age-limit checks
  attribution       jsonb        NOT NULL DEFAULT '{}'::jsonb,  -- snapshot of click IDs used
  user_data_hashed  jsonb        NOT NULL DEFAULT '{}'::jsonb,  -- hashed identifiers only
  match_method      text         NOT NULL DEFAULT 'none'
                    CHECK (match_method IN ('job_uuid','phone_hash','email_hash','fuzzy_flagged','none')),
  match_confidence  numeric(3,2) CHECK (match_confidence BETWEEN 0 AND 1),
  needs_review      boolean      NOT NULL DEFAULT false,
  meta_status       text         NOT NULL DEFAULT 'pending'
                    CHECK (meta_status IN ('pending','sent','failed','skipped_no_click_id','expired','not_applicable')),
  google_status     text         NOT NULL DEFAULT 'pending'
                    CHECK (google_status IN ('pending','sent','failed','skipped_no_click_id','expired','not_applicable')),
  meta_sent_at      timestamptz,
  google_sent_at    timestamptz,
  created_at        timestamptz  NOT NULL DEFAULT now(),
  updated_at        timestamptz  NOT NULL DEFAULT now(),

  CONSTRAINT events_uq_event_id UNIQUE (event_id),
  CONSTRAINT events_event_id_format CHECK (event_id ~ '^[0-9a-f]{64}$'),
  -- Rule 4, enforced structurally: revenue events can never reference Grok.
  CONSTRAINT events_revenue_no_grok
    CHECK (event_class = 'qualification' OR grok_audit_id IS NULL),
  -- Revenue events must carry a real value and currency.
  CONSTRAINT events_revenue_has_value
    CHECK (event_class <> 'revenue' OR (value IS NOT NULL AND currency IS NOT NULL))
);

CREATE INDEX events_loc_time_idx  ON events (location_id, event_time DESC);
CREATE INDEX events_lead_idx      ON events (lead_id);
CREATE INDEX events_source_idx    ON events (source_object, source_uuid);
CREATE INDEX events_meta_todo_idx   ON events (created_at) WHERE meta_status IN ('pending','failed');
CREATE INDEX events_google_todo_idx ON events (created_at) WHERE google_status IN ('pending','failed');
CREATE INDEX events_review_idx    ON events (location_id, created_at) WHERE needs_review;

CREATE TRIGGER trg_events_updated_at
  BEFORE UPDATE ON events
  FOR EACH ROW EXECUTE FUNCTION set_updated_at();

-- ---------------------------------------------------------------------
-- 7. dispatch_attempts (one row per send attempt per destination)
-- ---------------------------------------------------------------------
CREATE TABLE dispatch_attempts (
  attempt_id        bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  event_pk          uuid        NOT NULL REFERENCES events(event_pk) ON DELETE CASCADE,
  location_id       text        NOT NULL REFERENCES locations(location_id),
  destination       text        NOT NULL CHECK (destination IN ('meta','google')),
  attempt_no        integer     NOT NULL,
  request_summary   jsonb,                 -- hashed fields only, no raw PII
  http_status       integer,
  response_body     jsonb,
  outcome           text        NOT NULL
                    CHECK (outcome IN ('success','retryable_error','permanent_error','skipped')),
  error_message     text,
  duration_ms       integer,
  attempted_at      timestamptz NOT NULL DEFAULT now(),
  CONSTRAINT dispatch_attempts_uq UNIQUE (event_pk, destination, attempt_no)
);

CREATE INDEX dispatch_attempts_event_idx ON dispatch_attempts (event_pk, attempted_at DESC);
CREATE INDEX dispatch_attempts_fail_idx  ON dispatch_attempts (location_id, attempted_at DESC)
  WHERE outcome IN ('retryable_error','permanent_error');

-- ---------------------------------------------------------------------
-- 8. alerts (throttling and escalation state)
--    Upsert pattern, max one notification per signature per 15 minutes:
--      INSERT INTO alerts (...) VALUES (...)
--      ON CONFLICT (error_signature) WHERE status IN ('open','acknowledged')
--      DO UPDATE SET occurrence_count = alerts.occurrence_count + 1,
--                    last_seen_at = now();
--    Then notify only if last_notified_at IS NULL OR < now() - interval '15 minutes'.
-- ---------------------------------------------------------------------
CREATE TABLE alerts (
  alert_id            bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  location_id         text        REFERENCES locations(location_id),   -- NULL = global
  severity            text        NOT NULL CHECK (severity IN ('CRITICAL','WARNING','INFO')),
  error_signature     text        NOT NULL,   -- e.g. sha256(workflow|node|error class|location_id)
  workflow_name       text,
  node_name           text,
  execution_url       text,
  entity_type         text        CHECK (entity_type IN ('lead','job','event','outbox')),
  entity_id           text,
  message             text        NOT NULL,
  suggested_action    text,
  status              text        NOT NULL DEFAULT 'open'
                      CHECK (status IN ('open','acknowledged','resolved')),
  occurrence_count    integer     NOT NULL DEFAULT 1,
  first_seen_at       timestamptz NOT NULL DEFAULT now(),
  last_seen_at        timestamptz NOT NULL DEFAULT now(),
  last_notified_at    timestamptz,
  escalated_at        timestamptz,            -- second channel for unacknowledged CRITICAL
  acknowledged_at     timestamptz,
  acknowledged_by     text,
  resolved_at         timestamptz
);

CREATE UNIQUE INDEX alerts_uq_open_signature
  ON alerts (error_signature) WHERE status IN ('open','acknowledged');
CREATE INDEX alerts_open_idx
  ON alerts (severity, last_seen_at DESC) WHERE status = 'open';
CREATE INDEX alerts_loc_idx
  ON alerts (location_id, last_seen_at DESC);

-- ---------------------------------------------------------------------
-- 9. dead_letter (rows that exhausted retries; needs a human)
-- ---------------------------------------------------------------------
CREATE TABLE dead_letter (
  dl_id             bigint      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  location_id       text        REFERENCES locations(location_id),
  source_table      text        NOT NULL CHECK (source_table IN ('outbox','events')),
  source_id         text        NOT NULL,
  kind              text,
  payload           jsonb,                    -- REDACTED, no raw PII
  reason            text        NOT NULL,
  last_error        text,
  attempts          integer,
  alert_id          bigint      REFERENCES alerts(alert_id),
  created_at        timestamptz NOT NULL DEFAULT now(),
  resolved_at       timestamptz,
  resolved_by       text,
  resolution_note   text
);

-- One open dead-letter record per source row.
CREATE UNIQUE INDEX dead_letter_uq_open
  ON dead_letter (source_table, source_id) WHERE resolved_at IS NULL;
CREATE INDEX dead_letter_open_idx
  ON dead_letter (location_id, created_at DESC) WHERE resolved_at IS NULL;
