# SQL for n8n Postgres nodes. n8n passes every parameter as text, so every use is cast explicitly.

LOAD_LOCATION = r'''SELECT * FROM locations WHERE location_id = $1::text AND active LIMIT 1;'''

# $1 ctx (with pii) json text, $2 encryption key, $3 locked_by
INSERT_OUTBOX_CLAIM = r'''WITH c AS (SELECT $1::jsonb AS j, $2::text AS k),
ins AS (
  INSERT INTO outbox (location_id, kind, dedupe_key, payload, status, attempt_count, locked_at, locked_by)
  SELECT j->>'location_id', 'lead_intake', 'lead:' || (j->>'location_id') || ':' || (j->>'payload_hash'),
         (j - 'pii') || jsonb_build_object('pii_enc', encode(pgp_sym_encrypt((j->'pii')::text, k), 'hex')),
         'processing', 1, now(), $3::text
  FROM c
  ON CONFLICT (dedupe_key) DO NOTHING
  RETURNING outbox_id, payload
)
SELECT outbox_id, payload, true AS claimed FROM ins
UNION ALL
SELECT NULL::bigint, NULL::jsonb, false WHERE NOT EXISTS (SELECT 1 FROM ins);'''

# $1 location_id, $2 raw body json text, $3 errors json text, $4 key
PARK_REJECTED = r'''INSERT INTO outbox (location_id, kind, dedupe_key, payload, status, attempt_count, last_error)
SELECT $1::text, 'lead_intake', 'lead_rejected:' || $1::text || ':' || md5($2::text),
       jsonb_build_object('errors', $3::jsonb, 'raw_enc', encode(pgp_sym_encrypt($2::text, $4::text), 'hex')),
       'dead', 0, 'validation_rejected'
ON CONFLICT (dedupe_key) DO NOTHING
RETURNING outbox_id;'''

# $1 ctx json text (pii_enc present, no raw pii), $2 key
UPSERT_LEAD = r'''WITH c AS (SELECT $1::jsonb AS j, $2::text AS k),
p AS (
  SELECT k,
         j->>'location_id' AS loc,
         NULLIF(j->>'hashed_phone', '') AS hp,
         NULLIF(j->>'hashed_email', '') AS he,
         (j->>'occurred_at')::timestamptz AS ts,
         j->>'channel' AS channel,
         j->'tracking' AS t,
         pgp_sym_decrypt(decode(j->>'pii_enc', 'hex'), k)::jsonb AS pii
  FROM c
),
bp AS (SELECT l.lead_id FROM leads l, p WHERE l.location_id = p.loc AND p.hp IS NOT NULL AND l.hashed_phone = p.hp AND l.merged_into IS NULL LIMIT 1),
be AS (SELECT l.lead_id FROM leads l, p WHERE l.location_id = p.loc AND p.he IS NOT NULL AND l.hashed_email = p.he AND l.merged_into IS NULL LIMIT 1),
tgt AS (
  SELECT COALESCE((SELECT lead_id FROM bp), (SELECT lead_id FROM be)) AS lead_id,
         ((SELECT lead_id FROM bp) IS NOT NULL AND (SELECT lead_id FROM be) IS NOT NULL
          AND (SELECT lead_id FROM bp) <> (SELECT lead_id FROM be)) AS conflict
),
prior AS (SELECT l.lead_id, l.status AS prior_status FROM leads l, tgt WHERE l.lead_id = tgt.lead_id),
upd AS (
  UPDATE leads l SET
    hashed_phone       = COALESCE(l.hashed_phone, p.hp),
    hashed_email       = CASE WHEN tgt.conflict THEN l.hashed_email ELSE COALESCE(l.hashed_email, p.he) END,
    phone_enc          = COALESCE(l.phone_enc, CASE WHEN p.pii->>'phone' IS NOT NULL THEN pgp_sym_encrypt(p.pii->>'phone', p.k)::bytea END),
    email_enc          = COALESCE(l.email_enc, CASE WHEN p.pii->>'email' IS NOT NULL AND NOT tgt.conflict THEN pgp_sym_encrypt(p.pii->>'email', p.k)::bytea END),
    name_enc           = COALESCE(l.name_enc,  CASE WHEN p.pii->>'name'  IS NOT NULL THEN pgp_sym_encrypt(p.pii->>'name',  p.k)::bytea END),
    first_touch_at     = COALESCE(l.first_touch_at, p.ts),
    first_channel      = COALESCE(l.first_channel, p.channel),
    first_gclid        = COALESCE(l.first_gclid,   p.t->>'gclid'),
    first_gbraid       = COALESCE(l.first_gbraid,  p.t->>'gbraid'),
    first_wbraid       = COALESCE(l.first_wbraid,  p.t->>'wbraid'),
    first_fbclid       = COALESCE(l.first_fbclid,  p.t->>'fbclid'),
    first_fbp          = COALESCE(l.first_fbp,     p.t->>'fbp'),
    first_fbc          = COALESCE(l.first_fbc,     p.t->>'fbc'),
    first_msclkid      = COALESCE(l.first_msclkid, p.t->>'msclkid'),
    first_utm          = COALESCE(l.first_utm,     NULLIF(p.t->'utm', '{}'::jsonb)),
    first_landing_page = COALESCE(l.first_landing_page, p.t->>'landing_page'),
    first_referrer     = COALESCE(l.first_referrer,     p.t->>'referrer'),
    last_touch_at      = GREATEST(COALESCE(l.last_touch_at, p.ts), p.ts),
    attribution_status = CASE WHEN COALESCE(l.first_gclid, p.t->>'gclid', l.first_gbraid, p.t->>'gbraid', l.first_wbraid, p.t->>'wbraid',
                                            l.first_fbclid, p.t->>'fbclid', l.first_fbc, p.t->>'fbc', l.first_msclkid, p.t->>'msclkid') IS NOT NULL
                              THEN 'attributed' ELSE 'unattributed' END,
    status             = CASE WHEN l.status IN ('new','qualifying','needs_review','unqualified') THEN 'qualifying' ELSE l.status END
  FROM tgt, p
  WHERE l.lead_id = tgt.lead_id
  RETURNING l.lead_id, l.status
),
ins AS (
  INSERT INTO leads (location_id, hashed_phone, hashed_email, phone_enc, email_enc, name_enc,
                     first_touch_at, first_channel, first_gclid, first_gbraid, first_wbraid, first_fbclid, first_fbp, first_fbc, first_msclkid,
                     first_utm, first_landing_page, first_referrer, last_touch_at, attribution_status, status)
  SELECT p.loc, p.hp, p.he,
         CASE WHEN p.pii->>'phone' IS NOT NULL THEN pgp_sym_encrypt(p.pii->>'phone', p.k)::bytea END,
         CASE WHEN p.pii->>'email' IS NOT NULL THEN pgp_sym_encrypt(p.pii->>'email', p.k)::bytea END,
         CASE WHEN p.pii->>'name'  IS NOT NULL THEN pgp_sym_encrypt(p.pii->>'name',  p.k)::bytea END,
         p.ts, p.channel, p.t->>'gclid', p.t->>'gbraid', p.t->>'wbraid', p.t->>'fbclid', p.t->>'fbp', p.t->>'fbc', p.t->>'msclkid',
         NULLIF(p.t->'utm', '{}'::jsonb), p.t->>'landing_page', p.t->>'referrer', p.ts,
         CASE WHEN COALESCE(p.t->>'gclid', p.t->>'gbraid', p.t->>'wbraid', p.t->>'fbclid', p.t->>'fbc', p.t->>'msclkid') IS NOT NULL
              THEN 'attributed' ELSE 'unattributed' END,
         'qualifying'
  FROM p, tgt
  WHERE tgt.lead_id IS NULL
  ON CONFLICT DO NOTHING
  RETURNING lead_id, status
)
SELECT u.lead_id, u.status, pr.prior_status, false AS is_new, tgt.conflict AS identity_conflict
FROM upd u JOIN prior pr ON pr.lead_id = u.lead_id CROSS JOIN tgt
UNION ALL
SELECT i.lead_id, i.status, NULL::text, true, false FROM ins i;'''

# $1 ctx json text, $2 lead_id, $3 is_first
APPEND_TOUCH = r'''INSERT INTO lead_touches (lead_id, location_id, is_first, channel, occurred_at, gclid, gbraid, wbraid, fbclid, fbp, fbc, msclkid,
                          utm, landing_page, referrer, raw_payload, payload_hash)
SELECT $2::uuid, j->>'location_id', ($3::boolean OR NOT EXISTS (SELECT 1 FROM lead_touches t0 WHERE t0.lead_id = $2::uuid)), j->>'channel', (j->>'occurred_at')::timestamptz,
       j->'tracking'->>'gclid', j->'tracking'->>'gbraid', j->'tracking'->>'wbraid', j->'tracking'->>'fbclid',
       j->'tracking'->>'fbp', j->'tracking'->>'fbc', j->'tracking'->>'msclkid',
       COALESCE(j->'tracking'->'utm', '{}'::jsonb), j->'tracking'->>'landing_page', j->'tracking'->>'referrer',
       j - 'pii' - 'pii_enc', j->>'payload_hash'
FROM (SELECT $1::jsonb AS j) q
ON CONFLICT (lead_id, payload_hash) DO NOTHING
RETURNING touch_id;'''

# $1 json {event_id, location_id, lead_id, hashed_phone_meta}
INSERT_QUALIFIED_EVENT = r'''WITH c AS (SELECT $1::jsonb AS j),
e AS (
  INSERT INTO events (event_id, location_id, lead_id, event_type, event_class, grok_audit_id, source_object, source_uuid,
                      currency, event_time, click_time, attribution, user_data_hashed, match_method, match_confidence)
  SELECT j->>'event_id', j->>'location_id', l.lead_id, 'QualifiedLead', 'qualification',
         (SELECT g.audit_id FROM grok_audit g WHERE g.lead_id = l.lead_id AND g.decision = 'qualified' ORDER BY g.created_at DESC LIMIT 1),
         'lead', l.lead_id::text,
         (SELECT currency FROM locations WHERE location_id = j->>'location_id'),
         now(), l.first_touch_at,
         jsonb_strip_nulls(jsonb_build_object('gclid', l.first_gclid, 'gbraid', l.first_gbraid, 'wbraid', l.first_wbraid,
                                              'fbclid', l.first_fbclid, 'fbp', l.first_fbp, 'fbc', l.first_fbc, 'msclkid', l.first_msclkid)),
         jsonb_strip_nulls(jsonb_build_object('em', l.hashed_email, 'ph', l.hashed_phone, 'ph_meta', NULLIF(j->>'hashed_phone_meta', ''))),
         'none', 1.00
  FROM c JOIN leads l ON l.lead_id = (j->>'lead_id')::uuid
  ON CONFLICT (event_id) DO NOTHING
  RETURNING event_pk
),
d AS (
  INSERT INTO outbox (location_id, kind, dedupe_key, payload)
  SELECT j->>'location_id', 'dispatch', 'dispatch:' || (j->>'event_id'),
         jsonb_build_object('event_id', j->>'event_id', 'event_class', 'qualification')
  FROM c
  ON CONFLICT (dedupe_key) DO NOTHING
  RETURNING outbox_id
)
SELECT (SELECT count(*) FROM e)::int AS event_inserted, (SELECT count(*) FROM d)::int AS dispatch_queued;'''

# $1 pii_enc hex, $2 key, $3 lead_id
LOAD_PII_SM8_STATE = r'''SELECT pgp_sym_decrypt(decode($1::text, 'hex'), $2::text)::jsonb AS pii,
       l.servicem8_client_uuid, l.servicem8_job_uuid,
       md5($3::text || ':sm8:client')::uuid::text AS client_uuid_candidate,
       md5($3::text || ':sm8:job')::uuid::text    AS job_uuid_candidate
FROM leads l WHERE l.lead_id = $3::uuid;'''

# $1 lead_id, $2 client uuid, $3 job uuid
SAVE_SM8_IDS = r'''UPDATE leads
SET servicem8_client_uuid = COALESCE(servicem8_client_uuid, NULLIF($2::text, '')),
    servicem8_job_uuid    = COALESCE(servicem8_job_uuid,    NULLIF($3::text, ''))
WHERE lead_id = $1::uuid
RETURNING lead_id, servicem8_client_uuid, servicem8_job_uuid;'''

MARK_OUTBOX_DONE = r'''UPDATE outbox
SET status = 'done', processed_at = now(), locked_at = NULL, locked_by = NULL, last_error = NULL
WHERE outbox_id = $1::bigint
RETURNING outbox_id, status;'''

MARK_OUTBOX_FAILED = r'''UPDATE outbox
SET status = CASE WHEN attempt_count >= max_attempts THEN 'dead' ELSE 'failed' END,
    last_error = left($2::text, 2000),
    next_attempt_at = now() + make_interval(mins => LEAST(60, power(2, attempt_count)::int)),
    locked_at = NULL, locked_by = NULL
WHERE outbox_id = $1::bigint
RETURNING outbox_id, status, last_error;'''

# $1 json audit row
WRITE_GROK_AUDIT = r'''INSERT INTO grok_audit (lead_id, location_id, attempt_no, stage, model, prompt_version, schema_version, input_hash,
                        http_status, latency_ms, error_type, response_raw, parsed, is_spam, intent_score, qualified,
                        service_type, urgency, reason, confidence, decision)
SELECT (j->>'lead_id')::uuid, j->>'location_id',
       COALESCE((SELECT max(attempt_no) FROM grok_audit WHERE lead_id = (j->>'lead_id')::uuid), 0) + 1,
       j->>'stage', j->>'model', j->>'prompt_version', j->>'schema_version', NULLIF(j->>'input_hash', ''),
       (j->>'http_status')::int, (j->>'latency_ms')::int, COALESCE(j->>'error_type', 'none'), j->>'response_raw',
       NULLIF(j->'parsed', 'null'::jsonb), (j->>'is_spam')::boolean, (j->>'intent_score')::smallint, (j->>'qualified')::boolean,
       j->>'service_type', j->>'urgency', j->>'reason', (j->>'confidence')::numeric, NULLIF(j->>'decision', '')
FROM (SELECT $1::jsonb AS j) q
RETURNING *;'''

# $1 json finalize item
UPDATE_LEAD_DECISION = r'''UPDATE leads
SET status = j->>'decision',
    qualification_source = j->>'source',
    intent_score = (j->>'intent_score')::smallint,
    service_type = j->>'service_type',
    urgency = j->>'urgency',
    qualified_at = CASE WHEN j->>'decision' = 'qualified' THEN COALESCE(qualified_at, now()) ELSE qualified_at END
FROM (SELECT $1::jsonb AS j) q
WHERE lead_id = (j->>'lead_id')::uuid
RETURNING lead_id, status;'''

# $1 json {location_id, severity, error_signature, workflow_name, node_name, execution_url, entity_type, entity_id, message, suggested_action}
# Dedupes on the open/acknowledged signature; should_notify is true for a new alert or when the last notification is >15 min old.
RAISE_ALERT = r'''WITH c AS (SELECT $1::jsonb AS j),
prev AS (SELECT a.last_notified_at FROM alerts a, c WHERE a.error_signature = c.j->>'error_signature' AND a.status IN ('open','acknowledged')),
up AS (
INSERT INTO alerts (location_id, severity, error_signature, workflow_name, node_name, execution_url, entity_type, entity_id, message, suggested_action, last_notified_at)
SELECT NULLIF(j->>'location_id',''), COALESCE(NULLIF(j->>'severity',''),'WARNING'), j->>'error_signature', j->>'workflow_name', j->>'node_name',
       j->>'execution_url', NULLIF(j->>'entity_type',''), j->>'entity_id', left(j->>'message', 2000), j->>'suggested_action', now()
FROM c
ON CONFLICT (error_signature) WHERE status IN ('open','acknowledged')
DO UPDATE SET occurrence_count = alerts.occurrence_count + 1, last_seen_at = now(),
              last_notified_at = CASE WHEN alerts.last_notified_at IS NULL OR alerts.last_notified_at < now() - interval '15 minutes' THEN now() ELSE alerts.last_notified_at END
RETURNING alert_id, severity, occurrence_count
)
SELECT up.alert_id, up.severity, up.occurrence_count,
       (NOT EXISTS (SELECT 1 FROM prev) OR EXISTS (SELECT 1 FROM prev WHERE last_notified_at IS NULL OR last_notified_at < now() - interval '15 minutes')) AS should_notify
FROM up;'''
