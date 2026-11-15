> Status and scope: see docs/STATUS.md. Items to verify: docs/VERIFY.md. Diagram: docs/architecture.png.

# Attribution engine: WF-00 (shared), WF-01 (Lead Intake), WF-02 (Grok Qualification)

Built against `schema.sql`. Tested on **n8n 2.35.7** (self-hosted, SQLite for n8n's own DB) and **PostgreSQL 16**.

## Files
| File | Purpose |
|---|---|
| WF-00a Get Location Config | `locations` row -> config (service area, thresholds, ServiceM8 key *name*, Slack channel) |
| WF-00b Normalize Phone | to E.164 using the location's default country code |
| WF-00c Hash PII | SHA-256 email/phone (phone hashed with and without "+") |
| WF-00d Build Event ID | `sha256(source_id:event_type:location_id)` |
| WF-00e Call Grok | strict JSON-schema call, timeout, exponential backoff (2/4/8 s), never throws |
| WF-00f Raise Alert | DB alert first (deduped, 15-min throttle), then Slack |
| WF-01 Lead Intake | webhook -> outbox claim -> lead upsert -> qualify -> QualifiedLead event -> ServiceM8 |
| WF-02 Grok Qualification | Grok -> validate -> one re-prompt -> rules fallback -> `needs_review` |

## Install (one script)
On the machine that runs n8n (native or Docker), with `psql` and `python3` available:

    cp .env.example .env     # fill in DATABASE_URL, XAI_API_KEY, location values (INTAKE_SECRET and PII_ENCRYPTION_KEY are generated if empty)
    ./install.sh

It applies `db/schema.sql`, seeds the first location, creates the n8n credentials (Postgres, xAI, webhook secret, optional Slack), imports the 8 workflows with fixed IDs and publishes them. Then set the printed environment variables on the n8n process and restart n8n. Docker: set `N8N_DOCKER_CONTAINER` in `.env`; new env vars need the container recreated, not just restarted.

Notes:
- Do not paste several workflow files into one canvas and do not import through the UI: that merges sub-workflows into a single workflow and changes their IDs, so Execute Workflow nodes cannot find them. Use `install.sh` (or `n8n import:workflow --separate`).
- Every sub-workflow must be published (n8n 2.x refuses to run an unpublished one).
- Supabase/managed Postgres: use the direct (5432) or session-pooler connection, not the transaction pooler.
- n8n Cloud is not supported as-is: it has no CLI and no custom environment variables (`$env`), which the PII key and per-location ServiceM8 keys rely on.
- Publish to GitHub: `./publish-github.sh attribution-engine private` (needs the GitHub CLI).

Manual steps if you prefer: (1) load `db/schema.sql`, (2) insert a `locations` row (`db/seed.example.sql`), (3) create the credentials, (4) `workflows/import.sh`, (5) assign credentials, (6) set env vars: `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`, `PII_ENCRYPTION_KEY` (32+ chars, back it up), `XAI_MODEL`, `XAI_TIMEOUT_MS`, `SLACK_DEFAULT_CHANNEL`, one ServiceM8 key variable per location.

Example location row:

```sql
INSERT INTO locations (location_id, name, timezone, currency, servicem8_credential_ref, slack_channel, service_types, service_area)
VALUES ('au-syd','Sydney Plumbing','Australia/Sydney','AUD','SM8_KEY_AU_SYD','C0123456789','{plumbing,"hot water"}',
 '{"default_country_calling_code":"61","postcodes":["2000","2010"],"qualification":{"min_job_signals":["burst","quote"],"notes":"No commercial work.","intent_min":60,"confidence_min":0.6}}');
```

## Intake payload (POST `/webhook/lead-intake`, header secret required)
`location_id`, `channel` (form|calculator|chat|sms|whatsapp), `contact{name,email,phone}`, `message`, `postcode`, `service_requested`, `calculator{}`, `tracking{gclid,gbraid,wbraid,fbclid,fbp,fbc,msclkid,utm{},landing_page,referrer}`, `submission_id` (recommended: exact replay key), `honeypot`, `form_time_ms`, `occurred_at`.

## How the rules are met
- **Idempotency**: outbox `dedupe_key` (replays stop at the claim), lead match by hashed phone then email, `UNIQUE(lead_id,payload_hash)` touches, `events.event_id` UNIQUE with deterministic id.
- **DB before external**: outbox claim is the first write; the QualifiedLead event and dispatch row are written before ServiceM8 is called; every Grok attempt is in `grok_audit` before the lead status changes.
- **Respond fast**: webhook answers immediately (`onReceived`); all work is async. It returns HTTP 200, not 202 (n8n ignores the custom code in this mode).
- **Grok never blocks revenue**: it only sets lead status. Timeouts, 429, 5xx, malformed output all end in the rules fallback; the event schema forbids revenue events from referencing Grok.
- **PII**: hashed in WF-00c; raw PII only inside `pgp_sym_encrypt` blobs; redacted message goes to Grok. Verified by query: no raw email/phone/name in outbox, touches or events.
- **HTTP nodes**: timeout + retry config + error output + logging on xAI (custom backoff loop instead of the fixed-delay built-in retry), ServiceM8 (15 s, 3 tries, error output -> outbox failed + alert), Slack (10 s, 3 tries, error output logged; the alert row already exists).
- **No hardcoded secrets**: credentials and env vars; all location values from `locations`.

## Test results (all run, all passed)
- 22 + 13 Code-node unit tests (SHA fallback = Node crypto, phone normaliser, hashing, validation, fallback rules, retry/backoff, ServiceM8 planning).
- SQL against real Postgres 16: claim/replay, first-touch, identity conflict, touch dedupe, audit, event + dispatch idempotency, outbox retry/dead ladder, alert throttle.
- 38 end-to-end checks in a real n8n with mock Grok / ServiceM8 / Slack: happy path, replay x3, phone-only, email-only, invalid payload (parked), unknown location, bad/missing secret (403), unqualified, spam, low confidence -> needs_review + alert, malformed -> re-prompt -> ok, malformed twice -> fallback, 429 then ok, 401 not retried, 5xx x4 -> fallback, timeout x4 -> fallback (27 s), second submission keeps first touch and is not re-scored or re-evented, ServiceM8 down (event kept, outbox `failed`, 3 tries, alert, nothing half-saved), Slack throttle, second location uses its own ServiceM8 key, prompt-injection text.

## VERIFY before go-live (not confirmed against live APIs)
1. xAI model id (`XAI_MODEL`, default `grok-4`), `json_schema` strict support and rate limits.
2. ServiceM8: endpoint paths (`company.json`, `companycontact.json`, `job.json`), `X-API-Key` auth, field names, and **whether a client-supplied `uuid` on create is honoured**. If it is not, a crash between create and save could create a duplicate client/job on redrive; the code reads `x-record-uuid` first and only falls back to the supplied uuid.
3. Meta and Google hash formats for phone (both variants are stored; dispatch is WF-05).
4. n8n behaviour on versions other than 2.35.7 (node typeVersions were chosen from that install).

## Known limits
- The `WF-01 (redrive)` entry (called by WF-07) is wired but untested end to end because WF-07 does not exist yet. The state it needs (outbox row, saved IDs) is verified.
- Execution data can contain raw PII in memory. Workflows save no successful executions; failed executions are saved, so set `EXECUTIONS_DATA_PRUNE=true` with a short `EXECUTIONS_DATA_MAX_AGE`.
- Alert `execution_url` is a relative path (`/workflow/<id>/executions/<id>`); it names the sub-workflow that raised it.
- WF-03..WF-08 and WF-99 are not built. Until WF-99 exists, set no error workflow; WF-00f records alerts itself.
