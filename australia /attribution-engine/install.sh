#!/usr/bin/env bash
# Attribution engine installer: database schema, first location, n8n credentials, 8 workflows (imported with fixed IDs and published).
# Run on the machine that hosts n8n (native or Docker). Usage:  cp .env.example .env && nano .env && ./install.sh
set -euo pipefail
cd "$(dirname "$0")"
# Read .env as plain KEY=VALUE lines (no shell evaluation, so values may contain spaces, no quotes needed)
if [ -f .env ]; then
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue;; esac
    key="${line%%=*}"; val="${line#*=}"; val="${val%\"}"; val="${val#\"}"
    case "$key" in *[!A-Za-z0-9_]*|'') continue;; esac
    export "$key=$val"
  done < .env
fi

say() { printf '\n== %s\n' "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
: "${DATABASE_URL:?Set DATABASE_URL in .env}"
for c in psql python3; do command -v "$c" >/dev/null || die "$c is required"; done
N8N_DOCKER_CONTAINER="${N8N_DOCKER_CONTAINER:-}"
if [ -n "$N8N_DOCKER_CONTAINER" ]; then command -v docker >/dev/null || die "docker not found"; else command -v n8n >/dev/null || die "n8n CLI not found (native install). For Docker set N8N_DOCKER_CONTAINER in .env"; fi
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT

n8n_cli() { if [ -n "$N8N_DOCKER_CONTAINER" ]; then docker exec -u node "$N8N_DOCKER_CONTAINER" n8n "$@"; else n8n "$@"; fi; }

say "1/6 Database schema"
if [ "$(psql "$DATABASE_URL" -Atc "select to_regclass('public.locations') is not null")" = "t" ] && [ "${FORCE_SCHEMA:-0}" != "1" ]; then
  echo "tables already exist, skipping (set FORCE_SCHEMA=1 to re-apply; it is not destructive-safe on a live DB)"
else
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f db/schema.sql && echo "schema applied"
fi

say "2/6 First location"
if [ -n "${LOCATION_ID:-}" ]; then
  python3 - > "$WORK/location.sql" <<'PY'
import os, json
def q(s): return "'" + str(s).replace("'", "''") + "'"
e = os.environ
lst = lambda k: [x.strip() for x in e.get(k, '').split(',') if x.strip()]
area = {"default_country_calling_code": e.get("LOCATION_CALLING_CODE", ""), "postcodes": lst("LOCATION_POSTCODES")}
types = "{" + ",".join('"' + t.replace('"', '') + '"' for t in lst("LOCATION_SERVICE_TYPES")) + "}"
print("INSERT INTO locations (location_id,name,timezone,currency,servicem8_credential_ref,slack_channel,service_types,service_area) VALUES (%s,%s,%s,%s,%s,%s,%s,%s::jsonb) ON CONFLICT (location_id) DO NOTHING;" % (
  q(e["LOCATION_ID"].lower()), q(e.get("LOCATION_NAME", e["LOCATION_ID"])), q(e.get("LOCATION_TIMEZONE", "UTC")), q(e.get("LOCATION_CURRENCY", "USD")),
  q(e.get("LOCATION_SM8_ENV", "SM8_KEY_" + e["LOCATION_ID"].upper().replace("-", "_"))), "NULLIF(%s,'')" % q(e.get("LOCATION_SLACK_CHANNEL", "")), q(types), q(json.dumps(area))))
PY
  psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -f "$WORK/location.sql" && echo "location ${LOCATION_ID} ready"
else echo "LOCATION_ID empty: skipped (insert rows into locations yourself, see db/seed.example.sql)"; fi

say "3/6 Secrets"
if [ -z "${PII_ENCRYPTION_KEY:-}" ]; then
  PII_ENCRYPTION_KEY="$(python3 -c 'import secrets;print(secrets.token_hex(32))')"
  touch .env; printf '\nPII_ENCRYPTION_KEY=%s\n' "$PII_ENCRYPTION_KEY" >> .env; chmod 600 .env
  echo "generated PII_ENCRYPTION_KEY and saved it to .env (back it up now)"
fi
[ -n "${INTAKE_SECRET:-}" ] || { INTAKE_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(24))')"; printf '\nINTAKE_SECRET=%s\n' "$INTAKE_SECRET" >> .env; echo "generated INTAKE_SECRET and saved it to .env"; }
[ -n "${XAI_API_KEY:-}" ] || echo "WARNING: XAI_API_KEY empty. Grok calls will fail and the rules fallback will decide until you set the xAI credential in n8n."

say "4/6 n8n credentials"
export WORK
python3 - <<'PY'
import os, json
from urllib.parse import urlparse, unquote
e = os.environ
u = urlparse(e["DATABASE_URL"]); host = u.hostname or "localhost"
local = host in ("localhost", "127.0.0.1", "::1")
mode = e.get("PGSSLMODE") or ("disable" if local else "require")
ssl = "disable" if mode in ("disable", "") else ("allow" if mode == "allow" else "require")
creds = [
 {"id": "AttrCredPostgres1", "name": "Attribution Postgres", "type": "postgres", "data": {"host": host, "port": u.port or 5432, "database": (u.path or "/postgres").lstrip("/") or "postgres",
   "user": unquote(u.username or "postgres"), "password": unquote(u.password or ""), "ssl": ssl, "allowUnauthorizedCerts": ssl == "require" and not local, "maxConnections": 10, "sshTunnel": False}},
 {"id": "AttrCredXai00001", "name": "xAI API key", "type": "httpHeaderAuth", "data": {"name": "Authorization", "value": "Bearer " + e.get("XAI_API_KEY", "REPLACE_ME")}},
 {"id": "AttrCredWebhook01", "name": "Lead intake webhook secret", "type": "httpHeaderAuth", "data": {"name": "X-Intake-Secret", "value": e["INTAKE_SECRET"]}},
]
if e.get("SLACK_BOT_TOKEN"):
    creds.append({"id": "AttrCredSlack0001", "name": "Slack account", "type": "slackApi", "data": {"accessToken": e["SLACK_BOT_TOKEN"]}})
json.dump(creds, open(os.path.join(e["WORK"], "creds.json"), "w"))
# patch the workflow files with the credential ids above
os.makedirs(os.path.join(e["WORK"], "wf"))
src = "workflows"
for fn in sorted(os.listdir(src)):
    if not fn.endswith(".json"): continue
    d = json.load(open(os.path.join(src, fn)))
    for n in d["nodes"]:
        c = n.get("credentials") or {}
        if "postgres" in c: c["postgres"] = {"id": "AttrCredPostgres1", "name": "Attribution Postgres"}
        if "httpHeaderAuth" in c:
            webhook = n["type"].endswith(".webhook")
            c["httpHeaderAuth"] = {"id": "AttrCredWebhook01" if webhook else "AttrCredXai00001", "name": "Lead intake webhook secret" if webhook else "xAI API key"}
        if "slackApi" in c:
            if e.get("SLACK_BOT_TOKEN"): c["slackApi"] = {"id": "AttrCredSlack0001", "name": "Slack account"}
            else: n["credentials"].pop("slackApi")  # no token: Slack node stays unauthenticated, alerts remain in the DB
    json.dump(d, open(os.path.join(e["WORK"], "wf", fn), "w"))
PY
if [ -n "$N8N_DOCKER_CONTAINER" ]; then
  docker exec "$N8N_DOCKER_CONTAINER" rm -rf /tmp/attr && docker exec "$N8N_DOCKER_CONTAINER" mkdir -p /tmp/attr
  docker cp "$WORK/creds.json" "$N8N_DOCKER_CONTAINER":/tmp/attr/creds.json; docker cp "$WORK/wf" "$N8N_DOCKER_CONTAINER":/tmp/attr/wf
  CRED=/tmp/attr/creds.json; WFD=/tmp/attr/wf
else CRED="$WORK/creds.json"; WFD="$WORK/wf"; fi
n8n_cli import:credentials --input="$CRED" 2>&1 | grep -vi "confluence" | tail -3

say "5/6 Workflows (fixed IDs so Execute Workflow references resolve)"
n8n_cli import:workflow --separate --input="$WFD" 2>&1 | grep -vi "confluence" | tail -3
for id in AttrWf00aConfig1 AttrWf00bPhone01 AttrWf00cHashPii AttrWf00dEventId AttrWf00eGrokCal AttrWf00fAlert01 AttrWf02GrokQual AttrWf01Intake01; do
  n8n_cli publish:workflow --id="$id" 2>&1 | grep -vi confluence | grep -iE "error|cannot|not found" || true
done
echo "imported and published 8 workflows"

say "6/6 What you must do now"
cat <<MSG
Set these environment variables on the n8n process, then RESTART n8n (publish/import take effect on restart):

  N8N_BLOCK_ENV_ACCESS_IN_NODE=false
  PII_ENCRYPTION_KEY=<the value in .env>
  XAI_MODEL=${XAI_MODEL:-grok-4}
  SLACK_DEFAULT_CHANNEL=${SLACK_DEFAULT_CHANNEL:-}
  ${LOCATION_SM8_ENV:-SM8_KEY_<LOCATION>}=<that location's ServiceM8 API key>

Docker: add them with -e (or your compose file) and recreate the container; 'docker restart' does not pick up new env vars.
If you imported older copies of these workflows through the n8n UI, delete/archive them first: their IDs differ and they will not call each other.

Intake endpoint:  POST <your-n8n-url>/webhook/lead-intake   header  X-Intake-Secret: <INTAKE_SECRET in .env>
MSG
