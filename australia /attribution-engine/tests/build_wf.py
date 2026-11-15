#!/usr/bin/env python3
"""Emit importable n8n workflow JSON for WF-00a..f, WF-01, WF-02.
Usage: build_wf.py OUTDIR [--pg-cred-id ID] [--grok-cred-id ID] [--slack-cred-id ID] [--webhook-cred-id ID]
                         [--xai-url URL] [--sm8-url URL] [--slack-url URL]
"""
import json, sys, os, uuid, argparse, hashlib
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import jscode as J
import sqlcode as S

ap = argparse.ArgumentParser()
ap.add_argument('outdir')
ap.add_argument('--pg-cred-id', default='REPLACE_WITH_CREDENTIAL_ID')
ap.add_argument('--grok-cred-id', default='REPLACE_WITH_CREDENTIAL_ID')
ap.add_argument('--slack-cred-id', default='REPLACE_WITH_CREDENTIAL_ID')
ap.add_argument('--webhook-cred-id', default='REPLACE_WITH_CREDENTIAL_ID')
ap.add_argument('--xai-url', default='https://api.x.ai/v1/chat/completions')
ap.add_argument('--sm8-url', default='https://api.servicem8.com/api_1.0')
ap.add_argument('--slack-url', default='https://slack.com/api/chat.postMessage')
A = ap.parse_args()

IDS = {  # fixed ids so Execute Workflow references survive a CLI import (n8n import:workflow keeps "id")
    '00a': 'AttrWf00aConfig1', '00b': 'AttrWf00bPhone01', '00c': 'AttrWf00cHashPii', '00d': 'AttrWf00dEventId',
    '00e': 'AttrWf00eGrokCal', '00f': 'AttrWf00fAlert01', '01': 'AttrWf01Intake01', '02': 'AttrWf02GrokQual',
}
NAMES = {
    '00a': 'WF-00a Get Location Config', '00b': 'WF-00b Normalize Phone', '00c': 'WF-00c Hash PII',
    '00d': 'WF-00d Build Event ID', '00e': 'WF-00e Call Grok', '00f': 'WF-00f Raise Alert',
    '01': 'WF-01 Lead Intake', '02': 'WF-02 Grok Qualification',
}


def nid(wf, name):
    return str(uuid.UUID(hashlib.md5((wf + '|' + name).encode()).hexdigest()))


class WF:
    def __init__(self, key):
        self.key = key
        self.nodes = []
        self.conns = {}
        self.names = set()

    def add(self, name, type_, ver, params, pos, **extra):
        assert name not in self.names, 'duplicate node ' + name
        self.names.add(name)
        n = {'parameters': params, 'id': nid(self.key, name), 'name': name, 'type': type_, 'typeVersion': ver, 'position': list(pos)}
        n.update(extra)
        self.nodes.append(n)
        return name

    def link(self, a, b, out=0):
        assert a in self.names and b in self.names, (a, b)
        m = self.conns.setdefault(a, {'main': []})['main']
        while len(m) <= out:
            m.append([])
        m[out].append({'node': b, 'type': 'main', 'index': 0})

    def chain(self, *names):
        for a, b in zip(names, names[1:]):
            self.link(a, b)

    def dump(self, extra_settings=None):
        settings = {'executionOrder': 'v1', 'saveManualExecutions': False, 'saveDataSuccessExecution': 'none',
                    'saveDataErrorExecution': 'all', 'executionTimeout': 300}
        settings.update(extra_settings or {})
        return {'id': IDS[self.key], 'name': NAMES[self.key], 'nodes': self.nodes, 'connections': self.conns,
                'active': False, 'pinData': {}, 'settings': settings, 'tags': [], 'meta': {'templateCredsSetupCompleted': False}}


# ---------------------------------------------------------------- helpers ---
def pos(c, r=0):
    return (c * 240, r * 170)


def code(w, name, js, p, **x):
    return w.add(name, 'n8n-nodes-base.code', 2, {'jsCode': js}, p, **x)


def pg(w, name, query, repl, p, always=False, onerror=None, notes=None):
    ex = {'credentials': {'postgres': {'id': A.pg_cred_id, 'name': 'Attribution Postgres'}}}
    if always:
        ex['alwaysOutputData'] = True
    if onerror:
        ex['onError'] = onerror
    if notes:
        ex['notes'] = notes
    return w.add(name, 'n8n-nodes-base.postgres', 2.5,
                 {'operation': 'executeQuery', 'query': query, 'options': {'queryReplacement': repl}}, p, **ex)


def cond(left, op_type, op, right=None, single=True):
    c = {'id': str(uuid.uuid4()), 'leftValue': left, 'rightValue': '' if right is None else right,
         'operator': {'type': op_type, 'operation': op}}
    if single:
        c['operator']['singleValue'] = True
    return c


def if_(w, name, conds, p, comb='and'):
    return w.add(name, 'n8n-nodes-base.if', 2.2, {'conditions': {
        'options': {'caseSensitive': True, 'leftValue': '', 'typeValidation': 'loose', 'version': 2},
        'conditions': conds, 'combinator': comb}, 'options': {}}, p)


def true_(expr):
    return cond(expr, 'boolean', 'true')


def call_wf(w, name, key, p, onerror=None):
    ex = {}
    if onerror:
        ex['onError'] = onerror
    return w.add(name, 'n8n-nodes-base.executeWorkflow', 1.2,
                 {'source': 'database', 'workflowId': {'__rl': True, 'value': IDS[key], 'mode': 'id'}, 'options': {}}, p, **ex)


def trigger(w, name, p):
    return w.add(name, 'n8n-nodes-base.executeWorkflowTrigger', 1.1, {'inputSource': 'passthrough'}, p)


def sticky(w, name, text, p, wd=420, ht=160, color=4):
    return w.add(name, 'n8n-nodes-base.stickyNote', 1, {'content': text, 'height': ht, 'width': wd, 'color': color}, p)


KEY = '$env.PII_ENCRYPTION_KEY'
wfs = {}

# ============================================================ WF-00a ========
w = WF('00a'); wfs['00a'] = w
trigger(w, 'When Called', pos(0))
pg(w, 'Load Location', S.LOAD_LOCATION, "={{ [ String($json.location_id || '').toLowerCase().trim() ] }}", pos(1), always=True)
code(w, 'Shape Config', J.LOCATION_SHAPE, pos(2))
w.chain('When Called', 'Load Location', 'Shape Config')
sticky(w, 'Note', '## Get Location Config\nInput: `{location_id}`. Output: `found` plus config. Missing or inactive location returns `found:false`. All per-location values (ServiceM8 key NAME, Meta/Google IDs, Slack channel, postcodes, thresholds) come from the `locations` table.', pos(0, -1.2), 560, 130)

# ============================================================ WF-00b ========
w = WF('00b'); wfs['00b'] = w
trigger(w, 'When Called', pos(0))
code(w, 'Normalize Phone', J.NORMALIZE_PHONE, pos(1))
w.chain('When Called', 'Normalize Phone')

# ============================================================ WF-00c ========
w = WF('00c'); wfs['00c'] = w
trigger(w, 'When Called', pos(0))
code(w, 'Hash PII', J.HASH_PII, pos(1))
w.chain('When Called', 'Hash PII')
sticky(w, 'Note', '## Hash PII\nSHA-256 of lower-cased email and E.164 phone. Phone is hashed two ways: with "+" (ledger/Google) and digits only (Meta). **VERIFY** both formats against current Meta and Google docs before go-live.', pos(0, -1.2), 560, 130)

# ============================================================ WF-00d ========
w = WF('00d'); wfs['00d'] = w
trigger(w, 'When Called', pos(0))
code(w, 'Build Event ID', J.BUILD_EVENT_ID, pos(1))
w.chain('When Called', 'Build Event ID')

# ============================================================ WF-00e ========
w = WF('00e'); wfs['00e'] = w
trigger(w, 'When Called', pos(0))
code(w, 'Build Request', J.GROK_BUILD_REQUEST, pos(1))
code(w, 'Prepare Attempt', J.GROK_PREPARE_ATTEMPT, pos(2))
w.add('Call xAI', 'n8n-nodes-base.httpRequest', 4.2, {
    'method': 'POST', 'url': A.xai_url, 'authentication': 'genericCredentialType', 'genericAuthType': 'httpHeaderAuth',
    'sendBody': True, 'contentType': 'raw', 'rawContentType': 'application/json',
    'body': '={{ JSON.stringify($json.request) }}',
    'options': {'timeout': '={{ $json.timeout_ms }}', 'response': {'response': {'fullResponse': True, 'neverError': True}}}},
    pos(3), onError='continueErrorOutput', retryOnFail=False,
    credentials={'httpHeaderAuth': {'id': A.grok_cred_id, 'name': 'xAI API key (Authorization: Bearer ...)'}},
    notes='Timeout from XAI_TIMEOUT_MS. Retries are NOT the built-in fixed-delay retry: the Wait loop below gives exponential backoff (2/4/8 s). Transport errors leave via the error output and are classified, not dropped.')
code(w, 'Classify Response', J.GROK_CLASSIFY, pos(4))
code(w, 'Retry Decision', J.GROK_RETRY_FLAG, pos(5))
if_(w, 'Retry?', [true_('={{ $json.retry }}')], pos(6))
code(w, 'Backoff Wait', r'''
// Exponential backoff sleep (2/4/8 s). A Code-node sleep is used instead of the Wait node, whose default unit is HOURS
// and silently becomes a multi-hour wait if the unit parameter is lost on import/export.
const it = $input.first().json;
const secs = Math.min(Math.max(Number(it.backoff_seconds) || 0, 0), 30);
await new Promise((resolve) => setTimeout(resolve, secs * 1000));
return [{ json: it }];
''', pos(6, 1.2))
code(w, 'Return', J.GROK_RETURN, pos(7))
w.chain('When Called', 'Build Request', 'Prepare Attempt', 'Call xAI')
w.link('Call xAI', 'Classify Response', 0)
w.link('Call xAI', 'Classify Response', 1)
w.chain('Classify Response', 'Retry Decision', 'Retry?')
w.link('Retry?', 'Backoff Wait', 0)
w.link('Retry?', 'Return', 1)
w.link('Backoff Wait', 'Prepare Attempt')
sticky(w, 'Note', '## Call Grok (shared)\nStrict JSON-schema request. Never throws to the caller: always returns `{ok, error_type, content_raw, ...}` so a Grok outage cannot stop lead intake or revenue events.\n**VERIFY**: xAI model id (env `XAI_MODEL`), `response_format: json_schema` support for that model, and current rate limits.', pos(0, -1.4), 640, 150)

# ============================================================ WF-00f ========
w = WF('00f'); wfs['00f'] = w
trigger(w, 'When Called', pos(0))
pg(w, 'Raise Alert', S.RAISE_ALERT, '={{ [ JSON.stringify($json) ] }}', pos(1), onerror='continueRegularOutput',
   notes='Alert is written to the DB first; Slack is best effort. 15-minute throttle per error_signature.')
if_(w, 'Should Notify?', [true_('={{ $json.should_notify === true }}')], pos(2))
pg(w, 'Load Slack Channel', "SELECT slack_channel FROM locations WHERE location_id = $1::text;",
   "={{ [ String($('When Called').first().json.location_id || '') ] }}", pos(3), always=True)
code(w, 'Build Slack Message', r'''
const a = $('When Called').first().json;
const r = $('Raise Alert').first().json;
const row = $input.first().json || {};
const channel = row.slack_channel || $env.SLACK_DEFAULT_CHANNEL || '';
const icon = { CRITICAL: ':rotating_light:', WARNING: ':warning:', INFO: ':information_source:' }[a.severity] || ':warning:';
const lines = [
  icon + ' *' + (a.severity || 'WARNING') + '* ' + (a.workflow_name || '') + (a.node_name ? ' / ' + a.node_name : '') + (a.location_id ? '  `' + a.location_id + '`' : ''),
  String(a.message || '').slice(0, 1500),
  a.suggested_action ? '_Action:_ ' + a.suggested_action : '',
  (r.occurrence_count > 1 ? 'Occurrences: ' + r.occurrence_count + '  ' : '') + (a.execution_url ? 'Execution: ' + a.execution_url : '')
].filter(Boolean);
return [{ json: { channel, text: lines.join('\n'), has_channel: !!channel } }];
''', pos(4))
if_(w, 'Has Channel?', [true_('={{ $json.has_channel }}')], pos(5))
w.add('Post to Slack', 'n8n-nodes-base.httpRequest', 4.2, {
    'method': 'POST', 'url': A.slack_url, 'authentication': 'predefinedCredentialType', 'nodeCredentialType': 'slackApi',
    'sendBody': True, 'contentType': 'json', 'specifyBody': 'json',
    'jsonBody': '={{ JSON.stringify({ channel: $json.channel, text: $json.text }) }}',
    'options': {'timeout': 10000, 'response': {'response': {'neverError': True}}}},
    pos(6), onError='continueErrorOutput', retryOnFail=True, maxTries=3, waitBetweenTries=2000,
    credentials={'slackApi': {'id': A.slack_cred_id, 'name': 'Slack account'}},
    notes='Timeout 10s, 3 tries. Failure goes to the error output and is only logged: the alert row already exists in the DB.')
w.add('Log Slack Failure', 'n8n-nodes-base.noOp', 1, {}, pos(7, 1.2), notes='Slack delivery failed; the alert is still stored in the alerts table.')
w.add('No Channel', 'n8n-nodes-base.noOp', 1, {}, pos(6, 1.2), notes='No locations.slack_channel and no SLACK_DEFAULT_CHANNEL: alert stored in DB only.')
w.chain('When Called', 'Raise Alert', 'Should Notify?')
w.link('Should Notify?', 'Load Slack Channel', 0)
w.chain('Load Slack Channel', 'Build Slack Message', 'Has Channel?')
w.link('Has Channel?', 'Post to Slack', 0)
w.link('Has Channel?', 'No Channel', 1)
w.link('Post to Slack', 'Log Slack Failure', 1)

# ============================================================ WF-02 =========
w = WF('02'); wfs['02'] = w
T = 'When Called by WF-01'
trigger(w, T, pos(0))
call_wf(w, 'Get Location Config', '00a', pos(1))
code(w, 'Build Prompt', J.BUILD_PROMPT, pos(2))
call_wf(w, 'Call Grok (attempt 1)', '00e', pos(3), onerror='continueRegularOutput')
code(w, 'Parse + Validate 1', J.PARSE_VALIDATE.replace('__STAGE__', 'grok'), pos(4))
AUD = lambda n: "={{ [ JSON.stringify($json) ] }}"
pg(w, 'Write Audit 1', S.WRITE_GROK_AUDIT, AUD(1), pos(5))
if_(w, 'Valid Decision 1?', [cond('={{ $json.decision }}', 'string', 'notEmpty')], pos(6))
if_(w, 'Re-promptable?', [cond('={{ $json.error_type }}', 'string', 'equals', 'malformed', False),
                          cond('={{ $json.error_type }}', 'string', 'equals', 'schema_invalid', False)], pos(7, 1.3), comb='or')
code(w, 'Build Re-prompt', J.BUILD_REPROMPT, pos(8, 1.3))
call_wf(w, 'Call Grok (re-prompt)', '00e', pos(9, 1.3), onerror='continueRegularOutput')
code(w, 'Parse + Validate 2', J.PARSE_VALIDATE.replace('__STAGE__', 'grok_reprompt'), pos(10, 1.3))
pg(w, 'Write Audit 2', S.WRITE_GROK_AUDIT, AUD(2), pos(11, 1.3))
if_(w, 'Valid Decision 2?', [cond('={{ $json.decision }}', 'string', 'notEmpty')], pos(12, 1.3))
code(w, 'Rules Fallback', J.RULES_FALLBACK, pos(13, 2.6))
pg(w, 'Write Audit 3', S.WRITE_GROK_AUDIT, AUD(3), pos(14, 2.6))
code(w, 'Finalize', J.FINALIZE, pos(15, 0))
pg(w, 'Update Lead Decision', S.UPDATE_LEAD_DECISION, '={{ [ JSON.stringify($json) ] }}', pos(16, 0), always=True)
# Update Lead Decision reads $json = finalize item; kept in the same order as Finalize output
if_(w, 'Needs Alert?', [true_("={{ $('Finalize').first().json.decision === 'needs_review' || $('Finalize').first().json.source === 'rules_fallback' }}")], pos(17, 0))
code(w, 'Build Alert', J.BUILD_ALERT_WF02, pos(18, -1))
call_wf(w, 'Raise Alert', '00f', pos(19, -1), onerror='continueRegularOutput')
code(w, 'Return Result', J.RETURN_RESULT, pos(20, 0))
w.chain(T, 'Get Location Config', 'Build Prompt', 'Call Grok (attempt 1)', 'Parse + Validate 1', 'Write Audit 1', 'Valid Decision 1?')
w.link('Valid Decision 1?', 'Finalize', 0)
w.link('Valid Decision 1?', 'Re-promptable?', 1)
w.link('Re-promptable?', 'Build Re-prompt', 0)
w.link('Re-promptable?', 'Rules Fallback', 1)
w.chain('Build Re-prompt', 'Call Grok (re-prompt)', 'Parse + Validate 2', 'Write Audit 2', 'Valid Decision 2?')
w.link('Valid Decision 2?', 'Finalize', 0)
w.link('Valid Decision 2?', 'Rules Fallback', 1)
w.chain('Rules Fallback', 'Write Audit 3', 'Finalize', 'Update Lead Decision', 'Needs Alert?')
w.link('Needs Alert?', 'Build Alert', 0)
w.link('Needs Alert?', 'Return Result', 1)
w.chain('Build Alert', 'Raise Alert', 'Return Result')
sticky(w, 'Note', '## WF-02 Grok qualification (never blocks revenue events)\nGrok call -> validate -> (one re-prompt for malformed/schema_invalid only) -> deterministic rules fallback -> `needs_review`.\nEvery attempt is written to `grok_audit` before the lead status changes. Timeouts, 429 and 5xx go straight to the rules fallback after WF-00e exhausted its backoff retries.', pos(0, -1.5), 700, 140)

# ============================================================ WF-01 =========
w = WF('01'); wfs['01'] = w
w.add('Webhook - Lead Intake', 'n8n-nodes-base.webhook', 2, {
    'httpMethod': 'POST', 'path': 'lead-intake', 'authentication': 'headerAuth', 'responseMode': 'onReceived',
    'options': {'responseCode': 202, 'responseData': 'noData'}},
    pos(0), webhookId=str(uuid.UUID(hashlib.md5(b'wf01-webhook').hexdigest())),
    credentials={'httpHeaderAuth': {'id': A.webhook_cred_id, 'name': 'Lead intake webhook secret'}},
    notes='Responds 202 immediately (before any DB or external call); everything below runs asynchronously. Header-auth secret lives in an n8n credential.')
code(w, 'Parse Request', J.PARSE_REQUEST, pos(1))
call_wf(w, 'Get Location Config', '00a', pos(2))
if_(w, 'Location Found?', [true_('={{ $json.found === true }}')], pos(3))
code(w, 'Build Alert Unknown Location', r'''
const req = $('Parse Request').first().json;
return [{ json: {
  severity: 'WARNING', error_signature: 'wf01|unknown_location|' + (req.location_id || 'none'),
  workflow_name: 'WF-01 Lead Intake', node_name: 'Get Location Config',
  execution_url: '/workflow/' + $workflow.id + '/executions/' + $execution.id,
  location_id: null, entity_type: null, entity_id: null,
  message: 'Lead submission rejected: unknown or inactive location_id "' + String(req.location_id || '').slice(0, 60) + '".',
  suggested_action: 'Check the form/ad tracking snippet sends a location_id that exists in locations (active = true).'
} }];
''', pos(4, 1.3))
call_wf(w, 'Raise Alert (unknown location)', '00f', pos(5, 1.3), onerror='continueRegularOutput')
code(w, 'Prepare Phone Input', J.PREPARE_PHONE_INPUT, pos(4))
call_wf(w, 'Normalize Phone', '00b', pos(5))
code(w, 'Prepare Hash Input', J.PREPARE_HASH_INPUT, pos(6))
call_wf(w, 'Hash PII', '00c', pos(7))
code(w, 'Build Lead Context', J.BUILD_LEAD_CONTEXT, pos(8))
if_(w, 'Payload Valid?', [true_('={{ $json.valid }}')], pos(9))
pg(w, 'Park Rejected', S.PARK_REJECTED,
   "={{ [ $('Parse Request').first().json.location_id, $json.raw_body, JSON.stringify($json.errors), " + KEY + " ] }}", pos(10, 1.3),
   notes='Invalid payloads are parked (raw body encrypted) in the outbox as status=dead, not dropped.')
code(w, 'Build Alert Rejected', r'''
const req = $('Parse Request').first().json;
const v = $('Build Lead Context').first().json;
return [{ json: {
  severity: 'INFO', error_signature: 'wf01|payload_rejected|' + req.location_id,
  workflow_name: 'WF-01 Lead Intake', node_name: 'Build Lead Context',
  execution_url: '/workflow/' + $workflow.id + '/executions/' + $execution.id,
  location_id: req.location_id, entity_type: null, entity_id: null,
  message: 'Lead payload rejected and parked (' + v.errors.join(', ') + ').',
  suggested_action: 'Inspect the dead outbox row (kind=lead_intake, last_error=validation_rejected) and fix the sending form.'
} }];
''', pos(11, 1.3))
call_wf(w, 'Raise Alert (rejected)', '00f', pos(12, 1.3), onerror='continueRegularOutput')
pg(w, 'Insert Outbox (claim)', S.INSERT_OUTBOX_CLAIM,
   "={{ [ JSON.stringify($json.ctx), " + KEY + ", 'wf01:' + $execution.id ] }}", pos(10),
   notes='FIRST write: raw PII is encrypted here (pgp_sym_encrypt) and removed from the payload. Duplicate submissions hit the dedupe_key and return claimed=false.')
if_(w, 'New Submission?', [true_('={{ $json.claimed === true }}')], pos(11))
w.add('Duplicate - Stop', 'n8n-nodes-base.noOp', 1, {}, pos(12, 1.3), notes='Replay of an already-claimed submission: nothing else happens (idempotent).')
trigger(w, 'When Called by WF-07 (redrive)', pos(10, -1.5))
code(w, 'Context', J.CONTEXT, pos(12))
pg(w, 'Upsert Lead', S.UPSERT_LEAD, "={{ [ JSON.stringify($json.ctx), " + KEY + " ] }}", pos(13))
code(w, 'Lead Context', J.LEAD_CONTEXT, pos(14))
pg(w, 'Append Touch', S.APPEND_TOUCH, "={{ [ JSON.stringify($json.ctx), $json.lead_id, String($json.is_new) ] }}", pos(15), always=True)
if_(w, 'Identity Conflict?', [true_("={{ $('Lead Context').first().json.identity_conflict }}")], pos(16))
code(w, 'Build Alert Identity', J.BUILD_ALERT_IDENTITY, pos(17, -1.2))
call_wf(w, 'Raise Alert (identity)', '00f', pos(18, -1.2), onerror='continueRegularOutput')
if_(w, 'Needs Qualification?', [true_("={{ $('Lead Context').first().json.needs_qualification }}")], pos(19))
code(w, 'Prepare Qualification Input', J.PREPARE_QUALIFICATION_INPUT, pos(20, -0.6))
call_wf(w, 'Qualify (WF-02)', '02', pos(21, -0.6), onerror='continueErrorOutput')
code(w, 'Existing Decision', J.EXISTING_DECISION, pos(20, 0.8))
if_(w, 'Qualified?', [cond('={{ $json.decision }}', 'string', 'equals', 'qualified', False)], pos(22))
code(w, 'Prepare Event ID Input', J.PREPARE_EVENT_ID_INPUT, pos(23, -0.6))
call_wf(w, 'Build Event ID', '00d', pos(24, -0.6))
pg(w, 'Insert QualifiedLead Event', S.INSERT_QUALIFIED_EVENT,
   "={{ [ JSON.stringify({ event_id: $json.event_id, location_id: $('Lead Context').first().json.ctx.location_id, lead_id: $('Lead Context').first().json.lead_id, hashed_phone_meta: $('Lead Context').first().json.ctx.hashed_phone_meta }) ] }}", pos(25, -0.6),
   notes='Deterministic event_id = sha256(lead_id:QualifiedLead:location_id) + UNIQUE: replays are no-ops. Also queues the dispatch outbox row. Written BEFORE ServiceM8 and before any ad-platform call.')
pg(w, 'Load PII + ServiceM8 State', S.LOAD_PII_SM8_STATE,
   "={{ [ $('Lead Context').first().json.ctx.pii_enc, " + KEY + ", $('Lead Context').first().json.lead_id ] }}", pos(26, -0.6))
code(w, 'Plan ServiceM8', J.PLAN_SERVICEM8, pos(27, -0.6))
if_(w, 'Needs Client?', [true_('={{ $json.needs_client }}')], pos(28, -0.6))

SM8KEY = "={{ $env[$('Plan ServiceM8').first().json.sm8_key_env] }}"


def sm8(name, path, body_expr, p):
    return w.add(name, 'n8n-nodes-base.httpRequest', 4.2, {
        'method': 'POST', 'url': A.sm8_url + '/' + path, 'sendHeaders': True,
        'headerParameters': {'parameters': [{'name': 'X-API-Key', 'value': SM8KEY}, {'name': 'Accept', 'value': 'application/json'}]},
        'sendBody': True, 'contentType': 'json', 'specifyBody': 'json', 'jsonBody': body_expr,
        'options': {'timeout': 15000, 'response': {'response': {'fullResponse': True, 'neverError': False}}}},
        p, onError='continueErrorOutput', retryOnFail=True, maxTries=3, waitBetweenTries=3000,
        notes='Per-location API key is read from the env var named in locations.servicem8_credential_ref. Timeout 15s, 3 tries, error output -> outbox failed + alert. VERIFY endpoint paths, auth header and whether a client-supplied uuid is honoured.')


sm8('ServiceM8 - Create Client', 'company.json', "={{ JSON.stringify($('Plan ServiceM8').first().json.client_body) }}", pos(29, -1.4))
sm8('ServiceM8 - Create Contact', 'companycontact.json', "={{ JSON.stringify($('Plan ServiceM8').first().json.contact_body) }}", pos(30, -1.4))
code(w, 'Resolve Client', J.RESOLVE_CLIENT, pos(31, -0.6))
pg(w, 'Save ServiceM8 Client ID', S.SAVE_SM8_IDS,
   "={{ [ $('Lead Context').first().json.lead_id, $json.client_uuid, '' ] }}", pos(32, -0.6), always=True)
if_(w, 'Needs Job?', [true_("={{ $('Plan ServiceM8').first().json.needs_job }}")], pos(33, -0.6))
sm8('ServiceM8 - Create Job', 'job.json', "={{ JSON.stringify($('Resolve Client').first().json.job_body) }}", pos(34, -1.4))
code(w, 'Resolve Job', J.RESOLVE_JOB, pos(35, -0.6))
pg(w, 'Save ServiceM8 IDs', S.SAVE_SM8_IDS,
   "={{ [ $('Lead Context').first().json.lead_id, $json.client_uuid, $json.job_uuid ] }}", pos(36, -0.6), always=True)
pg(w, 'Mark Outbox Done', S.MARK_OUTBOX_DONE, "={{ [ $('Context').first().json.outbox_id ] }}", pos(37, 0.4))
pg(w, 'Mark Outbox Done (not qualified)', S.MARK_OUTBOX_DONE, "={{ [ $('Context').first().json.outbox_id ] }}", pos(23, 1.4))
pg(w, 'Mark Outbox Failed', S.MARK_OUTBOX_FAILED,
   "={{ [ $('Context').first().json.outbox_id, JSON.stringify($json.error || $json).slice(0, 1500) ] }}", pos(30, 2.4),
   notes='Backoff and dead-lettering: next_attempt_at doubles per attempt (max 60 min); status=dead once attempt_count >= max_attempts. WF-07 re-drives via WF-01 (redrive).')
code(w, 'Build Alert ServiceM8', J.BUILD_ALERT_SM8, pos(31, 2.4))
call_wf(w, 'Raise Alert (servicem8)', '00f', pos(32, 2.4), onerror='continueRegularOutput')

w.link('Webhook - Lead Intake', 'Parse Request')
w.chain('Parse Request', 'Get Location Config', 'Location Found?')
w.link('Location Found?', 'Prepare Phone Input', 0)
w.link('Location Found?', 'Build Alert Unknown Location', 1)
w.chain('Build Alert Unknown Location', 'Raise Alert (unknown location)')
w.chain('Prepare Phone Input', 'Normalize Phone', 'Prepare Hash Input', 'Hash PII', 'Build Lead Context', 'Payload Valid?')
w.link('Payload Valid?', 'Insert Outbox (claim)', 0)
w.link('Payload Valid?', 'Park Rejected', 1)
w.chain('Park Rejected', 'Build Alert Rejected', 'Raise Alert (rejected)')
w.chain('Insert Outbox (claim)', 'New Submission?')
w.link('New Submission?', 'Context', 0)
w.link('New Submission?', 'Duplicate - Stop', 1)
w.link('When Called by WF-07 (redrive)', 'Context')
w.chain('Context', 'Upsert Lead', 'Lead Context', 'Append Touch', 'Identity Conflict?')
w.link('Identity Conflict?', 'Build Alert Identity', 0)
w.link('Identity Conflict?', 'Needs Qualification?', 1)
w.chain('Build Alert Identity', 'Raise Alert (identity)', 'Needs Qualification?')
w.link('Needs Qualification?', 'Prepare Qualification Input', 0)
w.link('Needs Qualification?', 'Existing Decision', 1)
w.chain('Prepare Qualification Input', 'Qualify (WF-02)')
w.link('Qualify (WF-02)', 'Qualified?', 0)
w.link('Qualify (WF-02)', 'Mark Outbox Failed', 1)
w.link('Existing Decision', 'Qualified?')
w.link('Qualified?', 'Prepare Event ID Input', 0)
w.link('Qualified?', 'Mark Outbox Done (not qualified)', 1)
w.chain('Prepare Event ID Input', 'Build Event ID', 'Insert QualifiedLead Event', 'Load PII + ServiceM8 State', 'Plan ServiceM8', 'Needs Client?')
w.link('Needs Client?', 'ServiceM8 - Create Client', 0)
w.link('Needs Client?', 'Resolve Client', 1)
w.link('ServiceM8 - Create Client', 'ServiceM8 - Create Contact', 0)
w.link('ServiceM8 - Create Client', 'Mark Outbox Failed', 1)
w.link('ServiceM8 - Create Contact', 'Resolve Client', 0)
w.link('ServiceM8 - Create Contact', 'Mark Outbox Failed', 1)
w.chain('Resolve Client', 'Save ServiceM8 Client ID', 'Needs Job?')
w.link('Needs Job?', 'ServiceM8 - Create Job', 0)
w.link('Needs Job?', 'Resolve Job', 1)
w.link('ServiceM8 - Create Job', 'Resolve Job', 0)
w.link('ServiceM8 - Create Job', 'Mark Outbox Failed', 1)
w.chain('Resolve Job', 'Save ServiceM8 IDs', 'Mark Outbox Done')
w.chain('Mark Outbox Failed', 'Build Alert ServiceM8', 'Raise Alert (servicem8)')
sticky(w, 'Note A', '## WF-01 Lead Intake\n1. Webhook answers 202 at once.\n2. Normalise phone, hash PII, validate.\n3. **Outbox claim first** (PII encrypted). Duplicate = stop.\n4. Upsert lead (first-touch protected), append touch.\n5. WF-02 qualifies (Grok never blocks).\n6. QualifiedLead event written **before** ServiceM8.\n7. ServiceM8 client/contact/job; IDs saved after each step for safe redrive.', pos(0, -2), 520, 220)
sticky(w, 'Note B', '## Setup\nSet `N8N_BLOCK_ENV_ACCESS_IN_NODE=false`, `PII_ENCRYPTION_KEY` (32+ chars), `XAI_MODEL`, and one env var per location holding its ServiceM8 key (name stored in `locations.servicem8_credential_ref`). Assign credentials on the Postgres, Webhook, xAI and Slack nodes.', pos(3, -2), 520, 170, 6)

# ----------------------------------------------------------------- write ---
os.makedirs(A.outdir, exist_ok=True)
for k, wf in wfs.items():
    fn = os.path.join(A.outdir, NAMES[k].split(' ')[0] + '-' + NAMES[k].split(' ', 1)[1].lower().replace(' ', '-') + '.json')
    extra = {'executionTimeout': 900} if k in ('01', '02', '00e') else {}
    json.dump(wf.dump(extra), open(fn, 'w'), indent=2)
    print('wrote', fn, len(wf.nodes), 'nodes')
