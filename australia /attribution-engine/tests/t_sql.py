import json, subprocess, sys, re
sys.path.insert(0,'.')
import sqlcode as S
KEY='k'*32
def q(s): return "'"+s.replace("'","''")+"'"
out=[]; 
def prep(name, sql, n):
    out.append(f"PREPARE {name}({','.join(['text']*n)}) AS {sql}")
prep('load', S.LOAD_LOCATION,1); prep('claim',S.INSERT_OUTBOX_CLAIM,3); prep('park',S.PARK_REJECTED,4)
prep('upsert',S.UPSERT_LEAD,2); prep('touch',S.APPEND_TOUCH,3); prep('evt',S.INSERT_QUALIFIED_EVENT,1)
prep('pii',S.LOAD_PII_SM8_STATE,3); prep('sm8',S.SAVE_SM8_IDS,3); prep('done',S.MARK_OUTBOX_DONE,1)
prep('fail',S.MARK_OUTBOX_FAILED,2); prep('audit',S.WRITE_GROK_AUDIT,1); prep('dec',S.UPDATE_LEAD_DECISION,1); prep('alert',S.RAISE_ALERT,1)
ctx={"location_id":"au-syd","channel":"form","occurred_at":"2026-11-14T10:00:00.000Z","payload_hash":"d"*64,
 "hashed_phone":"a"*64,"hashed_email":"c"*64,"hashed_phone_meta":"b"*64,
 "tracking":{"gclid":"G1","fbclid":"F1","utm":{"source":"google"},"landing_page":"https://x/a"},
 "pii":{"name":"Jane Doe","email":"jane@example.com","phone":"+61412345678","message":"burst pipe"}}
c2=dict(ctx,payload_hash="e"*64,occurred_at="2026-11-15T10:00:00.000Z",tracking={"gclid":"G2","utm":{"source":"bing"}})
c3=dict(ctx,payload_hash="f"*64,hashed_phone="1"*64,hashed_email="c"*64)  # phone differs, email matches
c4=dict(ctx,payload_hash="9"*64,hashed_phone="a"*64,hashed_email="2"*64)   # new email on existing phone
c5=dict(ctx,payload_hash="8"*64,hashed_phone=None,hashed_email="7"*64,tracking={},pii={"email":"x@y.com"})
def j(o): return q(json.dumps(o))
def stripped(c): 
    d=dict(c); d.pop('pii',None); d['pii_enc']='HEX'; return d
out.append("\\set ON_ERROR_STOP off")
out.append("INSERT INTO locations(location_id,name,currency,servicem8_credential_ref,service_types) VALUES('au-syd','Syd','AUD','SM8_KEY_AU_SYD','{plumbing}'),('au-mel','Mel','AUD','SM8_KEY_AU_MEL','{plumbing}');")
out.append("\\echo ==LOAD"); out.append("EXECUTE load('au-syd'); EXECUTE load('nope');")
out.append("\\echo ==CLAIM1 (expect claimed t)"); 
for i,c in enumerate([ctx,ctx]):
    out.append(f"\\echo claim attempt {i+1}"); out.append(f"EXECUTE claim({j(c)},{q(KEY)},'wf01:1');")
out.append("\\echo ==PAYLOAD HAS NO RAW PII"); out.append("SELECT payload::text ~ 'jane@example|0412345678|Jane Doe' AS raw_pii_leak, payload ? 'pii_enc' AS has_enc, payload ? 'pii' AS has_pii FROM outbox WHERE kind='lead_intake';")
# build upsert input: ctx with pii_enc from outbox
out.append("\\echo ==UPSERT")
def upsert(c, label):
    cc=dict(c); pii=cc.pop('pii')
    return (f"\\echo {label}\n"
     f"SELECT set_config('t.enc', encode(pgp_sym_encrypt({q(json.dumps(pii))}, {q(KEY)}),'hex'), false) \\gset\n"
     f"SELECT (({q(json.dumps(cc))}::jsonb) || jsonb_build_object('pii_enc', current_setting('t.enc')))::text AS cj \\gset\n"
     f"EXECUTE upsert(:'cj',{q(KEY)});")
out.append(upsert(ctx,"first (new)")); out.append(upsert(ctx,"replay same (existing, is_new f)"))
out.append(upsert(c2,"second touch (later, different gclid)"))
out.append("SELECT first_gclid,first_fbclid,first_utm,first_touch_at,last_touch_at,attribution_status,status, pgp_sym_decrypt(phone_enc,"+q(KEY)+") ph FROM leads;")
out.append(upsert(c5,"email-only new lead"))
out.append(upsert(c3,"email match, different phone (second lead? phone new)"))
out.append("SELECT count(*) AS leads_now FROM leads;")
out.append("\\echo ==TOUCH")
out.append("SELECT lead_id FROM leads WHERE hashed_phone='"+"a"*64+"' \\gset")
out.append(f"EXECUTE touch({j(ctx)},:'lead_id','true'); EXECUTE touch({j(ctx)},:'lead_id','true'); EXECUTE touch({j(c2)},:'lead_id','false');")
out.append("SELECT is_first,gclid FROM lead_touches ORDER BY touch_id;")
out.append("\\echo ==AUDIT x2 then DECISION")
a={"lead_id":"LEADID","location_id":"au-syd","stage":"grok","model":"grok-4","prompt_version":"v1","schema_version":"v1","input_hash":"h","http_status":200,"latency_ms":800,"error_type":None,"response_raw":"{}","parsed":{"a":1},"is_spam":False,"intent_score":85,"qualified":True,"service_type":"plumbing","urgency":"emergency","reason":"r","confidence":0.9,"decision":"qualified"}
out.append("SELECT replace("+q(json.dumps(a))+",'LEADID',:'lead_id') AS aj \\gset")
out.append("EXECUTE audit(:'aj'); EXECUTE audit(:'aj');")
out.append("SELECT replace("+q(json.dumps({"lead_id":"LEADID","decision":"qualified","source":"grok","intent_score":85,"service_type":"plumbing","urgency":"emergency"}))+",'LEADID',:'lead_id') AS dj \\gset")
out.append("EXECUTE dec(:'dj'); EXECUTE dec(:'dj');")
out.append("\\echo ==EVENT (expect 1/1 then 0/0)")
out.append("SELECT replace("+q(json.dumps({"event_id":"e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1e1","location_id":"au-syd","lead_id":"LEADID","hashed_phone_meta":"b"*64}))+",'LEADID',:'lead_id') AS ej \\gset")
out.append("EXECUTE evt(:'ej'); EXECUTE evt(:'ej');")
out.append("SELECT event_type,event_class,currency,attribution,user_data_hashed,grok_audit_id IS NOT NULL AS has_audit FROM events;")
out.append("\\echo ==SM8 + PII")
out.append("SELECT payload->>'pii_enc' AS enc FROM outbox WHERE kind='lead_intake' LIMIT 1 \\gset")
out.append("EXECUTE pii(:'enc',"+q(KEY)+",:'lead_id');")
out.append("EXECUTE sm8(:'lead_id','C1',''); EXECUTE sm8(:'lead_id','C2','J1');")
out.append("\\echo ==OUTBOX DONE/FAIL ladder")
out.append("SELECT outbox_id AS oid FROM outbox WHERE kind='lead_intake' LIMIT 1 \\gset")
out.append("EXECUTE fail(:'oid','boom'); SELECT attempt_count,max_attempts,status FROM outbox WHERE outbox_id=:'oid';")
out.append("UPDATE outbox SET attempt_count=5 WHERE outbox_id=:'oid'; EXECUTE fail(:'oid','boom again'); EXECUTE done(:'oid');")
out.append("\\echo ==IDENTITY CONFLICT (phone A + email 7 => different leads)")
out.append(upsert(dict(ctx,payload_hash="6"*64,hashed_email="7"*64),"conflict"))
out.append("\\echo ==ALERT x3 (notify t, f, f) then age and re-raise (t)")
al=json.dumps({"location_id":"au-syd","severity":"CRITICAL","error_signature":"sig1","workflow_name":"WF-01","node_name":"n","execution_url":"u","entity_type":"lead","entity_id":"x","message":"m","suggested_action":"a"})
out.append(f"EXECUTE alert({q(al)}); EXECUTE alert({q(al)}); EXECUTE alert({q(al)});")
out.append("UPDATE alerts SET last_notified_at = now() - interval '20 minutes'; EXECUTE alert("+q(al)+");")
out.append("\\echo ==PARK x2 (second is no-op)")
out.append("EXECUTE park('au-syd','{\"a\":1}','[\"bad\"]',"+q(KEY)+"); EXECUTE park('au-syd','{\"a\":1}','[\"bad\"]',"+q(KEY)+");")
open('t_sql.sql','w').write("\n".join(out))
