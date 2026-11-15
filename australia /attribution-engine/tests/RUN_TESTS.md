# Test harness (what produced the results in README.md)
1. `node t_basic.js && node t_logic.js`      Code-node unit tests (emulator in jstest.js; no n8n needed)
2. `python3 t_sql.py` then `psql -f t_sql.sql` against a scratch DB loaded from schema.sql
3. End-to-end: `python3 build_wf.py wf --pg-cred-id PgCred000000001 --grok-cred-id XaiCred00000001 --slack-cred-id SlkCred00000001 --webhook-cred-id WhkCred00000001 --xai-url http://127.0.0.1:9000/grok --sm8-url http://127.0.0.1:9000/sm8 --slack-url http://127.0.0.1:9000/slack`
   `node mock.js &` (mock Grok / ServiceM8 / Slack), source env.sh, `n8n import:credentials --input=creds.example.json (placeholder values for a local test instance)`,
   `n8n import:workflow --separate --input=wf`, publish every workflow, start n8n, then `python3 scen.py`.
Locations au-syd / au-mel must exist (see scen.py header comments and README seed SQL).
