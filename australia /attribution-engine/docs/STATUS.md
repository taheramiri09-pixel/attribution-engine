# Status (honest scope)

| Area | State |
|---|---|
| Architecture diagram, SQL schema | Done. Schema loads cleanly in PostgreSQL 16. |
| WF-00a..f shared sub-workflows | Built and tested (n8n 2.35.7). |
| WF-01 Lead Intake | Built and tested against mock Grok / ServiceM8 / Slack. |
| WF-02 Grok Qualification | Built and tested (retry, re-prompt, rules fallback, needs_review). |
| WF-03 ServiceM8 webhook receiver, WF-04 job processor | Not built. |
| WF-05 Meta CAPI + Google offline dispatch | Not built. |
| WF-06 phone-call bridge, WF-07 retry/dead-letter, WF-08 daily reconciliation, WF-99 global error alerts | Not built. |

Nothing here has run against live Grok, ServiceM8, Meta or Google APIs, or in production.
Test evidence: 35 Code-node unit tests, SQL tests on Postgres 16, 38 end-to-end checks (see tests/RUN_TESTS.md).
