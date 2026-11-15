#!/usr/bin/env bash
# Imports WF-00a..f, WF-01, WF-02 keeping their fixed IDs (needed so Execute Workflow references resolve),
# then publishes them. Run on the n8n host, with n8n STOPPED (the CLI warns otherwise), then start n8n.
set -euo pipefail
DIR="$(cd "$(dirname "$0")" && pwd)"
n8n import:workflow --separate --input="$DIR"
for id in AttrWf00aConfig1 AttrWf00bPhone01 AttrWf00cHashPii AttrWf00dEventId AttrWf00eGrokCal AttrWf00fAlert01 AttrWf02GrokQual AttrWf01Intake01; do
  n8n publish:workflow --id="$id"
done
echo "Now assign credentials (Postgres, xAI, Slack, webhook secret) in the editor, then restart n8n."
