# Items to verify against live platforms before go-live
1. xAI model id (env XAI_MODEL, default grok-4), strict json_schema support, rate limits.
2. ServiceM8: endpoint paths, X-API-Key auth, field names, and whether a client-supplied uuid on create is honoured.
3. Meta and Google phone/email hash formats (phone stored hashed with and without "+").
4. Meta CAPI and Google offline conversion age limits, and event_id / order_id deduplication behaviour.
5. Google Ads developer-token approval status and OAuth setup per location.
6. n8n versions other than 2.35.7.
