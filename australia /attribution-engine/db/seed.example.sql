-- Example location row. Replace every value; keep real keys OUT of the database (only the env var NAME is stored).
INSERT INTO locations (location_id, name, timezone, currency, servicem8_credential_ref, slack_channel, service_types, service_area)
VALUES ('au-syd','Sydney Plumbing','Australia/Sydney','AUD','SM8_KEY_AU_SYD','C0123456789','{plumbing,"hot water"}',
 '{"default_country_calling_code":"61","postcodes":["2000","2010"],"qualification":{"min_job_signals":["burst","quote"],"notes":"No commercial work.","intent_min":60,"confidence_min":0.6}}');
