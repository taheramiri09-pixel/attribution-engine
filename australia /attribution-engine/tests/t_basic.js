const assert = require('assert');
const crypto = require('crypto');
const { run } = require('./jstest.js');
let pass = 0, fail = 0;
const t = (name, f) => { try { f(); pass++; } catch (e) { fail++; console.log('FAIL', name, '\n  ', e.message); } };
const h = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

// ---- pure-JS SHA-256 fallback vs node crypto (crypto blocked)
const samples = ['', 'a', 'abc', 'x'.repeat(55), 'x'.repeat(56), 'x'.repeat(63), 'x'.repeat(64), 'x'.repeat(65), 'x'.repeat(119), 'x'.repeat(120), 'x'.repeat(1000),
  'josé@example.com', '日本語テキスト', 'emoji 😀 test', 'lead-uuid:QualifiedLead:au-syd'];
t('pure-JS sha256 matches crypto on ' + samples.length + ' inputs', () => {
  for (const s of samples) {
    const out = run('BUILD_EVENT_ID', { input: { source_id: s || 'x', event_type: 'E', location_id: 'l' }, requireCrypto: false })[0];
    const expect = h((s || 'x').toLowerCase() + ':E:l');
    assert.strictEqual(out.event_id, expect, 'mismatch for len ' + s.length);
  }
});
t('crypto path gives the same answer', () => {
  const a = run('BUILD_EVENT_ID', { input: { source_id: 'ABC', event_type: 'JobPaid', location_id: 'AU-SYD' }, requireCrypto: true })[0];
  assert.strictEqual(a.event_id, h('abc:JobPaid:au-syd'));
});
t('build_event_id: deterministic, case-insensitive on ids, requires all parts', () => {
  const a = run('BUILD_EVENT_ID', { input: { source_id: 'AAA', event_type: 'JobPaid', location_id: 'au-syd' } })[0].event_id;
  const b = run('BUILD_EVENT_ID', { input: { source_id: 'aaa', event_type: 'JobPaid', location_id: 'AU-SYD' } })[0].event_id;
  assert.strictEqual(a, b); assert.match(a, /^[0-9a-f]{64}$/);
  assert.notStrictEqual(a, run('BUILD_EVENT_ID', { input: { source_id: 'aaa', event_type: 'JobCompleted', location_id: 'au-syd' } })[0].event_id);
  assert.throws(() => run('BUILD_EVENT_ID', { input: { source_id: '', event_type: 'x', location_id: 'y' } }));
});

// ---- normalize_phone
const np = (phone, cc) => run('NORMALIZE_PHONE', { input: { phone, default_country_calling_code: cc } })[0];
const cases = [
  ['+61 412 345 678', null, '+61412345678'], ['0412 345 678', '61', '+61412345678'], ['61412345678', '61', '+61412345678'],
  ['(415) 555-2671', '1', '+14155552671'], ['1 415 555 2671', '1', '+14155552671'], ['07911 123456', '44', '+447911123456'],
  ['447911123456', '44', '+447911123456'], ['00447911123456', null, '+447911123456'], ['tel:+61412345678', null, '+61412345678'],
  ['+1 (415) 555-2671 ext 12', null, '+14155552671'], ['+1 (415) 555-2671 x5', null, '+14155552671']
];
for (const [inp, cc, exp] of cases) t('phone ' + inp, () => { const r = np(inp, cc); assert.strictEqual(r.phone_e164, exp); assert.strictEqual(r.phone_valid, true); });
for (const [inp, cc, why] of [['', '61', 'empty'], ['abc', '61', 'no_digits'], ['0412 345 678', null, 'no_country_code'], ['12345', '61', 'invalid_length_or_format'], ['+1111111111', null, 'repeated_digit'], ['+0123456789', null, 'invalid_length_or_format']])
  t('phone rejects ' + JSON.stringify(inp), () => { const r = np(inp, cc); assert.strictEqual(r.phone_valid, false); assert.strictEqual(r.reason, why); assert.strictEqual(r.phone_e164, null); });

// ---- hash_pii
t('hash_pii', () => {
  const r = run('HASH_PII', { input: { email: '  Jane.Doe@Example.COM ', phone_e164: '+61412345678', canonical_payload: 'p' } })[0];
  assert.strictEqual(r.hashed_email, h('jane.doe@example.com'));
  assert.strictEqual(r.hashed_phone, h('+61412345678'));
  assert.strictEqual(r.hashed_phone_meta, h('61412345678'));
  assert.strictEqual(r.payload_hash, h('p'));
  const bad = run('HASH_PII', { input: { email: 'nope', phone_e164: null } })[0];
  assert.strictEqual(bad.hashed_email, null); assert.strictEqual(bad.hashed_phone, null); assert.strictEqual(bad.email_valid, false);
});

// ---- location shape
t('location shape', () => {
  const r = run('LOCATION_SHAPE', { input: { location_id: 'au-syd', name: 'Sydney', timezone: 'Australia/Sydney', currency: 'AUD', servicem8_credential_ref: 'SM8_KEY_AU_SYD',
    service_types: ['plumbing'], service_area: { default_country_calling_code: '+61', postcodes: ['2000', ' 2 010 '], qualification: { intent_min: 55, notes: 'n' } }, status_event_map: {}, platform_limits: {} } })[0];
  assert.strictEqual(r.found, true); assert.strictEqual(r.defaults.default_country_calling_code, '61');
  assert.deepStrictEqual(r.defaults.postcodes, ['2000', '2010']); assert.strictEqual(r.defaults.intent_min, 55); assert.strictEqual(r.defaults.confidence_min, 0.6);
  assert.deepStrictEqual(run('LOCATION_SHAPE', { input: {} })[0], { found: false });
});

console.log(pass + ' passed, ' + fail + ' failed');
process.exit(fail ? 1 : 0);
