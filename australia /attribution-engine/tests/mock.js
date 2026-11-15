const http = require('http'); const fs = require('fs');
let grokQueue = [], sm8Mode = 'ok', slack = [], log = [];
const good = (o) => ({ status: 200, body: { model: 'grok-4', choices: [{ message: { content: typeof o === 'string' ? o : JSON.stringify(o) } }] } });
http.createServer((req, res) => {
  let b = ''; req.on('data', (d) => b += d); req.on('end', () => {
    const send = (s, o, h = {}) => { res.writeHead(s, Object.assign({ 'content-type': 'application/json' }, h)); res.end(JSON.stringify(o)); };
    let j; try { j = JSON.parse(b); } catch (e) { j = b; }
    if (req.url === '/ctl') { if (j.grok) grokQueue = j.grok; if (j.sm8) sm8Mode = j.sm8; return send(200, { ok: true }); }
    if (req.url === '/state') return send(200, { log, slack, grokLeft: grokQueue.length });
    if (req.url === '/reset') { log = []; slack = []; grokQueue = []; sm8Mode = 'ok'; return send(200, {}); }
    log.push({ url: req.url, auth: req.headers.authorization || req.headers['x-api-key'] || null, body: j });
    if (req.url === '/grok') {
      const n = grokQueue.shift() || { kind: 'unset' };
      if (n.kind === 'ok') { const r = good(n.json); return send(r.status, r.body); }
      if (n.kind === 'raw') { const r = good(n.text); return send(r.status, r.body); }
      if (n.kind === 'status') return send(n.status, { error: 'x' });
      if (n.kind === 'hang') return; // never answers: client timeout
      return send(500, { error: 'no scenario' });
    }
    if (req.url.startsWith('/sm8/')) {
      if (sm8Mode === 'fail') return send(500, { error: 'boom' });
      const id = 'sm8-' + req.url.split('/').pop().replace('.json', '') + '-' + (j && j.uuid ? j.uuid : Math.random().toString(16).slice(2, 10));
      return send(200, { ok: 1 }, { 'x-record-uuid': (j && j.uuid) || id });
    }
    if (req.url === '/slack') { slack.push(j); return send(200, { ok: true }); }
    send(404, {});
  });
}).listen(9000, '127.0.0.1', () => console.log('mock up'));
