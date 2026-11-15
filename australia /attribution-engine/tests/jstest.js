// Minimal emulation of the n8n Code-node environment, to unit-test every code block.
const crypto = require('crypto');
const blocks = require('./blocks.json');

function run(name, { input = {}, nodes = {}, env = {}, requireCrypto = true, workflow = { id: 'WFID' }, execution = { id: 'EXEC1' } } = {}) {
  const items = (v) => (Array.isArray(v) ? v : [v]).map((j) => ({ json: j }));
  const $input = { first: () => items(input)[0], all: () => items(input), item: items(input)[0] };
  const $ = (n) => {
    if (!(n in nodes)) throw new Error('Node "' + n + '" not available in test');
    const it = items(nodes[n]);
    return { first: () => it[0], last: () => it[it.length - 1], all: () => it, item: it[0] };
  };
  const fakeRequire = (m) => { if (m === 'crypto' && requireCrypto) return crypto; throw new Error("Cannot find module '" + m + "'"); };
  const fn = new Function('$input', '$', '$env', '$workflow', '$execution', 'require', blocks[name]);
  return fn($input, $, env, workflow, execution, fakeRequire).map((x) => x.json);
}
module.exports = { run, blocks };
