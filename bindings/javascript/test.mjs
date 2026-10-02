import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { chains } from './dist/nostoi.js';

const draft = {at:'2026-09-27T12:00:00Z', actor:'agent:test', kind:'test',
  subject:undefined, bodyJson:'{"unicode":"🦆","large":18446744073709551615}'};
const one = chains.appendJsonl('', draft);
const two = chains.appendJsonl(one.trimEnd(), draft);
assert.equal(JSON.parse(chains.verifyJsonl(two, undefined)).verified, 2);
assert.match(one, /18446744073709551615/);
const altered = two.replace('agent:test', 'agent:other');
assert.equal(JSON.parse(chains.verifyJsonl(altered, undefined)).ok, false);
assert.throws(() => chains.appendJsonl(altered, draft));
assert.throws(() => chains.appendJsonl('', {...draft, bodyJson:'{"float":0.1}'}));
assert.throws(() => chains.verifyJsonl('', 'unknown'));
const vector = readFileSync(new URL('../../crates/nostoi-core/tests/vectors/weftmark-ledger.jsonl', import.meta.url), 'utf8');
assert.equal(JSON.parse(chains.verifyJsonl(vector, undefined)).ok, true);
if (process.env.NOSTOI_INTEROP_DIR) {
  const dir = process.env.NOSTOI_INTEROP_DIR;
  const python = readFileSync(`${dir}/python.jsonl`, 'utf8');
  assert.equal(python, one, 'Python and WIT produce byte-identical records');
  writeFileSync(`${dir}/javascript.jsonl`, two);
}
console.log('WIT/JavaScript: roundtrip, tamper refusal, integer precision, WeftMark vector passed');
