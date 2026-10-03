import assert from 'node:assert/strict';
import { readFileSync, writeFileSync } from 'node:fs';
import { attestations, chains } from './dist/nostoi.js';

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
// An attestation over the chain as it stood after the second record. The
// signature itself needs a key, so this only exercises the portable half.
const records = two.trimEnd().split('\n');
const attested = JSON.parse(records[records.length - 1]);
const document = {
  v:'nostoi-attestation-v1', chain:'test', format:'nostoi-v1', seq:attested.seq,
  digest:attested.digest, anchored_at:'2026-09-27T13:00:00Z',
  principal:'alice@laptop', fingerprint:'SHA256:' + 'A'.repeat(43),
  title:'caf\u00e9 freeze',
};
const signed = attestations.canonicalBytes(JSON.stringify(document));
assert.ok(signed.startsWith('{'), 'canonical bytes are the signed object itself');
assert.ok(signed.includes('\\u00e9'), 'non-ASCII is escaped, not dropped');
assert.equal(attestations.canonicalBytes(JSON.stringify(document)), signed);
// Key order in the host's object must not change what was signed.
const reordered = Object.fromEntries(Object.entries(document).reverse());
assert.equal(attestations.canonicalBytes(JSON.stringify(reordered)), signed);

const current = JSON.parse(attestations.verifyDocument(two, JSON.stringify(document), undefined));
assert.equal(current.ok, true);
assert.equal(current.coverage, 'current');
// Reports are JSON text with the same snake_case keys the Python binding uses.
assert.equal(current.covers_head, true);
assert.equal(current.signature, 'unchecked', 'no key here, so it must not claim one');
assert.equal(current.title, 'caf\u00e9 freeze');
// A chain that grew after the attestation is a finding, not an error.
const later = JSON.parse(attestations.verifyDocument(chains.appendJsonl(two, draft), JSON.stringify(document), undefined));
assert.equal(later.ok, true);
assert.equal(later.covers_head, false);
assert.equal(later.coverage.ahead_by, 1);
// A tampered record breaks the digest the attestation committed to.
assert.throws(() => attestations.verifyDocument(two.replace('agent:test', 'agent:evil'), JSON.stringify(document), undefined));
assert.throws(() => attestations.canonicalBytes('{'));
assert.throws(() => attestations.verifyDocument(two, '{', undefined));

if (process.env.NOSTOI_INTEROP_DIR) {
  const dir = process.env.NOSTOI_INTEROP_DIR;
  const python = readFileSync(`${dir}/python.jsonl`, 'utf8');
  assert.equal(python, one, 'Python and WIT produce byte-identical records');
  writeFileSync(`${dir}/javascript.jsonl`, two);
}
console.log('WIT/JavaScript: roundtrip, tamper refusal, integer precision, WeftMark vector, attestation documents passed');
