import test from 'node:test';
import assert from 'node:assert/strict';
import { runBounded, parseEvidence } from './rea-compare.mjs';

test('child execution preserves UTF-8 across writes and reports nonzero exit', async () => {
  const result = await runBounded(process.execPath, ['-e', "process.stdout.write('Türkçe');process.exitCode=4"]);
  assert.equal(result.stdout, 'Türkçe');
  assert.equal(result.exitCode, 4);
  assert.equal(result.status, 'error');
});

test('deadline terminates a stalled child instead of claiming evidence', async () => {
  const result = await runBounded(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeoutMs: 150 });
  assert.equal(result.status, 'timeout');
});

test('provider output is bounded before parsing', async () => {
  const result = await runBounded(process.execPath, ['-e', "process.stdout.write('x'.repeat(100000))"], { maxOutputBytes: 128 });
  assert.equal(result.status, 'output_limit');
  assert.ok(Buffer.byteLength(result.stdout) <= 128);
});

test('deadline settles even when process-tree termination never returns', async () => {
  const result = await runBounded(process.execPath, ['-e', 'setInterval(()=>{},1000)'], { timeoutMs: 150, terminateTree: () => new Promise(() => {}) });
  assert.equal(result.status, 'timeout');
  assert.equal(result.cleanupIncomplete, true);
  assert.ok(result.elapsedMs < 5000, `deadline exceeded: ${result.elapsedMs}`);
});

test('provider text or errors never become verified normalized evidence', () => {
  assert.throws(() => parseEvidence('not JSON'), /JSON/);
  assert.throws(() => parseEvidence('{"ok":false,"error":"failed"}'), /evidence/);
  assert.deepEqual(parseEvidence('{"evidence_id":"sample","normalized_result":{"functions":[]}}').normalized_result.functions, []);
  assert.equal(parseEvidence('{"evidence_id":"sample","normalized_result":"int fixture(void) { return 1; }"}').normalized_result, 'int fixture(void) { return 1; }');
});
