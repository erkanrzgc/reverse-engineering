// Optional developer validation. No agent registration or global installation.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

export const REA_VERSION = '6.4.0';
export const REA_REFERENCE_COMMIT = '3b0ea590fcc876fa017946f4cec009d653f02b38';
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');

export function runBounded(command, args, { timeoutMs = 330_000, maxOutputBytes = 10 * 1024 * 1024, cwd = root, env = process.env, terminateTree } = {}) {
  return new Promise((resolveResult) => {
    const started = Date.now();
    const child = spawn(command, args, { cwd, env, shell: false, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    const stdout = [], stderr = [];
    let bytes = 0, status, spawnError, cleanupTimer, cleanupIncomplete = false, settled = false;
    const finish = (exitCode) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      clearTimeout(cleanupTimer);
      resolveResult({ command, args, status: status ?? (exitCode === 0 ? 'complete' : 'error'), exitCode, elapsedMs: Date.now() - started,
        stdout: Buffer.concat(stdout).toString('utf8'), stderr: Buffer.concat(stderr).toString('utf8'), cleanupIncomplete, ...(spawnError ? { error: spawnError } : {}) });
    };
    const stop = (reason) => {
      if (status) return;
      status = reason;
      cleanupTimer = setTimeout(() => {
        cleanupIncomplete = true;
        child.kill();
        child.stdout.destroy();
        child.stderr.destroy();
        finish(null);
      }, 3000);
      if (terminateTree) {
        Promise.resolve().then(() => terminateTree(child)).catch(() => { cleanupIncomplete = true; child.kill(); });
      } else if (process.platform === 'win32' && child.pid) {
        // Kill only the process tree created by this request (including Java).
        const killer = spawn('taskkill.exe', ['/pid', String(child.pid), '/T', '/F'], { windowsHide: true, stdio: 'ignore' });
        killer.on('error', () => { cleanupIncomplete = true; child.kill(); });
        killer.on('exit', (code) => { if (code !== 0) { cleanupIncomplete = true; child.kill(); } });
      } else child.kill('SIGKILL');
    };
    const capture = (chunks, chunk) => {
      const remaining = Math.max(0, maxOutputBytes - bytes);
      if (remaining > 0) chunks.push(chunk.subarray(0, remaining));
      bytes += Math.min(chunk.length, remaining);
      if (chunk.length > remaining) stop('output_limit');
    };
    child.stdout.on('data', (chunk) => capture(stdout, chunk));
    child.stderr.on('data', (chunk) => capture(stderr, chunk));
    child.on('error', (error) => { spawnError = error.message; });
    const timer = setTimeout(() => stop('timeout'), timeoutMs);
    child.on('close', finish);
  });
}

export function parseEvidence(text) {
  let evidence;
  try { evidence = JSON.parse(text); } catch { throw new Error('Provider output is not valid JSON'); }
  if (!evidence || typeof evidence.evidence_id !== 'string' || evidence.normalized_result === null || !['object', 'string'].includes(typeof evidence.normalized_result)) {
    throw new Error('Provider output is not a normalized evidence record');
  }
  return evidence;
}

async function atomicJson(path, value) {
  const temporary = `${path}.${process.pid}.tmp`;
  await writeFile(temporary, JSON.stringify(value, null, 2) + '\n');
  await rename(temporary, path);
}

async function main() {
  const args = process.argv.slice(2);
  const option = (name, fallback) => {
    const index = args.indexOf(name);
    if (index < 0) return fallback;
    if (!args[index + 1] || args[index + 1].startsWith('--')) throw new Error(`Missing value for ${name}`);
    return args[index + 1];
  };
  if (args.includes('--help')) {
    console.log('node scripts/rea-compare.mjs --analyzer ABSOLUTE_EXE [--rea-entry rea.mjs] [--out DIR] [--skip-provider]\nRequires Windows x64, GCC, Node and optional REA 6.4.0 + Ghidra/JDK. Builds and executes only repository-owned fixture code.');
    return;
  }
  if (process.platform !== 'win32' || process.arch !== 'x64') throw new Error('Initial comparison lane requires Windows x64 native PE');
  const analyzerArg = option('--analyzer', null);
  if (!analyzerArg) throw new Error('Pass --analyzer from a freshly verified cargo build');
  const analyzer = resolve(analyzerArg);
  const out = resolve(option('--out', join(root, 'docs', 'reviews', '2026-10-13-rea')));
  const fixture = join(out, 'fixture');
  await mkdir(fixture, { recursive: true });
  const providerRequested = !args.includes('--skip-provider');
  const report = { schema_version: '1.0', created_at: new Date().toISOString(), reference: { repository: 'https://github.com/morluto/rea', commit: REA_REFERENCE_COMMIT, package_version: REA_VERSION },
    host: { platform: process.platform, arch: process.arch, node: process.version }, steps: {}, provider: { status: providerRequested ? 'pending' : 'skipped', reason: providerRequested ? 'Waiting for fixture validation' : '--skip-provider requested' },
    semantic_equivalence: { status: 'not_established', reason: 'Native fixture outcomes are an independent oracle; provider pseudocode and inventory agreement alone do not prove equivalence.' } };
  const record = async (name, command, commandArgs, settings) => {
    const result = await runBounded(command, commandArgs, settings);
    report.steps[name] = { ...result, stdout: `${name}.stdout.txt`, stderr: `${name}.stderr.txt`, stdout_sha256: createHash('sha256').update(result.stdout).digest('hex'), stderr_sha256: createHash('sha256').update(result.stderr).digest('hex') };
    await writeFile(join(out, `${name}.stdout.txt`), result.stdout);
    await writeFile(join(out, `${name}.stderr.txt`), result.stderr);
    await atomicJson(join(out, 'comparison.json'), report);
    return result;
  };
  const required = (result, name) => { if (result.status !== 'complete') throw new Error(`${name}: ${result.status}; see saved evidence`); };
  try {
    const sourceDir = join(root, 'tests', 'fixtures', 'semantic');
    const asm = join(sourceDir, 'cases.S');
    const oracleSource = join(sourceDir, 'oracle.c');
    report.source_sha256 = {};
    for (const path of [asm, oracleSource]) report.source_sha256[path.slice(root.length + 1)] = createHash('sha256').update(await readFile(path)).digest('hex');
    required(await record('compiler-version', process.env.CC ?? 'gcc', ['--version']), 'compiler');
    const binary = join(fixture, 'semantic-cases.exe');
    const oracle = join(fixture, 'native-oracle.exe');
    required(await record('build-fixture', process.env.CC ?? 'gcc', ['-nostdlib', '-Wl,--entry=fixture_conditional', '-Wl,--export-all-symbols', asm, '-o', binary]), 'fixture build');
    required(await record('build-oracle', process.env.CC ?? 'gcc', [oracleSource, asm, '-o', oracle]), 'oracle build');
    const native = await record('native-oracle', oracle, [], { timeoutMs: 10_000 });
    required(native, 'native oracle');
    report.native_oracle = JSON.parse(native.stdout);
    const expected = { conditional_zero: 0, conditional_one: 1, imul: 21, partial: 4694, movzx: 52, indexed_lea: 116 };
    if (JSON.stringify(report.native_oracle) !== JSON.stringify(expected)) throw new Error('Controlled fixture diverged from its known-source expected outcomes');
    report.binary_sha256 = createHash('sha256').update(await readFile(binary)).digest('hex');
    required(await record('analyzer-version', analyzer, ['--version']), 'analyzer version');
    report.analyzer_sha256 = createHash('sha256').update(await readFile(analyzer)).digest('hex');
    const rust = await record('rust-analysis', analyzer, ['analyze', binary, '--format', 'json', '--quiet']);
    if (!['complete', 'error'].includes(rust.status) || ![0, 4].includes(rust.exitCode)) throw new Error('Rust analysis did not return useful evidence');
    const rustJson = JSON.parse(rust.stdout);
    report.rust = { status: rustJson.status, binary: rustJson.binary, diagnostics: rustJson.diagnostics, exports: rustJson.report?.exports ?? [] };
    await writeFile(join(out, 'rust-generated.c'), rustJson.generated_c ?? '');
    const exportedNames = new Set(report.rust.exports.map(item => item.name));
    const names = ['fixture_conditional', 'fixture_imul', 'fixture_partial', 'fixture_movzx', 'fixture_indexed_lea', 'fixture_string'];
    report.rust.missing_fixture_exports = names.filter(name => !exportedNames.has(name));
    if (report.rust.missing_fixture_exports.length) throw new Error('Rust export inventory missed controlled fixture functions');
    const reconstructed = join(fixture, 'rust-oracle.exe');
    required(await record('build-rust-oracle', process.env.CC ?? 'gcc', [join(out, 'rust-generated.c'), oracleSource, '-o', reconstructed]), 'generated C compile');
    const reconstructedRun = await record('rust-oracle', reconstructed, [], { timeoutMs: 10_000 });
    required(reconstructedRun, 'generated C oracle');
    report.rust_oracle = JSON.parse(reconstructedRun.stdout);
    if (JSON.stringify(report.rust_oracle) !== JSON.stringify(expected)) throw new Error('Generated C diverged from independent native fixture outcomes');
    report.semantic_equivalence.fixture_cases = { status: 'verified', cases: Object.keys(expected), scope: 'Controlled fixture cases only; no general equivalence assertion.' };
    if (providerRequested) {
      report.provider = { status: 'preparing', name: 'ghidra' };
      const reaEntry = resolve(option('--rea-entry', process.env.REA_ENTRY ?? join(process.env.LOCALAPPDATA, 'reverse-engineering', 'providers', 'rea', 'node_modules', 'rea-agents', 'scripts', 'rea.mjs')));
      const packageJson = JSON.parse(await readFile(resolve(dirname(reaEntry), '..', 'package.json'), 'utf8'));
      if (packageJson.version !== REA_VERSION) throw new Error(`Expected REA ${REA_VERSION}, found ${packageJson.version}`);
      report.provider = { status: 'running', name: 'ghidra', package_version: packageJson.version };
      const doctor = await record('rea-doctor', process.execPath, [reaEntry, 'doctor', '--provider', 'ghidra', '--json', '--filter-output', 'healthy,scope_checks']);
      report.provider.doctor_exit_code = doctor.exitCode;
      const overview = await record('rea-overview', process.execPath, [reaEntry, 'inspect', binary, '--provider', 'ghidra', '--format', 'json']);
      required(overview, 'Ghidra overview');
      const evidence = parseEvidence(overview.stdout);
      if (evidence.subject?.digest?.sha256 !== report.binary_sha256) throw new Error('Ghidra overview evidence belongs to a different binary');
      report.provider.overview_evidence_id = evidence.evidence_id;
      report.provider.inventory = { rust_functions: rustJson.binary.function_count, ghidra_procedures: evidence.normalized_result.procedure_count, rust_string_occurrences: rustJson.binary.string_count, ghidra_defined_strings: evidence.normalized_result.string_count };
      const conditional = await record('rea-conditional', process.execPath, [reaEntry, 'decompile', binary, 'fixture_conditional', '--provider', 'ghidra', '--format', 'json']);
      required(conditional, 'Ghidra conditional');
      const conditionalEvidence = parseEvidence(conditional.stdout);
      if (conditionalEvidence.subject?.digest?.sha256 !== report.binary_sha256 || conditionalEvidence.provider?.id !== 'ghidra') throw new Error('Conditional evidence has an unexpected binary or provider binding');
      if (typeof conditionalEvidence.normalized_result !== 'string' || !conditionalEvidence.normalized_result.includes('return')) throw new Error('Conditional pseudocode is missing from provider evidence');
      report.provider.conditional_evidence_id = conditionalEvidence.evidence_id;
      report.provider.status = 'complete';
      report.provider.scope = 'Same controlled PE: overview inventory and conditional-function pseudocode; no equivalence assertion.';
    } else report.provider = { status: 'skipped', reason: '--skip-provider requested; no Ghidra validation' };
    report.status = 'complete';
  } catch (error) {
    report.status = 'failed';
    report.error = error.message;
    if (['running', 'preparing'].includes(report.provider.status)) report.provider.status = 'failed';
    if (report.provider.status === 'pending') report.provider = { status: 'not_run', reason: 'Preceding fixture validation failed' };
    process.exitCode = 1;
  } finally {
    await atomicJson(join(out, 'comparison.json'), report);
    console.log(JSON.stringify({ status: report.status, provider: report.provider.status, evidence: join(out, 'comparison.json'), error: report.error }));
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) await main();
