# REA-assisted local validation

The Rust analyzer remains standalone. The optional runner uses REA's real Ghidra provider as a comparative source and a separately compiled native program as the behavioral oracle. Agreement with Ghidra is not a proof of general correctness.

## Reference and provenance

- [REA source](https://github.com/morluto/rea/tree/3b0ea590fcc876fa017946f4cec009d653f02b38): commit `3b0ea590fcc876fa017946f4cec009d653f02b38`, MIT.
- npm package `rea-agents@6.4.0`; registry integrity `sha512-Vj1zWfSlna5bphGoaoI/TcVBuYvze9u+OyPC3Shz8YkBqaCTqB4COnnRoX7XDwMpwI24ZlFEel2yEj0k8LTWEQ==`.
- [REA testing methodology](https://github.com/morluto/rea/blob/3b0ea590fcc876fa017946f4cec009d653f02b38/docs/testing.md): controlled source fixtures, real providers and independent compiler oracles.
- [Windows provider boundary](https://github.com/morluto/rea/blob/3b0ea590fcc876fa017946f4cec009d653f02b38/docs/windows-ghidra-p0.md): experimental Windows x64 read-only native PE analysis.

This project uses the installed REA Java bridge through its CLI. No REA implementation source was copied into the Rust core. The repository-owned test assembly and oracle C are licensed with this project.

## Run

Use Windows x64 with GCC, Node 24.11+ (supported 24.x), Ghidra 12.1.4 and a full JDK 21+. REA and portable Ghidra/JDK can live outside the checkout; no agent registration is necessary.

```powershell
$providerRoot = Join-Path $env:LOCALAPPDATA 'reverse-engineering\providers'
npm install --prefix "$providerRoot\rea" --ignore-scripts --no-audit --no-fund rea-agents@6.4.0
$env:GHIDRA_INSTALL_DIR = Join-Path $providerRoot 'ghidra_12.1.4_PUBLIC'
$env:JAVA_HOME = Join-Path $providerRoot 'jdk-21.0.12.1+1'

# Use a fresh build path when resuming a renamed checkout.
$validationTarget = Join-Path $env:TEMP 'reverse-engineering-validation'
cargo build --locked --release --target-dir $validationTarget
node scripts/rea-compare.mjs --analyzer "$validationTarget\release\reverse-engineering.exe"
```

Install/extract the official Ghidra and JDK archives at the selected paths before the run. These are the validated archive hashes for this preparation:

| Archive | SHA-256 |
| --- | --- |
| `ghidra_12.1.4_PUBLIC_20260921.zip` | `ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db` |
| `OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip` | `f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e` |

Use `--rea-entry ABSOLUTE_PATH_TO_rea.mjs` for another local installation, `--out DIRECTORY` for evidence elsewhere, or `--skip-provider` for Rust/native-only checks. The package version is checked before provider execution. The runner builds and executes only this repository's controlled fixture and its generated C.

## What the evidence means

`comparison.json` records source, input and analyzer binary hashes, compiler/analyzer versions, command arguments, exit codes, elapsed times, provider evidence IDs, raw stdout/stderr filenames and hashes, and explicit failed/skipped states. Each child is bounded to 330 seconds and 10 MiB of combined output; native oracle executions use 10 seconds. Deadline/size failures attempt process-tree termination on Windows, with a further three-second cleanup ceiling. An incomplete cleanup is recorded explicitly and cannot become successful provider evidence.

The native oracle and generated C are checked for conditional-zero/one, three-operand multiplication, AL partial writes, MOVZX and indexed LEA. The real provider lane inspects the same PE and decompiles its conditional function. Provider text is retained as evidence; it is not executed or automatically trusted as a verdict.

Fast regressions:

```powershell
cargo test --locked --test decompiler_semantics --test binary_regressions --test analysis_regressions --test output_regressions
node --test scripts/rea-compare.test.mjs
```

## Remaining boundaries

Instruction coverage, indirect calls, general loops/switches, precise stack-frame aliasing and full ABI reconstruction remain incomplete. ARM Thumb/mixed mode and big-endian ARM are rejected where metadata exposes them; stripped mixed-mode inputs without surviving markers remain uncertain. ARM32 Mach-O is rejected until a mode-aware decoder is available. ELF stripped import names, Mach-O universal slices, sectionless ELF, PE overlays and verified Python marshal carving require further work. String extraction is heuristic; Unicode endian ambiguity needs explicit interpretation.

`complete` describes pipeline completion. C reconstruction remains approximate outside the independently tested fixture paths. Artifact truncation is a `partial` analysis with a structured diagnostic and manifest reasons. Decoded instruction counts and total CFG/AST memory still need dedicated limits for very large code sections.
