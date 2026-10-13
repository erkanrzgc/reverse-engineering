# reverse-engineering

A Rust toolkit for static binary analysis, control-flow exploration, and experimental C reconstruction.

[![Rust 1.87+](https://img.shields.io/badge/Rust-1.87%2B-93450a?logo=rust)](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/Cargo.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-2563eb)](LICENSE)
[![Status: Experimental](https://img.shields.io/badge/Status-Experimental-64748b)](#current-scope)

Inspect executable structure, follow function and string references, and produce readable reports or structured JSON from ELF, PE, and Mach-O binaries. The analyzer runs locally and does not execute the input binary.

## Capabilities

| Area | What you can inspect |
| --- | --- |
| Binary structure | Sections, entry points, imports, exports, and PE data directories |
| Disassembly | x86/x86-64 instructions through iced-x86; ARM/AArch64 through Capstone |
| Control flow | Function candidates, basic blocks, call graphs, cross-references, and thunk/jump-table candidates |
| Strings and APIs | Address-aware string references, PE import-address resolution, behavior indicators, and suggested CyberChef recipes |
| Runtime hints | Python, Dart/Flutter, .NET, Go, Rust, Electron/Node, and JVM indicators, with artifact inventories where available |
| Reconstruction | Approximate C output with partial recovery of expressions, conditions, parameters, and stack variables |
| Integration | Versioned JSON results, structured diagnostics, report packages, and configurable extraction limits |

Behavior indicators and runtime hints support analyst review; they do not establish a malware verdict or guarantee source recovery.

## Supported inputs

| Format | Typical inputs |
| --- | --- |
| ELF | Linux/Unix executables and shared objects |
| PE | Windows executables and DLLs |
| Mach-O | macOS executables and dynamic libraries |

Instruction decoding covers x86, x86-64, ARM A32, and AArch64 within the supported format/mode combinations. Thumb, identified mixed ARM/Thumb code, big-endian ARM, and ARM32 Mach-O are rejected. Stripped mixed-mode binaries and universal Mach-O inputs need additional care. C reconstruction is primarily developed around x86/x86-64 fixtures.

## Build and run

The current `0.2.0` development version lives on [`feat/rea-validation`](https://github.com/erkanrzgc/reverse-engineering/tree/feat/rea-validation). The examples below target that branch; `master` contains an earlier implementation.

Install Rust **1.87 or newer** and the native C build tools required by Capstone, then build from source:

```sh
git clone --branch feat/rea-validation --single-branch https://github.com/erkanrzgc/reverse-engineering.git
cd reverse-engineering
cargo build --locked --release
```

Generate a C reconstruction:

```sh
cargo run --locked --release --bin reverse-engineering -- analyze path/to/program -o output/program.c
```

Write structured JSON and a report package without C generation or runtime payload extraction:

```sh
cargo run --locked --release --bin reverse-engineering -- analyze path/to/program --only-report --report-dir output/reports -o output/analysis.json --quiet
```

Produce JSON, reports, and available runtime artifacts together:

```sh
cargo run --locked --release --bin reverse-engineering -- analyze path/to/program --format json --report-dir output/reports --artifacts-dir output/artifacts -o output/analysis.json
```

Use `analyze --help` to see all options. C output uses `basic` optimization by default; `--optimization none` and `--optimization aggressive` select the other modes. Without `-o`, the selected C or JSON output goes to stdout. Logs and diagnostics go to stderr; `--quiet` still preserves warnings.

## Reports and artifacts

| Output | Contents |
| --- | --- |
| `analysis.json` | Full analysis result, status, diagnostics, and selected outputs; the filename is chosen with `-o` |
| `report.txt`, `analysis_package.json` | Human-readable summary and structured report package |
| `functions.json`, `call_graph.json`, `xrefs.json`, `cfg_summary.json` | Function relationships and control-flow summaries |
| `strings.json`, `strings_by_function.json`, `import_xrefs.json` | Strings and import references linked to their analysis context |
| `behavior_report.*`, `api_insights.json`, `cyberchef_recipes.json` | Behavior indicators, API classifications, and decoding suggestions |
| `sections.json`, `imports.json`, `exports.json`, `pe_directories.json` | Binary metadata |
| `decompiled.c` | Approximate C reconstruction when C generation is enabled |
| `artifacts_manifest.json`, `runtime_report.txt` | Runtime artifact provenance, capture status, and extraction notes |

The JSON result contract is documented in the [analysis schema](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/docs/schema/analysis-result-v1.schema.json). Runtime payloads may include Python `.pyc` candidates; Dart/Flutter snapshot inventories do not imply recovery of the original Dart source.

Default limits are **512 MiB per input**, **100,000 extracted strings**, **1,024 runtime artifacts**, and **16 MiB of captured artifact payloads**. Adjust them with `--max-input-bytes`, `--max-extracted-strings`, `--max-runtime-artifacts`, and `--max-runtime-artifact-bytes`. Instruction counts and total CFG/AST memory do not yet have dedicated limits.

For automation, exit codes distinguish completed analysis (`0`), invalid CLI usage (`2`), analysis/output failure (`3`), and partial analysis (`4`). Inspect the result status and diagnostics alongside the exit code.

## Current scope

This is an experimental analysis tool. A `complete` result means the selected analysis pipeline finished; it does not establish that the generated C is semantically equivalent to the input.

General loop recovery, flag propagation across instructions, call signatures, overlapping stack accesses, and indirect control flow remain incomplete. Unsupported instructions may remain as assembly comments, and generated C may require manual correction. The [latest technical assessment](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/docs/PROJECT_REASSESSMENT_2026-10-13.md) records reproduced issues and the evidence behind them.

## Development and validation

```sh
cargo fmt -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-features
```

The test suites cover parsers, disassembly, reports, CLI behavior, and real-byte regressions. Selected x86/x64 reconstruction fixtures are compiled and compared with native behavior when GCC is available.

An optional [REA/Ghidra comparison workflow](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/docs/REA_VALIDATION.md) retains provider output and compares a controlled fixture against an independent native oracle. REA, Ghidra, Java, and Node.js are not required to run the Rust analyzer. Agreement with another decompiler is supporting evidence rather than proof of correctness.

## Documentation and contributions

- [Contributing](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/CONTRIBUTING.md): development workflow and contribution guidelines.
- [Security policy](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/SECURITY.md): reporting vulnerabilities.
- [Technical assessment](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/docs/PROJECT_REASSESSMENT_2026-10-13.md): current strengths, limitations, and reproducible findings.
- [Dataset research](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/docs/DATASET_RESEARCH_2026-10-13.md): candidate evaluation corpora, licensing, and benchmark boundaries.
- [REA validation](https://github.com/erkanrzgc/reverse-engineering/blob/feat/rea-validation/docs/REA_VALIDATION.md): setup, comparison procedure, and evidence provenance.

Useful contributions include small reproducible binaries, known-source regression cases, parser improvements, and report correctness fixes. Include the input architecture, format, expected behavior, and tool version when reporting a bug.

## License

Licensed under the [MIT License](LICENSE). Vendored binary fixtures have their own [attribution notes](tests/fixtures/binary/ATTRIBUTION.md).
