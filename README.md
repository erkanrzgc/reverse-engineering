<h1 align="center">reverse-engineering</h1>

<p align="center">
  <img src="https://img.shields.io/badge/mission-reverse%20engineering%20via%20rust-red?style=for-the-badge" alt="mission">
</p>

<p align="center">
  <img src="https://img.shields.io/badge/rust-1.87+-blue?style=flat-square&logo=rust" alt="rust">
  <img src="https://img.shields.io/badge/crates-12+-purple?style=flat-square" alt="crates">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="license">
  <img src="https://img.shields.io/badge/tests-real%20byte%20regressions-orange?style=flat-square" alt="tests">
  <img src="https://img.shields.io/github/last-commit/erkanrzgc/reverse-engineering?style=flat-square" alt="last commit">
</p>

The minimum supported Rust version (MSRV) is **1.87**. This matches the
compiler version required by the standard-library APIs used by the project.

<p align="center">
  <b>reverse-engineering</b> is a Rust-powered binary decompiler for ELF, PE, and Mach-O executables —
  disassembles x86 & ARM, detects runtime/language families, emits runtime-specific analysis reports,
  extracts runtime artifacts, writes complete reverse-engineering report packages,
  suggests CyberChef decode recipes with one-click deep links for encoded strings,
  classifies imported APIs into behavior categories, resolves PE import-address table calls, builds XREF indexes,
  builds control-flow graphs, detects functions, seeds tail-call targets, flags thunk and jump-table candidates,
  inventories PE data directories, recovers simple stack variables and calling-convention parameters,
  annotates string references, and generates readable approximate C code or machine-readable JSON.
</p>

---

## Features

### Binary Formats

| Format | Description |
|--------|-------------|
| **ELF** | Linux/Unix executables and shared objects |
| **PE** | Windows `.exe` and `.dll` (32-bit & 64-bit) |
| **Mach-O** | macOS executables and dylibs |

### Architectures

| Architecture | Engine |
|---|---|
| x86 / x86-64 | `iced-x86` |
| ARM / AArch64 | `capstone` |

### Decompilation Pipeline

| Stage | Description |
|---|---|
| **Runtime Detection** | Python/PyInstaller/Nuitka, Dart/Flutter, .NET, Go, Rust, Electron/Node, JVM hints |
| **Runtime Reports** | Actionable Python extraction, Dart/Flutter snapshot, CLR/IL, Go/Rust, Electron, JVM guidance |
| **Runtime Artifact Extraction** | Writes `runtime_report.txt`, `artifacts_manifest.json`, Python `.pyc` candidates, PyInstaller CArchive cookie inventory, and Dart/Flutter snapshot inventory |
| **RE Report Package** | Writes `report.txt`, `decompiled.c`, `functions.json`, `call_graph.json`, `xrefs.json`, `import_xrefs.json`, `sections.json`, `cfg_summary.json`, `strings.json`, `strings_by_function.json`, `suspicious_strings.json`, `cyberchef_recipes.json`, `api_insights.json`, `behavior_report.json`, `behavior_report.txt`, `jump_tables.json`, `pe_directories.json`, `import_addresses.json`, `imports.json`, `exports.json`, and `analysis_package.json` |
| **CyberChef Recipes** | Suggests CyberChef operation chains and browser-ready CyberChef links for Base64, hex, URL-percent-encoded, and escaped-byte strings |
| **Behavior Triage** | Groups imported APIs and suspicious strings into filesystem, registry, network, memory, dynamic loading, anti-debug, process execution, process injection, crypto, persistence, and credential categories |
| **Import Resolution** | Records PE IAT thunk RVAs and resolves indirect calls like `call [IAT]` to `dll!ApiName` in call/XREF reports and generated C |
| **CFG Construction** | Control-flow graph via `petgraph` |
| **Function Detection** | Entry point, exports, call targets, tail-call targets, MSVC prologues |
| **Thunk / Jump-Table Signals** | Marks single-jump tail-call thunks and jump-table-like indirect branches as report candidates |
| **AST Lifting** | Pseudo-register and stack assignments (`mov`, `xor reg, reg`, `[rbp-8]`, …) |
| **Structure Recovery** | CFG-aware `if/else` with diamond-shape detection |
| **Condition Recovery** | `cmp/test + jcc` → human-readable expressions |
| **Stack Recovery** | x86 `[rbp±off]` / `[rsp±off]` operands → `local_*`, `arg_*`, `stack_*` variables |
| **Signature Recovery** | Promotes early calling-convention register reads into typed C parameters and simple `rax` returns |
| **String References** | Remaining asm comments annotate matched addresses as `str_XXXX` symbols |
| **PE Metadata** | Reports present PE data directories such as imports, exports, resources, TLS, relocations, CLR, and debug data |
| **C Syntax Hardening** | Escapes strings/comments and sanitizes emitted identifiers |
| **Optimization** | Constant folding, dead-code elimination |
| **C Generation** | Address-annotated C output with direct x86/x64 and import-aware call recovery |
| **CLI Modes** | `analyze INPUT`, `--format c|json`, `--only-report`, package directories, and resource ceilings |

---

## Pipeline

```
parse_binary  ──►  RuntimeDetector  ──►  Runtime hints
       │
       └──────►  disasm (x86 / ARM)  ──►  Vec<Instruction>
                                                    │
                                         FunctionDetector
                                   (entry · exports · call-targets · prologues)
                                                    │
                                          Vec<FunctionInfo>
                                                    │
                                            lift_functions
                                                    │
                                          Vec<ast::Function>
                                                    │
                                   structure_functions_with_cfg
                                (ret · if/else · condition recovery)
                                                    │
                                  Optimizer::optimize_function
                                                    │
                                  CGenerator::generate_function
                                                    │
                                               String (C)
```

---

## Quick Start

```bash
git clone https://github.com/erkanrzgc/reverse-engineering.git
cd reverse-engineering
cargo build --release
```

```bash
# Decompile a binary
cargo run --release --bin reverse-engineering -- analyze <binary> -o output.c

# With optimization
cargo run --release --bin reverse-engineering -- analyze <binary> -o output.c --optimization basic

# Aggressive optimization
cargo run --release --bin reverse-engineering -- analyze <binary> -o output.c --optimization aggressive

# Extract runtime-specific artifacts
cargo run --release --bin reverse-engineering -- analyze <binary> --artifacts-dir artifacts

# Produce a complete reverse-engineering report package
cargo run --release --bin reverse-engineering -- analyze <binary> --report-dir out

# Print machine-readable analysis JSON
cargo run --release --bin reverse-engineering -- analyze <binary> --format json --quiet

# Build reports without generated C
cargo run --release --bin reverse-engineering -- analyze <binary> --report-dir out --only-report --quiet
```

Runtime artifact extraction writes `runtime_report.txt`, `artifacts_manifest.json`,
and any safely identified payloads such as Python `.pyc` candidates. Dart/Flutter
AOT inputs are inventoried as snapshots/markers; exact Dart source recovery is
not claimed.

Report package mode writes `report.txt`, `decompiled.c`, `functions.json`,
`call_graph.json`, `xrefs.json`, `import_xrefs.json`, `sections.json`,
`cfg_summary.json`, `strings.json`, `strings_by_function.json`,
`suspicious_strings.json`, `cyberchef_recipes.json`, `api_insights.json`,
`behavior_report.json`, `behavior_report.txt`, `jump_tables.json`,
`pe_directories.json`, `import_addresses.json`, `imports.json`,
`exports.json`, and `analysis_package.json`. Function reports include direct x86/x64 call
targets, tail-call targets, PE import-address table call targets, grouped call graph edges,
caller/callee XREFs, basic-block estimates, and exact string references when
the binary exposes referenced string addresses. PE reports also expose present
data directories such as resources, TLS, relocations, CLR, debug, imports, and
exports. Generated C also emits import declarations, recovers simple parameters
and return values, and turns resolvable IAT calls into readable API calls. Behavior
reports classify high-signal imports and suspicious strings for quick triage;
CyberChef recipe reports point analysts at likely decode steps and include
ready-to-open CyberChef links. They are
indicators, not a malware verdict.

**Windows smoke test:**
```bash
cargo run --release --bin reverse-engineering -- analyze C:\Windows\System32\notepad.exe -o notepad.c
# → 672 functions · 48,053 instructions · 52,000+ lines of C
```

---

## Output Sample

```c
// 0x11BF  sub_11BF  (export)
void sub_11BF(void) {
    uint64_t rax;
    uint64_t r8b;
    /* 0x11BF: sub rsp,98h */
    /* 0x11C6: mov rax,[34400h] */
    rax = 0;
    if ((r8b == 0)) {
        return;
    }
    sub_140012340();
    /* 0x11DE: xor rax,rsp */
}
```

---

## Tests

```bash
cargo test                  # all suites (unit + integration)
cargo test --lib            # unit tests only
cargo test --test binary_fixtures   # integration: format parsers
```

The suite includes real decoded-byte regressions, parser/CFG checks, bounded extraction tests, and generated-C compilation/execution checks when GCC is available. Run the commands below for the current results.

```bash
cargo test --locked --test decompiler_semantics
cargo test --locked --test binary_regressions
cargo test --locked --test analysis_regressions
cargo test --locked --test output_regressions
node --test scripts/rea-compare.test.mjs
```

**Integration fixtures** under `tests/fixtures/binary/` are vendored from the
[`goblin`](https://github.com/m4b/goblin) crate (MIT, m4b) — see
`tests/fixtures/binary/ATTRIBUTION.md` for licensing.

The optional [REA/Ghidra validation lane](docs/REA_VALIDATION.md) compares a
repository-owned native PE fixture, generated C and independent native outcomes,
with saved provider evidence and explicit deadlines/partial results.

---

## Project Structure

```
src/
├── binary/         # ELF · PE · Mach-O parsing  (goblin)
├── disasm/         # x86 (iced-x86) · ARM (capstone) · CFG
├── analysis/       # function detection · runtime hints/reports · string extraction · types
├── decompiler/     # AST · lifter · structure · string refs · C syntax helpers · optimizer · C gen
└── utils/          # error types
```

---

## Legal Disclaimer

> **This tool is for authorized reverse engineering and educational purposes only.**
> The developers assume no liability for misuse.

---

## License

This project is licensed under the MIT License. See the LICENSE file for more details.
