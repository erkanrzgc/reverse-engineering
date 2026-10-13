# REA-assisted correctness and validation

Date: 2026-10-13. Baseline: `e5070ab`. Branch: `feat/rea-validation`.

## Approved direction

The user accepted the preceding recommendation to use REA/Ghidra as a comparative provider, strengthen real-byte/source-oracle tests, and fix the reproduced defects in this repository. Keep the Rust analyzer standalone. Adopt REA's evidence and explicit-unknown approach; do not treat provider agreement as proof of semantic correctness.

## Design

Use the existing decoded instruction metadata for control flow and operand semantics. Retain instruction provenance through structuring, keep parameters separate from local declarations, and test emitted C with a native compiler where available. Fix parser/decoder and report defects in their owning modules without replacing the analyzer with an external provider.

Add an optional local comparison runner with bounded child-process execution, pinned REA provenance, binary hashes, raw provider evidence, and explicit skipped/error outcomes. It analyzes only our controlled PE fixture on Windows. REA/Ghidra remains an optional developer tool rather than a runtime dependency. Native fixture behavior is the independent oracle.

Alternatives considered: copying REA's TypeScript/provider stack would not repair Rust semantics and would enlarge the dependency surface; replacing this engine with Ghidra would change the product. The selected approach improves this engine while gaining external evidence and reproducible validation.

## Execution

- [x] Baseline: inspect current checkout and run locked tests in a clean-path target.
- [x] Decoder/parser fixes: ARM/x86 control flow, function discovery, ELF/Mach-O metadata and overlapping code sections; real-byte regressions.
- [x] C semantics fixes: provenance/branch handling, declarations, supported arithmetic/addressing and partial-register writes; compile and execute controlled generated C.
- [x] Analysis fixes: address-specific strings, conservative IAT resolution, tail-call consistency, bounded artifact extraction with partial diagnostics.
- [x] REA comparison: inspect and pin upstream source, implement/run optional local fixture comparison, record environmental limitations honestly.
- [x] Documentation/distribution: align examples and CI commands with the actual CLI and supported runners.
- [x] Review, fmt, locked tests, all-target clippy and release build; publish local implementation/verification notes.

## Boundaries

Known-source fixtures and byte regressions measure only their covered instructions and paths. Unsupported instruction modes and uncertain analyses must remain visible. No claim of general C semantic equivalence or live provider compatibility is made without an actual provider run. Existing audit reports remain available as the historical baseline.
