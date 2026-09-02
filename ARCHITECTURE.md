# Architecture

`reverse-engineering` is split into a library engine and a deliberately thin CLI.
`AnalysisEngine::analyze_path` owns input limits, parsing, disassembly, detection,
enrichment, and the stable `AnalysisResult` envelope. The CLI validates arguments,
selects outputs, writes files/JSON, and maps fatal errors to exit codes; it does not
implement analysis policy.

## Pipeline and boundaries

1. Read the input under `ResourceLimits` and identify ELF, PE, or Mach-O.
2. Parse sections, imports/exports, and metadata; disassemble supported x86/ARM code.
3. Detect functions, strings, runtimes, and control-flow graphs.
4. Build optional report packages, runtime artifacts, and generated C.
5. Sort address/name keyed collections and serialize the versioned result.

Input open/read, format/parse, missing code, and disassembly failures are fatal and
returned as `AnalysisError`. Independent enrichment limits/failures are represented
in `diagnostics`; the result is `complete` when diagnostics are empty and `partial`
when useful output remains with warnings. A result with no useful analysis is not
manufactured; callers receive a fatal error.

The JSON contract is `docs/schema/analysis-result-v1.schema.json` (`schema_version`
`"1.0"`). Optional outputs may be null or omitted by future producers. Ordering is
stable to make reports and golden fixtures reviewable. Input size and extracted-string
ceilings are enforced before unbounded work; callers should impose process/time
budgets as well.

## v0.2 limits and exclusions

This release is a dependable analysis baseline, not a full compiler. Unsupported or
malformed formats, architectures, and instructions are reported explicitly. SSA,
broad data-flow and type recovery, whole-program semantic reconstruction, GUI
workflows, and guaranteed correct C compilation are outside v0.2 and deferred.
