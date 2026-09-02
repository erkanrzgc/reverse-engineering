# Changelog

## [0.2.0] - 2026-09-02

- Added the stable `AnalysisEngine` boundary and versioned JSON result envelope
  (`schema_version: "1.0"`).
- Added deterministic ordering, explicit resource ceilings, typed diagnostics, and
  complete/partial/failed outcomes.
- Added optional generated C, report package, and runtime-artifact outputs.
- Added cross-platform quality gates, dependency auditing, and parser/IR fuzz targets.

Known limitations: malformed or unsupported formats/architectures remain fatal;
enrichment is best-effort; generated C is readable output rather than a correctness
or compilation guarantee. SSA, broad data-flow/type recovery, GUI support, and
whole-program semantic reconstruction are deferred.
