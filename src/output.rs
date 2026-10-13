//! Atomic output helpers.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

use crate::AnalysisResult;

/// Write selected machine output and optional report/artifact packages.
/// Existing known package files are replaced atomically; caller-owned unknown
/// files in those directories are intentionally preserved.
pub fn write_outputs(
    result: &AnalysisResult,
    json: bool,
    output: Option<&Path>,
    report_dir: Option<&Path>,
    artifacts_dir: Option<&Path>,
) -> Result<()> {
    let payload = if json {
        serde_json::to_vec_pretty(result)?
    } else {
        result
            .generated_c
            .as_deref()
            .unwrap_or("")
            .as_bytes()
            .to_vec()
    };
    // Complete every filesystem write before touching stdout. This keeps a
    // failed package write from producing a misleading successful payload.
    if let Some(path) = output {
        if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create output directory {}", parent.display())
            })?;
        }
        atomic_write(path, &payload)?;
    }
    if let Some(dir) = report_dir {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create report directory {}", dir.display()))?;
        if let Some(report) = &result.report {
            atomic_json(&dir.join("analysis_package.json"), report)?;
            write_report_components(dir, report)?;
            atomic_write(
                &dir.join("report.txt"),
                render_report(result, report).as_bytes(),
            )?;
            atomic_write(
                &dir.join("behavior_report.txt"),
                render_behavior(report).as_bytes(),
            )?;
        }
        if let Some(c) = &result.generated_c {
            atomic_write(&dir.join("decompiled.c"), c.as_bytes())?;
        }
    }
    if let Some(dir) = artifacts_dir {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("failed to create artifacts directory {}", dir.display()))?;
        if let Some(artifacts) = &result.runtime_artifacts {
            atomic_json(&dir.join("artifacts_manifest.json"), artifacts)?;
            let mut text = format!(
                "Runtime artifacts: {}\nCaptured bytes: {}\nTruncated: {}\n",
                artifacts.artifacts.len(),
                artifacts.captured_bytes,
                artifacts.truncated
            );
            for artifact in &artifacts.artifacts {
                text.push_str(&format!(
                    "\n{} ({:?}, {:?})\nSource: {}\n{}\n",
                    artifact.name, artifact.kind, artifact.status, artifact.source, artifact.detail
                ));
            }
            for note in &artifacts.notes {
                text.push_str(&format!("\nNote: {note}\n"));
            }
            atomic_write(&dir.join("runtime_report.txt"), text.as_bytes())?;
            for artifact in &artifacts.artifacts {
                if let Some(name) = &artifact.file_name {
                    atomic_write(&dir.join(name), &artifact.payload)?;
                }
            }
        }
    }
    if output.is_none() {
        std::io::stdout().write_all(&payload)?;
        if !payload.ends_with(b"\n") {
            println!();
        }
    }
    Ok(())
}

fn write_report_components(
    dir: &Path,
    report: &crate::analysis::AnalysisReportPackage,
) -> Result<()> {
    macro_rules! component {
        ($name:literal, $value:expr) => {
            atomic_json(&dir.join($name), $value)?;
        };
    }
    component!("functions.json", &report.functions);
    component!("jump_tables.json", &report.jump_tables);
    component!("call_graph.json", &report.call_graph);
    component!("xrefs.json", &report.xrefs);
    component!("import_xrefs.json", &report.xrefs.imports);
    component!("sections.json", &report.sections);
    component!("cfg_summary.json", &report.cfg_summary);
    component!("strings.json", &report.strings);
    component!("suspicious_strings.json", &report.suspicious_strings);
    component!("cyberchef_recipes.json", &report.cyberchef_recipes);
    component!("strings_by_function.json", &report.strings_by_function);
    component!("api_insights.json", &report.api_insights);
    component!("behavior_report.json", &report.behavior_report);
    component!("import_addresses.json", &report.import_addresses);
    component!("imports.json", &report.imports);
    component!("exports.json", &report.exports);
    component!("pe_directories.json", &report.pe_data_directories);
    Ok(())
}

fn render_report(
    result: &AnalysisResult,
    report: &crate::analysis::AnalysisReportPackage,
) -> String {
    let summary = &report.summary;
    let mut text = format!(
        "Reverse-engineering analysis\nInput: {}\nStatus: {:?}\nFormat: {} / {}\nEntry: 0x{:X}\nInstructions: {}\nFunctions: {}\nString occurrences: {}\n\nGenerated C is an approximate reconstruction. Analysis completion does not establish semantic equivalence.\n",
        summary.input_path, result.status, summary.format, summary.architecture,
        summary.entry_point, summary.instruction_count, summary.function_count, summary.string_count,
    );
    for diagnostic in &result.diagnostics {
        text.push_str(&format!("\nDiagnostic: {diagnostic}\n"));
    }
    for function in &report.functions {
        text.push_str(&format!(
            "\n0x{:X} {}: {} bytes, {} instructions, {} calls, {} tail calls\n",
            function.address,
            function.name,
            function.size,
            function.instruction_count,
            function.calls.len(),
            function.tail_calls.len()
        ));
    }
    text
}

fn render_behavior(report: &crate::analysis::AnalysisReportPackage) -> String {
    let behavior = &report.behavior_report;
    let mut text = format!(
        "Behavior triage\nRisk score: {} ({})\nIndicators require analyst interpretation.\n",
        behavior.risk_score, behavior.risk_level
    );
    for finding in &behavior.findings {
        text.push_str(&format!(
            "\n[{} / {}] {}: {}\n",
            finding.category, finding.severity, finding.source, finding.detail
        ));
    }
    text
}

fn atomic_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<()> {
    atomic_write(path, serde_json::to_vec_pretty(value)?.as_slice())
}

/// Atomically makes `contents` visible at `path`, replacing an existing file.
///
/// The temporary file is created beside the destination so the final persist
/// stays on one filesystem. Its contents are synced before replacement, and
/// dropping it after any failed step removes it. This does not sync the parent
/// directory, so it prevents readers from observing partial contents but does
/// not promise that the directory entry survives sudden power loss.
pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary output for {}", path.display()))?;

    temporary
        .write_all(contents)
        .with_context(|| format!("failed to write temporary output for {}", path.display()))?;
    temporary
        .flush()
        .with_context(|| format!("failed to flush temporary output for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("failed to sync temporary output for {}", path.display()))?;
    temporary
        .persist(path)
        .with_context(|| format!("failed to atomically replace {}", path.display()))?;

    Ok(())
}
