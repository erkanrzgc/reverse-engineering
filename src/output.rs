//! Atomic output helpers.

use anyhow::{Context, Result};
use std::io::Write;
use std::path::Path;

use crate::AnalysisResult;

/// Write selected machine output and optional report/artifact packages.
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
    Ok(())
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
