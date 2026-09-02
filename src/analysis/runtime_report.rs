//! Runtime-specific analysis reports.
//!
//! Runtime detection answers "what kind of program is this?". This pass answers
//! "what should the analyst do next for that runtime?" without pretending it
//! can recover unavailable original source code.

use crate::analysis::runtime::{RuntimeFamily, RuntimeMatch};
use crate::analysis::strings::StringInfo;
use crate::binary::parser::SectionInfo;

/// Inputs for runtime-specific report generation.
pub struct RuntimeReportInputs<'a> {
    pub runtime_matches: &'a [RuntimeMatch],
    pub sections: &'a [SectionInfo],
    pub strings: &'a [StringInfo],
}

/// Actionable runtime-specific report.
#[derive(Debug, Clone)]
pub struct RuntimeReport {
    pub family: RuntimeFamily,
    pub title: String,
    pub summary: String,
    pub artifacts: Vec<RuntimeArtifact>,
    pub actions: Vec<RuntimeAction>,
}

/// A notable artifact found in the binary.
#[derive(Debug, Clone)]
pub struct RuntimeArtifact {
    pub name: String,
    pub detail: String,
}

/// A recommended analysis action for the runtime.
#[derive(Debug, Clone)]
pub struct RuntimeAction {
    pub label: String,
    pub detail: String,
}

/// Builds actionable reports from runtime matches.
pub struct RuntimeReportBuilder;

impl RuntimeReportBuilder {
    pub fn new() -> Self {
        Self
    }

    pub fn build(&self, inputs: RuntimeReportInputs<'_>) -> Vec<RuntimeReport> {
        inputs
            .runtime_matches
            .iter()
            .map(|runtime| report_for_runtime(runtime, &inputs))
            .collect()
    }
}

impl Default for RuntimeReportBuilder {
    fn default() -> Self {
        Self::new()
    }
}

fn report_for_runtime(runtime: &RuntimeMatch, inputs: &RuntimeReportInputs<'_>) -> RuntimeReport {
    match runtime.family {
        RuntimeFamily::PythonPackaged => python_packaged_report(runtime, inputs),
        RuntimeFamily::PythonNative => python_native_report(runtime),
        RuntimeFamily::DartFlutter => dart_flutter_report(runtime, inputs),
        RuntimeFamily::DotNetClr => dotnet_report(runtime),
        RuntimeFamily::Go => go_report(runtime, inputs),
        RuntimeFamily::Rust => rust_report(runtime),
        RuntimeFamily::ElectronNode => electron_node_report(runtime, inputs),
        RuntimeFamily::Jvm => jvm_report(runtime),
    }
}

fn python_packaged_report(
    runtime: &RuntimeMatch,
    inputs: &RuntimeReportInputs<'_>,
) -> RuntimeReport {
    let mut artifacts = Vec::new();
    add_marker_artifact(inputs, &mut artifacts, "PYZ", "PyInstaller archive marker");
    add_marker_artifact(
        inputs,
        &mut artifacts,
        "_MEIPASS",
        "PyInstaller extraction directory marker",
    );
    add_marker_artifact(
        inputs,
        &mut artifacts,
        "pyi_rth",
        "PyInstaller runtime hook",
    );
    add_marker_artifact(
        inputs,
        &mut artifacts,
        "Nuitka",
        "Nuitka native Python marker",
    );

    RuntimeReport {
        family: runtime.family,
        title: runtime.name.to_string(),
        summary: "Python packaged executable: for PyInstaller-style bundles attempt archive extraction first, then bytecode recovery when .pyc payloads are present.".to_string(),
        artifacts,
        actions: vec![
            action(
                "Extract embedded Python archive",
                "Look for PyInstaller CArchive/PYZ payloads and recover bundled modules before native C pseudocode.",
            ),
            action(
                "Decompile bytecode when available",
                "Recovered .pyc files can often be decompiled back to Python-like source; Nuitka/Cython builds usually require native analysis instead.",
            ),
        ],
    }
}

fn python_native_report(runtime: &RuntimeMatch) -> RuntimeReport {
    RuntimeReport {
        family: runtime.family,
        title: runtime.name.to_string(),
        summary: "Embedded CPython runtime detected: source recovery depends on whether bytecode/modules are embedded or loaded externally.".to_string(),
        artifacts: runtime
            .evidence
            .iter()
            .map(|item| artifact(item, "Runtime evidence"))
            .collect(),
        actions: vec![
            action(
                "Inspect module loading paths",
                "Trace PyImport/Py_Initialize usage to find embedded modules, external paths, or encrypted loaders.",
            ),
            action(
                "Prefer bytecode recovery if present",
                "If .pyc payloads exist, decompile bytecode; otherwise continue with native pseudocode around the embedding API.",
            ),
        ],
    }
}

fn dart_flutter_report(runtime: &RuntimeMatch, inputs: &RuntimeReportInputs<'_>) -> RuntimeReport {
    let mut artifacts = Vec::new();
    for section in inputs.sections {
        if contains_case_insensitive(&section.name, "snapshot") {
            artifacts.push(artifact(
                &section.name,
                "Dart/Flutter snapshot-related section",
            ));
        }
    }
    add_marker_artifact(inputs, &mut artifacts, "dart:ui", "Flutter dart:ui marker");
    add_marker_artifact(inputs, &mut artifacts, "Flutter", "Flutter marker");

    RuntimeReport {
        family: runtime.family,
        title: runtime.name.to_string(),
        summary: "Dart/Flutter AOT binary: release builds are native snapshots, so exact Dart source recovery is not expected.".to_string(),
        artifacts,
        actions: vec![
            action(
                "Inventory snapshots and Flutter markers",
                "Report vm/isolate snapshot sections, dart:ui strings, and Flutter metadata before native decompilation.",
            ),
            action(
                "Use native pseudocode fallback",
                "Recover control flow, strings, and API usage; this is not exact Dart source reconstruction for AOT release builds.",
            ),
        ],
    }
}

fn dotnet_report(runtime: &RuntimeMatch) -> RuntimeReport {
    RuntimeReport {
        family: runtime.family,
        title: runtime.name.to_string(),
        summary: ".NET CLR binary: IL and metadata should be analyzed before treating it as opaque native code.".to_string(),
        artifacts: runtime
            .evidence
            .iter()
            .map(|item| artifact(item, "CLR evidence"))
            .collect(),
        actions: vec![
            action(
                "Prefer IL decompilation",
                "Extract CLR metadata/IL and inspect it with dnSpy, ILSpy, or a future reverse-engineering CLR backend.",
            ),
            action(
                "Use native fallback only for mixed-mode code",
                "Native pseudocode is still useful for unmanaged stubs, packed loaders, or mixed-mode components.",
            ),
        ],
    }
}

fn go_report(runtime: &RuntimeMatch, inputs: &RuntimeReportInputs<'_>) -> RuntimeReport {
    let mut artifacts = Vec::new();
    for section in inputs.sections {
        if contains_case_insensitive(&section.name, "gopclntab")
            || contains_case_insensitive(&section.name, "go.buildinfo")
        {
            artifacts.push(artifact(&section.name, "Go metadata section"));
        }
    }

    RuntimeReport {
        family: runtime.family,
        title: runtime.name.to_string(),
        summary: "Go native binary: recover function names and call graph from preserved runtime metadata when possible.".to_string(),
        artifacts,
        actions: vec![action(
            "Recover Go metadata",
            "Parse pclntab/buildinfo to improve function names before emitting native pseudocode.",
        )],
    }
}

fn rust_report(runtime: &RuntimeMatch) -> RuntimeReport {
    RuntimeReport {
        family: runtime.family,
        title: runtime.name.to_string(),
        summary: "Rust native binary: use panic paths, symbol remnants, and strings to improve native decompilation context.".to_string(),
        artifacts: runtime
            .evidence
            .iter()
            .map(|item| artifact(item, "Rust evidence"))
            .collect(),
        actions: vec![action(
            "Annotate Rust runtime evidence",
            "Use core/std panic markers and any demangled symbols to label functions before native pseudocode.",
        )],
    }
}

fn electron_node_report(runtime: &RuntimeMatch, inputs: &RuntimeReportInputs<'_>) -> RuntimeReport {
    let mut artifacts = Vec::new();
    add_marker_artifact(
        inputs,
        &mut artifacts,
        "app.asar",
        "Electron application archive",
    );
    add_marker_artifact(
        inputs,
        &mut artifacts,
        "node_modules",
        "Node package directory",
    );

    RuntimeReport {
        family: runtime.family,
        title: runtime.name.to_string(),
        summary: "Electron/Node packaged app: JavaScript assets may be recoverable separately from the native wrapper.".to_string(),
        artifacts,
        actions: vec![action(
            "Extract application assets",
            "Look for app.asar/resources and recover JavaScript/TypeScript assets before native wrapper analysis.",
        )],
    }
}

fn jvm_report(runtime: &RuntimeMatch) -> RuntimeReport {
    RuntimeReport {
        family: runtime.family,
        title: runtime.name.to_string(),
        summary: "JVM packaged app: class or JAR content may be recoverable and decompiled as bytecode.".to_string(),
        artifacts: runtime
            .evidence
            .iter()
            .map(|item| artifact(item, "JVM evidence"))
            .collect(),
        actions: vec![action(
            "Extract JVM bytecode",
            "Search for class/JAR resources and decompile bytecode before native launcher analysis.",
        )],
    }
}

fn add_marker_artifact(
    inputs: &RuntimeReportInputs<'_>,
    artifacts: &mut Vec<RuntimeArtifact>,
    needle: &str,
    detail: &str,
) {
    if inputs
        .strings
        .iter()
        .any(|string| contains_case_insensitive(&string.value, needle))
        || inputs
            .sections
            .iter()
            .any(|section| contains_ascii_bytes_case_insensitive(&section.raw_data, needle))
    {
        artifacts.push(artifact(needle, detail));
    }
}

fn action(label: &str, detail: &str) -> RuntimeAction {
    RuntimeAction {
        label: label.to_string(),
        detail: detail.to_string(),
    }
}

fn artifact(name: &str, detail: &str) -> RuntimeArtifact {
    RuntimeArtifact {
        name: name.to_string(),
        detail: detail.to_string(),
    }
}

fn contains_case_insensitive(haystack: &str, needle: &str) -> bool {
    haystack
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn contains_ascii_bytes_case_insensitive(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }

    haystack
        .windows(needle.len())
        .any(|window| ascii_bytes_eq_ignore_case(window, needle))
}

fn ascii_bytes_eq_ignore_case(left: &[u8], right: &[u8]) -> bool {
    left.iter()
        .zip(right.iter())
        .all(|(left, right)| left.eq_ignore_ascii_case(right))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::runtime::{RuntimeFamily, RuntimeMatch};
    use crate::analysis::strings::{StringEncoding, StringInfo};
    use crate::binary::parser::{SectionCharacteristics, SectionInfo};

    fn section(name: &str, data: &[u8]) -> SectionInfo {
        SectionInfo {
            name: name.to_string(),
            virtual_address: 0x1000,
            size: data.len() as u64,
            raw_data: data.to_vec(),
            characteristics: SectionCharacteristics::default(),
        }
    }

    fn string(address: u64, value: &str) -> StringInfo {
        StringInfo {
            address,
            value: value.to_string(),
            encoding: StringEncoding::Ascii,
            length: value.len(),
        }
    }

    fn runtime(family: RuntimeFamily) -> RuntimeMatch {
        RuntimeMatch {
            family,
            name: family.name(),
            confidence: 95,
            evidence: vec!["test evidence".to_string()],
            guidance: "test guidance",
        }
    }

    #[test]
    fn python_packaged_report_recommends_archive_and_pyc_recovery() {
        let sections = vec![section(".rdata", b"PYZ-00.pyz\0_MEIPASS\0pyi_rth")];
        let strings = vec![string(0x2000, "pyi_rth_pkgres")];
        let reports = RuntimeReportBuilder::new().build(RuntimeReportInputs {
            runtime_matches: &[runtime(RuntimeFamily::PythonPackaged)],
            sections: &sections,
            strings: &strings,
        });

        let report = reports
            .iter()
            .find(|report| report.family == RuntimeFamily::PythonPackaged)
            .expect("python report exists");

        assert!(report.summary.contains("PyInstaller"));
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.name.contains("PYZ")));
        assert!(report
            .actions
            .iter()
            .any(|action| action.detail.contains(".pyc")));
    }

    #[test]
    fn dart_flutter_report_lists_snapshot_sections_and_aot_limit() {
        let sections = vec![
            section("vm_snapshot_data", b""),
            section("isolate_snapshot_instructions", b""),
        ];
        let strings = vec![string(0x3000, "dart:ui"), string(0x3010, "Flutter")];
        let reports = RuntimeReportBuilder::new().build(RuntimeReportInputs {
            runtime_matches: &[runtime(RuntimeFamily::DartFlutter)],
            sections: &sections,
            strings: &strings,
        });

        let report = reports
            .iter()
            .find(|report| report.family == RuntimeFamily::DartFlutter)
            .expect("dart/flutter report exists");

        assert!(report.summary.contains("AOT"));
        assert!(report
            .artifacts
            .iter()
            .any(|artifact| artifact.name == "vm_snapshot_data"));
        assert!(report
            .actions
            .iter()
            .any(|action| action.detail.contains("not exact Dart source")));
    }

    #[test]
    fn dotnet_report_prefers_il_metadata_decompilation() {
        let reports = RuntimeReportBuilder::new().build(RuntimeReportInputs {
            runtime_matches: &[runtime(RuntimeFamily::DotNetClr)],
            sections: &[],
            strings: &[],
        });

        let report = reports
            .iter()
            .find(|report| report.family == RuntimeFamily::DotNetClr)
            .expect(".NET report exists");

        assert!(report
            .actions
            .iter()
            .any(|action| action.detail.contains("IL")));
        assert!(report
            .actions
            .iter()
            .any(|action| action.detail.contains("dnSpy")));
    }

    #[test]
    fn no_runtime_matches_produce_no_reports() {
        let reports = RuntimeReportBuilder::new().build(RuntimeReportInputs {
            runtime_matches: &[],
            sections: &[],
            strings: &[],
        });

        assert!(reports.is_empty());
    }
}
