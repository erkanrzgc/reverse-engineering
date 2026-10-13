//! Runtime-specific artifact extraction.

use crate::analysis::runtime::{RuntimeFamily, RuntimeMatch};
use crate::analysis::strings::StringInfo;
use crate::binary::parser::{ExportInfo, ImportInfo, SectionInfo};
use serde::Serialize;
use std::collections::HashMap;

const MAX_PYC_CANDIDATE_BYTES: usize = 1024 * 1024;
const PYINSTALLER_COOKIE_MAGIC: &[u8] = b"MEI\x0C\x0B\x0A\x0B\x0E";

/// Independent ceilings for metadata growth and captured payload bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RuntimeArtifactLimits {
    pub max_artifacts: usize,
    pub max_captured_bytes: usize,
}

impl Default for RuntimeArtifactLimits {
    fn default() -> Self {
        Self {
            max_artifacts: 1024,
            max_captured_bytes: 16 * 1024 * 1024,
        }
    }
}

/// A bounded extraction is incomplete when any of these ceilings is reached.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeArtifactTruncationReason {
    ArtifactCountLimit,
    CapturedBytesLimit,
    CandidateBytesLimit,
}

/// Inputs for runtime-specific artifact extraction.
pub struct RuntimeArtifactInputs<'a> {
    pub runtime_matches: &'a [RuntimeMatch],
    pub sections: &'a [SectionInfo],
    pub imports: &'a [ImportInfo],
    pub exports: &'a [ExportInfo],
    pub strings: &'a [StringInfo],
}

/// Structured extraction result written to the runtime artifacts manifest.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeArtifactResult {
    pub artifacts: Vec<RuntimeArtifact>,
    pub notes: Vec<String>,
    pub captured_bytes: usize,
    pub truncated: bool,
    pub truncation_reasons: Vec<RuntimeArtifactTruncationReason>,
}

/// One extracted or inventoried runtime artifact.
#[derive(Debug, Clone, Serialize)]
pub struct RuntimeArtifact {
    pub name: String,
    pub kind: RuntimeArtifactKind,
    pub status: RuntimeArtifactStatus,
    pub runtime: String,
    pub source: String,
    pub virtual_address: Option<u64>,
    pub size: usize,
    pub file_name: Option<String>,
    pub detail: String,
    /// Candidate carving can end at a resource ceiling rather than a format boundary.
    pub payload_truncated: bool,
    #[serde(skip_serializing)]
    pub payload: Vec<u8>,
}

/// Runtime artifact category.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeArtifactKind {
    PythonBytecode,
    PyInstallerArchive,
    PythonMarker,
    DartFlutterSnapshot,
    RuntimeEvidence,
}

/// Whether bytes were extracted or the artifact was only inventoried.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeArtifactStatus {
    Extracted,
    Inventoried,
}

/// Extracts runtime-specific artifacts from parsed binary data.
pub struct RuntimeArtifactExtractor;

impl RuntimeArtifactExtractor {
    pub fn new() -> Self {
        Self
    }

    pub fn extract(&self, inputs: RuntimeArtifactInputs<'_>) -> RuntimeArtifactResult {
        self.extract_with_limits(inputs, RuntimeArtifactLimits::default())
    }

    pub fn extract_with_limits(
        &self,
        inputs: RuntimeArtifactInputs<'_>,
        limits: RuntimeArtifactLimits,
    ) -> RuntimeArtifactResult {
        let mut result = RuntimeArtifactResult {
            artifacts: Vec::new(),
            notes: Vec::new(),
            captured_bytes: 0,
            truncated: false,
            truncation_reasons: Vec::new(),
        };

        if inputs.runtime_matches.is_empty() {
            result.notes.push(
                "No runtime/language family hints detected; no runtime artifacts were found."
                    .to_string(),
            );
            return result;
        }

        let mut used_file_names = HashMap::new();
        for runtime in inputs.runtime_matches {
            if !can_scan(limits, &mut result) {
                break;
            }
            match runtime.family {
                RuntimeFamily::PythonPackaged | RuntimeFamily::PythonNative => {
                    extract_python_bytecode_candidates(
                        runtime,
                        &inputs,
                        &mut used_file_names,
                        &mut result,
                        limits,
                    );
                    if can_scan(limits, &mut result) {
                        inventory_pyinstaller_carchive_cookies(
                            runtime,
                            &inputs,
                            &mut result,
                            limits,
                        );
                    }
                    if can_scan(limits, &mut result) {
                        inventory_python_markers(runtime, &inputs, &mut result, limits);
                    }
                }
                RuntimeFamily::DartFlutter => {
                    inventory_dart_flutter(runtime, &inputs, &mut result, limits);
                }
                _ => {
                    inventory_runtime_evidence(runtime, &mut result, limits);
                }
            }
        }

        if result.truncated {
            result.notes.push(format!("Runtime artifact extraction was truncated by {:?}; later candidates may not have been scanned.", result.truncation_reasons));
        }
        result
    }
}

impl Default for RuntimeArtifactExtractor {
    fn default() -> Self {
        Self::new()
    }
}

fn inventory_python_markers(
    runtime: &RuntimeMatch,
    inputs: &RuntimeArtifactInputs<'_>,
    result: &mut RuntimeArtifactResult,
    limits: RuntimeArtifactLimits,
) {
    let markers = [
        ("PYZ-00.pyz", "PyInstaller PYZ archive marker"),
        ("_MEIPASS", "PyInstaller extraction directory marker"),
        ("pyi_rth", "PyInstaller runtime hook marker"),
        ("Nuitka", "Nuitka native Python compiler marker"),
        ("__nuitka", "Nuitka native Python compiler marker"),
    ];

    for (marker, detail) in markers {
        if !can_scan(limits, result) {
            return;
        }
        if has_marker(inputs, marker) {
            result.artifacts.push(inventoried_artifact(
                marker,
                RuntimeArtifactKind::PythonMarker,
                runtime,
                "binary markers",
                detail,
            ));
        }
    }

    for import in inputs
        .imports
        .iter()
        .filter(|import| contains_case_insensitive(&import.name, "python"))
    {
        if !can_scan(limits, result) {
            return;
        }
        result.artifacts.push(inventoried_artifact(
            &import.name,
            RuntimeArtifactKind::PythonMarker,
            runtime,
            "imports",
            "Python runtime import",
        ));
    }
}

fn inventory_pyinstaller_carchive_cookies(
    runtime: &RuntimeMatch,
    inputs: &RuntimeArtifactInputs<'_>,
    result: &mut RuntimeArtifactResult,
    limits: RuntimeArtifactLimits,
) {
    for section in inputs.sections {
        for (offset, window) in section
            .raw_data
            .windows(PYINSTALLER_COOKIE_MAGIC.len())
            .enumerate()
        {
            if !can_scan(limits, result) {
                return;
            }
            if window != PYINSTALLER_COOKIE_MAGIC {
                continue;
            }
            let Some(virtual_address) = section.virtual_address.checked_add(offset as u64) else {
                continue;
            };
            result.artifacts.push(RuntimeArtifact {
                name: format!("PyInstaller CArchive cookie at 0x{:X}", virtual_address),
                kind: RuntimeArtifactKind::PyInstallerArchive,
                status: RuntimeArtifactStatus::Inventoried,
                runtime: runtime.name.to_string(),
                source: section.name.clone(),
                virtual_address: Some(virtual_address),
                size: PYINSTALLER_COOKIE_MAGIC.len(),
                file_name: None,
                detail: "PyInstaller CArchive cookie magic detected; future parsing can use this as the archive table anchor.".to_string(),
                payload_truncated: false,
                payload: Vec::new(),
            });
        }
    }
}

fn inventory_dart_flutter(
    runtime: &RuntimeMatch,
    inputs: &RuntimeArtifactInputs<'_>,
    result: &mut RuntimeArtifactResult,
    limits: RuntimeArtifactLimits,
) {
    let mut found = false;

    for section in inputs.sections {
        if !can_scan(limits, result) {
            return;
        }
        if contains_case_insensitive(&section.name, "snapshot") {
            found = true;
            result.artifacts.push(RuntimeArtifact {
                name: section.name.clone(),
                kind: RuntimeArtifactKind::DartFlutterSnapshot,
                status: RuntimeArtifactStatus::Inventoried,
                runtime: runtime.name.to_string(),
                source: "sections".to_string(),
                virtual_address: Some(section.virtual_address),
                size: section.raw_data.len(),
                file_name: None,
                detail: "Dart/Flutter snapshot-related section inventory.".to_string(),
                payload_truncated: false,
                payload: Vec::new(),
            });
        }
    }

    let markers = [
        ("dart:ui", "Flutter dart:ui library marker"),
        ("Flutter", "Flutter runtime marker"),
        ("kDartVmSnapshotData", "Dart VM snapshot data marker"),
        (
            "kDartIsolateSnapshotData",
            "Dart isolate snapshot data marker",
        ),
        ("vm_snapshot", "Dart VM snapshot marker"),
        ("isolate_snapshot", "Dart isolate snapshot marker"),
    ];

    for (marker, detail) in markers {
        if !can_scan(limits, result) {
            return;
        }
        if has_marker(inputs, marker) {
            found = true;
            result.artifacts.push(inventoried_artifact(
                marker,
                RuntimeArtifactKind::DartFlutterSnapshot,
                runtime,
                "binary markers",
                detail,
            ));
        }
    }

    if found {
        result
            .notes
            .push("Dart/Flutter AOT snapshot inventory only; exact Dart source reconstruction is not supported.".to_string());
    }
}

fn inventory_runtime_evidence(
    runtime: &RuntimeMatch,
    result: &mut RuntimeArtifactResult,
    limits: RuntimeArtifactLimits,
) {
    for evidence in &runtime.evidence {
        if !can_scan(limits, result) {
            return;
        }
        result.artifacts.push(inventoried_artifact(
            evidence,
            RuntimeArtifactKind::RuntimeEvidence,
            runtime,
            "runtime detector",
            "Runtime detector evidence",
        ));
    }
}

fn extract_python_bytecode_candidates(
    runtime: &RuntimeMatch,
    inputs: &RuntimeArtifactInputs<'_>,
    used_file_names: &mut HashMap<String, usize>,
    result: &mut RuntimeArtifactResult,
    limits: RuntimeArtifactLimits,
) {
    for section in inputs.sections {
        let mut offset = 0;
        while offset < section.raw_data.len() {
            if !can_scan(limits, result) {
                return;
            }
            if !is_pyc_candidate_at(&section.raw_data, offset) {
                offset += 1;
                continue;
            }

            let remaining_bytes = limits
                .max_captured_bytes
                .saturating_sub(result.captured_bytes);
            let candidate_limit = offset
                .saturating_add(MAX_PYC_CANDIDATE_BYTES)
                .min(section.raw_data.len());
            let capture_limit = offset.saturating_add(remaining_bytes).min(candidate_limit);
            let end = next_pyc_candidate_offset(&section.raw_data, offset + 1, capture_limit)
                .unwrap_or(capture_limit);
            let payload_truncated = end == capture_limit && end < section.raw_data.len();
            if payload_truncated {
                mark_truncated(
                    result,
                    if capture_limit < candidate_limit || remaining_bytes <= MAX_PYC_CANDIDATE_BYTES
                    {
                        RuntimeArtifactTruncationReason::CapturedBytesLimit
                    } else {
                        RuntimeArtifactTruncationReason::CandidateBytesLimit
                    },
                );
            }
            let payload = section.raw_data[offset..end].to_vec();
            let Some(virtual_address) = section.virtual_address.checked_add(offset as u64) else {
                offset = end.max(offset + 1);
                continue;
            };
            let base_name = format!(
                "python_bytecode_{}_0x{:X}",
                sanitize_file_stem(&section.name),
                virtual_address
            );
            let file_name = unique_file_name(&base_name, "pyc", used_file_names);

            result.captured_bytes += payload.len();
            result.artifacts.push(RuntimeArtifact {
                name: format!("Python bytecode candidate at 0x{:X}", virtual_address),
                kind: RuntimeArtifactKind::PythonBytecode,
                status: RuntimeArtifactStatus::Extracted,
                runtime: runtime.name.to_string(),
                source: section.name.clone(),
                virtual_address: Some(virtual_address),
                size: payload.len(),
                file_name: Some(file_name),
                detail: "CPython .pyc-like magic and marshal code marker detected; this is an unvalidated carving candidate, not a verified bytecode file.".to_string(),
                payload_truncated,
                payload,
            });

            offset = end.max(offset + 1);
        }
    }
}

fn inventoried_artifact(
    name: &str,
    kind: RuntimeArtifactKind,
    runtime: &RuntimeMatch,
    source: &str,
    detail: &str,
) -> RuntimeArtifact {
    RuntimeArtifact {
        name: name.to_string(),
        kind,
        status: RuntimeArtifactStatus::Inventoried,
        runtime: runtime.name.to_string(),
        source: source.to_string(),
        virtual_address: None,
        size: 0,
        file_name: None,
        detail: detail.to_string(),
        payload_truncated: false,
        payload: Vec::new(),
    }
}

fn next_pyc_candidate_offset(data: &[u8], start: usize, end: usize) -> Option<usize> {
    (start..end).find(|offset| is_pyc_candidate_at(data, *offset))
}

fn can_scan(limits: RuntimeArtifactLimits, result: &mut RuntimeArtifactResult) -> bool {
    let mut allowed = true;
    if result.artifacts.len() >= limits.max_artifacts {
        mark_truncated(result, RuntimeArtifactTruncationReason::ArtifactCountLimit);
        allowed = false;
    }
    if result.captured_bytes >= limits.max_captured_bytes {
        mark_truncated(result, RuntimeArtifactTruncationReason::CapturedBytesLimit);
        allowed = false;
    }
    allowed
}

fn mark_truncated(result: &mut RuntimeArtifactResult, reason: RuntimeArtifactTruncationReason) {
    result.truncated = true;
    if !result.truncation_reasons.contains(&reason) {
        result.truncation_reasons.push(reason);
    }
}

fn is_pyc_candidate_at(data: &[u8], offset: usize) -> bool {
    offset + 17 <= data.len()
        && data[offset + 2] == 0x0D
        && data[offset + 3] == 0x0A
        && matches!(data[offset + 16], 0xE3 | 0x63)
}

fn unique_file_name(
    base_name: &str,
    extension: &str,
    used_file_names: &mut HashMap<String, usize>,
) -> String {
    let first = format!("{base_name}.{extension}");
    let count = used_file_names.entry(first.clone()).or_insert(0);
    *count += 1;
    if *count == 1 {
        first
    } else {
        format!("{base_name}_{}.{extension}", *count)
    }
}

fn sanitize_file_stem(value: &str) -> String {
    let sanitized: String = value
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                ch
            } else {
                '_'
            }
        })
        .collect();

    if sanitized.is_empty() {
        "artifact".to_string()
    } else {
        sanitized
    }
}

fn has_marker(inputs: &RuntimeArtifactInputs<'_>, needle: &str) -> bool {
    inputs
        .strings
        .iter()
        .any(|string| contains_case_insensitive(&string.value, needle))
        || inputs
            .sections
            .iter()
            .any(|section| contains_ascii_bytes_case_insensitive(&section.raw_data, needle))
        || inputs
            .exports
            .iter()
            .any(|export| contains_case_insensitive(&export.name, needle))
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
    use crate::binary::parser::{ExportInfo, ImportInfo, SectionCharacteristics, SectionInfo};

    fn section(name: &str, virtual_address: u64, data: &[u8]) -> SectionInfo {
        SectionInfo {
            name: name.to_string(),
            virtual_address,
            size: data.len() as u64,
            raw_data: data.to_vec(),
            characteristics: SectionCharacteristics::default(),
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

    fn string(address: u64, value: &str) -> StringInfo {
        StringInfo {
            address,
            value: value.to_string(),
            encoding: StringEncoding::Ascii,
            length: value.len(),
        }
    }

    #[test]
    fn no_runtime_matches_produce_no_artifacts() {
        let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
            runtime_matches: &[],
            sections: &[],
            imports: &[] as &[ImportInfo],
            exports: &[] as &[ExportInfo],
            strings: &[],
        });

        assert!(result.artifacts.is_empty());
        assert!(result.notes.iter().any(|note| note.contains("No runtime")));
    }

    #[test]
    fn python_pyc_magic_produces_extracted_bytecode_candidate() {
        let pyc = [
            0xA7, 0x0D, 0x0D, 0x0A, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xE3, 1, 2, 3,
        ];
        let sections = vec![section(
            ".rdata",
            0x4000,
            &[b"noise".as_slice(), &pyc].concat(),
        )];
        let runtimes = vec![runtime(RuntimeFamily::PythonPackaged)];

        let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
            runtime_matches: &runtimes,
            sections: &sections,
            imports: &[] as &[ImportInfo],
            exports: &[] as &[ExportInfo],
            strings: &[],
        });

        let artifact = result
            .artifacts
            .iter()
            .find(|artifact| artifact.kind == RuntimeArtifactKind::PythonBytecode)
            .expect("pyc candidate should be extracted");

        assert_eq!(artifact.status, RuntimeArtifactStatus::Extracted);
        assert_eq!(artifact.virtual_address, Some(0x4005));
        assert!(artifact.file_name.as_deref().unwrap().ends_with(".pyc"));
        assert_eq!(&artifact.payload[..4], &[0xA7, 0x0D, 0x0D, 0x0A]);
    }

    #[test]
    fn python_markers_without_payload_are_inventoried() {
        let sections = vec![section(
            ".rdata",
            0x5000,
            b"PYZ-00.pyz\0_MEIPASS\0pyi_rth_pkgres",
        )];
        let strings = vec![string(0x5010, "pyi_rth_pkgres")];
        let runtimes = vec![runtime(RuntimeFamily::PythonPackaged)];

        let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
            runtime_matches: &runtimes,
            sections: &sections,
            imports: &[] as &[ImportInfo],
            exports: &[] as &[ExportInfo],
            strings: &strings,
        });

        assert!(result.artifacts.iter().any(|artifact| {
            artifact.status == RuntimeArtifactStatus::Inventoried
                && artifact.detail.contains("PyInstaller")
        }));
    }

    #[test]
    fn pyinstaller_carchive_cookie_is_inventoried_with_address() {
        let mut data = b"packed payload bytes".to_vec();
        data.extend_from_slice(b"MEI\x0C\x0B\x0A\x0B\x0E");
        data.extend_from_slice(&[0; 16]);
        let sections = vec![section("overlay", 0x7000, &data)];
        let runtimes = vec![runtime(RuntimeFamily::PythonPackaged)];

        let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
            runtime_matches: &runtimes,
            sections: &sections,
            imports: &[] as &[ImportInfo],
            exports: &[] as &[ExportInfo],
            strings: &[],
        });

        let artifact = result
            .artifacts
            .iter()
            .find(|artifact| artifact.name.contains("PyInstaller CArchive"))
            .expect("CArchive cookie should be inventoried");

        assert_eq!(artifact.kind, RuntimeArtifactKind::PyInstallerArchive);
        assert_eq!(artifact.status, RuntimeArtifactStatus::Inventoried);
        assert_eq!(artifact.virtual_address, Some(0x7014));
        assert!(artifact.detail.contains("cookie"));
    }

    #[test]
    fn dart_flutter_snapshot_markers_are_inventoried_without_source_claims() {
        let sections = vec![section("vm_snapshot_data", 0x6000, b"")];
        let strings = vec![string(0x6010, "dart:ui"), string(0x6020, "Flutter")];
        let runtimes = vec![runtime(RuntimeFamily::DartFlutter)];

        let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
            runtime_matches: &runtimes,
            sections: &sections,
            imports: &[] as &[ImportInfo],
            exports: &[] as &[ExportInfo],
            strings: &strings,
        });

        assert!(result
            .artifacts
            .iter()
            .any(|artifact| artifact.name == "vm_snapshot_data"));
        assert!(result
            .notes
            .iter()
            .any(|note| note.contains("not supported")));
    }
}
