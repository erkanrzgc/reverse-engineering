use reverse_engineering::{
    AnalysisConfig, AnalysisEngine, AnalysisStatus, DiagnosticCode, ResourceLimits,
};
use serde_json::Value;
use std::fs;
use std::path::Path;
use std::process::Command;

#[test]
fn runtime_artifact_limit_is_a_useful_partial_engine_result() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/binary/hello.so");
    let mut bytes = fs::read(fixture).unwrap();
    let elf = goblin::elf::Elf::parse(&bytes).unwrap();
    let section = elf
        .section_headers
        .iter()
        .find(|section| {
            section.sh_type == goblin::elf::section_header::SHT_PROGBITS
                && section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 == 0
                && section.sh_size >= 32
        })
        .unwrap();
    let offset = section.sh_offset as usize;
    bytes[offset..offset + 9].copy_from_slice(b"_MEIPASS\0");
    bytes[offset + 9..offset + 17].copy_from_slice(b"MEI\x0C\x0B\x0A\x0B\x0E");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("budget.elf");
    fs::write(&path, bytes).unwrap();
    let config = AnalysisConfig {
        limits: ResourceLimits {
            max_runtime_artifacts: 0,
            ..ResourceLimits::default()
        },
        ..AnalysisConfig::default()
    };
    let result = AnalysisEngine::analyze_path(&path, &config).unwrap();
    assert_eq!(result.status, AnalysisStatus::Partial);
    assert!(result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == DiagnosticCode::ArtifactLimitExceeded));
    let artifacts = result.runtime_artifacts.unwrap();
    assert!(artifacts.truncated);
    assert!(artifacts.artifacts.is_empty());
}

#[test]
fn report_only_is_available_in_cli_and_omits_generated_c() {
    let fixture = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/binary/hello.so");
    let output = Command::new(env!("CARGO_BIN_EXE_reverse-engineering"))
        .args([
            "analyze",
            fixture.to_str().unwrap(),
            "--only-report",
            "--quiet",
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(value["generated_c"].is_null());
    assert!(value["runtime_artifacts"].is_null());
    assert!(value["report"].is_object());
}

#[test]
fn report_package_contains_promised_text_xrefs_and_pe_directories() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/binary/lld_no_tls_64.exe");
    let dir = tempfile::tempdir().unwrap();
    // This minimal upstream PE has empty data directories. Give the controlled
    // test copy an IAT inventory entry; it needs no import descriptor or execution.
    let mut bytes = fs::read(&fixture).unwrap();
    let pe_offset = u32::from_le_bytes(bytes[60..64].try_into().unwrap()) as usize;
    let optional_header = pe_offset + 24;
    assert_eq!(
        u16::from_le_bytes(
            bytes[optional_header..optional_header + 2]
                .try_into()
                .unwrap()
        ),
        0x20b
    );
    let iat = optional_header + 112 + 12 * 8;
    bytes[iat..iat + 4].copy_from_slice(&0x1000u32.to_le_bytes());
    bytes[iat + 4..iat + 8].copy_from_slice(&8u32.to_le_bytes());
    let fixture = dir.path().join("directories.exe");
    fs::write(&fixture, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_reverse-engineering"))
        .args([
            "analyze",
            fixture.to_str().unwrap(),
            "--format",
            "json",
            "--quiet",
            "--output",
            dir.path().join("result.json").to_str().unwrap(),
            "--report-dir",
            dir.path().join("report").to_str().unwrap(),
            "--artifacts-dir",
            dir.path().join("artifacts").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    for name in [
        "report.txt",
        "behavior_report.txt",
        "import_xrefs.json",
        "pe_directories.json",
    ] {
        assert!(
            dir.path().join("report").join(name).is_file(),
            "missing {name}"
        );
    }
    assert!(dir.path().join("artifacts/runtime_report.txt").is_file());
    let directories: Value =
        serde_json::from_slice(&fs::read(dir.path().join("report/pe_directories.json")).unwrap())
            .unwrap();
    assert!(!directories.as_array().unwrap().is_empty());
}
