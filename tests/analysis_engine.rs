use reverse_engineering::{
    output::atomic_write, AnalysisConfig, AnalysisEngine, AnalysisStatus, DiagnosticCode,
    DiagnosticSeverity, OutputSelection, ResourceLimits,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("binary")
        .join(name)
}

fn temp_path(label: &str) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "reverse-engineering-{label}-{}-{sequence}",
        std::process::id()
    ))
}

fn write_temp(label: &str, bytes: &[u8]) -> PathBuf {
    let path = temp_path(label);
    fs::write(&path, bytes).expect("write temporary test input");
    path
}

#[test]
fn analyzes_real_elf_fixture_completely() {
    let config = AnalysisConfig {
        outputs: OutputSelection::all(),
        ..AnalysisConfig::default()
    };

    let result = AnalysisEngine::analyze_path(&fixture("hello.so"), &config).unwrap();

    assert_eq!(result.schema_version, "1.0");
    assert_eq!(result.status, AnalysisStatus::Complete);
    assert_eq!(result.binary.format, "ELF");
    assert!(matches!(result.binary.architecture.as_str(), "x86" | "x64"));
    assert!(result.binary.instruction_count > 0);
    assert!(result.binary.code_section_count > 0);
    assert!(result
        .generated_c
        .as_deref()
        .is_some_and(|c| c.contains("#include <stdint.h>")));
    assert!(result.report.is_some());
    assert!(result.runtime_artifacts.is_some());
    assert!(result.diagnostics.is_empty());
}

#[test]
fn string_limit_returns_useful_partial_result() {
    let config = AnalysisConfig {
        outputs: OutputSelection::report_only(),
        limits: ResourceLimits {
            max_extracted_strings: 0,
            ..ResourceLimits::default()
        },
        ..AnalysisConfig::default()
    };

    let result = AnalysisEngine::analyze_path(&fixture("hello.so"), &config).unwrap();

    assert_eq!(result.status, AnalysisStatus::Partial);
    assert!(result.binary.instruction_count > 0);
    assert_eq!(result.binary.string_count, 0);
    assert!(result.report.is_some());
    assert_eq!(result.diagnostics.len(), 1);
    assert_eq!(result.diagnostics[0].severity, DiagnosticSeverity::Warning);
    assert_eq!(
        result.diagnostics[0].code,
        DiagnosticCode::StringLimitExceeded
    );
}

#[test]
fn fatal_inputs_return_typed_errors_without_panicking() {
    let empty = write_temp("empty", b"");
    let truncated = write_temp("truncated", b"\x7fELF");
    let unsupported = write_temp("unsupported", b"not a supported binary");
    let oversized = write_temp("oversized", b"12345");
    let oversized_config = AnalysisConfig {
        limits: ResourceLimits {
            max_input_bytes: 4,
            ..ResourceLimits::default()
        },
        ..AnalysisConfig::default()
    };

    let cases = [
        (
            &empty,
            AnalysisConfig::default(),
            DiagnosticCode::EmptyInput,
        ),
        (
            &truncated,
            AnalysisConfig::default(),
            DiagnosticCode::ParseFailed,
        ),
        (
            &unsupported,
            AnalysisConfig::default(),
            DiagnosticCode::UnsupportedFormat,
        ),
        (
            &oversized,
            oversized_config,
            DiagnosticCode::InputLimitExceeded,
        ),
    ];

    for (path, config, expected_code) in cases {
        let outcome = std::panic::catch_unwind(|| AnalysisEngine::analyze_path(path, &config));
        let error = outcome.expect("analysis must not panic").unwrap_err();
        assert_eq!(error.status(), AnalysisStatus::Failed);
        assert_eq!(error.code(), expected_code);
        assert_eq!(error.diagnostic().severity, DiagnosticSeverity::Error);
    }

    for path in [empty, truncated, unsupported, oversized] {
        fs::remove_file(path).expect("remove temporary test input");
    }
}

#[test]
fn output_selection_controls_optional_result_payloads() {
    let c_only = AnalysisEngine::analyze_path(
        &fixture("hello.so"),
        &AnalysisConfig {
            outputs: OutputSelection::generated_c_only(),
            ..AnalysisConfig::default()
        },
    )
    .unwrap();
    assert!(c_only.generated_c.is_some());
    assert!(c_only.report.is_none());
    assert!(c_only.runtime_artifacts.is_none());

    let none = AnalysisEngine::analyze_path(
        &fixture("hello.so"),
        &AnalysisConfig {
            outputs: OutputSelection::none(),
            ..AnalysisConfig::default()
        },
    )
    .unwrap();
    assert!(none.generated_c.is_none());
    assert!(none.report.is_none());
    assert!(none.runtime_artifacts.is_none());
}

#[test]
fn output_selection_supports_every_payload_combination() {
    for generated_c in [false, true] {
        for report in [false, true] {
            for runtime_artifacts in [false, true] {
                let outputs = OutputSelection::none()
                    .with_generated_c(generated_c)
                    .with_report(report)
                    .with_runtime_artifacts(runtime_artifacts);

                assert_eq!(outputs.includes_generated_c(), generated_c);
                assert_eq!(outputs.includes_report(), report);
                assert_eq!(outputs.includes_runtime_artifacts(), runtime_artifacts);

                let result = AnalysisEngine::analyze_path(
                    &fixture("hello.so"),
                    &AnalysisConfig {
                        outputs,
                        ..AnalysisConfig::default()
                    },
                )
                .unwrap();

                assert_eq!(result.generated_c.is_some(), generated_c);
                assert_eq!(result.report.is_some(), report);
                assert_eq!(result.runtime_artifacts.is_some(), runtime_artifacts);
            }
        }
    }
}

#[test]
fn repeated_analysis_serializes_identically() {
    let config = AnalysisConfig {
        outputs: OutputSelection::all(),
        ..AnalysisConfig::default()
    };

    let first = AnalysisEngine::analyze_path(&fixture("hello.so"), &config).unwrap();
    let second = AnalysisEngine::analyze_path(&fixture("hello.so"), &config).unwrap();

    assert_eq!(
        serde_json::to_string_pretty(&first).unwrap(),
        serde_json::to_string_pretty(&second).unwrap()
    );
}

#[test]
fn unlimited_input_limit_does_not_overflow() {
    let config = AnalysisConfig {
        outputs: OutputSelection::none(),
        limits: ResourceLimits {
            max_input_bytes: u64::MAX,
            ..ResourceLimits::default()
        },
        ..AnalysisConfig::default()
    };

    let result = AnalysisEngine::analyze_path(&fixture("hello.so"), &config).unwrap();

    assert_eq!(
        result.binary.input_bytes,
        fs::metadata(fixture("hello.so")).unwrap().len()
    );
}

#[test]
fn atomic_writer_creates_and_replaces_files_without_leaving_temps() {
    let dir = temp_path("atomic-dir");
    fs::create_dir(&dir).expect("create atomic writer test directory");
    let path = dir.join("result.txt");

    atomic_write(&path, b"first").unwrap();
    atomic_write(&path, b"replacement").unwrap();

    assert_eq!(fs::read(&path).unwrap(), b"replacement");
    assert_eq!(fs::read_dir(&dir).unwrap().count(), 1);
    fs::remove_dir_all(dir).expect("remove atomic writer test directory");
}

#[test]
fn atomic_writer_returns_contextual_error_for_missing_parent() {
    let path = temp_path("missing-parent")
        .join("nested")
        .join("result.txt");

    let error = atomic_write(&path, b"payload").unwrap_err();

    assert!(error.to_string().contains(&path.display().to_string()));
}
