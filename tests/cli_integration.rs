use serde_json::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/binary")
        .join(name)
}

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_reverse-engineering"))
        .args(args)
        .output()
        .expect("run reverse-engineering")
}

#[test]
fn help_exposes_analyze_without_legacy_input() {
    let output = run(&["--help"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success());
    assert!(stdout.contains("analyze"));
    assert!(!stdout.contains("--input"));
}

#[test]
fn version_is_available_at_root() {
    let output = run(&["--version"]);
    assert!(output.status.success());
    assert!(String::from_utf8_lossy(&output.stdout).contains("reverse-engineering 0.2.0"));
}

#[test]
fn json_success_is_stdout_only() {
    let output = run(&[
        "analyze",
        fixture("hello.so").to_str().unwrap(),
        "--format",
        "json",
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).expect("JSON stdout");
    assert_eq!(value["schema_version"], "1.0");
    assert_eq!(value["status"], "complete");
    assert!(!String::from_utf8_lossy(&output.stderr).contains("schema_version"));
}

#[test]
fn c_success_is_stdout_only() {
    let output = run(&[
        "analyze",
        fixture("hello.so").to_str().unwrap(),
        "--format",
        "c",
    ]);
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("#include"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("#include"));
}

#[test]
fn fatal_input_has_exit_code_three_and_structured_stderr() {
    let path =
        std::env::temp_dir().join(format!("reverse-engineering-empty-{}", std::process::id()));
    fs::write(&path, []).unwrap();
    let output = run(&["analyze", path.to_str().unwrap(), "--format", "json"]);
    let _ = fs::remove_file(path);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("empty_input"));
}

#[test]
fn string_limit_is_partial_json_with_exit_code_four() {
    let output = run(&[
        "analyze",
        fixture("hello.so").to_str().unwrap(),
        "--format",
        "json",
        "--max-extracted-strings",
        "0",
    ]);
    assert_eq!(
        output.status.code(),
        Some(4),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(value["status"], "partial");
    assert_eq!(value["diagnostics"][0]["code"], "string_limit_exceeded");
}

#[test]
fn conflicting_or_invalid_options_are_usage_errors() {
    let output = run(&[
        "analyze",
        fixture("hello.so").to_str().unwrap(),
        "--quiet",
        "--verbose",
    ]);
    assert_eq!(output.status.code(), Some(2));
    let output = run(&[
        "analyze",
        fixture("hello.so").to_str().unwrap(),
        "--format",
        "wat",
    ]);
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn output_and_package_directories_are_created_and_replaced_atomically() {
    let root = std::env::temp_dir().join(format!("reverse-engineering-cli-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    let output_path = root.join("nested/result.c");
    let report_dir = root.join("reports");
    let artifacts_dir = root.join("artifacts");
    let output = run(&[
        "analyze",
        fixture("hello.so").to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
        "--report-dir",
        report_dir.to_str().unwrap(),
        "--artifacts-dir",
        artifacts_dir.to_str().unwrap(),
    ]);
    assert!(
        output.status.success(),
        "stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output_path.is_file());
    assert!(report_dir.join("analysis_package.json").is_file());
    assert!(report_dir.join("decompiled.c").is_file());
    assert!(artifacts_dir.join("artifacts_manifest.json").is_file());
    assert_eq!(
        fs::read_dir(output_path.parent().unwrap()).unwrap().count(),
        1
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn filesystem_output_failure_never_emits_stdout() {
    let root = std::env::temp_dir().join(format!(
        "reverse-engineering-cli-failure-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    let report_path = root.join("report-is-a-file");
    fs::write(&report_path, b"occupied").unwrap();
    let output = run(&[
        "analyze",
        fixture("hello.so").to_str().unwrap(),
        "--report-dir",
        report_path.to_str().unwrap(),
    ]);
    assert_eq!(output.status.code(), Some(3));
    assert!(
        output.stdout.is_empty(),
        "stdout leaked before filesystem failure"
    );
    let _ = fs::remove_dir_all(root);
}

#[test]
fn cli_replaces_existing_output_and_package_files() {
    let root = std::env::temp_dir().join(format!(
        "reverse-engineering-cli-replace-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    let output_path = root.join("result.bin");
    let report_dir = root.join("reports");
    let artifacts_dir = root.join("artifacts");
    let input = fixture("hello.so");
    let common = [
        "analyze",
        input.to_str().unwrap(),
        "--output",
        output_path.to_str().unwrap(),
        "--report-dir",
        report_dir.to_str().unwrap(),
        "--artifacts-dir",
        artifacts_dir.to_str().unwrap(),
    ];
    let first = run(&common);
    assert!(first.status.success());
    let first_output = fs::read(&output_path).unwrap();
    assert!(first_output.starts_with(b"// Decompiled"));
    let report_file = report_dir.join("analysis_package.json");
    fs::write(&report_file, b"stale sentinel").unwrap();
    let mut second_args = common.to_vec();
    second_args.extend(["--format", "json"]);
    let second = run(&second_args);
    assert!(second.status.success());
    let second_output = fs::read(&output_path).unwrap();
    assert_ne!(first_output, second_output);
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&second_output).unwrap()["schema_version"],
        "1.0"
    );
    let replaced_report = fs::read(&report_file).unwrap();
    assert!(!replaced_report.starts_with(b"stale sentinel"));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&replaced_report).unwrap()["summary"]["format"],
        "ELF"
    );
    assert_eq!(fs::read_dir(&root).unwrap().count(), 3);
    let _ = fs::remove_dir_all(root);
}
