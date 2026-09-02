use reverse_engineering::{AnalysisConfig, AnalysisEngine, OutputSelection};
use serde_json::Value;
use std::path::{Path, PathBuf};

fn fixture(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/binary")
        .join(name)
}

fn analyze(name: &str) -> reverse_engineering::AnalysisResult {
    AnalysisEngine::analyze_path(
        &fixture(name),
        &AnalysisConfig {
            outputs: OutputSelection::all(),
            ..Default::default()
        },
    )
    .unwrap()
}

fn assert_key_order(json: &str, keys: &[&str]) {
    let mut previous = 0;
    for key in keys {
        let needle = format!("\"{key}\":");
        let position = json
            .find(&needle)
            .unwrap_or_else(|| panic!("missing JSON key {key}"));
        assert!(position >= previous, "JSON key {key} is out of order");
        previous = position;
    }
}

#[test]
fn elf_and_pe_results_obey_v1_contract_and_are_byte_deterministic() {
    for (name, format) in [("hello.so", "ELF"), ("lld_no_tls_64.exe", "PE/EXE")].iter() {
        let first = analyze(name);
        let second = analyze(name);
        let first_json = serde_json::to_string(&first).unwrap();
        assert_eq!(
            first_json,
            serde_json::to_string(&second).unwrap(),
            "{name}"
        );
        let value: Value = serde_json::from_str(&first_json).unwrap();
        assert_key_order(
            &first_json,
            &[
                "schema_version",
                "status",
                "binary",
                "generated_c",
                "report",
                "runtime_artifacts",
                "diagnostics",
            ],
        );
        let binary_start = first_json.find("\"binary\":{").unwrap();
        let binary_end = first_json[binary_start..].find('}').unwrap() + binary_start;
        assert_key_order(
            &first_json[binary_start..=binary_end],
            &[
                "input_path",
                "format",
                "architecture",
                "entry_point",
                "input_bytes",
                "code_section_count",
                "instruction_count",
                "function_count",
                "string_count",
            ],
        );
        assert_eq!(value["schema_version"], "1.0");
        assert_eq!(value["status"], "complete");
        assert_eq!(value["binary"]["format"], *format);
        for field in [
            "input_path",
            "architecture",
            "entry_point",
            "input_bytes",
            "code_section_count",
            "instruction_count",
            "function_count",
            "string_count",
        ] {
            assert!(
                !value["binary"][field].is_null(),
                "{name}: missing binary.{field}"
            );
        }
        assert!(value["generated_c"]
            .as_str()
            .is_some_and(|c| c.contains("#include <stdint.h>")));
        assert!(value["report"].is_object());
        assert!(value["runtime_artifacts"].is_object());
        assert_eq!(value["diagnostics"].as_array().unwrap().len(), 0);
        assert_eq!(first.generated_c, second.generated_c);

        let report = value["report"].as_object().unwrap();
        let functions = report["functions"].as_array().unwrap();
        let addresses: Vec<u64> = functions
            .iter()
            .filter_map(|f| f["address"].as_u64())
            .collect();
        assert!(
            addresses.windows(2).all(|w| w[0] <= w[1]),
            "{name}: function addresses not sorted"
        );
        let names: Vec<&str> = functions
            .iter()
            .filter_map(|f| f["name"].as_str())
            .collect();
        assert!(
            names.windows(2).all(|w| w[0] <= w[1]),
            "{name}: function names not sorted"
        );
    }
}

#[test]
fn generated_c_contains_stable_header_and_is_repeatable() {
    let one = analyze("hello.so").generated_c.unwrap();
    let two = analyze("hello.so").generated_c.unwrap();
    assert_eq!(one, two);
    assert!(one.contains("#include <stdint.h>"));
    assert!(one.contains("#include <stddef.h>"));
}
