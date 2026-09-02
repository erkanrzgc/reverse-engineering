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

fn assert_sorted_by<F>(array: &Value, label: &str, key: F)
where
    F: Fn(&Value) -> String,
{
    let Some(items) = array.as_array() else {
        return;
    };
    let keys: Vec<String> = items.iter().map(key).collect();
    assert!(
        keys.windows(2).all(|pair| pair[0] <= pair[1]),
        "{label} is not sorted"
    );
}

fn text(item: &Value, field: &str) -> String {
    item[field].as_str().unwrap_or_default().to_owned()
}

fn number(item: &Value, field: &str) -> u64 {
    item[field].as_u64().unwrap_or_default()
}

fn assert_report_collections(report: &Value) {
    assert_sorted_by(&report["functions"], "functions", |v| {
        format!("{:020}:{}", number(v, "address"), text(v, "name"))
    });
    assert_sorted_by(&report["jump_tables"], "jump_tables", |v| {
        format!(
            "{:020}:{:020}",
            number(v, "function_address"),
            number(v, "instruction_address")
        )
    });
    assert_sorted_by(&report["call_graph"], "call_graph", |v| {
        format!(
            "{:020}:{:020}",
            number(v, "caller_address"),
            number(v, "callee_address")
        )
    });
    assert_sorted_by(&report["sections"], "sections", |v| {
        format!("{:020}:{}", number(v, "virtual_address"), text(v, "name"))
    });
    assert_sorted_by(&report["strings"], "strings", |v| {
        format!("{:020}:{}", number(v, "address"), text(v, "symbol"))
    });
    assert_sorted_by(&report["suspicious_strings"], "suspicious_strings", |v| {
        format!("{:020}:{}", number(v, "address"), text(v, "symbol"))
    });
    assert_sorted_by(&report["cyberchef_recipes"], "cyberchef_recipes", |v| {
        format!("{}:{}", text(v, "symbol"), text(v, "recipe_name"))
    });
    assert_sorted_by(&report["strings_by_function"], "strings_by_function", |v| {
        format!(
            "{:020}:{}",
            number(v, "function_address"),
            text(v, "function_name")
        )
    });
    assert_sorted_by(&report["api_insights"], "api_insights", |v| {
        format!("{}:{}", text(v, "library"), text(v, "function"))
    });
    assert_sorted_by(&report["import_addresses"], "import_addresses", |v| {
        format!(
            "{:020}:{}:{}",
            number(v, "address"),
            text(v, "library"),
            text(v, "function")
        )
    });
    assert_sorted_by(&report["imports"], "imports", |v| text(v, "name"));
    assert_sorted_by(&report["exports"], "exports", |v| {
        format!("{:020}:{}", number(v, "address"), text(v, "name"))
    });
    assert_sorted_by(&report["xrefs"]["functions"], "xrefs.functions", |v| {
        format!(
            "{:020}:{}",
            number(v, "function_address"),
            text(v, "function_name")
        )
    });
    assert_sorted_by(&report["xrefs"]["imports"], "xrefs.imports", |v| {
        format!("{}:{}", text(v, "library"), text(v, "function"))
    });
    assert_sorted_by(
        &report["behavior_report"]["categories"],
        "behavior categories",
        |v| text(v, "name"),
    );
    assert_sorted_by(
        &report["behavior_report"]["findings"],
        "behavior findings",
        |v| {
            format!(
                "{}:{}:{}",
                text(v, "category"),
                text(v, "source"),
                text(v, "detail")
            )
        },
    );
    if let Some(items) = report["functions"].as_array() {
        for item in items {
            assert_sorted_by(&item["calls"], "function calls", |v| {
                number(v, "instruction_address").to_string()
            });
            assert_sorted_by(&item["tail_calls"], "tail calls", |v| {
                number(v, "instruction_address").to_string()
            });
            assert_sorted_by(&item["string_refs"], "function string refs", |v| {
                number(v, "instruction_address").to_string()
            });
        }
    }
    if let Some(items) = report["call_graph"].as_array() {
        for item in items {
            assert_sorted_by(&item["call_sites"], "call sites", |v| {
                v.as_u64().unwrap_or_default().to_string()
            });
        }
    }
    if let Some(items) = report["strings_by_function"].as_array() {
        for item in items {
            assert_sorted_by(&item["strings"], "indexed strings", |v| {
                number(v, "instruction_address").to_string()
            });
        }
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
        let report = value["report"].as_object().unwrap();
        assert!(value["runtime_artifacts"].is_object());
        assert_sorted_by(&report["summary"]["runtime_hints"], "runtime hints", |v| {
            text(v, "name")
        });
        assert_sorted_by(
            &value["runtime_artifacts"]["artifacts"],
            "runtime artifacts",
            |v| format!("{}:{:020}", text(v, "kind"), number(v, "address")),
        );
        assert_sorted_by(
            &value["runtime_artifacts"]["notes"],
            "runtime artifact notes",
            |v| v.as_str().unwrap_or_default().to_owned(),
        );
        assert_eq!(value["diagnostics"].as_array().unwrap().len(), 0);
        assert_eq!(first.generated_c, second.generated_c);

        assert_report_collections(&value["report"]);
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
