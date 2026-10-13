use reverse_engineering::analysis::functions::FunctionInfo;
use reverse_engineering::analysis::report::{
    AnalysisReportBuilder, AnalysisReportInputs, AnalysisReportPackage,
};
use reverse_engineering::analysis::runtime::{RuntimeFamily, RuntimeMatch};
use reverse_engineering::analysis::runtime_artifacts::{
    RuntimeArtifactExtractor, RuntimeArtifactInputs, RuntimeArtifactLimits,
    RuntimeArtifactTruncationReason,
};
use reverse_engineering::analysis::runtime_report::{RuntimeReportBuilder, RuntimeReportInputs};
use reverse_engineering::analysis::strings::{StringEncoding, StringExtractor, StringInfo};
use reverse_engineering::binary::parser::{
    ImportAddressInfo, ImportInfo, PeDataDirectoryInfo, SectionCharacteristics, SectionInfo,
};
use reverse_engineering::disasm::{ArmDisassembler, Instruction, X86Disassembler};
use reverse_engineering::{AnalysisConfig, AnalysisEngine, DiagnosticCode, OutputSelection};

fn function(address: u64, bytes: &[u8]) -> FunctionInfo {
    FunctionInfo {
        name: format!("sub_{address:X}"),
        address,
        size: bytes.len(),
        instructions: X86Disassembler::new_x64()
            .disassemble(bytes, address)
            .unwrap()
            .into_iter()
            .map(Instruction::X86)
            .collect(),
        is_import: false,
        is_export: false,
    }
}

fn report(
    functions: &[FunctionInfo],
    strings: &[StringInfo],
    imports: &[ImportInfo],
    import_addresses: &[ImportAddressInfo],
) -> AnalysisReportPackage {
    AnalysisReportBuilder::new().build(AnalysisReportInputs {
        input_path: "controlled-byte-fixture",
        format: "fixture",
        architecture: "x64",
        entry_point: 0x1000,
        instruction_count: functions.iter().map(|f| f.instructions.len()).sum(),
        basic_block_count: 0,
        sections: &[],
        functions,
        strings,
        imports,
        import_addresses,
        exports: &[],
        runtime_matches: &[],
    })
}

fn import() -> (Vec<ImportInfo>, Vec<ImportAddressInfo>) {
    (
        vec![ImportInfo {
            name: "kernel32.dll".into(),
            functions: vec!["CreateFileW".into()],
        }],
        vec![ImportAddressInfo {
            library: "kernel32.dll".into(),
            function: "CreateFileW".into(),
            address: 0x4000,
            ordinal: None,
        }],
    )
}

#[test]
fn duplicate_string_occurrences_keep_second_address_xref() {
    let strings = StringExtractor::new().extract(b"same\0same\0", 0x3000);
    assert_eq!(strings.iter().filter(|s| s.value == "same").count(), 2);
    // lea rcx,[rip+0x1ffe] at0x1000 resolves to second occurrence0x3005.
    let functions = [function(
        0x1000,
        &[0x48, 0x8D, 0x0D, 0xFE, 0x1F, 0, 0, 0xC3],
    )];
    let package = report(&functions, &strings, &[], &[]);
    assert_eq!(package.functions[0].string_refs.len(), 1);
    assert_eq!(package.functions[0].string_refs[0].address, 0x3005);
}

#[test]
fn utf8_and_odd_offset_utf16_strings_preserve_encoding() {
    let strings = StringExtractor::new().extract("Türkçe\0".as_bytes(), 0x3000);
    assert!(strings
        .iter()
        .any(|s| s.value == "Türkçe" && s.encoding == StringEncoding::Utf8));
    for (encoding, little_endian) in [
        (StringEncoding::Utf16Le, true),
        (StringEncoding::Utf16Be, false),
    ] {
        let mut bytes = vec![0xFF];
        for unit in "Türkçe".encode_utf16().chain([0]) {
            bytes.extend(if little_endian {
                unit.to_le_bytes()
            } else {
                unit.to_be_bytes()
            });
        }
        let strings = StringExtractor::new().extract(&bytes, 0x3000);
        assert!(strings
            .iter()
            .any(|s| s.value == "Türkçe" && s.address == 0x3001 && s.encoding == encoding));
    }
}

#[test]
fn dynamic_base_and_index_calls_do_not_resolve_displacement_as_iat() {
    let (imports, addresses) = import();
    for bytes in [
        &[0xFF, 0x90, 0, 0x40, 0, 0][..],
        &[0xFF, 0x14, 0xC5, 0, 0x40, 0, 0][..],
    ] {
        let package = report(&[function(0x1000, bytes)], &[], &imports, &addresses);
        assert!(package.functions[0].calls.is_empty());
        assert!(package.xrefs.imports[0].referenced_by.is_empty());
    }
}

#[test]
fn intra_function_loop_is_not_a_tail_call_or_thunk() {
    let package = report(&[function(0x1000, &[0xEB, 0xFE])], &[], &[], &[]);
    assert!(package.functions[0].tail_calls.is_empty());
    assert_eq!(package.functions[0].function_kind, "normal");
    assert!(package.call_graph.is_empty());
}

#[test]
fn true_tail_transfer_populates_graph_callee_and_outgoing_xrefs() {
    let package = report(
        &[
            function(0x1000, &[0xE9, 0xFB, 0x0F, 0, 0]),
            function(0x2000, &[0xC3]),
        ],
        &[],
        &[],
        &[],
    );
    assert_eq!(package.functions[0].tail_calls.len(), 1);
    assert_eq!(package.call_graph.len(), 1);
    assert_eq!(package.call_graph[0].call_sites, vec![0x1000]);
    assert_eq!(package.xrefs.functions[1].called_by.len(), 1);
    assert_eq!(package.xrefs.functions[0].calls_out.len(), 1);
}

#[test]
fn import_tail_thunk_populates_import_caller_index() {
    let (imports, addresses) = import();
    // jmp qword ptr[rip+0x2ffa] -> IAT0x4000.
    let package = report(
        &[function(0x1000, &[0xFF, 0x25, 0xFA, 0x2F, 0, 0])],
        &[],
        &imports,
        &addresses,
    );
    assert_eq!(package.functions[0].tail_calls.len(), 1);
    assert_eq!(package.xrefs.imports[0].referenced_by.len(), 1);
    assert_eq!(package.call_graph.len(), 1);
}

#[test]
fn bcrypt_crypto_functions_are_classified() {
    let imports = [ImportInfo {
        name: "bcrypt.dll".into(),
        functions: vec!["BCryptEncrypt".into(), "BCryptGenRandom".into()],
    }];
    let package = report(&[], &[], &imports, &[]);
    assert_eq!(package.api_insights.len(), 2);
    assert!(package.api_insights.iter().all(|i| i.category == "crypto"));
}

#[test]
fn repeated_pyinstaller_cookie_metadata_is_bounded_by_default() {
    let mut data = b"MEI\x0C\x0B\x0A\x0B\x0E".repeat(4096);
    data.extend_from_slice(b"_MEIPASS\0");
    let sections = [SectionInfo {
        name: ".rdata".into(),
        virtual_address: 0x4000,
        size: data.len() as u64,
        raw_data: data,
        characteristics: SectionCharacteristics::default(),
    }];
    let runtimes = [RuntimeMatch {
        family: RuntimeFamily::PythonPackaged,
        name: "Python packaged",
        confidence: 95,
        evidence: vec![],
        guidance: "fixture",
    }];
    let result = RuntimeArtifactExtractor::new().extract(RuntimeArtifactInputs {
        runtime_matches: &runtimes,
        sections: &sections,
        imports: &[],
        exports: &[],
        strings: &[],
    });
    assert!(
        result.artifacts.len() <= 1024,
        "bounded inventory, got {}",
        result.artifacts.len()
    );
    assert!(result.truncated);
    assert!(result
        .truncation_reasons
        .contains(&RuntimeArtifactTruncationReason::ArtifactCountLimit));
    assert_eq!(result.captured_bytes, 0);
}

#[test]
fn pyc_payload_capture_obeys_shared_byte_budget_and_marks_partial_candidate() {
    let mut data = vec![0; 128];
    data[..4].copy_from_slice(&[0xA7, 0x0D, 0x0D, 0x0A]);
    data[16] = 0xE3;
    let sections = [SectionInfo {
        name: ".rdata".into(),
        virtual_address: 0x4000,
        size: data.len() as u64,
        raw_data: data,
        characteristics: SectionCharacteristics::default(),
    }];
    let runtimes = [RuntimeMatch {
        family: RuntimeFamily::PythonPackaged,
        name: "Python packaged",
        confidence: 95,
        evidence: vec![],
        guidance: "fixture",
    }];
    let result = RuntimeArtifactExtractor::new().extract_with_limits(
        RuntimeArtifactInputs {
            runtime_matches: &runtimes,
            sections: &sections,
            imports: &[],
            exports: &[],
            strings: &[],
        },
        RuntimeArtifactLimits {
            max_artifacts: 4,
            max_captured_bytes: 23,
        },
    );
    assert_eq!(result.artifacts.len(), 1);
    assert_eq!(result.artifacts[0].payload.len(), 23);
    assert_eq!(result.captured_bytes, 23);
    assert!(result.artifacts[0].payload_truncated);
    assert!(result.artifacts[0].detail.contains("unvalidated"));
    assert!(result.truncated);
    assert!(result
        .truncation_reasons
        .contains(&RuntimeArtifactTruncationReason::CapturedBytesLimit));
}

#[test]
fn zero_artifact_budget_stops_before_inventory_or_payload_capture() {
    let runtimes = [RuntimeMatch {
        family: RuntimeFamily::PythonNative,
        name: "Python native",
        confidence: 95,
        evidence: vec!["evidence".into()],
        guidance: "fixture",
    }];
    let result = RuntimeArtifactExtractor::new().extract_with_limits(
        RuntimeArtifactInputs {
            runtime_matches: &runtimes,
            sections: &[],
            imports: &[],
            exports: &[],
            strings: &[],
        },
        RuntimeArtifactLimits {
            max_artifacts: 0,
            max_captured_bytes: 100,
        },
    );
    assert!(result.artifacts.is_empty());
    assert!(result.truncated);
    assert_eq!(result.captured_bytes, 0);
}

#[test]
fn report_keeps_a_separate_pe_data_directory_component() {
    let package = report(&[], &[], &[], &[]);
    let json = serde_json::to_value(package).unwrap();
    assert_eq!(
        json.get("pe_data_directories"),
        Some(&serde_json::json!([]))
    );
    let directories = [PeDataDirectoryInfo {
        name: "IMPORT".into(),
        virtual_address: 0x3000,
        size: 40,
        section: Some(".idata".into()),
    }];
    let package = report(&[], &[], &[], &[]).with_pe_data_directories(&directories);
    assert_eq!(package.pe_data_directories.len(), 1);
    assert_eq!(package.pe_data_directories[0].virtual_address, 0x3000);
    assert_eq!(package.pe_data_directories[0].size, 40);
    assert_eq!(
        package.pe_data_directories[0].section.as_deref(),
        Some(".idata")
    );
}

#[test]
fn python_runtime_guidance_requires_candidate_validation_before_decompiling() {
    let runtimes = [RuntimeMatch {
        family: RuntimeFamily::PythonPackaged,
        name: "Python packaged",
        confidence: 95,
        evidence: vec![],
        guidance: "fixture",
    }];
    let reports = RuntimeReportBuilder::new().build(RuntimeReportInputs {
        runtime_matches: &runtimes,
        sections: &[],
        strings: &[],
    });
    assert!(reports[0]
        .actions
        .iter()
        .any(|action| action.detail.contains("Validate") && action.detail.contains("candidate")));
}

#[test]
fn aarch64_direct_calls_and_tail_transfers_use_decoder_targets() {
    for (opcode, tail) in [(0x94, false), (0x14, true)] {
        let instructions = ArmDisassembler::new_arm64()
            .unwrap()
            .disassemble(&[0x00, 0x04, 0x00, opcode], 0x1000)
            .unwrap()
            .into_iter()
            .map(Instruction::Arm)
            .collect();
        let caller = FunctionInfo {
            name: "caller".into(),
            address: 0x1000,
            size: 4,
            instructions,
            is_import: false,
            is_export: false,
        };
        let package = report(&[caller, function(0x2000, &[0xC3])], &[], &[], &[]);
        let refs = if tail {
            &package.functions[0].tail_calls
        } else {
            &package.functions[0].calls
        };
        assert_eq!(refs.len(), 1);
        assert_eq!(refs[0].target_address, 0x2000);
        assert_eq!(package.call_graph.len(), 1);
    }
}

#[test]
fn utf16_latin_does_not_fabricate_the_opposite_endian_occurrence() {
    let strings = StringExtractor::new().extract(b"T\0e\0s\0t\0\0\0", 0x3000);
    let strings = strings
        .iter()
        .filter(|string| string.address == 0x3000)
        .collect::<Vec<_>>();
    assert_eq!(strings.len(), 1);
    assert_eq!(strings[0].value, "Test");
    assert_eq!(strings[0].encoding, StringEncoding::Utf16Le);
}

#[test]
fn an_exact_string_budget_does_not_report_false_truncation() {
    let fixture =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/binary/hello.so");
    let baseline = AnalysisEngine::analyze_path(
        &fixture,
        &AnalysisConfig {
            outputs: OutputSelection::report_only(),
            ..Default::default()
        },
    )
    .unwrap();
    let count = baseline.report.unwrap().strings.len();
    assert!(count > 0);
    let mut config = AnalysisConfig {
        outputs: OutputSelection::report_only(),
        ..Default::default()
    };
    config.limits.max_extracted_strings = count;
    let result = AnalysisEngine::analyze_path(&fixture, &config).unwrap();
    assert_eq!(result.report.unwrap().strings.len(), count);
    assert!(!result
        .diagnostics
        .iter()
        .any(|diagnostic| diagnostic.code == DiagnosticCode::StringLimitExceeded));
}

#[test]
fn bounded_string_extraction_keeps_small_allowance_and_reports_overflow() {
    let data = (0..4096)
        .map(|index| format!("distinct_string_{index}\0"))
        .collect::<String>();
    let (strings, truncated) = StringExtractor::new().extract_bounded(data.as_bytes(), 0x3000, 2);
    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].value, "distinct_string_0");
    assert_eq!(strings[1].value, "distinct_string_1");
    assert!(truncated);
    let (strings, truncated) =
        StringExtractor::new().extract_bounded(b"first\0second\0", 0x3000, 2);
    assert_eq!(strings.len(), 2);
    assert!(!truncated);
}

#[test]
fn ambiguous_encoding_keeps_occurrences_but_string_xref_prefers_ascii() {
    let strings = StringExtractor::new().extract(b"abcdA\0B\0C\0\0\0", 0x3000);
    assert_eq!(
        strings
            .iter()
            .filter(|string| string.address == 0x3000)
            .count(),
        2
    );
    let functions = [function(
        0x1000,
        &[0x48, 0x8D, 0x0D, 0xF9, 0x1F, 0, 0, 0xC3],
    )];
    let package = report(&functions, &strings, &[], &[]);
    assert_eq!(
        package
            .strings
            .iter()
            .filter(|string| string.address == 0x3000)
            .count(),
        2
    );
    assert_eq!(package.functions[0].string_refs[0].value, "abcdA");
}
