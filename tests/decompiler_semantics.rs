//! Real-byte regressions. GCC executes only the controlled C emitted for these fixtures.
use reverse_engineering::analysis::FunctionInfo;
use reverse_engineering::binary::parser::ImportAddressInfo;
use reverse_engineering::decompiler::{
    lift_function, lift_functions_with_imports, recover_function_signatures,
    structure_function_with_cfg, CGenerator, CGeneratorConfig,
};
use reverse_engineering::disasm::{ControlFlowGraph, Instruction, X86Disassembler};
use std::process::Command;

fn fixture(bytes: &[u8]) -> (FunctionInfo, ControlFlowGraph) {
    let instructions = X86Disassembler::new_x64()
        .disassemble(bytes, 0x1000)
        .unwrap();
    let cfg = ControlFlowGraph::from_x86(instructions.clone());
    let info = FunctionInfo {
        name: "fixture".into(),
        address: 0x1000,
        size: bytes.len(),
        instructions: instructions.into_iter().map(Instruction::X86).collect(),
        is_import: false,
        is_export: false,
    };
    (info, cfg)
}

fn emitted(bytes: &[u8], signature_first: bool) -> String {
    let (info, cfg) = fixture(bytes);
    let mut functions = vec![lift_function(&info)];
    if signature_first {
        recover_function_signatures(&mut functions, std::slice::from_ref(&info), "PE/EXE", "x64");
    }
    structure_function_with_cfg(&mut functions[0], &cfg);
    recover_function_signatures(&mut functions, &[info], "PE/EXE", "x64");
    CGenerator::new(CGeneratorConfig::default()).generate_function(&functions[0])
}

fn run_c(c: &str, checks: &str) {
    let compiler = std::env::var("REA_C_COMPILER").unwrap_or_else(|_| "gcc".into());
    if Command::new(&compiler).arg("--version").output().is_err() {
        eprintln!("SKIPPED native C oracle: {compiler} unavailable; run with REA_C_COMPILER set");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("fixture.c");
    let executable = dir.path().join(if cfg!(windows) {
        "fixture.exe"
    } else {
        "fixture"
    });
    // A failed predicate exits normally; C abort/assert can open a Windows crash dialog.
    std::fs::write(&source, format!("#include <stdint.h>\n#define assert(c) do {{ if (!(c)) return 1; }} while (0)\n{c}\nint main(void) {{ {checks} return 0; }}\n")).unwrap();
    let output = Command::new(&compiler)
        .args(["-std=c11", "-O0", "-Wall", "-Werror"])
        .arg(&source)
        .arg("-o")
        .arg(&executable)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "generated C failed compilation:\n{}\n{c}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = Command::new(executable).output().unwrap();
    assert!(
        output.status.success(),
        "source oracle disagrees with generated C:\n{}\n{c}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn real_conditional_retains_both_arms_and_matches_source_oracle() {
    // cmp ecx,0; je zero; mov eax,1; ret; zero: xor eax,eax; ret
    let c = emitted(
        &[
            0x83, 0xf9, 0, 0x74, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3,
        ],
        true,
    );
    assert!(c.contains("if ("), "branch vanished:\n{c}");
    run_c(
        &c,
        "assert(fixture(0) == 0); assert(fixture(1) == 1); assert(fixture(0x100000000ULL) == 0);",
    );
}

#[test]
fn recovered_parameter_is_not_redeclared_as_local() {
    let c = emitted(&[0x8b, 0xc1, 0xc3], false);
    run_c(
        &c,
        "assert(fixture(42) == 42); assert(fixture(0x100000001ULL) == 1);",
    );
}

#[test]
fn lea_computes_address_without_reading_destination_or_memory() {
    // mov eax,99; lea eax,[rcx+rcx*2+5]; ret
    let c = emitted(&[0xb8, 99, 0, 0, 0, 0x8d, 0x44, 0x49, 5, 0xc3], true);
    run_c(
        &c,
        "assert(fixture(3) == 14); assert(fixture(0xffffffffULL) == 2);",
    );
}

#[test]
fn three_operand_imul_uses_both_source_operands() {
    // mov eax,99; imul eax,ecx,7; ret
    let c = emitted(&[0xb8, 99, 0, 0, 0, 0x6b, 0xc1, 7, 0xc3], true);
    run_c(
        &c,
        "assert(fixture(3) == 21); assert(fixture(0xffffffffULL) == 0xfffffff9ULL);",
    );
}

#[test]
fn low_byte_write_preserves_other_register_bits() {
    // mov rax,1234h; mov al,56h; ret
    let c = emitted(
        &[0x48, 0xc7, 0xc0, 0x34, 0x12, 0, 0, 0xb0, 0x56, 0xc3],
        true,
    );
    run_c(&c, "assert(fixture() == 0x1256);");
}

#[test]
fn movzx_reads_only_the_source_register_width() {
    // mov rax,1234h; movzx eax,al; ret
    let c = emitted(
        &[0x48, 0xc7, 0xc0, 0x34, 0x12, 0, 0, 0x0f, 0xb6, 0xc0, 0xc3],
        true,
    );
    run_c(&c, "assert(fixture() == 0x34);");
}

#[test]
fn indexed_frame_memory_is_preserved_as_unsupported() {
    // mov rax,[rbp+rcx*8-8]; ret: this is not the scalar slot local_8.
    let c = emitted(&[0x48, 0x8b, 0x44, 0xcd, 0xf8, 0xc3], true);
    assert!(
        !c.contains("local_8"),
        "indexed operand falsely became scalar stack slot:\n{c}"
    );
    assert!(
        c.contains("rbp+rcx*8-8"),
        "unsupported indexed load must stay visible:\n{c}"
    );
}

#[test]
fn dynamic_memory_call_does_not_resolve_an_iat_displacement() {
    let (info, _) = fixture(&[0xff, 0x90, 0, 0x40, 0, 0, 0xc3]); // call qword ptr [rax+4000h]
    let imports = [ImportAddressInfo {
        library: "fixture.dll".into(),
        function: "known_import".into(),
        address: 0x4000,
        ordinal: None,
    }];
    let functions = lift_functions_with_imports(&[info], &imports);
    let c = CGenerator::new(CGeneratorConfig::default()).generate_function(&functions[0]);
    assert!(
        !c.contains("known_import("),
        "dynamic base ignored during IAT resolution:\n{c}"
    );
}

#[test]
fn absolute_memory_call_resolves_the_known_iat_slot() {
    let (info, _) = fixture(&[0xff, 0x14, 0x25, 0, 0x40, 0, 0, 0xc3]);
    let imports = [ImportAddressInfo {
        library: "fixture.dll".into(),
        function: "known_import".into(),
        address: 0x4000,
        ordinal: None,
    }];
    let functions = lift_functions_with_imports(&[info], &imports);
    let c = CGenerator::new(CGeneratorConfig::default()).generate_function(&functions[0]);
    assert!(
        c.contains("known_import("),
        "known absolute IAT call lost:\n{c}"
    );
}

#[test]
fn locked_arithmetic_keeps_atomic_semantics_explicitly_unsupported() {
    // lock add dword ptr [rbp-8],ecx; ret
    let c = emitted(&[0xf0, 0x01, 0x4d, 0xf8, 0xc3], true);
    assert!(
        c.contains("lock add"),
        "atomic arithmetic became a plain assignment:\n{c}"
    );
    assert!(
        !c.contains("local_8 ="),
        "atomic memory operation silently lifted:\n{c}"
    );
}

#[test]
fn signed_and_unsigned_comparisons_use_the_register_view_width() {
    let signed = emitted(
        &[
            0x83, 0xf9, 0, 0x7c, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3,
        ],
        true,
    );
    run_c(
        &signed,
        "assert(fixture(0xffffffffULL) == 0); assert(fixture(0x100000001ULL) == 1);",
    );
    let unsigned = emitted(
        &[
            0x83, 0xf9, 0, 0x72, 6, 0xb8, 1, 0, 0, 0, 0xc3, 0x31, 0xc0, 0xc3,
        ],
        true,
    );
    run_c(
        &unsigned,
        "assert(fixture(0xffffffffULL) == 1); assert(fixture(0) == 1);",
    );
}

#[test]
fn partial_argument_write_preserves_incoming_upper_bits() {
    // mov cl,56h; mov rax,rcx; ret
    let c = emitted(&[0xb1, 0x56, 0x48, 0x8b, 0xc1, 0xc3], false);
    run_c(&c, "assert(fixture(0x1234) == 0x1256);");
}

#[test]
fn indexed_lea_recovers_both_address_register_parameters() {
    // lea rax,[rcx+rdx*8-8]; ret
    let c = emitted(&[0x48, 0x8d, 0x44, 0xd1, 0xf8, 0xc3], false);
    run_c(&c, "assert(fixture(100, 3) == 116);");
}

#[test]
fn extended_low_byte_register_alias_preserves_upper_bits() {
    // mov r8,1234h; mov r8b,56h; mov rax,r8; ret
    let c = emitted(
        &[
            0x49, 0xb8, 0x34, 0x12, 0, 0, 0, 0, 0, 0, 0x41, 0xb0, 0x56, 0x4c, 0x89, 0xc0, 0xc3,
        ],
        false,
    );
    run_c(&c, "assert(fixture() == 0x1256);");
}

#[test]
fn prefixed_return_keeps_decoded_control_flow_semantics() {
    // mov eax,7; rep ret (a legal prefixed RET idiom)
    let c = emitted(&[0xb8, 7, 0, 0, 0, 0xf3, 0xc3], false);
    run_c(&c, "assert(fixture() == 7);");
}

#[test]
fn typed_string_annotations_reject_dynamic_displacements_and_resolve_static_ip_targets() {
    use reverse_engineering::analysis::strings::{StringEncoding, StringInfo};
    use reverse_engineering::decompiler::annotate_string_references_with_instructions;
    let string = |address| StringInfo {
        address,
        value: "known string".into(),
        encoding: StringEncoding::Ascii,
        length: 12,
    };
    let (dynamic, _) = fixture(&[0x48, 0x8b, 0x80, 0, 0x40, 0, 0, 0xc3]);
    let (static_ip, _) = fixture(&[0x48, 0x8b, 0x05, 0xfe, 0x1f, 0, 0, 0xc3]); // target 0x3005
    let infos = [dynamic, static_ip];
    let mut functions = infos.iter().map(lift_function).collect::<Vec<_>>();
    annotate_string_references_with_instructions(
        &mut functions,
        &[string(0x4000), string(0x3005)],
        &infos,
    );
    let mut generator = CGenerator::new(CGeneratorConfig::default());
    let dynamic = generator.generate_function(&functions[0]);
    let static_ip = generator.generate_function(&functions[1]);
    assert!(
        !dynamic.contains("str_4000"),
        "dynamic displacement misannotated:\n{dynamic}"
    );
    assert!(
        static_ip.contains("str_3005"),
        "static IP target missed:\n{static_ip}"
    );
}
