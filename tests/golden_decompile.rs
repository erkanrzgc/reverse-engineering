use decompiler::analysis::functions::FunctionInfo;
use decompiler::analysis::TypeInfo;
use decompiler::decompiler::{
    recover_function_signatures, structure_function_with_cfg, CGenerator, CGeneratorConfig, Function,
};
use decompiler::disasm::{ControlFlowGraph, X86Instruction};

fn x86(address: u64, mnemonic: &str, operands: &str, target: Option<u64>) -> X86Instruction {
    X86Instruction {
        address,
        bytes: vec![],
        mnemonic: mnemonic.to_string(),
        operands: operands.to_string(),
        length: 1,
        ir: None,
        near_branch_target: target,
    }
}

fn function_info(name: &str, instructions: Vec<X86Instruction>) -> FunctionInfo {
    FunctionInfo {
        name: name.to_string(),
        address: instructions.first().map(|i| i.address).unwrap_or(0x1000),
        size: instructions.iter().map(|i| i.length).sum(),
        instructions: instructions
            .into_iter()
            .map(decompiler::disasm::control_flow::Instruction::X86)
            .collect(),
        is_import: false,
        is_export: false,
    }
}

fn func_from_inline(name: &str, body: Vec<(u64, &str)>) -> Function {
    Function {
        name: name.to_string(),
        return_type: TypeInfo::Void,
        parameters: vec![],
        body: body
            .into_iter()
            .map(|(address, disasm)| decompiler::decompiler::ast::Statement::InlineAsm {
                address,
                disasm: disasm.to_string(),
            })
            .collect(),
        is_variadic: false,
    }
}

#[test]
fn golden_if_else_cmp_jcc_produces_executable_condition() {
    // cmp eax, 0; je 0x1010; mov eax, 1; ret; 0x1010: xor eax,eax; ret
    let instructions = vec![
        x86(0x1000, "cmp", "eax, 0", None),
        x86(0x1001, "je", "1010h", Some(0x1010)),
        x86(0x1002, "mov", "eax, 1", None),
        x86(0x1003, "ret", "", None),
        x86(0x1010, "xor", "eax, eax", None),
        x86(0x1011, "ret", "", None),
    ];

    let cfg = ControlFlowGraph::from_x86(instructions.clone());
    let mut func = func_from_inline(
        "sub_1000",
        vec![
            (0x1000, "cmp eax, 0"),
            (0x1001, "je 1010h"),
            (0x1002, "mov eax, 1"),
            (0x1003, "ret"),
            (0x1010, "xor eax, eax"),
            (0x1011, "ret"),
        ],
    );

    structure_function_with_cfg(&mut func, &cfg);

    let mut gen = CGenerator::new(CGeneratorConfig::default());
    let c = gen.generate_function(&func);
    assert!(
        c.contains("if ((") && c.contains("==") && c.contains("0))"),
        "expected executable cmp-based if condition, got:\n{c}"
    );
}

#[test]
fn golden_stack_var_is_named_local_and_arg() {
    let instructions = vec![
        x86(0x2000, "mov", "qword ptr [rbp-8], eax", None),
        x86(0x2001, "mov", "rax, qword ptr [rbp-8]", None),
        x86(0x2002, "mov", "dword ptr [rbp+10h], 2Ah", None),
        x86(0x2003, "ret", "", None),
    ];
    let cfg = ControlFlowGraph::from_x86(instructions);
    let mut func = func_from_inline(
        "sub_2000",
        vec![
            (0x2000, "mov qword ptr [rbp-8], eax"),
            (0x2001, "mov rax, qword ptr [rbp-8]"),
            (0x2002, "mov dword ptr [rbp+10h], 2Ah"),
            (0x2003, "ret"),
        ],
    );

    structure_function_with_cfg(&mut func, &cfg);
    let mut gen = CGenerator::new(CGeneratorConfig::default());
    let c = gen.generate_function(&func);
    assert!(c.contains("local_8"), "expected local_8, got:\n{c}");
    assert!(c.contains("arg_10"), "expected arg_10, got:\n{c}");
}

#[test]
fn golden_signature_recovery_promotes_rcx_and_rax_return() {
    let mut functions = vec![func_from_inline(
        "sub_3000",
        vec![(0x3000, "mov rax, rcx"), (0x3001, "ret")],
    )];
    // Signature recovery expects structured statements (Assignment/Return),
    // not raw InlineAsm placeholders.
    decompiler::decompiler::structure_function(&mut functions[0]);
    let infos = vec![function_info(
        "sub_3000",
        vec![x86(0x3000, "mov", "rax, rcx", None), x86(0x3001, "ret", "", None)],
    )];

    recover_function_signatures(&mut functions, &infos, "PE/EXE", "x64");
    let mut gen = CGenerator::new(CGeneratorConfig::default());
    let c = gen.generate_function(&functions[0]);
    assert!(
        c.starts_with("uint64_t sub_3000(uint64_t rcx)"),
        "expected rcx param + u64 return, got:\n{c}"
    );
}

