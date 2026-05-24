//! Conservative function signature recovery.

use crate::analysis::{FunctionInfo, TypeInfo};
use crate::decompiler::ast::{Expression, Function, Parameter, Statement};
use crate::disasm::control_flow::Instruction;
use std::collections::BTreeSet;

/// Recover simple ABI-level function signatures and return values in place.
pub fn recover_function_signatures(
    functions: &mut [Function],
    infos: &[FunctionInfo],
    format: &str,
    architecture: &str,
) {
    for (function, info) in functions.iter_mut().zip(infos.iter()) {
        if function.parameters.is_empty() {
            function.parameters = infer_parameters(info, format, architecture);
        }
        recover_rax_return(function);
    }
}

fn infer_parameters(info: &FunctionInfo, format: &str, architecture: &str) -> Vec<Parameter> {
    let Some(arg_registers) = argument_registers(format, architecture) else {
        return Vec::new();
    };

    let mut written = BTreeSet::new();
    let mut used = BTreeSet::new();

    for instruction in info.instructions.iter().take(32) {
        if instruction.is_call() || instruction.is_return() {
            break;
        }
        let Some((mnemonic, operands)) = x86_parts(instruction) else {
            continue;
        };
        let operands = split_operands(operands);
        let dest = operands.first().copied();

        for register in read_registers(&mnemonic, &operands) {
            if arg_registers.contains(&register.as_str()) && !written.contains(&register) {
                used.insert(register);
            }
        }

        if writes_destination(&mnemonic) {
            if let Some(dest) = dest.and_then(register_in_operand) {
                written.insert(dest);
            }
        }
    }

    arg_registers
        .iter()
        .filter(|register| used.contains(**register))
        .map(|register| Parameter {
            name: (*register).to_string(),
            type_info: TypeInfo::U64,
        })
        .collect()
}

fn argument_registers(format: &str, architecture: &str) -> Option<&'static [&'static str]> {
    match (format, architecture) {
        ("PE/EXE", "x64") => Some(&["rcx", "rdx", "r8", "r9"]),
        (_, "x64") => Some(&["rdi", "rsi", "rdx", "rcx", "r8", "r9"]),
        _ => None,
    }
}

fn x86_parts(instruction: &Instruction) -> Option<(String, &str)> {
    let Instruction::X86(instruction) = instruction else {
        return None;
    };
    Some((
        instruction.mnemonic.to_ascii_lowercase(),
        instruction.operands.as_str(),
    ))
}

fn split_operands(operands: &str) -> Vec<&str> {
    operands
        .split(',')
        .map(str::trim)
        .filter(|operand| !operand.is_empty())
        .collect()
}

fn read_registers(mnemonic: &str, operands: &[&str]) -> Vec<String> {
    if mnemonic == "xor" && operands.len() == 2 && operands[0].eq_ignore_ascii_case(operands[1]) {
        return Vec::new();
    }

    let read_operands: &[&str] = match mnemonic {
        "mov" | "movzx" | "movsxd" | "lea" if operands.len() >= 2 => &operands[1..],
        "cmp" | "test" => operands,
        "add" | "sub" | "and" | "or" | "xor" | "imul" => operands,
        _ => operands,
    };

    read_operands
        .iter()
        .filter_map(|operand| register_in_operand(operand))
        .collect()
}

fn writes_destination(mnemonic: &str) -> bool {
    matches!(
        mnemonic,
        "mov" | "movzx" | "movsxd" | "lea" | "xor" | "add" | "sub" | "and" | "or" | "imul"
    )
}

fn register_in_operand(operand: &str) -> Option<String> {
    let cleaned = operand
        .trim()
        .trim_start_matches("byte ptr ")
        .trim_start_matches("word ptr ")
        .trim_start_matches("dword ptr ")
        .trim_start_matches("qword ptr ");
    let token = cleaned
        .split(|ch: char| !(ch.is_ascii_alphanumeric() || ch == '_'))
        .find(|part| !part.is_empty())?;
    canonical_register(token)
}

fn canonical_register(value: &str) -> Option<String> {
    let lower = value.to_ascii_lowercase();
    let canonical = match lower.as_str() {
        "al" | "ah" | "ax" | "eax" | "rax" => "rax",
        "bl" | "bh" | "bx" | "ebx" | "rbx" => "rbx",
        "cl" | "ch" | "cx" | "ecx" | "rcx" => "rcx",
        "dl" | "dh" | "dx" | "edx" | "rdx" => "rdx",
        "sil" | "si" | "esi" | "rsi" => "rsi",
        "dil" | "di" | "edi" | "rdi" => "rdi",
        "r8b" | "r8w" | "r8d" | "r8" => "r8",
        "r9b" | "r9w" | "r9d" | "r9" => "r9",
        _ => return None,
    };
    Some(canonical.to_string())
}

fn recover_rax_return(function: &mut Function) {
    for idx in 1..function.body.len() {
        if !matches!(function.body[idx], Statement::Return(None)) {
            continue;
        }
        if previous_statement_assigns_rax(&function.body[idx - 1]) {
            function.return_type = TypeInfo::U64;
            function.body[idx] = Statement::Return(Some(Expression::Variable("rax".to_string())));
        }
    }
}

fn previous_statement_assigns_rax(statement: &Statement) -> bool {
    matches!(
        statement,
        Statement::Expression(Expression::Assignment { target, .. })
            if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::FunctionInfo;
    use crate::disasm::X86Instruction;

    fn x86(address: u64, mnemonic: &str, operands: &str) -> Instruction {
        Instruction::X86(X86Instruction {
            address,
            bytes: vec![],
            mnemonic: mnemonic.to_string(),
            operands: operands.to_string(),
            length: 0,
            ir: None,
            near_branch_target: None,
        })
    }

    fn info(name: &str, instructions: Vec<Instruction>) -> FunctionInfo {
        FunctionInfo {
            name: name.to_string(),
            address: 0x1000,
            size: 0,
            instructions,
            is_import: false,
            is_export: false,
        }
    }

    fn empty_function(name: &str) -> Function {
        Function {
            name: name.to_string(),
            return_type: TypeInfo::Void,
            parameters: vec![],
            body: vec![],
            is_variadic: false,
        }
    }

    // ---- argument_registers ABI selection ----

    #[test]
    fn pe_x64_uses_microsoft_fastcall_argument_registers() {
        let regs = argument_registers("PE/EXE", "x64").expect("PE/x64 has an ABI");
        assert_eq!(regs, &["rcx", "rdx", "r8", "r9"]);
    }

    #[test]
    fn non_pe_x64_uses_sysv_argument_registers() {
        let regs = argument_registers("ELF", "x64").expect("ELF/x64 has an ABI");
        assert_eq!(regs, &["rdi", "rsi", "rdx", "rcx", "r8", "r9"]);
    }

    #[test]
    fn unknown_architecture_has_no_argument_registers() {
        assert!(argument_registers("ELF", "arm64").is_none());
        assert!(argument_registers("Mach-O", "x86").is_none());
    }

    // ---- canonical_register normalization ----

    #[test]
    fn canonical_register_collapses_register_class_aliases() {
        // All width variants of RAX collapse to "rax".
        for alias in ["al", "ah", "ax", "eax", "rax", "RAX", "Eax"] {
            assert_eq!(canonical_register(alias).as_deref(), Some("rax"));
        }
        // R8 class.
        for alias in ["r8b", "r8w", "r8d", "r8", "R8D"] {
            assert_eq!(canonical_register(alias).as_deref(), Some("r8"));
        }
    }

    #[test]
    fn canonical_register_rejects_non_register_tokens() {
        assert!(canonical_register("rbp").is_none(), "rbp is not an arg register and is intentionally unrecognized here");
        assert!(canonical_register("0x401000").is_none());
        assert!(canonical_register("").is_none());
        assert!(canonical_register("rax_typo").is_none());
    }

    // ---- register_in_operand stripping ----

    #[test]
    fn register_in_operand_strips_ptr_size_prefixes() {
        assert_eq!(
            register_in_operand("qword ptr [rcx+0x10]").as_deref(),
            Some("rcx")
        );
        assert_eq!(
            register_in_operand("dword ptr [r8d]").as_deref(),
            Some("r8")
        );
    }

    #[test]
    fn register_in_operand_returns_none_for_pure_immediate() {
        assert!(register_in_operand("0x1234").is_none());
        assert!(register_in_operand("42").is_none());
    }

    // ---- infer_parameters end-to-end ----

    #[test]
    fn infers_no_parameters_when_no_argument_registers_are_read() {
        // xor reg,reg writes to rcx but does NOT read it (special-cased in
        // read_registers), so rcx should not be picked up as a parameter.
        let func = info(
            "f",
            vec![
                x86(0x1000, "xor", "rcx, rcx"),
                x86(0x1003, "ret", ""),
            ],
        );
        assert!(infer_parameters(&func, "PE/EXE", "x64").is_empty());
    }

    #[test]
    fn infers_used_argument_registers_as_parameters_in_abi_order() {
        // Reads r8, then rcx, then rdx — but the output respects ABI order
        // (rcx, rdx, r8) regardless of first-read order.
        let func = info(
            "f",
            vec![
                x86(0x1000, "mov", "rax, r8"),
                x86(0x1003, "mov", "rbx, rcx"),
                x86(0x1006, "mov", "r10, rdx"),
                x86(0x1009, "ret", ""),
            ],
        );
        let params = infer_parameters(&func, "PE/EXE", "x64");
        let names: Vec<&str> = params.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["rcx", "rdx", "r8"]);
        assert!(params.iter().all(|p| p.type_info == TypeInfo::U64));
    }

    #[test]
    fn infer_parameters_ignores_register_after_it_has_been_written() {
        // First instruction writes rcx (mov rcx, ...); subsequent reads of rcx
        // come from a value produced inside the function, not from the caller.
        let func = info(
            "f",
            vec![
                x86(0x1000, "mov", "rcx, 0x5"),
                x86(0x1004, "mov", "rax, rcx"),
                x86(0x1007, "ret", ""),
            ],
        );
        assert!(infer_parameters(&func, "PE/EXE", "x64").is_empty());
    }

    #[test]
    fn infer_parameters_stops_at_first_call_or_return() {
        // After the call, we read rdx — but inference must stop at the call
        // because past that point, register state is caller-defined again and
        // not necessarily a parameter to this function.
        let func = info(
            "f",
            vec![
                x86(0x1000, "call", "0x2000"),
                x86(0x1005, "mov", "rax, rdx"), // should be ignored
            ],
        );
        assert!(infer_parameters(&func, "PE/EXE", "x64").is_empty());
    }

    #[test]
    fn infer_parameters_returns_empty_when_abi_is_unknown() {
        let func = info("f", vec![x86(0x1000, "mov", "rax, rcx")]);
        assert!(infer_parameters(&func, "Mach-O", "arm64").is_empty());
    }

    // ---- recover_rax_return ----

    #[test]
    fn recovers_rax_return_when_last_statement_is_assignment_then_void_return() {
        let mut func = empty_function("f");
        func.body = vec![
            Statement::Expression(Expression::Assignment {
                target: Box::new(Expression::Variable("rax".to_string())),
                value: Box::new(Expression::IntegerLiteral(0)),
            }),
            Statement::Return(None),
        ];
        recover_rax_return(&mut func);

        assert_eq!(func.return_type, TypeInfo::U64);
        assert!(matches!(
            &func.body[1],
            Statement::Return(Some(Expression::Variable(name))) if name == "rax"
        ));
    }

    #[test]
    fn does_not_recover_rax_return_when_previous_assigns_a_different_register() {
        let mut func = empty_function("f");
        func.body = vec![
            Statement::Expression(Expression::Assignment {
                target: Box::new(Expression::Variable("rcx".to_string())),
                value: Box::new(Expression::IntegerLiteral(7)),
            }),
            Statement::Return(None),
        ];
        recover_rax_return(&mut func);

        assert_eq!(func.return_type, TypeInfo::Void);
        assert!(matches!(&func.body[1], Statement::Return(None)));
    }

    #[test]
    fn recover_rax_return_is_safe_on_short_or_empty_bodies() {
        let mut empty = empty_function("f");
        recover_rax_return(&mut empty);
        assert_eq!(empty.return_type, TypeInfo::Void);

        let mut single = empty_function("g");
        single.body = vec![Statement::Return(None)];
        recover_rax_return(&mut single);
        assert!(matches!(&single.body[0], Statement::Return(None)));
        assert_eq!(single.return_type, TypeInfo::Void);
    }

    // ---- recover_function_signatures top-level integration ----

    #[test]
    fn recover_function_signatures_assigns_parameters_only_when_none_preexist() {
        let mut funcs = vec![empty_function("f")];
        let infos = vec![info(
            "f",
            vec![x86(0x1000, "mov", "rax, rcx"), x86(0x1003, "ret", "")],
        )];

        recover_function_signatures(&mut funcs, &infos, "PE/EXE", "x64");
        let names: Vec<&str> = funcs[0].parameters.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["rcx"]);

        // Run again with a preset parameter: inference must NOT overwrite it.
        funcs[0].parameters = vec![Parameter {
            name: "preset_arg".to_string(),
            type_info: TypeInfo::I32,
        }];
        recover_function_signatures(&mut funcs, &infos, "PE/EXE", "x64");
        let names: Vec<&str> = funcs[0].parameters.iter().map(|p| p.name.as_str()).collect();
        assert_eq!(names, vec!["preset_arg"]);
    }
}
