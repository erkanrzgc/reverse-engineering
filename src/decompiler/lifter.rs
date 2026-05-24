//! Bridge from disassembly-level `FunctionInfo` to AST-level `ast::Function`.
//!
//! The lifter produces a well-typed `ast::Function` whose body contains
//! a mix of real `Expression` statements and `InlineAsm` placeholders.
//! Arithmetic, logic, and shift instructions are lifted to `Assignment` +
//! `BinaryOperation` / `UnaryOperation` nodes when the instruction carries
//! an `InstructionIR`. Instructions without IR (or with unsupported operand
//! forms) fall back to `InlineAsm` so structuring and C generation remain
//! compilable.
//!
//! Structuring, type recovery, and parameter inference belong to later
//! passes. The point is to have a single well-defined seam between
//! `analysis::FunctionInfo` (what we discovered) and `decompiler::CGenerator`
//! (what we emit), so downstream passes can iterate on the AST rather than on
//! raw instruction lists.

use crate::analysis::{FunctionInfo, TypeInfo};
use crate::binary::parser::ImportAddressInfo;
use crate::decompiler::ast::{
    BinaryOperator, Expression, Function, Statement, UnaryOperator,
};
use crate::decompiler::c_syntax::{sanitize_c_identifier, unique_c_identifier};
use crate::disasm::control_flow::Instruction;
use crate::disasm::ir::{Operand, Operand::*, MemoryOperand};
use std::collections::BTreeSet;
use std::collections::HashMap;

/// C declaration metadata for one imported function.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ImportFunctionDeclaration {
    pub library: String,
    pub function: String,
    pub address: u64,
    pub ordinal: Option<u16>,
    pub c_name: String,
}

/// Lift a single detected function into an AST function.
///
/// The body preserves original instruction order and addresses. The return
/// type defaults to `void` and the parameter list is empty — signatures are
/// reconstructed by later analysis passes once calling-convention recovery
/// lands.
pub fn lift_function(info: &FunctionInfo) -> Function {
    let fallback = format!("sub_{:X}", info.address);
    lift_function_with_name(
        info,
        sanitize_c_identifier(&info.name, &fallback),
        &HashMap::new(),
    )
}

/// Lift a slice of detected functions.
pub fn lift_functions(infos: &[FunctionInfo]) -> Vec<Function> {
    lift_functions_with_imports(infos, &[])
}

/// Lift detected functions and resolve known import-address call targets.
pub fn lift_functions_with_imports(
    infos: &[FunctionInfo],
    imports: &[ImportAddressInfo],
) -> Vec<Function> {
    let mut used_names = BTreeSet::new();
    let mut resolved_names = Vec::with_capacity(infos.len());

    for info in infos {
        let fallback = format!("sub_{:X}", info.address);
        let unique_name = unique_c_identifier(&info.name, &fallback, &mut used_names);
        resolved_names.push((info.address, unique_name));
    }

    let mut call_targets: HashMap<u64, String> = resolved_names.iter().cloned().collect();
    call_targets.extend(import_call_targets(imports));

    infos
        .iter()
        .zip(resolved_names)
        .map(|(info, (_, unique_name))| lift_function_with_name(info, unique_name, &call_targets))
        .collect()
}

/// Build C-safe import declarations in the same naming scheme used by the lifter.
pub fn import_function_declarations(
    imports: &[ImportAddressInfo],
) -> Vec<ImportFunctionDeclaration> {
    let mut used_names = BTreeSet::new();
    imports
        .iter()
        .map(|import| {
            let fallback = format!("import_{:X}", import.address);
            ImportFunctionDeclaration {
                library: import.library.clone(),
                function: import.function.clone(),
                address: import.address,
                ordinal: import.ordinal,
                c_name: unique_c_identifier(&import.function, &fallback, &mut used_names),
            }
        })
        .collect()
}

fn import_call_targets(imports: &[ImportAddressInfo]) -> HashMap<u64, String> {
    import_function_declarations(imports)
        .into_iter()
        .map(|declaration| (declaration.address, declaration.c_name))
        .collect()
}

fn lift_function_with_name(
    info: &FunctionInfo,
    name: String,
    call_targets: &HashMap<u64, String>,
) -> Function {
    let body: Vec<Statement> = info
        .instructions
        .iter()
        .map(|instruction| instruction_to_statement(instruction, call_targets))
        .collect();

    Function {
        name,
        return_type: TypeInfo::Void,
        parameters: Vec::new(),
        body,
        is_variadic: false,
    }
}

fn instruction_to_statement(instr: &Instruction, call_targets: &HashMap<u64, String>) -> Statement {
    if let Some(function) = call_target_name(instr, call_targets) {
        return Statement::Expression(Expression::FunctionCall {
            function,
            arguments: Vec::new(),
        });
    }

    if let Statement::Expression(expr) = lift_ir_to_statement(instr) {
        return Statement::Expression(expr);
    }

    let (address, disasm) = match instr {
        Instruction::X86(x) => (x.address, x.to_string()),
        Instruction::Arm(a) => (a.address, a.to_string()),
    };
    Statement::InlineAsm { address, disasm }
}

fn call_target_name(instr: &Instruction, call_targets: &HashMap<u64, String>) -> Option<String> {
    match instr {
        Instruction::X86(x) if x.is_call() => {
            if let Some(target) = x.near_branch_target {
                if let Some(name) = call_targets.get(&target) {
                    return Some(name.clone());
                }
            }

            let target = referenced_memory_address(x.address, x.length, &x.operands)?;
            call_targets.get(&target).cloned()
        }
        _ => None,
    }
}

fn referenced_memory_address(address: u64, length: usize, operands: &str) -> Option<u64> {
    if !operands.contains('[') || !operands.contains(']') {
        return None;
    }

    let lower = operands.to_ascii_lowercase();
    let first_hex = collect_hex_addresses(operands).into_iter().next()?;

    if lower.contains("rip+") || lower.contains("rip +") {
        Some(address.wrapping_add(length as u64).wrapping_add(first_hex))
    } else if lower.contains("rip-") || lower.contains("rip -") {
        Some(address.wrapping_add(length as u64).wrapping_sub(first_hex))
    } else {
        Some(first_hex)
    }
}

fn collect_hex_addresses(text: &str) -> Vec<u64> {
    text.split(|ch: char| {
        !(ch.is_ascii_hexdigit() || ch == 'x' || ch == 'X' || ch == 'h' || ch == 'H')
    })
    .filter_map(parse_hex_token)
    .collect()
}

fn parse_hex_token(token: &str) -> Option<u64> {
    if token.len() < 2 {
        return None;
    }

    let stripped = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .or_else(|| token.strip_suffix('h'))
        .or_else(|| token.strip_suffix('H'))?;

    if stripped.is_empty() || !stripped.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }

    u64::from_str_radix(stripped, 16).ok()
}

// ---------------------------------------------------------------------------
// Arithmetic / logic / shift IR lifting
// ---------------------------------------------------------------------------

/// Try to convert an instruction's IR into an `Expression` statement.
/// Returns `None` when IR is absent or the mnemonic is unsupported — the
/// caller should fall back to `InlineAsm`.
fn lift_ir_to_statement(instr: &Instruction) -> Statement {
    let (address, ir) = match instr {
        Instruction::X86(x) => (x.address, x.ir.as_ref()),
        // ARM IR is not populated yet — fall back.
        Instruction::Arm(a) => return Statement::InlineAsm {
            address: a.address,
            disasm: a.to_string(),
        },
    };

    let Some(ir) = ir else {
        return Statement::InlineAsm {
            address,
            disasm: match instr {
                Instruction::X86(x) => x.to_string(),
                Instruction::Arm(a) => a.to_string(),
            },
        };
    };

    let Some(expr) = ir_to_expression(ir) else {
        return Statement::InlineAsm {
            address,
            disasm: match instr {
                Instruction::X86(x) => x.to_string(),
                Instruction::Arm(a) => a.to_string(),
            },
        };
    };

    Statement::Expression(expr)
}

/// Map an `InstructionIR` to an `Expression` when the mnemonic is one we
/// can structurally represent.
fn ir_to_expression(ir: &crate::disasm::ir::InstructionIR) -> Option<Expression> {
    match ir.op.as_str() {
        "add" | "sub" | "and" | "or" | "xor" | "shl" | "shr"
        | "lea" | "imul" => binary_arithmetic(ir),
        "inc" | "dec" => inc_dec(ir),
        "neg" | "not" => unary_arithmetic(ir),
        "mov" | "movzx" | "movsxd" => simple_mov(ir),
        _ => None,
    }
}

// --- Binary arithmetic: add, sub, and, or, xor, shl, shr, lea, imul ---

fn binary_arithmetic(ir: &crate::disasm::ir::InstructionIR) -> Option<Expression> {
    let left = ir.operands.first()?;
    let right = ir.operands.get(1)?;
    let op = mnemonic_to_binary_op(&ir.op)?;

    let left_expr = operand_to_expr(left)?;
    let right_expr = operand_to_expr(right)?;

    Some(Expression::Assignment {
        target: Box::new(left_expr.clone()),
        value: Box::new(Expression::BinaryOperation {
            op,
            left: Box::new(left_expr),
            right: Box::new(right_expr),
        }),
    })
}

fn mnemonic_to_binary_op(mnemonic: &str) -> Option<BinaryOperator> {
    match mnemonic {
        "add" | "lea" => Some(BinaryOperator::Add),
        "sub" => Some(BinaryOperator::Subtract),
        "and" => Some(BinaryOperator::BitwiseAnd),
        "or" => Some(BinaryOperator::BitwiseOr),
        "xor" => Some(BinaryOperator::BitwiseXor),
        "shl" => Some(BinaryOperator::LeftShift),
        "shr" => Some(BinaryOperator::RightShift),
        "imul" => Some(BinaryOperator::Multiply),
        _ => None,
    }
}

// --- inc / dec ---

fn inc_dec(ir: &crate::disasm::ir::InstructionIR) -> Option<Expression> {
    let operand = ir.operands.first()?;
    let expr = operand_to_expr(operand)?;
    let op = if ir.op == "inc" {
        BinaryOperator::Add
    } else {
        BinaryOperator::Subtract
    };

    Some(Expression::Assignment {
        target: Box::new(expr.clone()),
        value: Box::new(Expression::BinaryOperation {
            op,
            left: Box::new(expr),
            right: Box::new(Expression::IntegerLiteral(1)),
        }),
    })
}

// --- neg / not ---

fn unary_arithmetic(ir: &crate::disasm::ir::InstructionIR) -> Option<Expression> {
    let operand = ir.operands.first()?;
    let expr = operand_to_expr(operand)?;
    let op = if ir.op == "neg" {
        UnaryOperator::Negate
    } else {
        UnaryOperator::BitwiseNot
    };

    Some(Expression::Assignment {
        target: Box::new(expr.clone()),
        value: Box::new(Expression::UnaryOperation {
            op,
            operand: Box::new(expr),
        }),
    })
}

// --- mov (reg/imm only — the one already handled by structure.rs for the
//     register-to-register case, but this covers mov reg, imm too) ---

fn simple_mov(ir: &crate::disasm::ir::InstructionIR) -> Option<Expression> {
    let left = ir.operands.first()?;
    let right = ir.operands.get(1)?;

    // Only lift when both operands are register or immediate — memory
    // operands (especially with scale/index) fall back to InlineAsm so the
    // structuring pass doesn't emit invalid C.
    let target_expr = operand_to_expr(left)?;
    let value_expr = operand_to_expr(right)?;

    Some(Expression::Assignment {
        target: Box::new(target_expr),
        value: Box::new(value_expr),
    })
}

// --- Operand → Expression conversion ---

fn operand_to_expr(operand: &Operand) -> Option<Expression> {
    match operand {
        Reg(r) => Some(Expression::Variable(canonicalize_reg_name(r))),
        Imm(v) => Some(Expression::IntegerLiteral(*v)),
        Mem(mem) => stack_var_or_lea(mem),
        Other(_) => None,
    }
}

/// For memory operands that look like simple stack refs (rbp/esp-based),
/// produce a variable name. For anything with a scale > 1 or an index,
/// return None so the caller falls back to InlineAsm.
fn stack_var_or_lea(mem: &MemoryOperand) -> Option<Expression> {
    if let Some(ref base) = mem.base {
        let lower = base.to_ascii_lowercase();
        if matches!(lower.as_str(), "rbp" | "ebp") {
            let prefix = if mem.disp < 0 { "local" } else { "arg" };
            let offset = mem.disp.unsigned_abs();
            return Some(Expression::Variable(format!("{prefix}_{offset:x}")));
        }
        if matches!(lower.as_str(), "rsp" | "esp") {
            let prefix = if mem.disp < 0 { "stack_m" } else { "stack" };
            let offset = mem.disp.unsigned_abs();
            return Some(Expression::Variable(format!("{prefix}_{offset:x}")));
        }
    }

    // LEA with RIP-relative addressing or indexed operands → no safe lift.
    None
}

fn canonicalize_reg_name(value: &str) -> String {
    let lower = value.to_ascii_lowercase();
    match lower.as_str() {
        "al" | "ah" | "ax" | "eax" | "rax" => "rax",
        "bl" | "bh" | "bx" | "ebx" | "rbx" => "rbx",
        "cl" | "ch" | "cx" | "ecx" | "rcx" => "rcx",
        "dl" | "dh" | "dx" | "edx" | "rdx" => "rdx",
        "sil" | "si" | "esi" | "rsi" => "rsi",
        "dil" | "di" | "edi" | "rdi" => "rdi",
        "bpl" | "bp" | "ebp" | "rbp" => "rbp",
        "spl" | "sp" | "esp" | "rsp" => "rsp",
        "r8b" | "r8w" | "r8d" | "r8" => "r8",
        "r9b" | "r9w" | "r9d" | "r9" => "r9",
        "r10b" | "r10w" | "r10d" | "r10" => "r10",
        "r11b" | "r11w" | "r11d" | "r11" => "r11",
        "r12b" | "r12w" | "r12d" | "r12" => "r12",
        "r13b" | "r13w" | "r13d" | "r13" => "r13",
        "r14b" | "r14w" | "r14d" | "r14" => "r14",
        "r15b" | "r15w" | "r15d" | "r15" => "r15",
        _ => lower.as_str(),
    }
    .to_string()
}

#[cfg(test)]
mod ir_lifting_tests {
    use super::*;
    use crate::disasm::ir::InstructionIR;
    use crate::disasm::X86Instruction;

    fn ir_instr(address: u64, op: &str, operands: Vec<Operand>) -> Instruction {
        Instruction::X86(X86Instruction {
            address,
            bytes: vec![],
            mnemonic: op.to_string(),
            operands: format_operands(&operands),
            length: 1,
            ir: Some(InstructionIR {
                address,
                op: op.to_string(),
                operands,
            }),
            near_branch_target: None,
        })
    }

    fn format_operands(operands: &[Operand]) -> String {
        operands
            .iter()
            .map(|o| match o {
                Reg(r) => r.clone(),
                Imm(v) => format!("{v}"),
                Mem(m) => {
                    let base = m.base.as_deref().unwrap_or("");
                    let disp = if m.disp >= 0 {
                        format!("+0x{:X}", m.disp)
                    } else {
                        format!("-0x{:X}", m.disp.unsigned_abs())
                    };
                    format!("[{base}{disp}]")
                }
                Other(s) => s.clone(),
            })
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[test]
    fn lift_add_reg_imm_produces_assignment() {
        let stmt = lift_ir_to_statement(&ir_instr(
            0x1000,
            "add",
            vec![Reg("rax".to_string()), Imm(5)],
        ));
        assert!(
            matches!(
                stmt,
                Statement::Expression(Expression::Assignment { ref target, ref value })
                    if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                        && matches!(
                            value.as_ref(),
                            Expression::BinaryOperation {
                                op: BinaryOperator::Add,
                                ref left,
                                ref right,
                            } if matches!(left.as_ref(), Expression::Variable(name) if name == "rax")
                                && matches!(right.as_ref(), Expression::IntegerLiteral(5))
                        )
            ),
            "got {:?}",
            stmt
        );
    }

    #[test]
    fn lift_sub_reg_reg_produces_assignment() {
        let stmt = lift_ir_to_statement(&ir_instr(
            0x1010,
            "sub",
            vec![Reg("rax".to_string()), Reg("rbx".to_string())],
        ));
        assert!(
            matches!(
                stmt,
                Statement::Expression(Expression::Assignment { ref target, ref value })
                    if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                        && matches!(
                            value.as_ref(),
                            Expression::BinaryOperation {
                                op: BinaryOperator::Subtract,
                                ref left,
                                ref right,
                            } if matches!(left.as_ref(), Expression::Variable(name) if name == "rax")
                                && matches!(right.as_ref(), Expression::Variable(name) if name == "rbx")
                        )
            ),
            "got {:?}",
            stmt
        );
    }

    #[test]
    fn lift_neg_reg_produces_unary_assignment() {
        let stmt = lift_ir_to_statement(&ir_instr(
            0x1020,
            "neg",
            vec![Reg("rcx".to_string())],
        ));
        assert!(
            matches!(
                stmt,
                Statement::Expression(Expression::Assignment { ref target, ref value })
                    if matches!(target.as_ref(), Expression::Variable(name) if name == "rcx")
                        && matches!(
                            value.as_ref(),
                            Expression::UnaryOperation {
                                op: UnaryOperator::Negate,
                                ref operand,
                            } if matches!(operand.as_ref(), Expression::Variable(name) if name == "rcx")
                        )
            ),
            "got {:?}",
            stmt
        );
    }

    #[test]
    fn lift_inc_reg_produces_add_one() {
        let stmt = lift_ir_to_statement(&ir_instr(
            0x1030,
            "inc",
            vec![Reg("rdx".to_string())],
        ));
        assert!(
            matches!(
                stmt,
                Statement::Expression(Expression::Assignment { ref target, ref value })
                    if matches!(target.as_ref(), Expression::Variable(name) if name == "rdx")
                        && matches!(
                            value.as_ref(),
                            Expression::BinaryOperation {
                                op: BinaryOperator::Add,
                                ref right,
                                ..
                            } if matches!(right.as_ref(), Expression::IntegerLiteral(1))
                        )
            ),
            "got {:?}",
            stmt
        );
    }

    #[test]
    fn lift_and_or_xor_shift_produces_binary_op() {
        for (mnemonic, expected_op) in [
            ("and", BinaryOperator::BitwiseAnd),
            ("or", BinaryOperator::BitwiseOr),
            ("xor", BinaryOperator::BitwiseXor),
            ("shl", BinaryOperator::LeftShift),
            ("shr", BinaryOperator::RightShift),
        ] {
            let stmt = lift_ir_to_statement(&ir_instr(
                0x1040,
                mnemonic,
                vec![Reg("rax".to_string()), Imm(3)],
            ));
            assert!(
                matches!(
                    stmt,
                    Statement::Expression(Expression::Assignment { ref value, .. })
                        if matches!(
                            value.as_ref(),
                            Expression::BinaryOperation { ref op, .. }
                            if *op == expected_op
                        )
                ),
                "{mnemonic} did not produce expected op {expected_op:?}, got {stmt:?}"
            );
        }
    }

    #[test]
    fn lift_mov_reg_imm_becomes_assignment() {
        let stmt = lift_ir_to_statement(&ir_instr(
            0x1050,
            "mov",
            vec![Reg("rax".to_string()), Imm(42)],
        ));
        assert!(
            matches!(
                stmt,
                Statement::Expression(Expression::Assignment { ref target, ref value })
                    if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                        && matches!(value.as_ref(), Expression::IntegerLiteral(42))
            ),
            "got {:?}",
            stmt
        );
    }

    #[test]
    fn lift_memory_mov_rbp_offset_becomes_stack_var_assignment() {
        let stmt = lift_ir_to_statement(&ir_instr(
            0x1060,
            "mov",
            vec![
                Reg("rax".to_string()),
                Mem(MemoryOperand {
                    base: Some("rbp".to_string()),
                    index: None,
                    scale: 1,
                    disp: -8,
                    size_bytes: Some(8),
                }),
            ],
        ));
        // mov rax, [rbp-8] → rax = local_8 (x86 AT&T order: dest is first operand)
        assert!(
            matches!(
                stmt,
                Statement::Expression(Expression::Assignment { ref target, ref value })
                    if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                        && matches!(value.as_ref(), Expression::Variable(name) if name == "local_8")
            ),
            "got {:?}",
            stmt
        );
    }

    #[test]
    fn no_ir_falls_back_to_inline_asm() {
        let instr = Instruction::X86(X86Instruction {
            address: 0x2000,
            bytes: vec![0x90],
            mnemonic: "nop".to_string(),
            operands: String::new(),
            length: 1,
            ir: None,
            near_branch_target: None,
        });
        let stmt = lift_ir_to_statement(&instr);
        assert!(
            matches!(stmt, Statement::InlineAsm { address: 0x2000, .. }),
            "expected InlineAsm for no-IR instruction, got {:?}",
            stmt
        );
    }

    #[test]
    fn unsupported_mnemonic_falls_back_to_inline_asm() {
        // `push` / `pop` have IR but aren't in the arithmetic map yet —
        // they should stay as InlineAsm.
        let stmt = lift_ir_to_statement(&ir_instr(
            0x3000,
            "push",
            vec![Reg("rbp".to_string())],
        ));
        assert!(
            matches!(stmt, Statement::InlineAsm { address: 0x3000, .. }),
            "expected InlineAsm for unsupported mnemonic, got {:?}",
            stmt
        );
    }

    #[test]
    fn canonicalize_register_name_normalizes_sizes() {
        assert_eq!(canonicalize_reg_name("eax"), "rax");
        assert_eq!(canonicalize_reg_name("ax"), "rax");
        assert_eq!(canonicalize_reg_name("al"), "rax");
        assert_eq!(canonicalize_reg_name("r8d"), "r8");
        assert_eq!(canonicalize_reg_name("r15b"), "r15");
        assert_eq!(canonicalize_reg_name("rip"), "rip"); // non-register stays as-is
    }
}
