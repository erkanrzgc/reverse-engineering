//! String-reference annotation pass.
//!
//! This pass keeps the AST conservative: it does not convert instructions into
//! semantic string-load expressions yet. Instead, it rewrites address-looking
//! operands inside remaining `InlineAsm` comments to the global string symbols
//! emitted by `main.rs` (`str_XXXX`). That makes generated C easier to read
//! while preserving the original instruction text as a comment.

use crate::analysis::strings::StringInfo;
use crate::decompiler::ast::{Function, Statement};
use regex::Regex;
use std::collections::HashMap;
use std::sync::OnceLock;

/// Annotate string references in all functions.
///
/// The pass scans remaining `InlineAsm` statements and replaces exact hex
/// address references that match extracted strings with their generated global
/// symbol names, e.g. `0x401000` or `401000h` becomes `str_401000`.
pub fn annotate_string_references(functions: &mut [Function], strings: &[StringInfo]) {
    if strings.is_empty() {
        return;
    }

    let symbols = build_string_symbol_map(strings);
    if symbols.is_empty() {
        return;
    }

    for function in functions {
        annotate_statements(&mut function.body, &symbols);
    }
}

/// Annotate using original decoded operands rather than guessing target addresses
/// from numbers in formatted instruction text.
pub fn annotate_string_references_with_instructions(
    functions: &mut [Function],
    strings: &[StringInfo],
    infos: &[crate::analysis::FunctionInfo],
) {
    let symbols = build_string_symbol_map(strings);
    if symbols.is_empty() {
        return;
    }
    for (function, info) in functions.iter_mut().zip(infos) {
        let instructions: HashMap<_, _> = info
            .instructions
            .iter()
            .map(|instruction| (instruction.address(), instruction))
            .collect();
        for statement in &mut function.body {
            annotate_typed_statement(statement, &symbols, &instructions);
        }
    }
}

fn annotate_typed_statement(
    statement: &mut Statement,
    symbols: &HashMap<u64, String>,
    instructions: &HashMap<u64, &crate::disasm::Instruction>,
) {
    use crate::disasm::{Instruction, Operand};
    match statement {
        Statement::InlineAsm { address, disasm } => {
            let Some(Instruction::X86(instruction)) = instructions.get(address).copied() else {
                return;
            };
            let Some(ir) = &instruction.ir else {
                return;
            };
            // A bracketed operand is replaced only when the typed memory target
            // is static. Register-relative/indexed displacements are not addresses.
            let target = ir.operands.iter().find_map(|operand| match operand {
                Operand::Mem(memory)
                    if memory.index.is_none()
                        && matches!(memory.base.as_deref(), None | Some("rip") | Some("eip")) =>
                {
                    symbols.get(&(memory.disp as u64))
                }
                _ => None,
            });
            if let Some(symbol) = target {
                if let Some(start) = disasm.find('[') {
                    if let Some(end) = disasm[start..].find(']') {
                        disasm.replace_range(start..=start + end, &format!("[{symbol}]"));
                    }
                }
            }
            let immediates: HashMap<_, _> = ir
                .operands
                .iter()
                .filter_map(|operand| match operand {
                    Operand::Imm(value) => symbols
                        .get(&(*value as u64))
                        .map(|symbol| (*value as u64, symbol)),
                    _ => None,
                })
                .collect();
            // Immediate operands may name string addresses. Do not replace a
            // matching number inside an unrelated dynamic memory expression.
            let original = disasm.clone();
            *disasm = hex_address_regex()
                .replace_all(&original, |captures: &regex::Captures<'_>| {
                    let matched = captures.get(0).expect("full match");
                    let prefix = &original[..matched.start()];
                    let in_memory = prefix
                        .rfind('[')
                        .is_some_and(|start| prefix.rfind(']').is_none_or(|end| start > end));
                    if in_memory {
                        return matched.as_str().to_string();
                    }
                    captured_hex_address(captures)
                        .and_then(|address| immediates.get(&address))
                        .map(|symbol| (*symbol).clone())
                        .unwrap_or_else(|| matched.as_str().to_string())
                })
                .into_owned();
        }
        Statement::Instruction { statement, .. } => {
            annotate_typed_statement(statement, symbols, instructions)
        }
        Statement::If {
            then_block,
            else_block,
            ..
        } => {
            for statement in then_block {
                annotate_typed_statement(statement, symbols, instructions);
            }
            if let Some(else_block) = else_block {
                for statement in else_block {
                    annotate_typed_statement(statement, symbols, instructions);
                }
            }
        }
        Statement::Block(body) | Statement::While { body, .. } | Statement::For { body, .. } => {
            for statement in body {
                annotate_typed_statement(statement, symbols, instructions);
            }
        }
        _ => {}
    }
}

fn build_string_symbol_map(strings: &[StringInfo]) -> HashMap<u64, String> {
    strings
        .iter()
        .map(|string| (string.address, format!("str_{:X}", string.address)))
        .collect()
}

fn annotate_statements(statements: &mut [Statement], symbols: &HashMap<u64, String>) {
    for statement in statements {
        annotate_statement(statement, symbols);
    }
}

fn annotate_statement(statement: &mut Statement, symbols: &HashMap<u64, String>) {
    match statement {
        Statement::Instruction { statement, .. } => annotate_statement(statement, symbols),
        Statement::InlineAsm { disasm, .. } => {
            *disasm = annotate_disasm(disasm, symbols);
        }
        Statement::If {
            then_block,
            else_block,
            ..
        } => {
            annotate_statements(then_block, symbols);
            if let Some(else_block) = else_block {
                annotate_statements(else_block, symbols);
            }
        }
        Statement::While { body, .. } => {
            annotate_statements(body, symbols);
        }
        Statement::For { init, body, .. } => {
            if let Some(init) = init {
                annotate_statement(init, symbols);
            }
            annotate_statements(body, symbols);
        }
        Statement::Block(statements) => {
            annotate_statements(statements, symbols);
        }
        _ => {}
    }
}

fn annotate_disasm(disasm: &str, symbols: &HashMap<u64, String>) -> String {
    hex_address_regex()
        .replace_all(disasm, |captures: &regex::Captures<'_>| {
            let full_match = captures
                .get(0)
                .expect("regex captures should always include the full match")
                .as_str();

            let Some(address) = captured_hex_address(captures) else {
                return full_match.to_string();
            };

            symbols
                .get(&address)
                .cloned()
                .unwrap_or_else(|| full_match.to_string())
        })
        .into_owned()
}

fn hex_address_regex() -> &'static Regex {
    static HEX_ADDRESS_REGEX: OnceLock<Regex> = OnceLock::new();

    HEX_ADDRESS_REGEX.get_or_init(|| {
        Regex::new(r"(?i)\b0x([0-9a-f]+)\b|\b([0-9a-f]+)h\b")
            .expect("string-reference address regex should compile")
    })
}

fn captured_hex_address(captures: &regex::Captures<'_>) -> Option<u64> {
    let hex = captures.get(1).or_else(|| captures.get(2))?.as_str();
    u64::from_str_radix(hex, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::strings::StringEncoding;
    use crate::analysis::TypeInfo;
    use crate::decompiler::ast::{Expression, Statement};

    fn string(address: u64, value: &str) -> StringInfo {
        StringInfo {
            address,
            value: value.to_string(),
            encoding: StringEncoding::Ascii,
            length: value.len(),
        }
    }

    fn function_with(body: Vec<Statement>) -> Function {
        Function {
            name: "sub_1000".to_string(),
            return_type: TypeInfo::Void,
            parameters: Vec::new(),
            body,
            is_variadic: false,
        }
    }

    fn inline(address: u64, disasm: &str) -> Statement {
        Statement::InlineAsm {
            address,
            disasm: disasm.to_string(),
        }
    }

    #[test]
    fn annotates_0x_prefixed_string_addresses() {
        let mut functions = vec![function_with(vec![inline(
            0x1000,
            "lea rcx, [rip+0x401000]",
        )])];

        annotate_string_references(&mut functions, &[string(0x401000, "hello")]);

        assert!(matches!(
            &functions[0].body[0],
            Statement::InlineAsm { disasm, .. } if disasm == "lea rcx, [rip+str_401000]"
        ));
    }

    #[test]
    fn annotates_intel_suffix_hex_string_addresses() {
        let mut functions = vec![function_with(vec![inline(
            0x1000,
            "mov rax, qword ptr [401000h]",
        )])];

        annotate_string_references(&mut functions, &[string(0x401000, "hello")]);

        assert!(matches!(
            &functions[0].body[0],
            Statement::InlineAsm { disasm, .. } if disasm == "mov rax, qword ptr [str_401000]"
        ));
    }

    #[test]
    fn leaves_unmatched_hex_addresses_unchanged() {
        let mut functions = vec![function_with(vec![inline(
            0x1000,
            "mov rax, qword ptr [0x402000]",
        )])];

        annotate_string_references(&mut functions, &[string(0x401000, "hello")]);

        assert!(matches!(
            &functions[0].body[0],
            Statement::InlineAsm { disasm, .. } if disasm == "mov rax, qword ptr [0x402000]"
        ));
    }

    #[test]
    fn annotates_multiple_references_in_one_instruction() {
        let mut functions = vec![function_with(vec![inline(
            0x1000,
            "cmp qword ptr [0x401000], 402000h",
        )])];

        annotate_string_references(
            &mut functions,
            &[string(0x401000, "left"), string(0x402000, "right")],
        );

        assert!(matches!(
            &functions[0].body[0],
            Statement::InlineAsm { disasm, .. }
                if disasm == "cmp qword ptr [str_401000], str_402000"
        ));
    }

    #[test]
    fn recurses_into_nested_statement_blocks() {
        let mut functions = vec![function_with(vec![Statement::If {
            condition: Expression::IntegerLiteral(1),
            then_block: vec![inline(0x1000, "lea rcx, [0x401000]")],
            else_block: Some(vec![Statement::Block(vec![inline(
                0x1010,
                "lea rdx, [402000h]",
            )])]),
        }])];

        annotate_string_references(
            &mut functions,
            &[string(0x401000, "then"), string(0x402000, "else")],
        );

        let Statement::If {
            then_block,
            else_block,
            ..
        } = &functions[0].body[0]
        else {
            panic!("expected if statement");
        };

        assert!(matches!(
            &then_block[0],
            Statement::InlineAsm { disasm, .. } if disasm == "lea rcx, [str_401000]"
        ));

        assert!(matches!(
            else_block.as_deref(),
            Some([Statement::Block(statements)])
                if matches!(
                    &statements[0],
                    Statement::InlineAsm { disasm, .. } if disasm == "lea rdx, [str_402000]"
                )
        ));
    }

    #[test]
    fn empty_string_table_is_noop() {
        let mut functions = vec![function_with(vec![inline(0x1000, "lea rcx, [0x401000]")])];

        annotate_string_references(&mut functions, &[]);

        assert!(matches!(
            &functions[0].body[0],
            Statement::InlineAsm { disasm, .. } if disasm == "lea rcx, [0x401000]"
        ));
    }
}
