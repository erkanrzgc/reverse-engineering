//! Conservative AST structuring pass.
//!
//! The lifter intentionally starts with one `InlineAsm` statement per
//! instruction. This pass upgrades only instructions whose semantics are
//! unambiguous while preserving every other address-anchored placeholder for
//! later, richer control-flow structuring.

use crate::analysis::TypeInfo;
use crate::decompiler::ast::{BinaryOperator, Expression, Function, Statement};
use crate::disasm::{ControlFlowGraph, EdgeType, Instruction, InstructionIR, MemoryOperand, Operand};
use petgraph::graph::NodeIndex;
use petgraph::visit::EdgeRef;
use std::collections::{BTreeSet, HashMap, HashSet};

/// Structure all functions in place.
pub fn structure_functions(functions: &mut [Function]) {
    for function in functions {
        structure_function(function);
    }
}

/// Structure all functions with CFG context.
pub fn structure_functions_with_cfg(functions: &mut [Function], cfg: &ControlFlowGraph) {
    for function in functions {
        structure_function_with_cfg(function, cfg);
    }
}

/// Structure a single function in place.
pub fn structure_function(function: &mut Function) {
    for statement in &mut function.body {
        structure_statement(statement);
    }
}

/// Structure a single function with CFG context.
pub fn structure_function_with_cfg(function: &mut Function, cfg: &ControlFlowGraph) {
    let original_indices = address_to_statement_index(function);
    structure_function(function);
    structure_terminal_if_else(function, cfg, &original_indices);
    insert_pseudo_register_declarations(function);
}

fn structure_statement(statement: &mut Statement) {
    match statement {
        Statement::InlineAsm { disasm, .. } if is_void_return(disasm) => {
            *statement = Statement::Return(None);
        }
        Statement::InlineAsm { disasm, .. } => {
            if let Some(assignment) = simple_assignment(disasm) {
                *statement = assignment;
            }
        }
        Statement::Block(statements) => {
            for nested in statements {
                structure_statement(nested);
            }
        }
        Statement::If {
            then_block,
            else_block,
            ..
        } => {
            for nested in then_block {
                structure_statement(nested);
            }
            if let Some(else_block) = else_block {
                for nested in else_block {
                    structure_statement(nested);
                }
            }
        }
        Statement::While { body, .. } | Statement::For { body, .. } => {
            for nested in body {
                structure_statement(nested);
            }
        }
        _ => {}
    }
}

fn is_void_return(disasm: &str) -> bool {
    let mnemonic = disasm
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();

    matches!(
        mnemonic.as_str(),
        "ret" | "retn" | "retf" | "iret" | "iretd" | "iretq" | "eret"
    )
}

fn simple_assignment(disasm: &str) -> Option<Statement> {
    let (mnemonic, operands) = split_instruction(disasm)?;
    let (target, value) = split_operands(&operands)?;

    let target_expr = assignment_target_expression(&target)?;
    let value_expr = match mnemonic.as_str() {
        "mov" | "movzx" | "movsxd" => operand_expression(&value)?,
        "xor" if target.eq_ignore_ascii_case(&value) => Expression::IntegerLiteral(0),
        _ => return None,
    };

    Some(Statement::Expression(Expression::Assignment {
        target: Box::new(target_expr),
        value: Box::new(value_expr),
    }))
}

fn structure_terminal_if_else(
    function: &mut Function,
    cfg: &ControlFlowGraph,
    address_to_index: &HashMap<u64, usize>,
) {
    let mut rewrites = Vec::new();

    for node in cfg.graph().node_indices() {
        let Some(block) = cfg.graph().node_weight(node) else {
            continue;
        };
        let Some(last) = block.instructions.last() else {
            continue;
        };
        if !last.is_conditional_jump() {
            continue;
        }

        let Some((true_node, false_node)) = branch_successors(cfg, node) else {
            continue;
        };
        let Some(true_block) = cfg.graph().node_weight(true_node) else {
            continue;
        };
        let Some(false_block) = cfg.graph().node_weight(false_node) else {
            continue;
        };
        let Some(branch_index) = address_to_index.get(&last.address()).copied() else {
            continue;
        };
        let head_range = (branch_index, branch_index);
        let Some(true_range) = block_range(true_block, address_to_index) else {
            continue;
        };
        let Some(false_range) = block_range(false_block, address_to_index) else {
            continue;
        };

        if block_ends_in_return(true_block) && block_ends_in_return(false_block) {
            if let Some(rewrite) =
                terminal_if_else_rewrite(function, cfg, head_range, true_range, false_range)
            {
                rewrites.push(rewrite);
            }
            continue;
        }

        if let Some(rewrite) = diamond_if_else_rewrite(
            function,
            cfg,
            head_range,
            true_node,
            true_range,
            false_node,
            false_range,
        ) {
            rewrites.push(rewrite);
        }
    }

    rewrites.sort_by_key(|rewrite| rewrite.start);
    let mut occupied = HashSet::new();
    let mut selected = Vec::new();
    for rewrite in rewrites {
        if (rewrite.start..=rewrite.end).any(|idx| occupied.contains(&idx)) {
            continue;
        }
        for idx in rewrite.start..=rewrite.end {
            occupied.insert(idx);
        }
        selected.push(rewrite);
    }

    for rewrite in selected.into_iter().rev() {
        function.body.splice(
            rewrite.start..=rewrite.end,
            std::iter::once(rewrite.statement),
        );
    }
}

struct IfRewrite {
    start: usize,
    end: usize,
    statement: Statement,
}

fn terminal_if_else_rewrite(
    function: &Function,
    cfg: &ControlFlowGraph,
    head_range: (usize, usize),
    true_range: (usize, usize),
    false_range: (usize, usize),
) -> Option<IfRewrite> {
    let covered = covered_indices(&[head_range, true_range, false_range]);
    let start = *covered.iter().min().unwrap_or(&0);
    let end = *covered.iter().max().unwrap_or(&0);
    if !range_is_contiguous(start, end, &covered) {
        return None;
    }

    let condition = branch_condition_with_cfg(function, cfg, head_range.0)
        .or_else(|| branch_condition(function, head_range.0))?;
    let then_block = function.body[true_range.0..=true_range.1].to_vec();
    let else_block = function.body[false_range.0..=false_range.1].to_vec();

    Some(IfRewrite {
        start,
        end,
        statement: Statement::If {
            condition,
            then_block,
            else_block: Some(else_block),
        },
    })
}

fn diamond_if_else_rewrite(
    function: &Function,
    cfg: &ControlFlowGraph,
    head_range: (usize, usize),
    true_node: NodeIndex,
    true_range: (usize, usize),
    false_node: NodeIndex,
    false_range: (usize, usize),
) -> Option<IfRewrite> {
    let true_exit = arm_exit(cfg, true_node, true_range)?;
    let false_exit = arm_exit(cfg, false_node, false_range)?;
    if true_exit.join != false_exit.join {
        return None;
    }

    let covered = covered_indices(&[head_range, true_exit.covered, false_exit.covered]);
    let start = *covered.iter().min().unwrap_or(&0);
    let end = *covered.iter().max().unwrap_or(&0);
    if !range_is_contiguous(start, end, &covered) {
        return None;
    }

    let condition = branch_condition_with_cfg(function, cfg, head_range.0)
        .or_else(|| branch_condition(function, head_range.0))?;
    let then_block = payload_statements(function, true_exit.payload);
    let else_block = payload_statements(function, false_exit.payload);

    Some(IfRewrite {
        start,
        end,
        statement: Statement::If {
            condition,
            then_block,
            else_block: Some(else_block),
        },
    })
}

struct ArmExit {
    join: NodeIndex,
    covered: (usize, usize),
    payload: Option<(usize, usize)>,
}

fn address_to_statement_index(function: &Function) -> HashMap<u64, usize> {
    function
        .body
        .iter()
        .enumerate()
        .filter_map(|(idx, statement)| match statement {
            Statement::InlineAsm { address, .. } => Some((*address, idx)),
            _ => None,
        })
        .collect()
}

fn branch_successors(cfg: &ControlFlowGraph, node: NodeIndex) -> Option<(NodeIndex, NodeIndex)> {
    let mut true_node = None;
    let mut false_node = None;

    for edge in cfg.graph().edges(node) {
        match edge.weight() {
            EdgeType::BranchTrue => true_node = Some(edge.target()),
            EdgeType::BranchFalse => false_node = Some(edge.target()),
            _ => {}
        }
    }

    Some((true_node?, false_node?))
}

fn arm_exit(
    cfg: &ControlFlowGraph,
    node: NodeIndex,
    full_range: (usize, usize),
) -> Option<ArmExit> {
    if let Some(join) = successor_by_edge(cfg, node, EdgeType::Unconditional) {
        let payload = if full_range.0 < full_range.1 {
            Some((full_range.0, full_range.1 - 1))
        } else {
            None
        };
        return Some(ArmExit {
            join,
            covered: full_range,
            payload,
        });
    }

    let join = successor_by_edge(cfg, node, EdgeType::FallThrough)?;
    Some(ArmExit {
        join,
        covered: full_range,
        payload: Some(full_range),
    })
}

fn successor_by_edge(
    cfg: &ControlFlowGraph,
    node: NodeIndex,
    edge_type: EdgeType,
) -> Option<NodeIndex> {
    cfg.graph()
        .edges(node)
        .find(|edge| *edge.weight() == edge_type)
        .map(|edge| edge.target())
}

fn block_ends_in_return(block: &crate::disasm::BasicBlock) -> bool {
    block
        .instructions
        .last()
        .map(|instruction| instruction.is_return())
        .unwrap_or(false)
}

fn block_range(
    block: &crate::disasm::BasicBlock,
    address_to_index: &HashMap<u64, usize>,
) -> Option<(usize, usize)> {
    let first = block.instructions.first()?.address();
    let last = block.instructions.last()?.address();
    Some((
        *address_to_index.get(&first)?,
        *address_to_index.get(&last)?,
    ))
}

fn covered_indices(ranges: &[(usize, usize)]) -> HashSet<usize> {
    let mut covered = HashSet::new();
    for (start, end) in ranges {
        for idx in *start..=*end {
            covered.insert(idx);
        }
    }
    covered
}

fn range_is_contiguous(start: usize, end: usize, covered: &HashSet<usize>) -> bool {
    (start..=end).all(|idx| covered.contains(&idx))
}

fn branch_condition(function: &Function, branch_index: usize) -> Option<Expression> {
    let Statement::InlineAsm { address, disasm } = function.body.get(branch_index)? else {
        return None;
    };

    if let Some(recovered) = recovered_condition(function, branch_index, disasm) {
        return Some(recovered);
    }

    Some(Expression::Unknown(format!(
        "/* condition: 0x{:X} {} */ 1",
        address,
        sanitize_comment(disasm)
    )))
}

fn branch_condition_with_cfg(
    function: &Function,
    cfg: &ControlFlowGraph,
    branch_index: usize,
) -> Option<Expression> {
    let Statement::InlineAsm { address, disasm } = function.body.get(branch_index)? else {
        return None;
    };

    if let Some(recovered) = recovered_condition_ir(cfg, *address) {
        return Some(recovered);
    }

    // Fallback to the legacy string-based recovery.
    if let Some(recovered) = recovered_condition(function, branch_index, disasm) {
        return Some(recovered);
    }

    Some(Expression::Unknown(format!(
        "/* condition: 0x{:X} {} */ 1",
        address,
        sanitize_comment(disasm)
    )))
}

fn payload_statements(function: &Function, payload: Option<(usize, usize)>) -> Vec<Statement> {
    payload
        .map(|(start, end)| function.body[start..=end].to_vec())
        .unwrap_or_default()
}

fn recovered_condition(
    function: &Function,
    branch_index: usize,
    branch_disasm: &str,
) -> Option<Expression> {
    let setup_index = branch_index.checked_sub(1)?;
    let Statement::InlineAsm {
        disasm: setup_disasm,
        ..
    } = function.body.get(setup_index)?
    else {
        return None;
    };

    let (setup_mnemonic, setup_operands) = split_instruction(setup_disasm)?;
    let (branch_mnemonic, _) = split_instruction(branch_disasm)?;
    match setup_mnemonic.as_str() {
        "cmp" => recover_cmp_condition(
            setup_disasm,
            &setup_operands,
            branch_disasm,
            &branch_mnemonic,
        ),
        "test" => recover_test_condition(
            setup_disasm,
            &setup_operands,
            branch_disasm,
            &branch_mnemonic,
        ),
        _ => None,
    }
}

fn recovered_condition_ir(cfg: &ControlFlowGraph, branch_address: u64) -> Option<Expression> {
    let branch_instr = cfg.instruction_by_address(branch_address)?;
    let setup_instr = cfg.previous_instruction_in_block(branch_address)?;

    let (setup_ir, setup_text) = instruction_ir_and_text(setup_instr)?;
    let (branch_ir, branch_text) = instruction_ir_and_text(branch_instr)?;

    match setup_ir.op.as_str() {
        "cmp" => recover_cmp_condition_ir(&setup_ir, &setup_text, &branch_ir, &branch_text),
        "test" => recover_test_condition_ir(&setup_ir, &setup_text, &branch_ir, &branch_text),
        _ => None,
    }
}

fn instruction_ir_and_text(instr: &Instruction) -> Option<(InstructionIR, String)> {
    match instr {
        Instruction::X86(x) => Some((x.ir.clone()?, x.to_string())),
        Instruction::Arm(_) => None,
    }
}

fn recover_cmp_condition_ir(
    setup: &InstructionIR,
    setup_text: &str,
    branch: &InstructionIR,
    branch_text: &str,
) -> Option<Expression> {
    let left = setup.operands.get(0)?;
    let right = setup.operands.get(1)?;
    let op = cmp_operator_for_branch(branch.op.as_str())?;

    let expression_text = format!(
        "{} {} {}",
        operand_to_text(left),
        op.symbol(),
        operand_to_text(right)
    );

    let Some(left_expr) = operand_to_expression(left) else {
        return Some(comment_condition(
            &expression_text,
            setup_text,
            branch_text,
        ));
    };
    let Some(right_expr) = operand_to_expression(right) else {
        return Some(comment_condition(
            &expression_text,
            setup_text,
            branch_text,
        ));
    };

    Some(Expression::BinaryOperation {
        op,
        left: Box::new(left_expr),
        right: Box::new(right_expr),
    })
}

fn recover_test_condition_ir(
    setup: &InstructionIR,
    setup_text: &str,
    branch: &InstructionIR,
    branch_text: &str,
) -> Option<Expression> {
    let left = setup.operands.get(0)?;
    let right = setup.operands.get(1)?;
    let compares_equal_zero = branch_is_zero(branch.op.as_str())?;
    let op = if compares_equal_zero {
        BinaryOperator::Equal
    } else {
        BinaryOperator::NotEqual
    };

    if operand_to_text(left).eq_ignore_ascii_case(&operand_to_text(right)) {
        let expression_text = format!("{} {} 0", operand_to_text(left), op.symbol());
        let Some(left_expr) = operand_to_expression(left) else {
            return Some(comment_condition(
                &expression_text,
                setup_text,
                branch_text,
            ));
        };
        return Some(Expression::BinaryOperation {
            op,
            left: Box::new(left_expr),
            right: Box::new(Expression::IntegerLiteral(0)),
        });
    }

    let expression_text = format!(
        "({} & {}) {} 0",
        operand_to_text(left),
        operand_to_text(right),
        op.symbol()
    );

    let Some(left_expr) = operand_to_expression(left) else {
        return Some(comment_condition(
            &expression_text,
            setup_text,
            branch_text,
        ));
    };
    let Some(right_expr) = operand_to_expression(right) else {
        return Some(comment_condition(
            &expression_text,
            setup_text,
            branch_text,
        ));
    };

    Some(Expression::BinaryOperation {
        op,
        left: Box::new(Expression::BinaryOperation {
            op: BinaryOperator::BitwiseAnd,
            left: Box::new(left_expr),
            right: Box::new(right_expr),
        }),
        right: Box::new(Expression::IntegerLiteral(0)),
    })
}

fn operand_to_text(operand: &Operand) -> String {
    match operand {
        Operand::Reg(r) => r.clone(),
        Operand::Imm(v) => format!("{v}"),
        Operand::Mem(mem) => {
            let mut out = String::from("[");
            if let Some(base) = mem.base.as_ref() {
                out.push_str(base);
            }
            if mem.disp != 0 {
                if mem.disp > 0 {
                    out.push_str(&format!("+0x{:X}", mem.disp));
                } else {
                    out.push_str(&format!("-0x{:X}", -mem.disp));
                }
            }
            out.push(']');
            out
        }
        Operand::Other(s) => s.clone(),
    }
}

fn operand_to_expression(operand: &Operand) -> Option<Expression> {
    match operand {
        Operand::Reg(r) => Some(Expression::Variable(canonicalize_register_name(r))),
        Operand::Imm(v) => Some(Expression::IntegerLiteral(*v)),
        Operand::Mem(mem) => stack_variable_name_from_mem(mem).map(Expression::Variable),
        Operand::Other(_) => None,
    }
}

fn stack_variable_name_from_mem(mem: &MemoryOperand) -> Option<String> {
    let base = mem.base.as_deref()?.to_ascii_lowercase();
    if matches!(base.as_str(), "rbp" | "ebp") {
        if mem.disp < 0 {
            Some(format!("local_{:x}", (-mem.disp) as u64))
        } else {
            Some(format!("arg_{:x}", mem.disp as u64))
        }
    } else if matches!(base.as_str(), "rsp" | "esp") {
        if mem.disp < 0 {
            Some(format!("stack_m_{:x}", (-mem.disp) as u64))
        } else {
            Some(format!("stack_{:x}", mem.disp as u64))
        }
    } else {
        None
    }
}

// ---------------------------------------------------------------------------
// LEGACY string-based condition recovery.
//
// These helpers (`recover_cmp_condition`, `recover_test_condition`, and their
// supporting `operand_expression` / `assignment_target_expression` /
// `split_operands` / `split_instruction`) reconstruct condition expressions
// directly from the formatted disasm strings of the previous instruction.
//
// They are retained for two reasons:
//
//   1. `branch_condition_with_cfg` prefers the IR-aware path
//      (`recovered_condition_ir`, see above) but falls back here whenever the
//      lifter has not yet populated `X86Instruction::ir` for an instruction.
//   2. `branch_condition` (the non-CFG entry point used by `structure_function`)
//      has no CFG context, and the IR-only path requires the CFG to locate the
//      setup/branch pair.
//
// The IR variants in `recover_cmp_condition_ir` / `recover_test_condition_ir`
// are the preferred long-term implementation. As coverage of the IR producer
// in `disasm::x86::to_ir()` grows, the call sites here will gradually become
// dead code and can be removed without affecting test output.
// ---------------------------------------------------------------------------

fn recover_cmp_condition(
    setup_disasm: &str,
    operands: &str,
    branch_disasm: &str,
    branch_mnemonic: &str,
) -> Option<Expression> {
    let (left, right) = split_operands(operands)?;
    let op = cmp_operator_for_branch(branch_mnemonic)?;
    let expression_text = format!("{} {} {}", left, op.symbol(), right);

    let Some(left_expr) = operand_expression(&left) else {
        return Some(comment_condition(
            &expression_text,
            setup_disasm,
            branch_disasm,
        ));
    };
    let Some(right_expr) = operand_expression(&right) else {
        return Some(comment_condition(
            &expression_text,
            setup_disasm,
            branch_disasm,
        ));
    };

    Some(Expression::BinaryOperation {
        op,
        left: Box::new(left_expr),
        right: Box::new(right_expr),
    })
}

fn recover_test_condition(
    setup_disasm: &str,
    operands: &str,
    branch_disasm: &str,
    branch_mnemonic: &str,
) -> Option<Expression> {
    let (left, right) = split_operands(operands)?;
    let compares_equal_zero = branch_is_zero(branch_mnemonic)?;
    let op = if compares_equal_zero {
        BinaryOperator::Equal
    } else {
        BinaryOperator::NotEqual
    };

    if left.eq_ignore_ascii_case(&right) {
        let expression_text = format!("{} {} 0", left, op.symbol());
        let Some(left_expr) = operand_expression(&left) else {
            return Some(comment_condition(
                &expression_text,
                setup_disasm,
                branch_disasm,
            ));
        };
        return Some(Expression::BinaryOperation {
            op,
            left: Box::new(left_expr),
            right: Box::new(Expression::IntegerLiteral(0)),
        });
    }

    let expression_text = format!("({} & {}) {} 0", left, right, op.symbol());
    let Some(left_expr) = operand_expression(&left) else {
        return Some(comment_condition(
            &expression_text,
            setup_disasm,
            branch_disasm,
        ));
    };
    let Some(right_expr) = operand_expression(&right) else {
        return Some(comment_condition(
            &expression_text,
            setup_disasm,
            branch_disasm,
        ));
    };

    Some(Expression::BinaryOperation {
        op,
        left: Box::new(Expression::BinaryOperation {
            op: BinaryOperator::BitwiseAnd,
            left: Box::new(left_expr),
            right: Box::new(right_expr),
        }),
        right: Box::new(Expression::IntegerLiteral(0)),
    })
}

fn operand_expression(operand: &str) -> Option<Expression> {
    let normalized = operand.trim();
    if is_register_name(normalized) {
        return Some(Expression::Variable(canonicalize_register_name(normalized)));
    }
    if let Some(name) = stack_variable_name(normalized) {
        return Some(Expression::Variable(name));
    }

    parse_integer_literal(normalized).map(Expression::IntegerLiteral)
}

fn assignment_target_expression(operand: &str) -> Option<Expression> {
    let normalized = operand.trim();
    if is_register_name(normalized) {
        return Some(Expression::Variable(canonicalize_register_name(normalized)));
    }
    stack_variable_name(normalized).map(Expression::Variable)
}

fn stack_variable_name(operand: &str) -> Option<String> {
    let memory = normalize_memory_operand(operand)?;
    let compact = memory.replace(' ', "");

    for base in ["rbp", "ebp"] {
        if let Some(rest) = compact.strip_prefix(base) {
            return stack_name_from_offset(rest, "local", "arg");
        }
    }

    for base in ["rsp", "esp"] {
        if let Some(rest) = compact.strip_prefix(base) {
            return stack_name_from_offset(rest, "stack_m", "stack");
        }
    }

    None
}

fn normalize_memory_operand(operand: &str) -> Option<String> {
    let mut normalized = operand.trim().to_ascii_lowercase();
    for prefix in [
        "byte ptr ",
        "word ptr ",
        "dword ptr ",
        "qword ptr ",
        "tword ptr ",
        "oword ptr ",
        "xmmword ptr ",
        "ymmword ptr ",
        "zmmword ptr ",
    ] {
        if let Some(rest) = normalized.strip_prefix(prefix) {
            normalized = rest.trim().to_string();
            break;
        }
    }

    let inner = normalized
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))?;
    Some(inner.to_string())
}

fn stack_name_from_offset(
    rest: &str,
    negative_prefix: &str,
    positive_prefix: &str,
) -> Option<String> {
    let (prefix, offset) = if let Some(offset) = rest.strip_prefix('-') {
        (negative_prefix, offset)
    } else if let Some(offset) = rest.strip_prefix('+') {
        (positive_prefix, offset)
    } else {
        return None;
    };

    let component = normalized_offset_component(offset)?;
    Some(format!("{}_{}", prefix, component))
}

fn normalized_offset_component(offset: &str) -> Option<String> {
    let trimmed = offset.trim();
    if trimmed.is_empty() {
        return None;
    }

    let without_hex_prefix = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let without_hex_suffix = without_hex_prefix
        .strip_suffix('h')
        .or_else(|| without_hex_prefix.strip_suffix('H'))
        .unwrap_or(without_hex_prefix);

    let component = without_hex_suffix.trim_start_matches('0');
    if component.is_empty() {
        Some("0".to_string())
    } else if component.chars().all(|c| c.is_ascii_hexdigit()) {
        Some(component.to_ascii_lowercase())
    } else {
        None
    }
}

fn parse_integer_literal(value: &str) -> Option<i64> {
    let trimmed = value.trim();
    let unsigned = trimmed.strip_prefix('-').unwrap_or(trimmed);
    let parsed = if let Some(hex) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else if let Some(hex) = unsigned
        .strip_suffix('h')
        .or_else(|| unsigned.strip_suffix('H'))
    {
        i64::from_str_radix(hex, 16).ok()?
    } else {
        unsigned.parse::<i64>().ok()?
    };

    if trimmed.starts_with('-') {
        Some(-parsed)
    } else {
        Some(parsed)
    }
}

fn split_instruction(disasm: &str) -> Option<(String, String)> {
    let trimmed = disasm.trim();
    if trimmed.is_empty() {
        return None;
    }

    let mut parts = trimmed.splitn(2, char::is_whitespace);
    let mnemonic = parts.next()?.to_ascii_lowercase();
    let operands = parts.next().unwrap_or("").trim().to_string();
    Some((mnemonic, operands))
}

fn split_operands(operands: &str) -> Option<(String, String)> {
    let mut parts = operands.splitn(2, ',');
    let left = parts.next()?.trim();
    let right = parts.next()?.trim();
    if left.is_empty() || right.is_empty() {
        return None;
    }
    Some((left.to_string(), right.to_string()))
}

fn cmp_operator_for_branch(branch_mnemonic: &str) -> Option<BinaryOperator> {
    match branch_mnemonic {
        "je" | "jz" => Some(BinaryOperator::Equal),
        "jne" | "jnz" => Some(BinaryOperator::NotEqual),
        "jl" | "jnge" | "jb" | "jnae" | "jc" => Some(BinaryOperator::LessThan),
        "jle" | "jng" | "jbe" | "jna" => Some(BinaryOperator::LessThanOrEqual),
        "jg" | "jnle" | "ja" | "jnbe" => Some(BinaryOperator::GreaterThan),
        "jge" | "jnl" | "jae" | "jnb" | "jnc" => Some(BinaryOperator::GreaterThanOrEqual),
        _ => None,
    }
}

fn branch_is_zero(branch_mnemonic: &str) -> Option<bool> {
    match branch_mnemonic {
        "je" | "jz" => Some(true),
        "jne" | "jnz" => Some(false),
        _ => None,
    }
}

fn sanitize_comment(value: &str) -> String {
    value.replace("*/", "* /")
}

fn comment_condition(expression: &str, setup_disasm: &str, branch_disasm: &str) -> Expression {
    Expression::Unknown(format!(
        "/* condition: {} (from {}; {}) */ 1",
        sanitize_comment(expression),
        sanitize_comment(setup_disasm),
        sanitize_comment(branch_disasm)
    ))
}

fn insert_pseudo_register_declarations(function: &mut Function) {
    let mut existing: HashSet<String> = function
        .body
        .iter()
        .filter_map(|statement| match statement {
            Statement::VariableDeclaration { name, .. } => Some(name.clone()),
            _ => None,
        })
        .collect();
    existing.extend(
        function
            .parameters
            .iter()
            .map(|parameter| parameter.name.clone()),
    );
    let mut registers = BTreeSet::new();
    for statement in &function.body {
        collect_pseudo_registers_from_statement(statement, &mut registers);
    }
    let declarations: Vec<Statement> = registers
        .into_iter()
        .filter(|name| !existing.contains(name))
        .map(|name| Statement::VariableDeclaration {
            name,
            type_info: TypeInfo::U64,
            init: None,
        })
        .collect();

    if !declarations.is_empty() {
        function.body.splice(0..0, declarations);
    }
}

fn collect_pseudo_registers_from_statement(
    statement: &Statement,
    registers: &mut BTreeSet<String>,
) {
    match statement {
        Statement::Expression(expr) | Statement::Return(Some(expr)) => {
            collect_pseudo_registers_from_expression(expr, registers);
        }
        Statement::If {
            condition,
            then_block,
            else_block,
        } => {
            collect_pseudo_registers_from_expression(condition, registers);
            for nested in then_block {
                collect_pseudo_registers_from_statement(nested, registers);
            }
            if let Some(else_block) = else_block {
                for nested in else_block {
                    collect_pseudo_registers_from_statement(nested, registers);
                }
            }
        }
        Statement::While { condition, body } => {
            collect_pseudo_registers_from_expression(condition, registers);
            for nested in body {
                collect_pseudo_registers_from_statement(nested, registers);
            }
        }
        Statement::For {
            init,
            condition,
            update,
            body,
        } => {
            if let Some(init) = init {
                collect_pseudo_registers_from_statement(init, registers);
            }
            if let Some(condition) = condition {
                collect_pseudo_registers_from_expression(condition, registers);
            }
            if let Some(update) = update {
                collect_pseudo_registers_from_expression(update, registers);
            }
            for nested in body {
                collect_pseudo_registers_from_statement(nested, registers);
            }
        }
        Statement::VariableDeclaration {
            init: Some(init), ..
        } => {
            collect_pseudo_registers_from_expression(init, registers);
        }
        Statement::VariableDeclaration { init: None, .. } => {}
        Statement::Block(statements) => {
            for nested in statements {
                collect_pseudo_registers_from_statement(nested, registers);
            }
        }
        _ => {}
    }
}

fn collect_pseudo_registers_from_expression(expr: &Expression, registers: &mut BTreeSet<String>) {
    match expr {
        Expression::Variable(name) if is_register_name(name) => {
            registers.insert(canonicalize_register_name(name));
        }
        Expression::Variable(name) if is_stack_variable_name(name) => {
            registers.insert(name.to_ascii_lowercase());
        }
        Expression::BinaryOperation { left, right, .. } => {
            collect_pseudo_registers_from_expression(left, registers);
            collect_pseudo_registers_from_expression(right, registers);
        }
        Expression::UnaryOperation { operand, .. } => {
            collect_pseudo_registers_from_expression(operand, registers);
        }
        Expression::FunctionCall { arguments, .. } => {
            for argument in arguments {
                collect_pseudo_registers_from_expression(argument, registers);
            }
        }
        Expression::Assignment { target, value } => {
            collect_pseudo_registers_from_expression(target, registers);
            collect_pseudo_registers_from_expression(value, registers);
        }
        Expression::Cast { value, .. } => {
            collect_pseudo_registers_from_expression(value, registers);
        }
        Expression::AddressOf(expr) | Expression::Dereference(expr) => {
            collect_pseudo_registers_from_expression(expr, registers);
        }
        Expression::ArrayAccess { array, index } => {
            collect_pseudo_registers_from_expression(array, registers);
            collect_pseudo_registers_from_expression(index, registers);
        }
        Expression::MemberAccess { object, .. } => {
            collect_pseudo_registers_from_expression(object, registers);
        }
        _ => {}
    }
}

fn canonicalize_register_name(value: &str) -> String {
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

fn is_register_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "al" | "ah"
            | "ax"
            | "eax"
            | "rax"
            | "bl"
            | "bh"
            | "bx"
            | "ebx"
            | "rbx"
            | "cl"
            | "ch"
            | "cx"
            | "ecx"
            | "rcx"
            | "dl"
            | "dh"
            | "dx"
            | "edx"
            | "rdx"
            | "sil"
            | "si"
            | "esi"
            | "rsi"
            | "dil"
            | "di"
            | "edi"
            | "rdi"
            | "bpl"
            | "bp"
            | "ebp"
            | "rbp"
            | "spl"
            | "sp"
            | "esp"
            | "rsp"
            | "r8b"
            | "r8w"
            | "r8d"
            | "r8"
            | "r9b"
            | "r9w"
            | "r9d"
            | "r9"
            | "r10b"
            | "r10w"
            | "r10d"
            | "r10"
            | "r11b"
            | "r11w"
            | "r11d"
            | "r11"
            | "r12b"
            | "r12w"
            | "r12d"
            | "r12"
            | "r13b"
            | "r13w"
            | "r13d"
            | "r13"
            | "r14b"
            | "r14w"
            | "r14d"
            | "r14"
            | "r15b"
            | "r15w"
            | "r15d"
            | "r15"
    )
}

fn is_stack_variable_name(value: &str) -> bool {
    let lower = value.to_ascii_lowercase();
    lower.starts_with("local_") || lower.starts_with("arg_") || lower.starts_with("stack_")
}

trait BinaryOperatorText {
    fn symbol(self) -> &'static str;
}

impl BinaryOperatorText for BinaryOperator {
    fn symbol(self) -> &'static str {
        match self {
            BinaryOperator::Equal => "==",
            BinaryOperator::NotEqual => "!=",
            BinaryOperator::LessThan => "<",
            BinaryOperator::LessThanOrEqual => "<=",
            BinaryOperator::GreaterThan => ">",
            BinaryOperator::GreaterThanOrEqual => ">=",
            BinaryOperator::BitwiseAnd => "&",
            _ => "?",
        }
    }
}

#[cfg(test)]
mod ir_condition_recovery_tests {
    //! Direct unit tests for the IR-driven helpers in this file. End-to-end
    //! `structure_function*` integration tests live in `decompiler::mod`.

    use super::*;

    fn reg(name: &str) -> Operand {
        Operand::Reg(name.to_string())
    }

    fn imm(value: i64) -> Operand {
        Operand::Imm(value)
    }

    fn mem(base: Option<&str>, disp: i64) -> Operand {
        Operand::Mem(MemoryOperand {
            base: base.map(|b| b.to_string()),
            index: None,
            scale: 1,
            disp,
            size_bytes: None,
        })
    }

    fn ir(address: u64, op: &str, operands: Vec<Operand>) -> InstructionIR {
        InstructionIR {
            address,
            op: op.to_string(),
            operands,
        }
    }

    // ---- cmp_operator_for_branch ----

    #[test]
    fn cmp_operator_for_branch_maps_every_documented_jcc_alias() {
        // Equality
        for m in ["je", "jz"] {
            assert_eq!(cmp_operator_for_branch(m), Some(BinaryOperator::Equal), "{m}");
        }
        for m in ["jne", "jnz"] {
            assert_eq!(
                cmp_operator_for_branch(m),
                Some(BinaryOperator::NotEqual),
                "{m}"
            );
        }
        // Signed AND unsigned less-than family collapse to LessThan; this is
        // intentional because the lifter doesn't yet carry signedness.
        for m in ["jl", "jnge", "jb", "jnae", "jc"] {
            assert_eq!(
                cmp_operator_for_branch(m),
                Some(BinaryOperator::LessThan),
                "{m}"
            );
        }
        for m in ["jle", "jng", "jbe", "jna"] {
            assert_eq!(
                cmp_operator_for_branch(m),
                Some(BinaryOperator::LessThanOrEqual),
                "{m}"
            );
        }
        for m in ["jg", "jnle", "ja", "jnbe"] {
            assert_eq!(
                cmp_operator_for_branch(m),
                Some(BinaryOperator::GreaterThan),
                "{m}"
            );
        }
        for m in ["jge", "jnl", "jae", "jnb", "jnc"] {
            assert_eq!(
                cmp_operator_for_branch(m),
                Some(BinaryOperator::GreaterThanOrEqual),
                "{m}"
            );
        }
    }

    #[test]
    fn cmp_operator_for_branch_returns_none_for_unconditional_or_unknown_mnemonics() {
        assert!(cmp_operator_for_branch("jmp").is_none());
        assert!(cmp_operator_for_branch("call").is_none());
        assert!(cmp_operator_for_branch("ret").is_none());
        assert!(cmp_operator_for_branch("nop").is_none());
        // Case-sensitive on purpose: branch mnemonics from the IR are already lowercase.
        assert!(cmp_operator_for_branch("JE").is_none());
    }

    // ---- branch_is_zero ----

    #[test]
    fn branch_is_zero_returns_true_for_zero_branches_and_false_for_nonzero_branches() {
        assert_eq!(branch_is_zero("je"), Some(true));
        assert_eq!(branch_is_zero("jz"), Some(true));
        assert_eq!(branch_is_zero("jne"), Some(false));
        assert_eq!(branch_is_zero("jnz"), Some(false));
    }

    #[test]
    fn branch_is_zero_returns_none_for_comparison_branches_that_test_cannot_express() {
        // `test` only sets ZF/SF/PF — signed/unsigned ordering branches are not
        // recoverable from a `test reg,reg` setup, so these must return None.
        for m in ["jl", "jg", "jle", "jge", "ja", "jb", "jnz_typo"] {
            assert!(
                branch_is_zero(m).is_none(),
                "branch_is_zero({m}) must reject non-zero-flag branches"
            );
        }
    }

    // ---- operand_to_text ----

    #[test]
    fn operand_to_text_renders_registers_and_immediates_verbatim() {
        assert_eq!(operand_to_text(&reg("rax")), "rax");
        assert_eq!(operand_to_text(&imm(42)), "42");
        assert_eq!(operand_to_text(&imm(-7)), "-7");
    }

    #[test]
    fn operand_to_text_renders_memory_with_sign_aware_hex_displacement() {
        assert_eq!(operand_to_text(&mem(Some("rbp"), 0)), "[rbp]");
        assert_eq!(operand_to_text(&mem(Some("rbp"), -0x10)), "[rbp-0x10]");
        assert_eq!(operand_to_text(&mem(Some("rsp"), 0x20)), "[rsp+0x20]");
        // Bare displacement with no base.
        assert_eq!(operand_to_text(&mem(None, 0x401000)), "[+0x401000]");
    }

    #[test]
    fn operand_to_text_passes_other_variant_through_unchanged() {
        assert_eq!(
            operand_to_text(&Operand::Other("xmmword ptr [rip+10h]".to_string())),
            "xmmword ptr [rip+10h]"
        );
    }

    // ---- operand_to_expression ----

    #[test]
    fn operand_to_expression_canonicalizes_register_aliases_to_class_name() {
        // `eax` and `r8d` are sub-register views; classified to rax/r8.
        assert!(matches!(
            operand_to_expression(&reg("eax")),
            Some(Expression::Variable(ref n)) if n == "rax"
        ));
        assert!(matches!(
            operand_to_expression(&reg("r8d")),
            Some(Expression::Variable(ref n)) if n == "r8"
        ));
    }

    #[test]
    fn operand_to_expression_produces_integer_literal_for_immediate() {
        assert!(matches!(
            operand_to_expression(&imm(0)),
            Some(Expression::IntegerLiteral(0))
        ));
        assert!(matches!(
            operand_to_expression(&imm(-1)),
            Some(Expression::IntegerLiteral(-1))
        ));
    }

    #[test]
    fn operand_to_expression_produces_named_stack_variable_for_rbp_relative_memory() {
        assert!(matches!(
            operand_to_expression(&mem(Some("rbp"), -0x10)),
            Some(Expression::Variable(ref n)) if n == "local_10"
        ));
        assert!(matches!(
            operand_to_expression(&mem(Some("rsp"), 0x20)),
            Some(Expression::Variable(ref n)) if n == "stack_20"
        ));
    }

    #[test]
    fn operand_to_expression_returns_none_for_non_stack_memory_and_other_operands() {
        // [rax] is a heap/data deref, not a stack slot.
        assert!(operand_to_expression(&mem(Some("rax"), 0)).is_none());
        assert!(operand_to_expression(&mem(None, 0x401000)).is_none());
        assert!(operand_to_expression(&Operand::Other("xmm0".into())).is_none());
    }

    // ---- stack_variable_name_from_mem ----

    #[test]
    fn stack_variable_name_from_mem_uses_local_for_negative_rbp_and_arg_for_positive_rbp() {
        let cases = [
            (Some("rbp"), -0x08i64, "local_8"),
            (Some("RBP"), -0x100, "local_100"),
            (Some("ebp"), -0x4, "local_4"),
            (Some("rbp"), 0x10, "arg_10"),
            (Some("ebp"), 0x20, "arg_20"),
        ];
        for (base, disp, expected) in cases {
            assert_eq!(
                stack_variable_name_from_mem(&MemoryOperand {
                    base: base.map(str::to_string),
                    index: None,
                    scale: 1,
                    disp,
                    size_bytes: None,
                })
                .as_deref(),
                Some(expected),
                "base={base:?} disp={disp:#x}"
            );
        }
    }

    #[test]
    fn stack_variable_name_from_mem_uses_stack_prefixes_for_rsp_relative_slots() {
        // Negative rsp → stack_m_*, positive rsp → stack_*.
        assert_eq!(
            stack_variable_name_from_mem(&MemoryOperand {
                base: Some("rsp".into()),
                index: None,
                scale: 1,
                disp: -0x18,
                size_bytes: None,
            })
            .as_deref(),
            Some("stack_m_18")
        );
        assert_eq!(
            stack_variable_name_from_mem(&MemoryOperand {
                base: Some("rsp".into()),
                index: None,
                scale: 1,
                disp: 0x28,
                size_bytes: None,
            })
            .as_deref(),
            Some("stack_28")
        );
    }

    #[test]
    fn stack_variable_name_from_mem_returns_none_for_general_purpose_or_missing_base() {
        // [rax], [rdi], baseless absolute — none are stack slots.
        for base in [Some("rax"), Some("rdi"), Some("r12"), None] {
            assert!(
                stack_variable_name_from_mem(&MemoryOperand {
                    base: base.map(str::to_string),
                    index: None,
                    scale: 1,
                    disp: 0,
                    size_bytes: None,
                })
                .is_none(),
                "base={base:?} should NOT name a stack variable"
            );
        }
    }

    // ---- recover_cmp_condition_ir end-to-end ----

    #[test]
    fn recover_cmp_condition_ir_with_reg_reg_setup_produces_typed_binary_op() {
        let setup = ir(0x1000, "cmp", vec![reg("rax"), reg("rbx")]);
        let branch = ir(0x1003, "je", vec![]);
        let expr = recover_cmp_condition_ir(&setup, "cmp rax, rbx", &branch, "je 0x2000")
            .expect("cmp+je must produce a condition expression");

        let Expression::BinaryOperation { op, left, right } = expr else {
            panic!("expected BinaryOperation, got something else");
        };
        assert_eq!(op, BinaryOperator::Equal);
        assert!(matches!(left.as_ref(), Expression::Variable(n) if n == "rax"));
        assert!(matches!(right.as_ref(), Expression::Variable(n) if n == "rbx"));
    }

    #[test]
    fn recover_cmp_condition_ir_with_reg_imm_setup_uses_integer_literal_right_operand() {
        // `cmp rax, 0` + `jne` → rax != 0
        let setup = ir(0x1000, "cmp", vec![reg("rax"), imm(0)]);
        let branch = ir(0x1003, "jne", vec![]);
        let expr = recover_cmp_condition_ir(&setup, "cmp rax, 0", &branch, "jne 0x2000")
            .expect("cmp+jne must produce a condition");

        let Expression::BinaryOperation { op, right, .. } = expr else {
            panic!("expected BinaryOperation");
        };
        assert_eq!(op, BinaryOperator::NotEqual);
        assert!(matches!(right.as_ref(), Expression::IntegerLiteral(0)));
    }

    #[test]
    fn recover_cmp_condition_ir_falls_back_to_comment_when_an_operand_is_non_expressible() {
        // `[rax]` is not a stack-frame memory, so operand_to_expression returns
        // None — but the function must still produce a readable Unknown comment
        // instead of dropping the condition altogether.
        let setup = ir(0x1000, "cmp", vec![reg("rax"), mem(Some("rax"), 0)]);
        let branch = ir(0x1003, "jl", vec![]);
        let expr = recover_cmp_condition_ir(&setup, "cmp rax, [rax]", &branch, "jl 0x2000")
            .expect("must fall back to a comment, not None");

        match expr {
            Expression::Unknown(text) => {
                assert!(text.contains("condition:"), "got: {text}");
                assert!(text.contains("rax < [rax]"), "got: {text}");
            }
            other => panic!("expected Unknown fallback, got {other:?}"),
        }
    }

    #[test]
    fn recover_cmp_condition_ir_returns_none_when_branch_mnemonic_is_unsupported() {
        let setup = ir(0x1000, "cmp", vec![reg("rax"), reg("rbx")]);
        let branch = ir(0x1003, "jmp", vec![]);
        assert!(
            recover_cmp_condition_ir(&setup, "cmp rax, rbx", &branch, "jmp 0x2000").is_none()
        );
    }

    // ---- recover_test_condition_ir ----

    #[test]
    fn recover_test_condition_ir_for_self_test_emits_register_compared_to_zero() {
        // test rax, rax + je → rax == 0
        let setup = ir(0x1000, "test", vec![reg("rax"), reg("rax")]);
        let branch = ir(0x1003, "je", vec![]);
        let expr = recover_test_condition_ir(&setup, "test rax, rax", &branch, "je 0x2000")
            .expect("test self + je must produce condition");

        let Expression::BinaryOperation { op, left, right } = expr else {
            panic!("expected BinaryOperation");
        };
        assert_eq!(op, BinaryOperator::Equal);
        assert!(matches!(left.as_ref(), Expression::Variable(n) if n == "rax"));
        assert!(matches!(right.as_ref(), Expression::IntegerLiteral(0)));
    }

    #[test]
    fn recover_test_condition_ir_for_distinct_operands_emits_masked_compare_with_zero() {
        // test rax, rbx + jnz → (rax & rbx) != 0
        let setup = ir(0x1000, "test", vec![reg("rax"), reg("rbx")]);
        let branch = ir(0x1003, "jnz", vec![]);
        let expr = recover_test_condition_ir(&setup, "test rax, rbx", &branch, "jnz 0x2000")
            .expect("test rax,rbx + jnz must produce condition");

        let Expression::BinaryOperation { op, left, right } = expr else {
            panic!("expected outer BinaryOperation");
        };
        assert_eq!(op, BinaryOperator::NotEqual);
        assert!(matches!(right.as_ref(), Expression::IntegerLiteral(0)));

        let Expression::BinaryOperation {
            op: inner_op,
            left: a,
            right: b,
        } = left.as_ref()
        else {
            panic!("expected inner BinaryAnd");
        };
        assert_eq!(*inner_op, BinaryOperator::BitwiseAnd);
        assert!(matches!(a.as_ref(), Expression::Variable(n) if n == "rax"));
        assert!(matches!(b.as_ref(), Expression::Variable(n) if n == "rbx"));
    }

    #[test]
    fn recover_test_condition_ir_returns_none_when_branch_is_not_a_zero_flag_branch() {
        // `test`+`jl` is meaningless — must return None rather than guess.
        let setup = ir(0x1000, "test", vec![reg("rax"), reg("rax")]);
        let branch = ir(0x1003, "jl", vec![]);
        assert!(
            recover_test_condition_ir(&setup, "test rax, rax", &branch, "jl 0x2000").is_none()
        );
    }

    // ---- comment_condition sanitization ----

    #[test]
    fn comment_condition_escapes_block_comment_terminator_in_every_component() {
        // The wrapper format itself emits a `/* ... */` around the content, so
        // exactly one `*/` (the closing terminator) is legitimate. Any embedded
        // `*/` from the inputs must be split to `* /` so the comment doesn't
        // end early when the generated C is compiled.
        let expr = comment_condition("a */ b", "cmp */ rax", "jne */ 0x2000");
        let Expression::Unknown(text) = expr else {
            panic!("expected Unknown");
        };

        assert_eq!(
            text.matches("*/").count(),
            1,
            "exactly one (closing) `*/` allowed, got: {text}"
        );
        // The placeholder must still end with `1` so it remains a valid C
        // truthy expression in the generated source.
        assert!(text.trim_end().ends_with("*/ 1"), "got: {text}");
        // Each sanitized component should appear as `* /` (with the inserted space).
        assert!(text.contains("a * / b"), "expr was not sanitized: {text}");
        assert!(text.contains("cmp * / rax"), "setup was not sanitized: {text}");
        assert!(
            text.contains("jne * / 0x2000"),
            "branch was not sanitized: {text}"
        );
    }
}
