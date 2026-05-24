//! Code optimization

use crate::decompiler::ast::{BinaryOperator, Expression, Function, Statement};

/// Optimization level
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OptimizationLevel {
    /// No optimization
    None,
    /// Basic optimizations
    Basic,
    /// Aggressive optimizations
    Aggressive,
}

/// Optimizer
pub struct Optimizer {
    level: OptimizationLevel,
}

impl Optimizer {
    /// Create a new optimizer
    pub fn new(level: OptimizationLevel) -> Self {
        Self { level }
    }

    /// Optimize a function
    pub fn optimize_function(&self, func: &mut Function) {
        if self.level == OptimizationLevel::None {
            return;
        }

        // Optimize statements
        for stmt in &mut func.body {
            self.optimize_statement(stmt);
        }

        // Remove empty statements
        func.body.retain(|stmt| !matches!(stmt, Statement::Empty));

        if self.level == OptimizationLevel::Aggressive {
            // Aggressive optimizations
            self.optimize_aggressive(func);
        }
    }

    /// Optimize a statement
    fn optimize_statement(&self, stmt: &mut Statement) {
        match stmt {
            Statement::Expression(expr) => {
                self.optimize_expression(expr);
            }
            Statement::Return(Some(expr)) => {
                self.optimize_expression(expr);
            }
            Statement::If {
                condition,
                then_block,
                else_block,
            } => {
                self.optimize_expression(condition);
                for s in then_block {
                    self.optimize_statement(s);
                }
                if let Some(else_block) = else_block {
                    for s in else_block {
                        self.optimize_statement(s);
                    }
                }
            }
            Statement::While { condition, body } => {
                self.optimize_expression(condition);
                for s in body {
                    self.optimize_statement(s);
                }
            }
            Statement::For {
                init,
                condition,
                update,
                body,
            } => {
                if let Some(init_stmt) = init {
                    self.optimize_statement(init_stmt);
                }
                if let Some(cond_expr) = condition {
                    self.optimize_expression(cond_expr);
                }
                if let Some(update_expr) = update {
                    self.optimize_expression(update_expr);
                }
                for s in body {
                    self.optimize_statement(s);
                }
            }
            Statement::Block(statements) => {
                for s in statements {
                    self.optimize_statement(s);
                }
            }
            _ => {}
        }
    }

    /// Optimize an expression
    fn optimize_expression(&self, expr: &mut Expression) {
        match expr {
            Expression::BinaryOperation { op, left, right } => {
                self.optimize_expression(left);
                self.optimize_expression(right);

                // Constant folding
                if let Some(folded) = self.fold_constant(*op, left, right) {
                    *expr = folded;
                }
            }
            Expression::UnaryOperation { operand, .. } => {
                self.optimize_expression(operand);
            }
            Expression::FunctionCall { arguments, .. } => {
                for arg in arguments {
                    self.optimize_expression(arg);
                }
            }
            Expression::Assignment { target, value } => {
                self.optimize_expression(target);
                self.optimize_expression(value);
            }
            Expression::Cast { value, .. } => {
                self.optimize_expression(value);
            }
            Expression::AddressOf(expr) | Expression::Dereference(expr) => {
                self.optimize_expression(expr);
            }
            Expression::ArrayAccess { array, index } => {
                self.optimize_expression(array);
                self.optimize_expression(index);
            }
            Expression::MemberAccess { object, .. } => {
                self.optimize_expression(object);
            }
            _ => {}
        }
    }

    /// Fold constant expressions
    fn fold_constant(
        &self,
        op: BinaryOperator,
        left: &Expression,
        right: &Expression,
    ) -> Option<Expression> {
        let left_val = match left {
            Expression::IntegerLiteral(v) => Some(*v),
            _ => None,
        };

        let right_val = match right {
            Expression::IntegerLiteral(v) => Some(*v),
            _ => None,
        };

        if let (Some(l), Some(r)) = (left_val, right_val) {
            // Use checked arithmetic so that overflow, division by zero, or
            // out-of-range shift amounts return None instead of panicking in
            // debug builds (and silently producing wrong values in release).
            // When folding is unsafe, the original BinaryOperation is left
            // intact for the C generator and a human reviewer to interpret.
            let shift_amount = u32::try_from(r).ok();

            let result = match op {
                BinaryOperator::Add => l.checked_add(r)?,
                BinaryOperator::Subtract => l.checked_sub(r)?,
                BinaryOperator::Multiply => l.checked_mul(r)?,
                BinaryOperator::Divide => l.checked_div(r)?,
                BinaryOperator::Modulo => l.checked_rem(r)?,
                BinaryOperator::BitwiseAnd => l & r,
                BinaryOperator::BitwiseOr => l | r,
                BinaryOperator::BitwiseXor => l ^ r,
                BinaryOperator::LeftShift => l.checked_shl(shift_amount?)?,
                BinaryOperator::RightShift => l.checked_shr(shift_amount?)?,
                _ => return None,
            };
            Some(Expression::IntegerLiteral(result))
        } else {
            None
        }
    }

    /// Aggressive optimizations
    fn optimize_aggressive(&self, func: &mut Function) {
        // Conservative dead-code pruning:
        // Only remove statements that are *unreachable by construction* within a single
        // straight-line block (e.g. statements after an unconditional `return`).
        //
        // Anything CFG-sensitive (e.g. reachability across branches) is deliberately
        // out of scope here to avoid deleting code incorrectly.
        self.prune_unreachable_after_terminators(func);

        // Inline simple functions
        self.inline_simple_functions(func);
    }

    fn prune_unreachable_after_terminators(&self, func: &mut Function) {
        prune_after_return_in_block(&mut func.body);
    }

    /// Inline simple functions
    fn inline_simple_functions(&self, _func: &mut Function) {
        // TODO: Implement function inlining
    }
}

fn prune_after_return_in_block(statements: &mut Vec<Statement>) {
    let mut idx = 0;
    while idx < statements.len() {
        match &mut statements[idx] {
            Statement::If {
                then_block,
                else_block,
                ..
            } => {
                prune_after_return_in_block(then_block);
                if let Some(else_block) = else_block.as_mut() {
                    prune_after_return_in_block(else_block);
                }
            }
            Statement::While { body, .. } => {
                prune_after_return_in_block(body);
            }
            Statement::For { body, init, .. } => {
                if let Some(init) = init.as_mut() {
                    // `init` is a single boxed statement, but it may contain nested blocks.
                    prune_after_return_in_statement(init);
                }
                prune_after_return_in_block(body);
            }
            Statement::Block(nested) => {
                prune_after_return_in_block(nested);
            }
            _ => {}
        }

        if matches!(statements[idx], Statement::Return(_)) {
            statements.truncate(idx + 1);
            return;
        }
        idx += 1;
    }
}

fn prune_after_return_in_statement(statement: &mut Box<Statement>) {
    match statement.as_mut() {
        Statement::If {
            then_block,
            else_block,
            ..
        } => {
            prune_after_return_in_block(then_block);
            if let Some(else_block) = else_block.as_mut() {
                prune_after_return_in_block(else_block);
            }
        }
        Statement::While { body, .. } => {
            prune_after_return_in_block(body);
        }
        Statement::For { body, init, .. } => {
            if let Some(init) = init.as_mut() {
                prune_after_return_in_statement(init);
            }
            prune_after_return_in_block(body);
        }
        Statement::Block(nested) => {
            prune_after_return_in_block(nested);
        }
        _ => {}
    }
}

impl Default for Optimizer {
    fn default() -> Self {
        Self::new(OptimizationLevel::Basic)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::TypeInfo;
    use crate::decompiler::ast::{Expression, Function, Statement, UnaryOperator};

    fn lit(value: i64) -> Expression {
        Expression::IntegerLiteral(value)
    }

    fn bin(op: BinaryOperator, left: Expression, right: Expression) -> Expression {
        Expression::BinaryOperation {
            op,
            left: Box::new(left),
            right: Box::new(right),
        }
    }

    fn empty_function(body: Vec<Statement>) -> Function {
        Function {
            name: "f".to_string(),
            return_type: TypeInfo::Void,
            parameters: vec![],
            body,
            is_variadic: false,
        }
    }

    fn run(level: OptimizationLevel, body: Vec<Statement>) -> Function {
        let mut func = empty_function(body);
        Optimizer::new(level).optimize_function(&mut func);
        func
    }

    // ---- constant folding ----

    #[test]
    fn folds_addition_of_integer_literals() {
        let func = run(
            OptimizationLevel::Basic,
            vec![Statement::Expression(bin(
                BinaryOperator::Add,
                lit(2),
                lit(3),
            ))],
        );
        assert!(matches!(
            &func.body[..],
            [Statement::Expression(Expression::IntegerLiteral(5))]
        ));
    }

    #[test]
    fn folds_bitwise_and_or_xor_shifts() {
        let cases = [
            (BinaryOperator::BitwiseAnd, 0xF0_F0, 0x0F_FF, 0x00_F0),
            (BinaryOperator::BitwiseOr, 0xF0, 0x0F, 0xFF),
            (BinaryOperator::BitwiseXor, 0xFF, 0x0F, 0xF0),
            (BinaryOperator::LeftShift, 1, 4, 16),
            (BinaryOperator::RightShift, 256, 4, 16),
        ];

        for (op, a, b, expected) in cases {
            let func = run(
                OptimizationLevel::Basic,
                vec![Statement::Expression(bin(op, lit(a), lit(b)))],
            );
            assert!(
                matches!(
                    &func.body[..],
                    [Statement::Expression(Expression::IntegerLiteral(v))]
                        if *v == expected
                ),
                "op {:?} produced unexpected body: {:?}",
                op,
                func.body
            );
        }
    }

    #[test]
    fn folds_nested_binary_expressions_bottom_up() {
        // (1 + 2) * (3 + 4) → 21
        let inner_left = bin(BinaryOperator::Add, lit(1), lit(2));
        let inner_right = bin(BinaryOperator::Add, lit(3), lit(4));
        let outer = bin(BinaryOperator::Multiply, inner_left, inner_right);

        let func = run(OptimizationLevel::Basic, vec![Statement::Expression(outer)]);
        assert!(matches!(
            &func.body[..],
            [Statement::Expression(Expression::IntegerLiteral(21))]
        ));
    }

    #[test]
    fn does_not_fold_when_either_operand_is_non_literal() {
        let expr = bin(
            BinaryOperator::Add,
            Expression::Variable("x".to_string()),
            lit(7),
        );
        let func = run(
            OptimizationLevel::Basic,
            vec![Statement::Expression(expr)],
        );
        assert!(matches!(
            &func.body[..],
            [Statement::Expression(Expression::BinaryOperation { .. })]
        ));
    }

    #[test]
    fn does_not_fold_comparison_or_logical_operators() {
        // Folding these would silently produce 0/1 ints; current contract leaves them alone.
        let cases = [
            BinaryOperator::Equal,
            BinaryOperator::NotEqual,
            BinaryOperator::LessThan,
            BinaryOperator::GreaterThan,
            BinaryOperator::LogicalAnd,
            BinaryOperator::LogicalOr,
        ];

        for op in cases {
            let func = run(
                OptimizationLevel::Basic,
                vec![Statement::Expression(bin(op, lit(1), lit(2)))],
            );
            assert!(
                matches!(
                    &func.body[..],
                    [Statement::Expression(Expression::BinaryOperation { .. })]
                ),
                "op {:?} unexpectedly folded into {:?}",
                op,
                func.body
            );
        }
    }

    #[test]
    fn level_none_skips_all_optimizations() {
        let body = vec![
            Statement::Expression(bin(BinaryOperator::Add, lit(2), lit(3))),
            Statement::Empty,
        ];
        let func = run(OptimizationLevel::None, body);

        // Add survived unfolded, AND Empty survived (no retain happened).
        assert_eq!(func.body.len(), 2);
        assert!(matches!(
            &func.body[0],
            Statement::Expression(Expression::BinaryOperation { .. })
        ));
        assert!(matches!(&func.body[1], Statement::Empty));
    }

    #[test]
    fn basic_level_drops_empty_statements() {
        let body = vec![
            Statement::Empty,
            Statement::Expression(lit(1)),
            Statement::Empty,
        ];
        let func = run(OptimizationLevel::Basic, body);
        assert_eq!(func.body.len(), 1);
        assert!(matches!(
            &func.body[0],
            Statement::Expression(Expression::IntegerLiteral(1))
        ));
    }

    #[test]
    fn recurses_into_if_then_else_blocks() {
        let body = vec![Statement::If {
            condition: bin(BinaryOperator::Add, lit(0), lit(1)),
            then_block: vec![Statement::Expression(bin(
                BinaryOperator::Multiply,
                lit(4),
                lit(5),
            ))],
            else_block: Some(vec![Statement::Expression(bin(
                BinaryOperator::Subtract,
                lit(10),
                lit(3),
            ))]),
        }];
        let func = run(OptimizationLevel::Basic, body);

        let Statement::If {
            condition,
            then_block,
            else_block,
        } = &func.body[0]
        else {
            panic!("expected if, got {:?}", func.body);
        };
        assert!(matches!(condition, Expression::IntegerLiteral(1)));
        assert!(matches!(
            &then_block[..],
            [Statement::Expression(Expression::IntegerLiteral(20))]
        ));
        assert!(matches!(
            else_block.as_deref(),
            Some([Statement::Expression(Expression::IntegerLiteral(7))])
        ));
    }

    #[test]
    fn recurses_into_while_and_for_bodies() {
        let body = vec![
            Statement::While {
                condition: bin(BinaryOperator::Add, lit(1), lit(0)),
                body: vec![Statement::Expression(bin(
                    BinaryOperator::Add,
                    lit(3),
                    lit(4),
                ))],
            },
            Statement::For {
                init: Some(Box::new(Statement::Expression(bin(
                    BinaryOperator::Add,
                    lit(0),
                    lit(0),
                )))),
                condition: Some(bin(BinaryOperator::LessThan, lit(1), lit(10))),
                update: Some(bin(BinaryOperator::Add, lit(1), lit(1))),
                body: vec![Statement::Expression(bin(
                    BinaryOperator::Multiply,
                    lit(2),
                    lit(2),
                ))],
            },
        ];
        let func = run(OptimizationLevel::Basic, body);

        let Statement::While { condition, body } = &func.body[0] else {
            panic!("expected while");
        };
        assert!(matches!(condition, Expression::IntegerLiteral(1)));
        assert!(matches!(
            &body[..],
            [Statement::Expression(Expression::IntegerLiteral(7))]
        ));

        let Statement::For { update, body, .. } = &func.body[1] else {
            panic!("expected for");
        };
        assert!(matches!(update, Some(Expression::IntegerLiteral(2))));
        assert!(matches!(
            &body[..],
            [Statement::Expression(Expression::IntegerLiteral(4))]
        ));
    }

    #[test]
    fn recurses_into_unary_assignment_and_function_call_arguments() {
        // -(2 + 3) → -5, var = (1+1), f((4+1))
        let neg = Expression::UnaryOperation {
            op: UnaryOperator::Negate,
            operand: Box::new(bin(BinaryOperator::Add, lit(2), lit(3))),
        };
        let assign = Expression::Assignment {
            target: Box::new(Expression::Variable("x".to_string())),
            value: Box::new(bin(BinaryOperator::Add, lit(1), lit(1))),
        };
        let call = Expression::FunctionCall {
            function: "f".to_string(),
            arguments: vec![bin(BinaryOperator::Add, lit(4), lit(1))],
        };

        let func = run(
            OptimizationLevel::Basic,
            vec![
                Statement::Expression(neg),
                Statement::Expression(assign),
                Statement::Expression(call),
            ],
        );

        // Negate doesn't get folded — only the inner BinaryOperation does.
        let Statement::Expression(Expression::UnaryOperation { operand, .. }) = &func.body[0]
        else {
            panic!("expected unary");
        };
        assert!(matches!(operand.as_ref(), Expression::IntegerLiteral(5)));

        let Statement::Expression(Expression::Assignment { value, .. }) = &func.body[1] else {
            panic!("expected assignment");
        };
        assert!(matches!(value.as_ref(), Expression::IntegerLiteral(2)));

        let Statement::Expression(Expression::FunctionCall { arguments, .. }) = &func.body[2]
        else {
            panic!("expected call");
        };
        assert!(matches!(&arguments[..], [Expression::IntegerLiteral(5)]));
    }

    // ---- aggressive: dead-code after return ----

    #[test]
    fn aggressive_prunes_statements_after_return_in_top_level() {
        let body = vec![
            Statement::Return(None),
            Statement::Expression(lit(42)),
            Statement::Expression(lit(43)),
        ];
        let func = run(OptimizationLevel::Aggressive, body);
        assert_eq!(func.body.len(), 1);
        assert!(matches!(func.body[0], Statement::Return(None)));
    }

    #[test]
    fn aggressive_prunes_inside_if_branches_independently() {
        let body = vec![Statement::If {
            condition: Expression::Variable("c".to_string()),
            then_block: vec![
                Statement::Return(Some(lit(1))),
                Statement::Expression(lit(99)), // dead
            ],
            else_block: Some(vec![
                Statement::Return(Some(lit(2))),
                Statement::Expression(lit(88)), // dead
            ]),
        }];
        let func = run(OptimizationLevel::Aggressive, body);

        let Statement::If {
            then_block,
            else_block,
            ..
        } = &func.body[0]
        else {
            panic!("expected if");
        };
        assert_eq!(then_block.len(), 1);
        assert_eq!(else_block.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn basic_level_does_not_prune_dead_code() {
        let body = vec![
            Statement::Return(None),
            Statement::Expression(lit(42)),
        ];
        let func = run(OptimizationLevel::Basic, body);
        assert_eq!(func.body.len(), 2);
    }

    // ---- checked-arithmetic safety net for fold_constant ----

    /// Run the optimizer and assert that the (single) folded body statement
    /// is still a BinaryOperation with the same operator — i.e. folding was
    /// skipped because the operation was unsafe at the given operand values.
    fn assert_left_unfolded(op: BinaryOperator, left: i64, right: i64) {
        let func = run(
            OptimizationLevel::Basic,
            vec![Statement::Expression(bin(op, lit(left), lit(right)))],
        );
        assert!(
            matches!(
                &func.body[..],
                [Statement::Expression(Expression::BinaryOperation { op: actual, .. })]
                    if *actual == op
            ),
            "expected {:?} {} {} to be left as a BinaryOperation, got {:?}",
            op,
            left,
            right,
            func.body
        );
    }

    #[test]
    fn fold_constant_leaves_division_by_zero_unfolded_instead_of_panicking() {
        assert_left_unfolded(BinaryOperator::Divide, 1, 0);
        assert_left_unfolded(BinaryOperator::Divide, i64::MIN, 0);
    }

    #[test]
    fn fold_constant_leaves_modulo_by_zero_unfolded_instead_of_panicking() {
        assert_left_unfolded(BinaryOperator::Modulo, 7, 0);
    }

    #[test]
    fn fold_constant_leaves_signed_overflow_unfolded_instead_of_panicking() {
        // i64::MAX + 1, i64::MIN - 1, i64::MIN * -1 — all overflow.
        assert_left_unfolded(BinaryOperator::Add, i64::MAX, 1);
        assert_left_unfolded(BinaryOperator::Subtract, i64::MIN, 1);
        assert_left_unfolded(BinaryOperator::Multiply, i64::MIN, -1);
    }

    #[test]
    fn fold_constant_leaves_division_overflow_unfolded() {
        // i64::MIN / -1 overflows because the absolute value would be i64::MAX+1.
        assert_left_unfolded(BinaryOperator::Divide, i64::MIN, -1);
    }

    #[test]
    fn fold_constant_leaves_oversized_or_negative_shifts_unfolded() {
        // Out-of-range shift amounts that would invoke UB are rejected.
        for (op, amount) in [
            (BinaryOperator::LeftShift, 64i64),
            (BinaryOperator::LeftShift, 128),
            (BinaryOperator::LeftShift, -1),
            (BinaryOperator::RightShift, 64),
            (BinaryOperator::RightShift, -1),
        ] {
            assert_left_unfolded(op, 1, amount);
        }
    }

    #[test]
    fn fold_constant_still_folds_when_arithmetic_is_safe() {
        // Regression guard: the safety net must not break the common case.
        let func = run(
            OptimizationLevel::Basic,
            vec![
                Statement::Expression(bin(BinaryOperator::Add, lit(2), lit(3))),
                Statement::Expression(bin(BinaryOperator::Divide, lit(20), lit(4))),
                Statement::Expression(bin(BinaryOperator::LeftShift, lit(1), lit(63))),
            ],
        );

        let values: Vec<i64> = func
            .body
            .iter()
            .filter_map(|s| match s {
                Statement::Expression(Expression::IntegerLiteral(v)) => Some(*v),
                _ => None,
            })
            .collect();
        assert_eq!(values, vec![5, 5, i64::MIN]);
    }
}
