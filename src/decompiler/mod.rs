//! Decompilation module

pub mod ast;
pub mod c_generator;
pub mod c_syntax;
pub mod lifter;
pub mod optimization;
pub mod string_refs;
pub mod structure;

pub use ast::{AstNode, AstNodeType, Expression, Function, Statement};
pub use c_generator::{CGenerator, CGeneratorConfig};
pub use c_syntax::{
    escape_c_string, quote_c_string, sanitize_c_comment, sanitize_c_identifier, unique_c_identifier,
};
pub use lifter::{
    import_function_declarations, lift_function, lift_functions, lift_functions_with_imports,
    ImportFunctionDeclaration,
};
pub use optimization::{OptimizationLevel, Optimizer};
pub use signatures::recover_function_signatures;
pub use string_refs::annotate_string_references;
pub use structure::{
    structure_function, structure_function_with_cfg, structure_functions,
    structure_functions_with_cfg,
};
pub mod signatures;

#[cfg(test)]
mod structure_tests {
    use super::ast::{BinaryOperator, Expression, Function, Parameter, Statement};
    use super::structure::{structure_function, structure_function_with_cfg, structure_functions};
    use super::{recover_function_signatures, CGenerator, CGeneratorConfig};
    use crate::analysis::functions::FunctionInfo;
    use crate::analysis::TypeInfo;
    use crate::disasm::{ControlFlowGraph, X86Instruction};

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
            address: 0x1000,
            size: instructions.iter().map(|instr| instr.length).sum(),
            instructions: instructions
                .into_iter()
                .map(crate::disasm::control_flow::Instruction::X86)
                .collect(),
            is_import: false,
            is_export: false,
        }
    }

    #[test]
    fn converts_ret_inline_asm_to_return_statement() {
        let mut func = function_with(vec![
            Statement::InlineAsm {
                address: 0x1000,
                disasm: "push rbp".to_string(),
            },
            Statement::InlineAsm {
                address: 0x1001,
                disasm: "ret".to_string(),
            },
        ]);

        structure_function(&mut func);

        assert!(matches!(
            func.body[0],
            Statement::InlineAsm {
                address: 0x1000,
                ..
            }
        ));
        assert!(matches!(func.body[1], Statement::Return(None)));
    }

    #[test]
    fn ret_with_stack_adjustment_is_still_void_return() {
        let mut func = function_with(vec![Statement::InlineAsm {
            address: 0x2000,
            disasm: "ret 10h".to_string(),
        }]);

        structure_function(&mut func);

        assert!(matches!(func.body.as_slice(), [Statement::Return(None)]));
    }

    #[test]
    fn structures_multiple_functions_without_reordering() {
        let first = function_with(vec![Statement::InlineAsm {
            address: 0x1000,
            disasm: "ret".to_string(),
        }]);
        let second = function_with(vec![Statement::InlineAsm {
            address: 0x2000,
            disasm: "nop".to_string(),
        }]);
        let mut functions = vec![first, second];

        structure_functions(&mut functions);

        assert_eq!(functions[0].name, "sub_1000");
        assert!(matches!(
            functions[0].body.as_slice(),
            [Statement::Return(None)]
        ));
        assert!(matches!(
            functions[1].body.as_slice(),
            [Statement::InlineAsm {
                address: 0x2000,
                ..
            }]
        ));
    }

    #[test]
    fn mov_register_immediate_becomes_assignment() {
        let mut func = function_with(vec![inline(0x3000, "mov eax, 2")]);

        structure_function(&mut func);

        assert!(matches!(
            func.body.as_slice(),
            [Statement::Expression(Expression::Assignment { target, value })]
                if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                    && matches!(value.as_ref(), Expression::IntegerLiteral(2))
        ));
    }

    #[test]
    fn xor_register_with_itself_becomes_zero_assignment() {
        let mut func = function_with(vec![inline(0x3000, "xor r8d, r8d")]);

        structure_function(&mut func);

        assert!(matches!(
            func.body.as_slice(),
            [Statement::Expression(Expression::Assignment { target, value })]
                if matches!(target.as_ref(), Expression::Variable(name) if name == "r8")
                    && matches!(value.as_ref(), Expression::IntegerLiteral(0))
        ));
    }

    #[test]
    fn memory_mov_stays_inline_asm() {
        let mut func = function_with(vec![inline(0x3000, "mov [rcx+28h], eax")]);

        structure_function(&mut func);

        assert!(matches!(
            func.body.as_slice(),
            [Statement::InlineAsm {
                address: 0x3000,
                ..
            }]
        ));
    }

    #[test]
    fn stack_mov_load_and_store_become_assignments() {
        let mut func = function_with(vec![
            inline(0x3000, "mov qword ptr [rbp-8], eax"),
            inline(0x3001, "mov rax, qword ptr [rbp-8]"),
            inline(0x3002, "mov dword ptr [rbp+10h], 2Ah"),
        ]);

        structure_function(&mut func);

        assert!(matches!(
            func.body.as_slice(),
            [
                Statement::Expression(Expression::Assignment { target: store_target, value: store_value }),
                Statement::Expression(Expression::Assignment { target: load_target, value: load_value }),
                Statement::Expression(Expression::Assignment { target: arg_target, value: arg_value }),
            ] if matches!(store_target.as_ref(), Expression::Variable(name) if name == "local_8")
                && matches!(store_value.as_ref(), Expression::Variable(name) if name == "rax")
                && matches!(load_target.as_ref(), Expression::Variable(name) if name == "rax")
                && matches!(load_value.as_ref(), Expression::Variable(name) if name == "local_8")
                && matches!(arg_target.as_ref(), Expression::Variable(name) if name == "arg_10")
                && matches!(arg_value.as_ref(), Expression::IntegerLiteral(42))
        ));
    }

    #[test]
    fn cfg_path_declares_stack_variables_used_by_assignments() {
        let cfg = ControlFlowGraph::from_x86(vec![]);
        let mut func = function_with(vec![inline(0x3000, "mov qword ptr [rbp-8], eax")]);

        structure_function_with_cfg(&mut func, &cfg);

        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "local_8"
        ));
        assert!(matches!(
            &func.body[1],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));
        assert!(matches!(
            &func.body[2],
            Statement::Expression(Expression::Assignment { target, value })
                if matches!(target.as_ref(), Expression::Variable(name) if name == "local_8")
                    && matches!(value.as_ref(), Expression::Variable(name) if name == "rax")
        ));
    }

    #[test]
    fn cfg_path_declares_registers_used_by_assignments() {
        let cfg = ControlFlowGraph::from_x86(vec![]);
        let mut func = function_with(vec![inline(0x3000, "mov eax, 2")]);

        structure_function_with_cfg(&mut func, &cfg);

        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));
        assert!(matches!(
            &func.body[1],
            Statement::Expression(Expression::Assignment { target, value })
                if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                    && matches!(value.as_ref(), Expression::IntegerLiteral(2))
        ));
    }

    #[test]
    fn cfg_path_does_not_redeclare_signature_parameters() {
        let cfg = ControlFlowGraph::from_x86(vec![]);
        let mut func = function_with(vec![inline(0x3000, "mov eax, ecx")]);
        func.parameters.push(Parameter {
            name: "rcx".to_string(),
            type_info: TypeInfo::U64,
        });

        structure_function_with_cfg(&mut func, &cfg);

        assert!(!func.body.iter().any(|statement| {
            matches!(
                statement,
                Statement::VariableDeclaration { name, .. } if name == "rcx"
            )
        }));
        assert!(func.body.iter().any(|statement| {
            matches!(
                statement,
                Statement::VariableDeclaration { name, .. } if name == "rax"
            )
        }));
    }

    #[test]
    fn signature_recovery_promotes_used_argument_registers_and_rax_return() {
        let mut functions = vec![function_with(vec![
            Statement::Expression(Expression::Assignment {
                target: Box::new(Expression::Variable("rax".to_string())),
                value: Box::new(Expression::Variable("rcx".to_string())),
            }),
            Statement::Return(None),
        ])];
        let infos = vec![function_info(
            "sub_1000",
            vec![
                x86(0x1000, "mov", "rax, rcx", None),
                x86(0x1001, "ret", "", None),
            ],
        )];

        recover_function_signatures(&mut functions, &infos, "PE/EXE", "x64");

        assert_eq!(functions[0].parameters.len(), 1);
        assert_eq!(functions[0].parameters[0].name, "rcx");
        assert_eq!(functions[0].return_type, TypeInfo::U64);
        assert!(matches!(
            functions[0].body.as_slice(),
            [
                Statement::Expression(Expression::Assignment { .. }),
                Statement::Return(Some(Expression::Variable(name)))
            ] if name == "rax"
        ));

        let mut generator = CGenerator::new(CGeneratorConfig::default());
        let c = generator.generate_function(&functions[0]);
        assert!(c.starts_with("uint64_t sub_1000(uint64_t rcx)"));
    }

    #[test]
    fn cfg_conditional_with_two_returning_arms_becomes_if_else() {
        let instructions = vec![
            x86(0x1000, "jne", "1010h", Some(0x1010)),
            x86(0x1001, "mov", "eax, 1", None),
            x86(0x1002, "ret", "", None),
            x86(0x1010, "xor", "eax, eax", None),
            x86(0x1011, "ret", "", None),
        ];
        let cfg = ControlFlowGraph::from_x86(instructions);
        let mut func = function_with(vec![
            inline(0x1000, "jne 1010h"),
            inline(0x1001, "mov eax, 1"),
            inline(0x1002, "ret"),
            inline(0x1010, "xor eax, eax"),
            inline(0x1011, "ret"),
        ]);

        structure_function_with_cfg(&mut func, &cfg);

        assert_eq!(func.body.len(), 2);
        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));
        let Statement::If {
            condition,
            then_block,
            else_block,
        } = &func.body[1]
        else {
            panic!("expected if/else, got {:?}", func.body);
        };

        assert!(
            matches!(condition, Expression::Unknown(s) if s == "/* condition: 0x1000 jne 1010h */ 1")
        );
        assert!(matches!(
            then_block.as_slice(),
            [
                Statement::Expression(Expression::Assignment { target, value }),
                Statement::Return(None)
            ] if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                && matches!(value.as_ref(), Expression::IntegerLiteral(0))
        ));
        assert!(matches!(
            else_block.as_deref(),
            Some([
                Statement::Expression(Expression::Assignment { target, value }),
                Statement::Return(None)
            ]) if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                && matches!(value.as_ref(), Expression::IntegerLiteral(1))
        ));
    }

    #[test]
    fn cfg_if_keeps_condition_setup_before_the_branch() {
        let instructions = vec![
            x86(0x1000, "cmp", "eax, 0", None),
            x86(0x1001, "jne", "1010h", Some(0x1010)),
            x86(0x1002, "mov", "eax, 1", None),
            x86(0x1003, "ret", "", None),
            x86(0x1010, "xor", "eax, eax", None),
            x86(0x1011, "ret", "", None),
        ];
        let cfg = ControlFlowGraph::from_x86(instructions);
        let mut func = function_with(vec![
            inline(0x1000, "cmp eax, 0"),
            inline(0x1001, "jne 1010h"),
            inline(0x1002, "mov eax, 1"),
            inline(0x1003, "ret"),
            inline(0x1010, "xor eax, eax"),
            inline(0x1011, "ret"),
        ]);

        structure_function_with_cfg(&mut func, &cfg);

        assert_eq!(func.body.len(), 3);
        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));
        assert!(matches!(
            func.body[1],
            Statement::InlineAsm {
                address: 0x1000,
                ..
            }
        ));
        assert!(matches!(
            func.body[2],
            Statement::If {
                condition: Expression::BinaryOperation { .. },
                ..
            }
        ));
    }

    #[test]
    fn cfg_diamond_with_join_becomes_if_else_and_keeps_join() {
        let instructions = vec![
            x86(0x1000, "cmp", "eax, 0", None),
            x86(0x1001, "je", "1010h", Some(0x1010)),
            x86(0x1002, "mov", "eax, 1", None),
            x86(0x1003, "jmp", "1020h", Some(0x1020)),
            x86(0x1010, "xor", "eax, eax", None),
            x86(0x1020, "add", "eax, 2", None),
            x86(0x1021, "ret", "", None),
        ];
        let cfg = ControlFlowGraph::from_x86(instructions);
        let mut func = function_with(vec![
            inline(0x1000, "cmp eax, 0"),
            inline(0x1001, "je 1010h"),
            inline(0x1002, "mov eax, 1"),
            inline(0x1003, "jmp 1020h"),
            inline(0x1010, "xor eax, eax"),
            inline(0x1020, "add eax, 2"),
            inline(0x1021, "ret"),
        ]);

        structure_function_with_cfg(&mut func, &cfg);

        assert_eq!(func.body.len(), 5);
        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));
        assert!(matches!(
            func.body[1],
            Statement::InlineAsm {
                address: 0x1000,
                ..
            }
        ));
        let Statement::If {
            then_block,
            else_block,
            ..
        } = &func.body[2]
        else {
            panic!("expected if/else, got {:?}", func.body);
        };
        assert!(matches!(
            then_block.as_slice(),
            [Statement::Expression(Expression::Assignment { target, value })]
                if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                    && matches!(value.as_ref(), Expression::IntegerLiteral(0))
        ));
        assert!(matches!(
            else_block.as_deref(),
            Some([Statement::Expression(Expression::Assignment { target, value })])
                if matches!(target.as_ref(), Expression::Variable(name) if name == "rax")
                    && matches!(value.as_ref(), Expression::IntegerLiteral(1))
        ));
        assert!(matches!(
            func.body[3],
            Statement::InlineAsm {
                address: 0x1020,
                ..
            }
        ));
        assert!(matches!(func.body[4], Statement::Return(None)));
    }

    #[test]
    fn memory_cmp_condition_stays_human_readable_comment() {
        let instructions = vec![
            x86(0x1000, "cmp", "[rcx+28h], 0", None),
            x86(0x1001, "je", "1010h", Some(0x1010)),
            x86(0x1002, "mov", "eax, 1", None),
            x86(0x1003, "jmp", "1020h", Some(0x1020)),
            x86(0x1010, "xor", "eax, eax", None),
            x86(0x1020, "ret", "", None),
        ];
        let cfg = ControlFlowGraph::from_x86(instructions);
        let mut func = function_with(vec![
            inline(0x1000, "cmp [rcx+28h], 0"),
            inline(0x1001, "je 1010h"),
            inline(0x1002, "mov eax, 1"),
            inline(0x1003, "jmp 1020h"),
            inline(0x1010, "xor eax, eax"),
            inline(0x1020, "ret"),
        ]);

        structure_function_with_cfg(&mut func, &cfg);

        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));
        let Statement::If { condition, .. } = &func.body[2] else {
            panic!("expected if/else, got {:?}", func.body);
        };
        assert!(matches!(
            condition,
            Expression::Unknown(s)
                if s == "/* condition: [rcx+28h] == 0 (from cmp [rcx+28h], 0; je 1010h) */ 1"
        ));
    }

    #[test]
    fn simple_register_cmp_condition_becomes_executable_expression() {
        let instructions = vec![
            x86(0x1000, "cmp", "eax, 0", None),
            x86(0x1001, "je", "1010h", Some(0x1010)),
            x86(0x1002, "mov", "eax, 1", None),
            x86(0x1003, "jmp", "1020h", Some(0x1020)),
            x86(0x1010, "xor", "eax, eax", None),
            x86(0x1020, "ret", "", None),
        ];
        let cfg = ControlFlowGraph::from_x86(instructions);
        let mut func = function_with(vec![
            inline(0x1000, "cmp eax, 0"),
            inline(0x1001, "je 1010h"),
            inline(0x1002, "mov eax, 1"),
            inline(0x1003, "jmp 1020h"),
            inline(0x1010, "xor eax, eax"),
            inline(0x1020, "ret"),
        ]);

        structure_function_with_cfg(&mut func, &cfg);

        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));

        let Statement::If { condition, .. } = &func.body[2] else {
            panic!(
                "expected if/else after pseudo-register declaration, got {:?}",
                func.body
            );
        };
        assert!(matches!(
            condition,
            Expression::BinaryOperation {
                op: BinaryOperator::Equal,
                left,
                right,
            } if matches!(left.as_ref(), Expression::Variable(name) if name == "rax")
                && matches!(right.as_ref(), Expression::IntegerLiteral(0))
        ));
    }

    #[test]
    fn simple_register_test_condition_becomes_executable_expression() {
        let instructions = vec![
            x86(0x2000, "test", "r8b, r8b", None),
            x86(0x2001, "jne", "2010h", Some(0x2010)),
            x86(0x2002, "mov", "eax, 1", None),
            x86(0x2003, "jmp", "2020h", Some(0x2020)),
            x86(0x2010, "xor", "eax, eax", None),
            x86(0x2020, "ret", "", None),
        ];
        let cfg = ControlFlowGraph::from_x86(instructions);
        let mut func = function_with(vec![
            inline(0x2000, "test r8b, r8b"),
            inline(0x2001, "jne 2010h"),
            inline(0x2002, "mov eax, 1"),
            inline(0x2003, "jmp 2020h"),
            inline(0x2010, "xor eax, eax"),
            inline(0x2020, "ret"),
        ]);

        structure_function_with_cfg(&mut func, &cfg);

        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "r8"
        ));
        assert!(matches!(
            &func.body[1],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));

        let Statement::If { condition, .. } = &func.body[3] else {
            panic!(
                "expected if/else after pseudo-register declaration, got {:?}",
                func.body
            );
        };
        assert!(matches!(
            condition,
            Expression::BinaryOperation {
                op: BinaryOperator::NotEqual,
                left,
                right,
            } if matches!(left.as_ref(), Expression::Variable(name) if name == "r8")
                && matches!(right.as_ref(), Expression::IntegerLiteral(0))
        ));
    }

    #[test]
    fn memory_test_condition_stays_human_readable_comment() {
        let instructions = vec![
            x86(0x2000, "test", "[rcx+28h], rax", None),
            x86(0x2001, "jne", "2010h", Some(0x2010)),
            x86(0x2002, "mov", "eax, 1", None),
            x86(0x2003, "jmp", "2020h", Some(0x2020)),
            x86(0x2010, "xor", "eax, eax", None),
            x86(0x2020, "ret", "", None),
        ];
        let cfg = ControlFlowGraph::from_x86(instructions);
        let mut func = function_with(vec![
            inline(0x2000, "test [rcx+28h], rax"),
            inline(0x2001, "jne 2010h"),
            inline(0x2002, "mov eax, 1"),
            inline(0x2003, "jmp 2020h"),
            inline(0x2010, "xor eax, eax"),
            inline(0x2020, "ret"),
        ]);

        structure_function_with_cfg(&mut func, &cfg);

        assert!(matches!(
            &func.body[0],
            Statement::VariableDeclaration {
                name,
                type_info: TypeInfo::U64,
                init: None,
            } if name == "rax"
        ));
        let Statement::If { condition, .. } = &func.body[2] else {
            panic!("expected if/else, got {:?}", func.body);
        };
        assert!(matches!(
            condition,
            Expression::Unknown(s)
                if s == "/* condition: ([rcx+28h] & rax) != 0 (from test [rcx+28h], rax; jne 2010h) */ 1"
        ));
    }
}
