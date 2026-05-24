//! C code generator from AST

use crate::analysis::TypeInfo;
use crate::decompiler::ast::{BinaryOperator, Expression, Function, Statement, UnaryOperator};
use crate::decompiler::c_syntax::{quote_c_string, sanitize_c_comment, sanitize_c_identifier};

/// C generator configuration
#[derive(Debug, Clone)]
pub struct CGeneratorConfig {
    /// Indentation size
    pub indent_size: usize,
    /// Whether to include comments
    pub include_comments: bool,
    /// Whether to use stdint.h types
    pub use_stdint: bool,
}

impl Default for CGeneratorConfig {
    fn default() -> Self {
        Self {
            indent_size: 4,
            include_comments: true,
            use_stdint: true,
        }
    }
}

/// C code generator
pub struct CGenerator {
    config: CGeneratorConfig,
    indent_level: usize,
}

impl CGenerator {
    /// Create a new C generator
    pub fn new(config: CGeneratorConfig) -> Self {
        Self {
            config,
            indent_level: 0,
        }
    }

    /// Generate C code from a function
    pub fn generate_function(&mut self, func: &Function) -> String {
        let mut output = String::new();

        // Function signature
        output.push_str(&self.generate_function_signature(func));
        output.push_str(" {\n");
        self.indent_level += 1;

        // Function body
        for stmt in &func.body {
            output.push_str(&self.generate_statement(stmt));
            output.push('\n');
        }

        self.indent_level -= 1;
        output.push_str("}\n");

        output
    }

    /// Generate function signature
    fn generate_function_signature(&self, func: &Function) -> String {
        let return_type = self.type_to_c_string(&func.return_type);
        let function_name = sanitize_c_identifier(&func.name, "sub");
        let params: Vec<String> = func
            .parameters
            .iter()
            .map(|p| {
                let param_type = self.type_to_c_string(&p.type_info);
                let param_name = sanitize_c_identifier(&p.name, "arg");
                format!("{} {}", param_type, param_name)
            })
            .collect();

        let params_str = if params.is_empty() {
            "void".to_string()
        } else {
            params.join(", ")
        };

        format!("{} {}({})", return_type, function_name, params_str)
    }

    /// Generate C code from a statement
    fn generate_statement(&mut self, stmt: &Statement) -> String {
        let indent = " ".repeat(self.indent_level * self.config.indent_size);

        match stmt {
            Statement::Expression(expr) => {
                format!("{}{};", indent, self.generate_expression(expr))
            }
            Statement::Return(None) => {
                format!("{}return;", indent)
            }
            Statement::Return(Some(expr)) => {
                format!("{}return {};", indent, self.generate_expression(expr))
            }
            Statement::If {
                condition,
                then_block,
                else_block,
            } => {
                let mut output = format!(
                    "{}if ({}) {{\n",
                    indent,
                    self.generate_expression(condition)
                );
                self.indent_level += 1;

                for s in then_block {
                    output.push_str(&self.generate_statement(s));
                    output.push('\n');
                }

                self.indent_level -= 1;
                output.push_str(&format!("{}}}", indent));

                if let Some(else_block) = else_block {
                    output.push_str(" else {\n");
                    self.indent_level += 1;

                    for s in else_block {
                        output.push_str(&self.generate_statement(s));
                        output.push('\n');
                    }

                    self.indent_level -= 1;
                    output.push_str(&format!("{}}}", indent));
                }

                output
            }
            Statement::While { condition, body } => {
                let mut output = format!(
                    "{}while ({}) {{\n",
                    indent,
                    self.generate_expression(condition)
                );
                self.indent_level += 1;

                for s in body {
                    output.push_str(&self.generate_statement(s));
                    output.push('\n');
                }

                self.indent_level -= 1;
                output.push_str(&format!("{}}}", indent));
                output
            }
            Statement::For {
                init,
                condition,
                update,
                body,
            } => {
                let init_str = init
                    .as_ref()
                    .map(|s| self.generate_statement(s).trim_end_matches(';').to_string())
                    .unwrap_or_else(|| "".to_string());

                let cond_str = condition
                    .as_ref()
                    .map(|c| self.generate_expression(c))
                    .unwrap_or_else(|| "1".to_string());

                let update_str = update
                    .as_ref()
                    .map(|c| self.generate_expression(c))
                    .unwrap_or_else(|| "".to_string());

                let mut output = format!(
                    "{}for ({}; {}; {}) {{\n",
                    indent, init_str, cond_str, update_str
                );
                self.indent_level += 1;

                for s in body {
                    output.push_str(&self.generate_statement(s));
                    output.push('\n');
                }

                self.indent_level -= 1;
                output.push_str(&format!("{}}}", indent));
                output
            }
            Statement::VariableDeclaration {
                name,
                type_info,
                init,
            } => {
                let type_str = self.type_to_c_string(type_info);
                let name = sanitize_c_identifier(name, "var");
                match init {
                    Some(expr) => format!(
                        "{}{} {} = {};",
                        indent,
                        type_str,
                        name,
                        self.generate_expression(expr)
                    ),
                    None => format!("{}{} {};", indent, type_str, name),
                }
            }
            Statement::Block(statements) => {
                let mut output = format!("{}{{\n", indent);
                self.indent_level += 1;

                for s in statements {
                    output.push_str(&self.generate_statement(s));
                    output.push('\n');
                }

                self.indent_level -= 1;
                output.push_str(&format!("{}}}", indent));
                output
            }
            Statement::Break => {
                format!("{}break;", indent)
            }
            Statement::Continue => {
                format!("{}continue;", indent)
            }
            Statement::Empty => {
                format!("{};", indent)
            }
            Statement::InlineAsm { address, disasm } => {
                // Emit as a C comment so output stays compilable. The address
                // prefix anchors each line back to the original binary for
                // diagnostics and for later structuring passes.
                format!(
                    "{}/* 0x{:X}: {} */",
                    indent,
                    address,
                    sanitize_c_comment(disasm)
                )
            }
        }
    }

    /// Generate C code from an expression
    fn generate_expression(&self, expr: &Expression) -> String {
        match expr {
            Expression::IntegerLiteral(value) => value.to_string(),
            Expression::StringLiteral(s) => quote_c_string(s),
            Expression::Variable(name) => sanitize_c_identifier(name, "var"),
            Expression::BinaryOperation { op, left, right } => {
                let left_str = self.generate_expression(left);
                let right_str = self.generate_expression(right);
                let op_str = self.binary_operator_to_string(*op);
                format!("({} {} {})", left_str, op_str, right_str)
            }
            Expression::UnaryOperation { op, operand } => {
                let operand_str = self.generate_expression(operand);
                let op_str = self.unary_operator_to_string(*op);
                format!("{}{}", op_str, operand_str)
            }
            Expression::FunctionCall {
                function,
                arguments,
            } => {
                let args: Vec<String> = arguments
                    .iter()
                    .map(|a| self.generate_expression(a))
                    .collect();
                format!(
                    "{}({})",
                    sanitize_c_identifier(function, "func"),
                    args.join(", ")
                )
            }
            Expression::Assignment { target, value } => {
                let target_str = self.generate_expression(target);
                let value_str = self.generate_expression(value);
                format!("{} = {}", target_str, value_str)
            }
            Expression::Cast { type_info, value } => {
                let type_str = self.type_to_c_string(type_info);
                let value_str = self.generate_expression(value);
                format!("({}){}", type_str, value_str)
            }
            Expression::AddressOf(expr) => {
                let expr_str = self.generate_expression(expr);
                format!("&{}", expr_str)
            }
            Expression::Dereference(expr) => {
                let expr_str = self.generate_expression(expr);
                format!("*{}", expr_str)
            }
            Expression::ArrayAccess { array, index } => {
                let array_str = self.generate_expression(array);
                let index_str = self.generate_expression(index);
                format!("{}[{}]", array_str, index_str)
            }
            Expression::MemberAccess { object, member } => {
                let object_str = self.generate_expression(object);
                let member = sanitize_c_identifier(member, "field");
                format!("{}.{}", object_str, member)
            }
            Expression::Unknown(s) => s.clone(),
        }
    }

    /// Convert binary operator to C string
    fn binary_operator_to_string(&self, op: BinaryOperator) -> &'static str {
        match op {
            BinaryOperator::Add => "+",
            BinaryOperator::Subtract => "-",
            BinaryOperator::Multiply => "*",
            BinaryOperator::Divide => "/",
            BinaryOperator::Modulo => "%",
            BinaryOperator::Equal => "==",
            BinaryOperator::NotEqual => "!=",
            BinaryOperator::LessThan => "<",
            BinaryOperator::LessThanOrEqual => "<=",
            BinaryOperator::GreaterThan => ">",
            BinaryOperator::GreaterThanOrEqual => ">=",
            BinaryOperator::LogicalAnd => "&&",
            BinaryOperator::LogicalOr => "||",
            BinaryOperator::BitwiseAnd => "&",
            BinaryOperator::BitwiseOr => "|",
            BinaryOperator::BitwiseXor => "^",
            BinaryOperator::LeftShift => "<<",
            BinaryOperator::RightShift => ">>",
        }
    }

    /// Convert unary operator to C string
    fn unary_operator_to_string(&self, op: UnaryOperator) -> &'static str {
        match op {
            UnaryOperator::Negate => "-",
            UnaryOperator::LogicalNot => "!",
            UnaryOperator::BitwiseNot => "~",
            UnaryOperator::Address => "&",
            UnaryOperator::Dereference => "*",
        }
    }

    /// Convert type info to C string
    fn type_to_c_string(&self, type_info: &TypeInfo) -> String {
        type_info.to_c_type().to_string()
    }
}

impl Default for CGenerator {
    fn default() -> Self {
        Self::new(CGeneratorConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analysis::TypeInfo;
    use crate::decompiler::ast::{Function, Parameter, Statement};

    fn gen() -> CGenerator {
        CGenerator::default()
    }

    fn func(name: &str, body: Vec<Statement>) -> Function {
        Function {
            name: name.to_string(),
            return_type: TypeInfo::Void,
            parameters: vec![],
            body,
            is_variadic: false,
        }
    }

    // ---- signatures ----

    #[test]
    fn empty_parameter_list_emits_void_in_signature() {
        let mut g = gen();
        let out = g.generate_function(&func("sub_1000", vec![]));
        assert!(out.starts_with("void sub_1000(void) {"), "got: {out}");
    }

    #[test]
    fn parameters_render_with_types_and_sanitized_names() {
        let mut g = gen();
        let f = Function {
            name: "do_thing".to_string(),
            return_type: TypeInfo::I32,
            parameters: vec![
                Parameter {
                    name: "size".to_string(),
                    type_info: TypeInfo::U64,
                },
                Parameter {
                    // Reserved C keyword must be suffixed by sanitize_c_identifier.
                    name: "return".to_string(),
                    type_info: TypeInfo::I32,
                },
            ],
            body: vec![Statement::Return(Some(Expression::IntegerLiteral(0)))],
            is_variadic: false,
        };
        let out = g.generate_function(&f);
        let first_line = out.lines().next().unwrap();
        assert_eq!(first_line, "int32_t do_thing(uint64_t size, int32_t return_) {");
    }

    #[test]
    fn function_name_is_sanitized_to_valid_c_identifier() {
        let mut g = gen();
        // Dots are illegal in C identifiers; sanitizer collapses them to `_`.
        let out = g.generate_function(&func("kernel32.dll!CreateFileW", vec![]));
        assert!(out.starts_with("void kernel32_dll_CreateFileW(void) {"), "got: {out}");
    }

    // ---- statements ----

    #[test]
    fn return_none_renders_as_bare_return() {
        let mut g = gen();
        let out = g.generate_function(&func("f", vec![Statement::Return(None)]));
        assert!(out.contains("    return;"), "got: {out}");
    }

    #[test]
    fn return_with_value_renders_expression() {
        let mut g = gen();
        let out = g.generate_function(&func(
            "f",
            vec![Statement::Return(Some(Expression::IntegerLiteral(42)))],
        ));
        assert!(out.contains("    return 42;"), "got: {out}");
    }

    #[test]
    fn variable_declaration_with_and_without_init() {
        let mut g = gen();
        let out = g.generate_function(&func(
            "f",
            vec![
                Statement::VariableDeclaration {
                    name: "rax".to_string(),
                    type_info: TypeInfo::U64,
                    init: None,
                },
                Statement::VariableDeclaration {
                    name: "rcx".to_string(),
                    type_info: TypeInfo::U64,
                    init: Some(Expression::IntegerLiteral(0)),
                },
            ],
        ));
        assert!(out.contains("    uint64_t rax;"), "got: {out}");
        assert!(out.contains("    uint64_t rcx = 0;"), "got: {out}");
    }

    #[test]
    fn if_else_indents_nested_blocks_with_four_spaces() {
        let mut g = gen();
        let body = vec![Statement::If {
            condition: Expression::Variable("rax".to_string()),
            then_block: vec![Statement::Return(Some(Expression::IntegerLiteral(1)))],
            else_block: Some(vec![Statement::Return(Some(Expression::IntegerLiteral(0)))]),
        }];
        let out = g.generate_function(&func("f", body));
        assert!(out.contains("    if (rax) {\n"), "got: {out}");
        assert!(out.contains("        return 1;"), "then indented 8 spaces, got: {out}");
        assert!(out.contains("    } else {"), "else line matches outer indent, got: {out}");
        assert!(out.contains("        return 0;"), "else body indented 8 spaces, got: {out}");
    }

    #[test]
    fn inline_asm_becomes_address_prefixed_c_comment_with_sanitized_terminator() {
        let mut g = gen();
        // `*/` inside a /* ... */ comment would terminate it early; sanitize_c_comment
        // must split it into `* /`.
        let out = g.generate_function(&func(
            "f",
            vec![Statement::InlineAsm {
                address: 0x401000,
                disasm: "mov rax, qword ptr [rip+*/oops]".to_string(),
            }],
        ));
        assert!(
            out.contains("    /* 0x401000: mov rax, qword ptr [rip+* /oops] */"),
            "got: {out}"
        );
        assert!(
            !out.contains("*/oops"),
            "comment terminator must be split: {out}"
        );
    }

    #[test]
    fn block_statement_emits_braces_and_indents_body() {
        let mut g = gen();
        let body = vec![Statement::Block(vec![Statement::Return(None)])];
        let out = g.generate_function(&func("f", body));
        assert!(out.contains("    {\n"), "got: {out}");
        assert!(out.contains("        return;"), "got: {out}");
    }

    #[test]
    fn break_continue_render_as_keywords() {
        let mut g = gen();
        let out = g.generate_function(&func(
            "f",
            vec![Statement::Break, Statement::Continue],
        ));
        assert!(out.contains("    break;"));
        assert!(out.contains("    continue;"));
    }

    // ---- expressions ----

    fn render_expression(expr: Expression) -> String {
        let mut g = gen();
        let out = g.generate_function(&func("f", vec![Statement::Expression(expr)]));
        // Body line for an expression statement is `    <expr>;` — extract it.
        out.lines()
            .find(|l| l.starts_with("    ") && !l.starts_with("    /*"))
            .unwrap_or("")
            .trim()
            .trim_end_matches(';')
            .to_string()
    }

    #[test]
    fn binary_operation_is_fully_parenthesized() {
        let expr = Expression::BinaryOperation {
            op: BinaryOperator::Add,
            left: Box::new(Expression::IntegerLiteral(1)),
            right: Box::new(Expression::BinaryOperation {
                op: BinaryOperator::Multiply,
                left: Box::new(Expression::IntegerLiteral(2)),
                right: Box::new(Expression::IntegerLiteral(3)),
            }),
        };
        assert_eq!(render_expression(expr), "(1 + (2 * 3))");
    }

    #[test]
    fn unary_negate_emits_minus_prefix_without_space() {
        let expr = Expression::UnaryOperation {
            op: UnaryOperator::Negate,
            operand: Box::new(Expression::IntegerLiteral(5)),
        };
        assert_eq!(render_expression(expr), "-5");
    }

    #[test]
    fn cast_renders_in_c_parenthesized_form() {
        let expr = Expression::Cast {
            type_info: TypeInfo::I32,
            value: Box::new(Expression::Variable("x".to_string())),
        };
        assert_eq!(render_expression(expr), "(int32_t)x");
    }

    #[test]
    fn function_call_sanitizes_name_and_joins_arguments_with_comma_space() {
        let expr = Expression::FunctionCall {
            function: "kernel32.dll!CreateFileW".to_string(),
            arguments: vec![
                Expression::Variable("path".to_string()),
                Expression::IntegerLiteral(0),
                Expression::IntegerLiteral(1),
            ],
        };
        assert_eq!(
            render_expression(expr),
            "kernel32_dll_CreateFileW(path, 0, 1)"
        );
    }

    #[test]
    fn string_literal_is_escaped_and_double_quoted() {
        let expr = Expression::StringLiteral("hi\nthere".to_string());
        assert_eq!(render_expression(expr), "\"hi\\nthere\"");
    }

    #[test]
    fn array_access_and_dereference_render_with_pointer_syntax() {
        let arr = Expression::ArrayAccess {
            array: Box::new(Expression::Variable("buf".to_string())),
            index: Box::new(Expression::IntegerLiteral(7)),
        };
        let deref = Expression::Dereference(Box::new(Expression::Variable("p".to_string())));

        assert_eq!(render_expression(arr), "buf[7]");
        assert_eq!(render_expression(deref), "*p");
    }

    #[test]
    fn variable_keyword_collisions_get_suffixed() {
        // A pseudo-variable accidentally named after a C keyword must not leak
        // into the output verbatim; sanitize_c_identifier appends `_`.
        let expr = Expression::Variable("return".to_string());
        assert_eq!(render_expression(expr), "return_");
    }
}
