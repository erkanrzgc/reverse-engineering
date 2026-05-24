//! Abstract Syntax Tree for decompiled code

use crate::analysis::TypeInfo;

/// AST node type
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AstNodeType {
    /// Function
    Function,
    /// Statement
    Statement,
    /// Expression
    Expression,
    /// Variable declaration
    VariableDeclaration,
    /// Type declaration
    TypeDeclaration,
}

/// Expression
#[derive(Debug, Clone)]
pub enum Expression {
    /// Integer literal
    IntegerLiteral(i64),
    /// String literal
    StringLiteral(String),
    /// Variable reference
    Variable(String),
    /// Binary operation
    BinaryOperation {
        op: BinaryOperator,
        left: Box<Expression>,
        right: Box<Expression>,
    },
    /// Unary operation
    UnaryOperation {
        op: UnaryOperator,
        operand: Box<Expression>,
    },
    /// Function call
    FunctionCall {
        function: String,
        arguments: Vec<Expression>,
    },
    /// Assignment
    Assignment {
        target: Box<Expression>,
        value: Box<Expression>,
    },
    /// Cast
    Cast {
        type_info: TypeInfo,
        value: Box<Expression>,
    },
    /// Address of
    AddressOf(Box<Expression>),
    /// Dereference
    Dereference(Box<Expression>),
    /// Array access
    ArrayAccess {
        array: Box<Expression>,
        index: Box<Expression>,
    },
    /// Member access
    MemberAccess {
        object: Box<Expression>,
        member: String,
    },
    /// Unknown
    Unknown(String),
}

/// Binary operator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BinaryOperator {
    Add,
    Subtract,
    Multiply,
    Divide,
    Modulo,
    Equal,
    NotEqual,
    LessThan,
    LessThanOrEqual,
    GreaterThan,
    GreaterThanOrEqual,
    LogicalAnd,
    LogicalOr,
    BitwiseAnd,
    BitwiseOr,
    BitwiseXor,
    LeftShift,
    RightShift,
}

/// Unary operator
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnaryOperator {
    Negate,
    LogicalNot,
    BitwiseNot,
    Address,
    Dereference,
}

/// Statement
#[derive(Debug, Clone)]
pub enum Statement {
    /// Expression statement
    Expression(Expression),
    /// Return statement
    Return(Option<Expression>),
    /// If statement
    If {
        condition: Expression,
        then_block: Vec<Statement>,
        else_block: Option<Vec<Statement>>,
    },
    /// While loop
    While {
        condition: Expression,
        body: Vec<Statement>,
    },
    /// For loop
    For {
        init: Option<Box<Statement>>,
        condition: Option<Expression>,
        update: Option<Expression>,
        body: Vec<Statement>,
    },
    /// Variable declaration
    VariableDeclaration {
        name: String,
        type_info: TypeInfo,
        init: Option<Expression>,
    },
    /// Block
    Block(Vec<Statement>),
    /// Break
    Break,
    /// Continue
    Continue,
    /// Empty
    Empty,
    /// Raw disassembly placeholder. Every AST node stays addressable so later
    /// structuring passes can correlate back to the original instruction.
    InlineAsm { address: u64, disasm: String },
}

/// Function
#[derive(Debug, Clone)]
pub struct Function {
    pub name: String,
    pub return_type: TypeInfo,
    pub parameters: Vec<Parameter>,
    pub body: Vec<Statement>,
    pub is_variadic: bool,
}

/// Function parameter
#[derive(Debug, Clone)]
pub struct Parameter {
    pub name: String,
    pub type_info: TypeInfo,
}

/// AST node
#[derive(Debug, Clone)]
pub struct AstNode {
    pub node_type: AstNodeType,
    pub expression: Option<Expression>,
    pub statement: Option<Statement>,
    pub function: Option<Function>,
}

impl AstNode {
    /// Create a new AST node from an expression
    pub fn from_expression(expr: Expression) -> Self {
        Self {
            node_type: AstNodeType::Expression,
            expression: Some(expr),
            statement: None,
            function: None,
        }
    }

    /// Create a new AST node from a statement
    pub fn from_statement(stmt: Statement) -> Self {
        Self {
            node_type: AstNodeType::Statement,
            expression: None,
            statement: Some(stmt),
            function: None,
        }
    }

    /// Create a new AST node from a function
    pub fn from_function(func: Function) -> Self {
        Self {
            node_type: AstNodeType::Function,
            expression: None,
            statement: None,
            function: Some(func),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_function() -> Function {
        Function {
            name: "f".to_string(),
            return_type: TypeInfo::Void,
            parameters: vec![],
            body: vec![],
            is_variadic: false,
        }
    }

    #[test]
    fn from_expression_tags_node_type_and_only_populates_expression_slot() {
        let node = AstNode::from_expression(Expression::IntegerLiteral(7));
        assert_eq!(node.node_type, AstNodeType::Expression);
        assert!(matches!(node.expression, Some(Expression::IntegerLiteral(7))));
        assert!(node.statement.is_none());
        assert!(node.function.is_none());
    }

    #[test]
    fn from_statement_tags_node_type_and_only_populates_statement_slot() {
        let node = AstNode::from_statement(Statement::Return(None));
        assert_eq!(node.node_type, AstNodeType::Statement);
        assert!(matches!(node.statement, Some(Statement::Return(None))));
        assert!(node.expression.is_none());
        assert!(node.function.is_none());
    }

    #[test]
    fn from_function_tags_node_type_and_only_populates_function_slot() {
        let node = AstNode::from_function(empty_function());
        assert_eq!(node.node_type, AstNodeType::Function);
        assert!(node.function.is_some());
        assert!(node.expression.is_none());
        assert!(node.statement.is_none());
    }

    #[test]
    fn ast_node_type_equality_distinguishes_variants() {
        // The discriminator must be reliable — passes downstream use it to
        // dispatch without inspecting the optional payloads.
        assert_eq!(AstNodeType::Function, AstNodeType::Function);
        assert_ne!(AstNodeType::Expression, AstNodeType::Statement);
        assert_ne!(AstNodeType::VariableDeclaration, AstNodeType::TypeDeclaration);
    }

    #[test]
    fn operator_enums_compare_by_variant() {
        assert_eq!(BinaryOperator::Add, BinaryOperator::Add);
        assert_ne!(BinaryOperator::Add, BinaryOperator::Subtract);
        assert_eq!(UnaryOperator::Negate, UnaryOperator::Negate);
        assert_ne!(UnaryOperator::Negate, UnaryOperator::BitwiseNot);
    }

    #[test]
    fn function_struct_supports_clone_and_preserves_signature_fields() {
        let mut original = empty_function();
        original.name = "sub_4010".to_string();
        original.return_type = TypeInfo::U32;
        original.parameters.push(Parameter {
            name: "arg1".to_string(),
            type_info: TypeInfo::U64,
        });
        original.is_variadic = true;

        let cloned = original.clone();
        assert_eq!(cloned.name, "sub_4010");
        assert_eq!(cloned.return_type, TypeInfo::U32);
        assert_eq!(cloned.parameters.len(), 1);
        assert_eq!(cloned.parameters[0].name, "arg1");
        assert!(cloned.is_variadic);
    }
}
