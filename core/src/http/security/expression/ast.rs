//! Abstract Syntax Tree for security expressions.

/// Binary operators for combining expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BinaryOp {
    /// Logical AND (both must be true)
    And,
    /// Logical OR (at least one must be true)
    Or,
}

/// Unary operators for modifying expressions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnaryOp {
    /// Logical NOT (inverts the result)
    Not,
}

/// A security expression AST node.
#[derive(Debug, Clone, PartialEq)]
pub enum Expression {
    /// A boolean literal (true/false)
    Boolean(bool),

    /// A function call with name and arguments
    /// e.g., `hasRole('ADMIN')` -> Function("hasRole", vec!["ADMIN"])
    Function { name: String, args: Vec<String> },

    /// A binary operation combining two expressions
    /// e.g., `hasRole('ADMIN') AND hasRole('USER')`
    Binary {
        left: Box<Expression>,
        op: BinaryOp,
        right: Box<Expression>,
    },

    /// A unary operation on an expression
    /// e.g., `NOT hasRole('ADMIN')`
    Unary { op: UnaryOp, expr: Box<Expression> },

    /// A grouped expression (parentheses)
    /// e.g., `(hasRole('ADMIN') OR hasRole('USER'))`
    Group(Box<Expression>),
}

impl Expression {
    /// Creates a new function expression.
    pub fn function(name: impl Into<String>, args: Vec<String>) -> Self {
        Expression::Function {
            name: name.into(),
            args,
        }
    }

    /// Creates a new AND expression.
    pub fn and(left: Expression, right: Expression) -> Self {
        Expression::Binary {
            left: Box::new(left),
            op: BinaryOp::And,
            right: Box::new(right),
        }
    }

    /// Creates a new OR expression.
    pub fn or(left: Expression, right: Expression) -> Self {
        Expression::Binary {
            left: Box::new(left),
            op: BinaryOp::Or,
            right: Box::new(right),
        }
    }

    /// Creates a new NOT expression.
    #[allow(clippy::should_implement_trait)]
    pub fn not(expr: Expression) -> Self {
        Expression::Unary {
            op: UnaryOp::Not,
            expr: Box::new(expr),
        }
    }

    /// Creates a grouped expression.
    pub fn group(expr: Expression) -> Self {
        Expression::Group(Box::new(expr))
    }
}
