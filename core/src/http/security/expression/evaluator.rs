//! Expression evaluator.
//!
//! Evaluates a security expression AST against a user.

use std::sync::Arc;

use super::ast::{BinaryOp, Expression, UnaryOp};
use super::root::{DefaultExpressionRoot, ExpressionRoot};
use super::ParseError;
use crate::http::security::User;

/// Error type for expression evaluation.
#[derive(Debug, Clone)]
pub enum EvaluationError {
    /// Unknown function in the expression
    UnknownFunction(String),
}

impl std::fmt::Display for EvaluationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvaluationError::UnknownFunction(name) => {
                write!(f, "unknown function: '{}'", name)
            }
        }
    }
}

impl std::error::Error for EvaluationError {}

/// Evaluates security expressions against a user.
///
/// # Spring Security Equivalent
/// `MethodSecurityExpressionHandler`
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::expression::{
///     ExpressionEvaluator, SecurityExpression, DefaultExpressionRoot
/// };
///
/// let evaluator = ExpressionEvaluator::new();
/// let expr = SecurityExpression::parse("hasRole('ADMIN')")?;
/// let result = evaluator.evaluate(expr.ast(), Some(&user))?;
/// ```
pub struct ExpressionEvaluator {
    root: Arc<dyn ExpressionRoot>,
}

impl ExpressionEvaluator {
    /// Creates a new evaluator with the default expression root.
    pub fn new() -> Self {
        ExpressionEvaluator {
            root: Arc::new(DefaultExpressionRoot::new()),
        }
    }

    /// Creates a new evaluator with a custom expression root.
    ///
    /// # Example
    /// ```ignore
    /// let custom_root = MyCustomExpressionRoot::new();
    /// let evaluator = ExpressionEvaluator::with_root(custom_root);
    /// ```
    pub fn with_root<R: ExpressionRoot + 'static>(root: R) -> Self {
        ExpressionEvaluator {
            root: Arc::new(root),
        }
    }

    /// Evaluates an expression against a user.
    ///
    /// # Arguments
    /// * `expr` - The expression AST to evaluate
    /// * `user` - The authenticated user, if any
    ///
    /// # Returns
    /// * `Ok(true)` - Access granted
    /// * `Ok(false)` - Access denied
    /// * `Err(EvaluationError)` - Evaluation failed (unknown function, etc.)
    pub fn evaluate(
        &self,
        expr: &Expression,
        user: Option<&User>,
    ) -> Result<bool, EvaluationError> {
        match expr {
            Expression::Boolean(value) => Ok(*value),

            Expression::Function { name, args } => {
                self.root
                    .evaluate_function(name, args, user)
                    .ok_or_else(|| EvaluationError::UnknownFunction(name.clone()))
            }

            Expression::Binary { left, op, right } => {
                let left_result = self.evaluate(left, user)?;

                match op {
                    BinaryOp::And => {
                        // Short-circuit: if left is false, don't evaluate right
                        if !left_result {
                            return Ok(false);
                        }
                        self.evaluate(right, user)
                    }
                    BinaryOp::Or => {
                        // Short-circuit: if left is true, don't evaluate right
                        if left_result {
                            return Ok(true);
                        }
                        self.evaluate(right, user)
                    }
                }
            }

            Expression::Unary { op, expr } => {
                let result = self.evaluate(expr, user)?;
                match op {
                    UnaryOp::Not => Ok(!result),
                }
            }

            Expression::Group(inner) => self.evaluate(inner, user),
        }
    }

    /// Parses and evaluates an expression string.
    ///
    /// Convenience method that combines parsing and evaluation.
    ///
    /// # Arguments
    /// * `expr` - The expression string
    /// * `user` - The authenticated user, if any
    ///
    /// # Returns
    /// * `Ok(true)` - Access granted
    /// * `Ok(false)` - Access denied
    /// * `Err` - Parse or evaluation error
    pub fn evaluate_str(
        &self,
        expr: &str,
        user: Option<&User>,
    ) -> Result<bool, ExpressionError> {
        let parsed = super::SecurityExpression::parse(expr)?;
        self.evaluate(parsed.ast(), user)
            .map_err(ExpressionError::Evaluation)
    }
}

impl Default for ExpressionEvaluator {
    fn default() -> Self {
        Self::new()
    }
}

impl Clone for ExpressionEvaluator {
    fn clone(&self) -> Self {
        ExpressionEvaluator {
            root: Arc::clone(&self.root),
        }
    }
}

/// Combined error type for parsing and evaluation.
#[derive(Debug)]
pub enum ExpressionError {
    /// Parse error
    Parse(ParseError),
    /// Evaluation error
    Evaluation(EvaluationError),
}

impl std::fmt::Display for ExpressionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ExpressionError::Parse(e) => write!(f, "parse error: {}", e),
            ExpressionError::Evaluation(e) => write!(f, "evaluation error: {}", e),
        }
    }
}

impl std::error::Error for ExpressionError {}

impl From<ParseError> for ExpressionError {
    fn from(err: ParseError) -> Self {
        ExpressionError::Parse(err)
    }
}

impl From<EvaluationError> for ExpressionError {
    fn from(err: EvaluationError) -> Self {
        ExpressionError::Evaluation(err)
    }
}
