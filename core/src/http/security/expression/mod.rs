//! Security Expression Language (SpEL-like) for authorization.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.access.expression`
//!
//! # Overview
//! This module provides a Spring Security-like expression language for
//! defining complex authorization rules.
//!
//! # Supported Expressions
//!
//! ## Built-in Functions
//! - `hasRole('ROLE')` - Check if user has the specified role
//! - `hasAnyRole('ROLE1', 'ROLE2')` - Check if user has any of the roles
//! - `hasAuthority('AUTH')` - Check if user has the specified authority
//! - `hasAnyAuthority('AUTH1', 'AUTH2')` - Check if user has any authority
//! - `isAuthenticated()` - Check if user is authenticated
//! - `permitAll()` - Always returns true
//! - `denyAll()` - Always returns false
//!
//! ## Operators
//! - `AND` / `and` / `&&` - Logical AND
//! - `OR` / `or` / `||` - Logical OR
//! - `NOT` / `not` / `!` - Logical NOT
//! - `(` `)` - Grouping
//!
//! # Examples
//! ```ignore
//! use actix_security_core::http::security::expression::SecurityExpression;
//!
//! let expr = SecurityExpression::parse("hasRole('ADMIN') OR hasAuthority('users:write')")?;
//! let result = expr.evaluate(&user);
//! ```
//!
//! # Extensibility
//! Custom expressions can be added by implementing the `ExpressionRoot` trait:
//!
//! ```ignore
//! use actix_security_core::http::security::expression::{ExpressionRoot, DefaultExpressionRoot};
//! use actix_security_core::http::security::User;
//!
//! struct CustomExpressionRoot {
//!     default: DefaultExpressionRoot,
//! }
//!
//! impl ExpressionRoot for CustomExpressionRoot {
//!     fn evaluate_function(&self, name: &str, args: &[String], user: Option<&User>) -> Option<bool> {
//!         match name {
//!             "isAdmin" => Some(user.map_or(false, |u| u.has_role("ADMIN"))),
//!             "hasIpAddress" => {
//!                 // Custom IP check logic
//!                 Some(true)
//!             }
//!             _ => self.default.evaluate_function(name, args, user),
//!         }
//!     }
//! }
//! ```

mod ast;
mod evaluator;
mod parser;
mod root;

pub use ast::{BinaryOp, Expression, UnaryOp};
pub use evaluator::ExpressionEvaluator;
pub use parser::{ParseError, SecurityExpression};
pub use root::{DefaultExpressionRoot, ExpressionRoot};

#[cfg(test)]
mod tests;
