//! Expression root trait for extensible security expressions.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.access.expression.SecurityExpressionRoot`

use crate::http::security::User;

/// Trait for evaluating security expression functions.
///
/// # Spring Security Equivalent
/// `SecurityExpressionRoot` + `MethodSecurityExpressionOperations`
///
/// Implement this trait to add custom security expressions.
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::expression::{ExpressionRoot, DefaultExpressionRoot};
/// use actix_security_core::http::security::User;
///
/// struct CustomExpressionRoot {
///     default: DefaultExpressionRoot,
///     allowed_departments: Vec<String>,
/// }
///
/// impl ExpressionRoot for CustomExpressionRoot {
///     fn evaluate_function(&self, name: &str, args: &[String], user: Option<&User>) -> Option<bool> {
///         match name {
///             "inDepartment" => {
///                 let dept = args.first()?;
///                 Some(self.allowed_departments.contains(dept))
///             }
///             _ => self.default.evaluate_function(name, args, user),
///         }
///     }
/// }
/// ```
pub trait ExpressionRoot: Send + Sync {
    /// Evaluates a function expression.
    ///
    /// # Arguments
    /// * `name` - The function name (e.g., "hasRole", "hasAuthority")
    /// * `args` - The function arguments (e.g., ["ADMIN"])
    /// * `user` - The authenticated user, if any
    ///
    /// # Returns
    /// * `Some(true)` - Function evaluated to true
    /// * `Some(false)` - Function evaluated to false
    /// * `None` - Unknown function (will result in an error)
    fn evaluate_function(&self, name: &str, args: &[String], user: Option<&User>) -> Option<bool>;
}

/// Default implementation of security expression functions.
///
/// # Spring Security Equivalent
/// `SecurityExpressionRoot`
///
/// Provides the standard Spring Security-like functions:
/// - `hasRole(role)` - Check single role
/// - `hasAnyRole(role1, role2, ...)` - Check any of multiple roles
/// - `hasAuthority(authority)` - Check single authority
/// - `hasAnyAuthority(auth1, auth2, ...)` - Check any of multiple authorities
/// - `isAuthenticated()` - Check if authenticated
/// - `isAnonymous()` - Check if anonymous (not authenticated)
/// - `permitAll()` - Always true
/// - `denyAll()` - Always false
#[derive(Debug, Clone, Default)]
pub struct DefaultExpressionRoot;

impl DefaultExpressionRoot {
    /// Creates a new default expression root.
    pub fn new() -> Self {
        DefaultExpressionRoot
    }
}

impl ExpressionRoot for DefaultExpressionRoot {
    fn evaluate_function(&self, name: &str, args: &[String], user: Option<&User>) -> Option<bool> {
        match name {
            // Role-based functions
            "hasRole" => {
                let role = args.first()?;
                Some(user.is_some_and(|u| u.has_role(role)))
            }
            "hasAnyRole" => {
                if args.is_empty() {
                    return Some(false);
                }
                Some(user.is_some_and(|u| {
                    args.iter().any(|role| u.has_role(role))
                }))
            }

            // Authority-based functions
            "hasAuthority" => {
                let authority = args.first()?;
                Some(user.is_some_and(|u| u.has_authority(authority)))
            }
            "hasAnyAuthority" => {
                if args.is_empty() {
                    return Some(false);
                }
                Some(user.is_some_and(|u| {
                    args.iter().any(|auth| u.has_authority(auth))
                }))
            }

            // Authentication state functions
            "isAuthenticated" => Some(user.is_some()),
            "isAnonymous" => Some(user.is_none()),

            // Permission functions
            "permitAll" => Some(true),
            "denyAll" => Some(false),

            // Unknown function
            _ => None,
        }
    }
}
