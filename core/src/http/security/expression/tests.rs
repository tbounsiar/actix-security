//! Unit tests for the expression module.

use super::*;
use crate::http::security::User;

// =============================================================================
// Parser Tests
// =============================================================================

#[test]
fn test_parse_simple_function() {
    let expr = SecurityExpression::parse("hasRole('ADMIN')").unwrap();
    match expr.ast() {
        Expression::Function { name, args } => {
            assert_eq!(name, "hasRole");
            assert_eq!(args, &["ADMIN"]);
        }
        _ => panic!("Expected function expression"),
    }
}

#[test]
fn test_parse_function_with_multiple_args() {
    let expr = SecurityExpression::parse("hasAnyRole('ADMIN', 'USER', 'MANAGER')").unwrap();
    match expr.ast() {
        Expression::Function { name, args } => {
            assert_eq!(name, "hasAnyRole");
            assert_eq!(args, &["ADMIN", "USER", "MANAGER"]);
        }
        _ => panic!("Expected function expression"),
    }
}

#[test]
fn test_parse_function_no_args() {
    let expr = SecurityExpression::parse("isAuthenticated()").unwrap();
    match expr.ast() {
        Expression::Function { name, args } => {
            assert_eq!(name, "isAuthenticated");
            assert!(args.is_empty());
        }
        _ => panic!("Expected function expression"),
    }
}

#[test]
fn test_parse_and_expression() {
    let expr = SecurityExpression::parse("hasRole('ADMIN') AND hasAuthority('write')").unwrap();
    match expr.ast() {
        Expression::Binary { left, op, right } => {
            assert_eq!(*op, BinaryOp::And);
            assert!(matches!(left.as_ref(), Expression::Function { name, .. } if name == "hasRole"));
            assert!(
                matches!(right.as_ref(), Expression::Function { name, .. } if name == "hasAuthority")
            );
        }
        _ => panic!("Expected binary expression"),
    }
}

#[test]
fn test_parse_or_expression() {
    let expr = SecurityExpression::parse("hasRole('ADMIN') OR hasRole('MANAGER')").unwrap();
    match expr.ast() {
        Expression::Binary { left, op, right } => {
            assert_eq!(*op, BinaryOp::Or);
            assert!(matches!(left.as_ref(), Expression::Function { .. }));
            assert!(matches!(right.as_ref(), Expression::Function { .. }));
        }
        _ => panic!("Expected binary expression"),
    }
}

#[test]
fn test_parse_not_expression() {
    let expr = SecurityExpression::parse("NOT hasRole('GUEST')").unwrap();
    match expr.ast() {
        Expression::Unary { op, expr } => {
            assert_eq!(*op, UnaryOp::Not);
            assert!(matches!(expr.as_ref(), Expression::Function { name, .. } if name == "hasRole"));
        }
        _ => panic!("Expected unary expression"),
    }
}

#[test]
fn test_parse_grouped_expression() {
    let expr =
        SecurityExpression::parse("(hasRole('ADMIN') OR hasRole('USER')) AND isAuthenticated()")
            .unwrap();
    match expr.ast() {
        Expression::Binary { left, op, right } => {
            assert_eq!(*op, BinaryOp::And);
            assert!(matches!(left.as_ref(), Expression::Group(_)));
            assert!(
                matches!(right.as_ref(), Expression::Function { name, .. } if name == "isAuthenticated")
            );
        }
        _ => panic!("Expected binary expression"),
    }
}

#[test]
fn test_parse_complex_expression() {
    let expr = SecurityExpression::parse(
        "hasRole('ADMIN') OR (hasRole('USER') AND hasAuthority('users:write'))",
    )
    .unwrap();

    // Should parse as: ADMIN OR (USER AND write)
    match expr.ast() {
        Expression::Binary { op, .. } => {
            assert_eq!(*op, BinaryOp::Or);
        }
        _ => panic!("Expected OR at top level"),
    }
}

#[test]
fn test_parse_operator_precedence() {
    // AND has higher precedence than OR
    // "A OR B AND C" should parse as "A OR (B AND C)"
    let expr = SecurityExpression::parse(
        "hasRole('A') OR hasRole('B') AND hasRole('C')",
    )
    .unwrap();

    match expr.ast() {
        Expression::Binary { left, op, right } => {
            assert_eq!(*op, BinaryOp::Or);
            // Left should be just hasRole('A')
            assert!(matches!(left.as_ref(), Expression::Function { name, .. } if name == "hasRole"));
            // Right should be (B AND C)
            assert!(matches!(right.as_ref(), Expression::Binary { op: BinaryOp::And, .. }));
        }
        _ => panic!("Expected OR at top level"),
    }
}

#[test]
fn test_parse_symbol_operators() {
    // Test && and || operators
    let expr = SecurityExpression::parse("hasRole('ADMIN') && hasRole('USER')").unwrap();
    assert!(matches!(expr.ast(), Expression::Binary { op: BinaryOp::And, .. }));

    let expr = SecurityExpression::parse("hasRole('ADMIN') || hasRole('USER')").unwrap();
    assert!(matches!(expr.ast(), Expression::Binary { op: BinaryOp::Or, .. }));
}

#[test]
fn test_parse_not_symbol() {
    let expr = SecurityExpression::parse("!hasRole('GUEST')").unwrap();
    assert!(matches!(expr.ast(), Expression::Unary { op: UnaryOp::Not, .. }));
}

#[test]
fn test_parse_boolean_literals() {
    let expr = SecurityExpression::parse("true").unwrap();
    assert!(matches!(expr.ast(), Expression::Boolean(true)));

    let expr = SecurityExpression::parse("false").unwrap();
    assert!(matches!(expr.ast(), Expression::Boolean(false)));
}

#[test]
fn test_parse_double_quoted_strings() {
    let expr = SecurityExpression::parse("hasRole(\"ADMIN\")").unwrap();
    match expr.ast() {
        Expression::Function { args, .. } => {
            assert_eq!(args, &["ADMIN"]);
        }
        _ => panic!("Expected function"),
    }
}

#[test]
fn test_parse_error_unclosed_paren() {
    let result = SecurityExpression::parse("hasRole('ADMIN'");
    assert!(matches!(result, Err(ParseError::UnclosedParen)));
}

#[test]
fn test_parse_error_unclosed_string() {
    let result = SecurityExpression::parse("hasRole('ADMIN)");
    assert!(matches!(result, Err(ParseError::UnclosedString)));
}

#[test]
fn test_parse_error_empty_expression() {
    let result = SecurityExpression::parse("");
    assert!(matches!(result, Err(ParseError::EmptyExpression)));
}

// =============================================================================
// Evaluator Tests
// =============================================================================

fn create_admin_user() -> User {
    User::new("admin".to_string(), "password".to_string())
        .roles(&["ADMIN".to_string(), "USER".to_string()])
        .authorities(&["users:read".to_string(), "users:write".to_string()])
}

fn create_user() -> User {
    User::new("user".to_string(), "password".to_string())
        .roles(&["USER".to_string()])
        .authorities(&["users:read".to_string()])
}

fn create_guest() -> User {
    User::new("guest".to_string(), "password".to_string())
        .roles(&["GUEST".to_string()])
}

#[test]
fn test_evaluate_has_role_success() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_admin_user();

    let result = evaluator
        .evaluate_str("hasRole('ADMIN')", Some(&user))
        .unwrap();
    assert!(result);
}

#[test]
fn test_evaluate_has_role_failure() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_user();

    let result = evaluator
        .evaluate_str("hasRole('ADMIN')", Some(&user))
        .unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_has_any_role_success() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_user();

    let result = evaluator
        .evaluate_str("hasAnyRole('ADMIN', 'USER')", Some(&user))
        .unwrap();
    assert!(result);
}

#[test]
fn test_evaluate_has_any_role_failure() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_guest();

    let result = evaluator
        .evaluate_str("hasAnyRole('ADMIN', 'USER')", Some(&user))
        .unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_has_authority_success() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_admin_user();

    let result = evaluator
        .evaluate_str("hasAuthority('users:write')", Some(&user))
        .unwrap();
    assert!(result);
}

#[test]
fn test_evaluate_has_authority_failure() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_user();

    let result = evaluator
        .evaluate_str("hasAuthority('users:write')", Some(&user))
        .unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_is_authenticated() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_user();

    let result = evaluator
        .evaluate_str("isAuthenticated()", Some(&user))
        .unwrap();
    assert!(result);

    let result = evaluator.evaluate_str("isAuthenticated()", None).unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_is_anonymous() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_user();

    let result = evaluator
        .evaluate_str("isAnonymous()", Some(&user))
        .unwrap();
    assert!(!result);

    let result = evaluator.evaluate_str("isAnonymous()", None).unwrap();
    assert!(result);
}

#[test]
fn test_evaluate_permit_all() {
    let evaluator = ExpressionEvaluator::new();

    let result = evaluator.evaluate_str("permitAll()", None).unwrap();
    assert!(result);
}

#[test]
fn test_evaluate_deny_all() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_admin_user();

    let result = evaluator
        .evaluate_str("denyAll()", Some(&user))
        .unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_and_expression() {
    let evaluator = ExpressionEvaluator::new();
    let admin = create_admin_user();
    let user = create_user();

    // Admin has both ADMIN role and write authority
    let result = evaluator
        .evaluate_str("hasRole('ADMIN') AND hasAuthority('users:write')", Some(&admin))
        .unwrap();
    assert!(result);

    // User has USER role but not write authority
    let result = evaluator
        .evaluate_str("hasRole('USER') AND hasAuthority('users:write')", Some(&user))
        .unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_or_expression() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_user();

    // User doesn't have ADMIN but has users:read
    let result = evaluator
        .evaluate_str("hasRole('ADMIN') OR hasAuthority('users:read')", Some(&user))
        .unwrap();
    assert!(result);
}

#[test]
fn test_evaluate_not_expression() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_user();

    // User is not ADMIN
    let result = evaluator
        .evaluate_str("NOT hasRole('ADMIN')", Some(&user))
        .unwrap();
    assert!(result);

    // User is USER
    let result = evaluator
        .evaluate_str("NOT hasRole('USER')", Some(&user))
        .unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_complex_expression() {
    let evaluator = ExpressionEvaluator::new();
    let admin = create_admin_user();
    let user = create_user();

    // (ADMIN OR USER) AND authenticated
    let expr = "(hasRole('ADMIN') OR hasRole('USER')) AND isAuthenticated()";

    let result = evaluator.evaluate_str(expr, Some(&admin)).unwrap();
    assert!(result);

    let result = evaluator.evaluate_str(expr, Some(&user)).unwrap();
    assert!(result);

    let result = evaluator.evaluate_str(expr, None).unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_spring_like_expression() {
    let evaluator = ExpressionEvaluator::new();
    let admin = create_admin_user();
    let user = create_user();

    // Spring-like: hasRole('ADMIN') or hasAuthority('users:write')
    let expr = "hasRole('ADMIN') or hasAuthority('users:write')";

    let result = evaluator.evaluate_str(expr, Some(&admin)).unwrap();
    assert!(result); // Admin has both

    let result = evaluator.evaluate_str(expr, Some(&user)).unwrap();
    assert!(!result); // User has neither ADMIN nor write
}

#[test]
fn test_evaluate_unknown_function_error() {
    let evaluator = ExpressionEvaluator::new();
    let user = create_user();

    let result = evaluator.evaluate_str("unknownFunction()", Some(&user));
    assert!(result.is_err());
}

#[test]
fn test_evaluate_boolean_literals() {
    let evaluator = ExpressionEvaluator::new();

    let result = evaluator.evaluate_str("true", None).unwrap();
    assert!(result);

    let result = evaluator.evaluate_str("false", None).unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_short_circuit_and() {
    let evaluator = ExpressionEvaluator::new();

    // false AND <anything> should short-circuit to false
    // even if the right side would error
    let result = evaluator
        .evaluate_str("false AND unknownFunction()", None)
        .unwrap();
    assert!(!result);
}

#[test]
fn test_evaluate_short_circuit_or() {
    let evaluator = ExpressionEvaluator::new();

    // true OR <anything> should short-circuit to true
    // even if the right side would error
    let result = evaluator
        .evaluate_str("true OR unknownFunction()", None)
        .unwrap();
    assert!(result);
}

// =============================================================================
// Custom Expression Root Tests
// =============================================================================

struct CustomExpressionRoot {
    default: DefaultExpressionRoot,
    premium_users: Vec<String>,
}

impl CustomExpressionRoot {
    fn new(premium_users: Vec<String>) -> Self {
        CustomExpressionRoot {
            default: DefaultExpressionRoot::new(),
            premium_users,
        }
    }
}

impl ExpressionRoot for CustomExpressionRoot {
    fn evaluate_function(&self, name: &str, args: &[String], user: Option<&User>) -> Option<bool> {
        match name {
            // Custom function: isPremium()
            "isPremium" => {
                let username = user.map(|u| u.get_username())?;
                Some(self.premium_users.contains(&username.to_string()))
            }
            // Custom function: hasMinRoles(count)
            "hasMinRoles" => {
                let count: usize = args.first()?.parse().ok()?;
                Some(user.map_or(false, |u| u.get_roles().len() >= count))
            }
            // Delegate to default
            _ => self.default.evaluate_function(name, args, user),
        }
    }
}

#[test]
fn test_custom_expression_root() {
    let root = CustomExpressionRoot::new(vec!["admin".to_string()]);
    let evaluator = ExpressionEvaluator::with_root(root);

    let admin = create_admin_user();
    let user = create_user();

    // Test custom isPremium function
    let result = evaluator
        .evaluate_str("isPremium()", Some(&admin))
        .unwrap();
    assert!(result);

    let result = evaluator
        .evaluate_str("isPremium()", Some(&user))
        .unwrap();
    assert!(!result);
}

#[test]
fn test_custom_expression_with_args() {
    let root = CustomExpressionRoot::new(vec![]);
    let evaluator = ExpressionEvaluator::with_root(root);

    let admin = create_admin_user(); // Has 2 roles: ADMIN, USER
    let user = create_user(); // Has 1 role: USER

    let result = evaluator
        .evaluate_str("hasMinRoles('2')", Some(&admin))
        .unwrap();
    assert!(result);

    let result = evaluator
        .evaluate_str("hasMinRoles('2')", Some(&user))
        .unwrap();
    assert!(!result);
}

#[test]
fn test_custom_expression_combined_with_builtin() {
    let root = CustomExpressionRoot::new(vec!["admin".to_string()]);
    let evaluator = ExpressionEvaluator::with_root(root);

    let admin = create_admin_user();

    // Combine custom and built-in functions
    let result = evaluator
        .evaluate_str("isPremium() AND hasRole('ADMIN')", Some(&admin))
        .unwrap();
    assert!(result);
}
