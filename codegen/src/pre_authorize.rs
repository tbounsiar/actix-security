//! The `#[pre_authorize]` macro for expression-based method security.
//!
//! # Spring Security Equivalent
//! `@PreAuthorize("...")`

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::{format_ident, quote};
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{
    parse_macro_input, Expr, ExprLit, FnArg, GenericArgument, ItemFn, Lit, Pat, PathArguments,
    ReturnType, Token, Type,
};

use crate::helpers::{core_crate_path, find_user_param, missing_user_param_error};

/// Parsed arguments for #[pre_authorize(...)]
pub enum PreAuthorizeCheck {
    /// #[pre_authorize(authenticated)]
    Authenticated,
    /// #[pre_authorize(role = "ADMIN")] or #[pre_authorize(roles = ["ADMIN", "USER"])]
    Roles(Vec<String>),
    /// #[pre_authorize(authority = "read")] or #[pre_authorize(authorities = ["read", "write"])]
    Authorities(Vec<String>),
    /// #[pre_authorize("hasRole('ADMIN') OR hasAuthority('write')")]
    Expression(String),
}

pub struct PreAuthorizeArgs {
    pub check: PreAuthorizeCheck,
}

impl Parse for PreAuthorizeArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        // Check for string literal (expression syntax)
        if input.peek(syn::LitStr) {
            let lit: syn::LitStr = input.parse()?;
            return Ok(PreAuthorizeArgs {
                check: PreAuthorizeCheck::Expression(lit.value()),
            });
        }

        // Check for bare "authenticated" identifier
        if input.peek(syn::Ident) {
            let ident: syn::Ident = input.parse()?;

            if ident == "authenticated" {
                return Ok(PreAuthorizeArgs {
                    check: PreAuthorizeCheck::Authenticated,
                });
            }

            // Check for key = value syntax
            if input.peek(Token![=]) {
                input.parse::<Token![=]>()?;

                match ident.to_string().as_str() {
                    "role" | "roles" => {
                        let roles = parse_string_or_array(input)?;
                        return Ok(PreAuthorizeArgs {
                            check: PreAuthorizeCheck::Roles(roles),
                        });
                    }
                    "authority" | "authorities" => {
                        let authorities = parse_string_or_array(input)?;
                        return Ok(PreAuthorizeArgs {
                            check: PreAuthorizeCheck::Authorities(authorities),
                        });
                    }
                    _ => {
                        return Err(syn::Error::new_spanned(
                            ident,
                            "expected 'authenticated', 'role', 'roles', 'authority', or 'authorities'",
                        ));
                    }
                }
            }

            return Err(syn::Error::new_spanned(
                ident,
                "expected 'authenticated' or 'key = value' syntax",
            ));
        }

        Err(syn::Error::new(
            input.span(),
            r#"expected one of: "expression", authenticated, role = "...", authority = "...""#,
        ))
    }
}

/// Parses either a single string "value" or an array ["a", "b"]
fn parse_string_or_array(input: ParseStream) -> syn::Result<Vec<String>> {
    if input.peek(syn::token::Bracket) {
        // Array syntax: ["a", "b"]
        let content;
        syn::bracketed!(content in input);
        let args: Punctuated<Expr, Token![,]> = Punctuated::parse_terminated(&content)?;

        let mut values = Vec::new();
        for arg in args {
            if let Expr::Lit(ExprLit {
                lit: Lit::Str(lit_str),
                ..
            }) = arg
            {
                values.push(lit_str.value());
            } else {
                return Err(syn::Error::new_spanned(arg, "expected string literal"));
            }
        }
        Ok(values)
    } else {
        // Single string: "value"
        let lit: syn::LitStr = input.parse()?;
        Ok(vec![lit.value()])
    }
}

// =============================================================================
// Parameter Extraction - handles extracting values from Path, Query, Json, etc.
// =============================================================================

/// Information about a handler parameter that can be referenced in expressions
#[derive(Debug, Clone)]
#[allow(dead_code)] // inner_type and tuple_index reserved for future tuple support
struct HandlerParam {
    /// The parameter name (e.g., "tenant_id")
    name: String,
    /// The extractor type (e.g., "Path", "Query", "Json")
    extractor_type: String,
    /// The inner type as a string (e.g., "i64", "(i64, String)")
    inner_type: String,
    /// For tuple extractors, the position of this param (0-indexed)
    tuple_index: Option<usize>,
    /// The full parameter identifier
    ident: proc_macro2::Ident,
}

/// Extracts information about handler parameters that can be referenced
fn extract_handler_params(item_fn: &ItemFn) -> Vec<HandlerParam> {
    let mut params = Vec::new();

    for arg in &item_fn.sig.inputs {
        if let FnArg::Typed(pat_type) = arg {
            // Get the parameter name
            let param_name = if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                pat_ident.ident.to_string()
            } else {
                continue;
            };

            let param_ident = if let Pat::Ident(pat_ident) = pat_type.pat.as_ref() {
                pat_ident.ident.clone()
            } else {
                continue;
            };

            // Check if this is an extractor type (Path, Query, Json, etc.)
            if let Type::Path(type_path) = pat_type.ty.as_ref() {
                if let Some(segment) = type_path.path.segments.last() {
                    let type_name = segment.ident.to_string();

                    // Check for supported extractor types
                    if matches!(type_name.as_str(), "Path" | "Query" | "Json" | "Form") {
                        // Extract the inner type
                        if let PathArguments::AngleBracketed(args) = &segment.arguments {
                            if let Some(GenericArgument::Type(inner_ty)) = args.args.first() {
                                let inner_type_str = quote::quote!(#inner_ty).to_string();

                                // Check if it's a tuple type
                                if let Type::Tuple(tuple) = inner_ty {
                                    // For tuples, we can't automatically map param names
                                    // The user would need to use index syntax or we match by name
                                    // For now, store the whole tuple info
                                    params.push(HandlerParam {
                                        name: param_name,
                                        extractor_type: type_name,
                                        inner_type: inner_type_str,
                                        tuple_index: None,
                                        ident: param_ident,
                                    });

                                    // Note: For tuple support, we'd need additional syntax
                                    // like #path.0 or explicit naming in the Path<...>
                                    let _ = tuple; // Acknowledge we see the tuple
                                } else {
                                    // Single value extractor
                                    params.push(HandlerParam {
                                        name: param_name,
                                        extractor_type: type_name,
                                        inner_type: inner_type_str,
                                        tuple_index: None,
                                        ident: param_ident,
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    params
}

/// Finds a handler parameter by name and generates code to extract its value
fn generate_param_extraction(
    param_name: &str,
    handler_params: &[HandlerParam],
) -> Result<TokenStream2, String> {
    // First, look for a direct match by parameter name
    for param in handler_params {
        if param.name == param_name {
            let param_ident = &param.ident;
            let param_var = format_ident!("__param_{}", param_name);

            // Generate extraction code based on extractor type
            // Note: We dereference the extractor to get the inner value
            return match param.extractor_type.as_str() {
                "Path" | "Query" | "Json" | "Form" => {
                    // Use deref (*) to get the inner value, then clone it
                    Ok(quote! {
                        let #param_var = (*#param_ident).clone();
                    })
                }
                _ => Err(format!(
                    "unsupported extractor type '{}' for parameter '{}'",
                    param.extractor_type, param_name
                )),
            };
        }
    }

    Err(format!(
        "parameter '{}' not found in handler. Available parameters: {}",
        param_name,
        handler_params
            .iter()
            .map(|p| p.name.as_str())
            .collect::<Vec<_>>()
            .join(", ")
    ))
}

// =============================================================================
// Expression Compiler - compiles expression strings to Rust code at compile time
// =============================================================================

/// Compiles a security expression to Rust code.
/// Returns the parsed expression with code and metadata.
fn compile_expression(
    expr: &str,
    user_param: &proc_macro2::Ident,
) -> Result<ParsedExpression, String> {
    let tokens = tokenize_expression(expr)?;
    if tokens.is_empty() {
        return Err("empty expression".to_string());
    }

    let parser = ExpressionParser::new(tokens);
    parser.parse(user_param)
}

#[derive(Debug, Clone, PartialEq)]
enum ExprToken {
    Ident(String),
    String(String),
    /// Parameter reference: #param_name
    ParamRef(String),
    LParen,
    RParen,
    Comma,
    And,
    Or,
    Not,
    True,
    False,
}

/// Represents a function argument - either a string literal or a parameter reference
#[derive(Debug, Clone)]
enum FunctionArg {
    /// A string literal argument: 'value'
    StringLit(String),
    /// A parameter reference: #param_name
    ParamRef(String),
}

fn tokenize_expression(expr: &str) -> Result<Vec<ExprToken>, String> {
    let mut tokens = Vec::new();
    let mut chars = expr.chars().peekable();

    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                chars.next();
                tokens.push(ExprToken::LParen);
            }
            ')' => {
                chars.next();
                tokens.push(ExprToken::RParen);
            }
            ',' => {
                chars.next();
                tokens.push(ExprToken::Comma);
            }
            '\'' | '"' => {
                let quote = chars.next().unwrap();
                let mut value = String::new();
                loop {
                    match chars.next() {
                        Some(c) if c == quote => break,
                        Some('\\') => {
                            if let Some(escaped) = chars.next() {
                                value.push(escaped);
                            }
                        }
                        Some(c) => value.push(c),
                        None => return Err("unclosed string literal".to_string()),
                    }
                }
                tokens.push(ExprToken::String(value));
            }
            '&' => {
                chars.next();
                if chars.peek() == Some(&'&') {
                    chars.next();
                    tokens.push(ExprToken::And);
                } else {
                    return Err("expected && operator".to_string());
                }
            }
            '|' => {
                chars.next();
                if chars.peek() == Some(&'|') {
                    chars.next();
                    tokens.push(ExprToken::Or);
                } else {
                    return Err("expected || operator".to_string());
                }
            }
            '!' => {
                chars.next();
                tokens.push(ExprToken::Not);
            }
            // Parameter reference: #param_name
            '#' => {
                chars.next();
                let mut param_name = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        param_name.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if param_name.is_empty() {
                    return Err("expected parameter name after '#'".to_string());
                }
                tokens.push(ExprToken::ParamRef(param_name));
            }
            'a'..='z' | 'A'..='Z' | '_' => {
                let mut ident = String::new();
                while let Some(&c) = chars.peek() {
                    if c.is_alphanumeric() || c == '_' {
                        ident.push(c);
                        chars.next();
                    } else {
                        break;
                    }
                }
                match ident.to_lowercase().as_str() {
                    "and" => tokens.push(ExprToken::And),
                    "or" => tokens.push(ExprToken::Or),
                    "not" => tokens.push(ExprToken::Not),
                    "true" => tokens.push(ExprToken::True),
                    "false" => tokens.push(ExprToken::False),
                    _ => tokens.push(ExprToken::Ident(ident)),
                }
            }
            _ => return Err(format!("unexpected character: '{}'", c)),
        }
    }

    Ok(tokens)
}

/// Result of parsing an expression - contains the code and any parameter references
struct ParsedExpression {
    /// The generated Rust code for the expression
    code: TokenStream2,
    /// Parameter references found in the expression (for custom functions)
    param_refs: Vec<String>,
    /// Whether the expression contains custom async functions
    has_custom_functions: bool,
}

struct ExpressionParser {
    tokens: Vec<ExprToken>,
    pos: usize,
    /// Collected parameter references from custom function calls
    param_refs: Vec<String>,
    /// Whether we've seen any custom (non-builtin) functions
    has_custom_functions: bool,
}

impl ExpressionParser {
    fn new(tokens: Vec<ExprToken>) -> Self {
        ExpressionParser {
            tokens,
            pos: 0,
            param_refs: Vec::new(),
            has_custom_functions: false,
        }
    }

    fn peek(&self) -> Option<&ExprToken> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<ExprToken> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
    }

    fn parse(mut self, user: &proc_macro2::Ident) -> Result<ParsedExpression, String> {
        let code = self.parse_or(user)?;
        Ok(ParsedExpression {
            code,
            param_refs: self.param_refs,
            has_custom_functions: self.has_custom_functions,
        })
    }

    fn parse_or(&mut self, user: &proc_macro2::Ident) -> Result<TokenStream2, String> {
        let mut left = self.parse_and(user)?;

        while matches!(self.peek(), Some(ExprToken::Or)) {
            self.advance();
            let right = self.parse_and(user)?;
            left = quote! { (#left) || (#right) };
        }

        Ok(left)
    }

    fn parse_and(&mut self, user: &proc_macro2::Ident) -> Result<TokenStream2, String> {
        let mut left = self.parse_unary(user)?;

        while matches!(self.peek(), Some(ExprToken::And)) {
            self.advance();
            let right = self.parse_unary(user)?;
            left = quote! { (#left) && (#right) };
        }

        Ok(left)
    }

    fn parse_unary(&mut self, user: &proc_macro2::Ident) -> Result<TokenStream2, String> {
        if matches!(self.peek(), Some(ExprToken::Not)) {
            self.advance();
            let expr = self.parse_unary(user)?;
            return Ok(quote! { !(#expr) });
        }

        self.parse_primary(user)
    }

    fn parse_primary(&mut self, user: &proc_macro2::Ident) -> Result<TokenStream2, String> {
        match self.peek().cloned() {
            Some(ExprToken::True) => {
                self.advance();
                Ok(quote! { true })
            }
            Some(ExprToken::False) => {
                self.advance();
                Ok(quote! { false })
            }
            Some(ExprToken::LParen) => {
                self.advance();
                let expr = self.parse_or(user)?;
                if !matches!(self.peek(), Some(ExprToken::RParen)) {
                    return Err("unclosed parenthesis".to_string());
                }
                self.advance();
                Ok(quote! { (#expr) })
            }
            Some(ExprToken::Ident(name)) => {
                self.advance();
                self.parse_function_call(&name, user)
            }
            Some(token) => Err(format!("unexpected token: {:?}", token)),
            None => Err("unexpected end of expression".to_string()),
        }
    }

    fn parse_function_call(
        &mut self,
        name: &str,
        user: &proc_macro2::Ident,
    ) -> Result<TokenStream2, String> {
        // Expect opening parenthesis
        if !matches!(self.peek(), Some(ExprToken::LParen)) {
            return Err(format!("expected '(' after function name '{}'", name));
        }
        self.advance();

        // Parse arguments (can be strings, identifiers, or param refs)
        let mut args: Vec<FunctionArg> = Vec::new();
        if !matches!(self.peek(), Some(ExprToken::RParen)) {
            loop {
                match self.peek().cloned() {
                    Some(ExprToken::String(s)) => {
                        self.advance();
                        args.push(FunctionArg::StringLit(s));
                    }
                    Some(ExprToken::Ident(s)) => {
                        self.advance();
                        args.push(FunctionArg::StringLit(s));
                    }
                    Some(ExprToken::ParamRef(param_name)) => {
                        self.advance();
                        // Track this parameter reference
                        if !self.param_refs.contains(&param_name) {
                            self.param_refs.push(param_name.clone());
                        }
                        args.push(FunctionArg::ParamRef(param_name));
                    }
                    Some(token) => {
                        return Err(format!(
                            "unexpected token in function arguments: {:?}",
                            token
                        ))
                    }
                    None => return Err("unclosed function call".to_string()),
                }

                match self.peek() {
                    Some(ExprToken::Comma) => {
                        self.advance();
                    }
                    Some(ExprToken::RParen) => break,
                    Some(token) => {
                        return Err(format!("unexpected token: {:?}", token));
                    }
                    None => return Err("unclosed function call".to_string()),
                }
            }
        }

        // Expect closing parenthesis
        if !matches!(self.peek(), Some(ExprToken::RParen)) {
            return Err("unclosed function call".to_string());
        }
        self.advance();

        // Check if this is a built-in function or custom function
        if Self::is_builtin_function(name) {
            self.generate_builtin_function_code(name, &args, user)
        } else {
            self.has_custom_functions = true;
            self.generate_custom_function_code(name, &args, user)
        }
    }

    fn is_builtin_function(name: &str) -> bool {
        matches!(
            name,
            // camelCase (Spring Security style)
            "hasRole"
                | "hasAnyRole"
                | "hasAuthority"
                | "hasAnyAuthority"
                | "isAuthenticated"
                | "permitAll"
                | "denyAll"
                // snake_case (Rust style)
                | "has_role"
                | "has_any_role"
                | "has_authority"
                | "has_any_authority"
                | "is_authenticated"
                | "permit_all"
                | "deny_all"
        )
    }

    /// Normalizes a built-in function name to its canonical form for code generation.
    /// Both camelCase and snake_case are accepted.
    fn normalize_builtin_function(name: &str) -> &'static str {
        match name {
            "hasRole" | "has_role" => "hasRole",
            "hasAnyRole" | "has_any_role" => "hasAnyRole",
            "hasAuthority" | "has_authority" => "hasAuthority",
            "hasAnyAuthority" | "has_any_authority" => "hasAnyAuthority",
            "isAuthenticated" | "is_authenticated" => "isAuthenticated",
            "permitAll" | "permit_all" => "permitAll",
            "denyAll" | "deny_all" => "denyAll",
            // This should never be reached if is_builtin_function was called first
            _ => unreachable!(
                "normalize_builtin_function called with non-builtin: {}",
                name
            ),
        }
    }

    fn generate_builtin_function_code(
        &self,
        name: &str,
        args: &[FunctionArg],
        user: &proc_macro2::Ident,
    ) -> Result<TokenStream2, String> {
        // Extract string literals for built-in functions (they don't support param refs)
        let string_args: Result<Vec<&str>, String> = args
            .iter()
            .map(|arg| match arg {
                FunctionArg::StringLit(s) => Ok(s.as_str()),
                FunctionArg::ParamRef(p) => Err(format!(
                    "built-in function '{}' does not support parameter references (got #{})",
                    name, p
                )),
            })
            .collect();
        let string_args = string_args?;

        // Normalize function name to handle both camelCase and snake_case
        let canonical_name = Self::normalize_builtin_function(name);

        match canonical_name {
            "hasRole" => {
                let role = string_args
                    .first()
                    .ok_or_else(|| "hasRole requires a role argument".to_string())?;
                Ok(quote! { #user.has_role(#role) })
            }
            "hasAnyRole" => {
                if string_args.is_empty() {
                    return Err("hasAnyRole requires at least one role argument".to_string());
                }
                Ok(quote! { #user.has_any_role(&[#(#string_args),*]) })
            }
            "hasAuthority" => {
                let authority = string_args
                    .first()
                    .ok_or_else(|| "hasAuthority requires an authority argument".to_string())?;
                Ok(quote! { #user.has_authority(#authority) })
            }
            "hasAnyAuthority" => {
                if string_args.is_empty() {
                    return Err(
                        "hasAnyAuthority requires at least one authority argument".to_string()
                    );
                }
                Ok(quote! { #user.has_any_authority(&[#(#string_args),*]) })
            }
            "isAuthenticated" => {
                // AuthenticatedUser extractor guarantees authentication
                Ok(quote! { true })
            }
            "permitAll" => Ok(quote! { true }),
            "denyAll" => Ok(quote! { false }),
            _ => unreachable!("is_builtin_function should have caught this"),
        }
    }

    fn generate_custom_function_code(
        &self,
        name: &str,
        args: &[FunctionArg],
        user: &proc_macro2::Ident,
    ) -> Result<TokenStream2, String> {
        let func_ident = format_ident!("{}", name);

        // Generate argument tokens
        let arg_tokens: Vec<TokenStream2> = args
            .iter()
            .map(|arg| match arg {
                FunctionArg::StringLit(s) => quote! { #s },
                FunctionArg::ParamRef(param_name) => {
                    let param_var = format_ident!("__param_{}", param_name);
                    quote! { #param_var }
                }
            })
            .collect();

        // Custom functions are called with user as first argument, then the other args
        // The function signature should be: async fn name(user: &User, ...) -> bool
        // Use &* to dereference AuthenticatedUser (which implements Deref<Target=User>)
        Ok(quote! { #func_ident(&*#user, #(#arg_tokens),*).await })
    }
}

/// Flexible method security annotation with SpEL-like expressions.
///
/// # Spring Security Equivalent
/// `@PreAuthorize("...")`
///
/// # Usage
/// ```ignore
/// use actix_security::http::security::AuthenticatedUser;
/// use actix_security_codegen::pre_authorize;
///
/// // Expression syntax (Spring Security-like)
/// #[pre_authorize("hasRole('ADMIN') OR hasAuthority('users:write')")]
/// #[get("/admin")]
/// async fn admin(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Admin")
/// }
///
/// // Complex expressions with AND, OR, NOT
/// #[pre_authorize("(hasRole('ADMIN') OR hasRole('MANAGER')) AND hasAuthority('users:read')")]
/// #[get("/management")]
/// async fn management(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Management")
/// }
///
/// // Check authentication only
/// #[pre_authorize(authenticated)]
/// #[get("/protected")]
/// async fn protected(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Protected")
/// }
///
/// // Check single role (shorthand)
/// #[pre_authorize(role = "ADMIN")]
/// #[get("/admin-only")]
/// async fn admin_only(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Admin Only")
/// }
///
/// // Check multiple roles (OR logic)
/// #[pre_authorize(roles = ["ADMIN", "MANAGER"])]
/// #[get("/managers")]
/// async fn managers(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Managers")
/// }
///
/// // Check authority
/// #[pre_authorize(authority = "users:read")]
/// #[get("/api/users")]
/// async fn get_users(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Users")
/// }
///
/// // Check multiple authorities (OR logic)
/// #[pre_authorize(authorities = ["users:read", "users:write"])]
/// #[get("/api/users/manage")]
/// async fn manage_users(user: AuthenticatedUser) -> impl Responder {
///     HttpResponse::Ok().body("Manage users")
/// }
/// ```
///
/// # Custom Authorization Functions
///
/// You can use custom async functions with parameter references (Spring Security style):
///
/// ```ignore
/// // Define your custom authorization function
/// // It must be async and return bool, with user as first parameter
/// pub async fn is_tenant_admin(user: &User, tenant_id: i64) -> bool {
///     user.has_authority(&format!("tenant:{}:admin", tenant_id))
/// }
///
/// // Use #param_name to reference handler parameters
/// #[pre_authorize("is_tenant_admin(#tenant_id)")]
/// #[get("/tenants/{tenant_id}")]
/// async fn get_tenant(
///     tenant_id: Path<i64>,
///     user: AuthenticatedUser,
/// ) -> impl Responder {
///     HttpResponse::Ok().body("Tenant data")
/// }
///
/// // Combine with built-in functions
/// #[pre_authorize("hasRole('ADMIN') OR is_tenant_admin(#tenant_id)")]
/// #[get("/tenants/{tenant_id}/settings")]
/// async fn get_tenant_settings(
///     tenant_id: Path<i64>,
///     user: AuthenticatedUser,
/// ) -> impl Responder {
///     HttpResponse::Ok().body("Tenant settings")
/// }
///
/// // Multiple parameters
/// pub async fn can_access_document(user: &User, tenant_id: i64, doc_id: String) -> bool {
///     // Custom authorization logic
///     true
/// }
///
/// #[pre_authorize("can_access_document(#tenant_id, #doc_id)")]
/// #[get("/tenants/{tenant_id}/documents/{doc_id}")]
/// async fn get_document(
///     tenant_id: Path<i64>,
///     doc_id: Path<String>,
///     user: AuthenticatedUser,
/// ) -> impl Responder {
///     HttpResponse::Ok().body("Document")
/// }
/// ```
///
/// ## Supported Extractor Types for #param
///
/// - `Path<T>` - URL path parameters
/// - `Query<T>` - Query string parameters
/// - `Json<T>` - JSON request body
/// - `Form<T>` - Form data
///
/// # Supported Expression Functions
///
/// ## Built-in Functions
/// - `hasRole('ROLE')` - Check if user has the specified role
/// - `hasAnyRole('ROLE1', 'ROLE2')` - Check if user has any of the roles
/// - `hasAuthority('AUTH')` - Check if user has the specified authority
/// - `hasAnyAuthority('AUTH1', 'AUTH2')` - Check if user has any authority
/// - `isAuthenticated()` - Check if user is authenticated (always true with AuthenticatedUser)
/// - `permitAll()` - Always returns true
/// - `denyAll()` - Always returns false
///
/// ## Custom Functions
/// Any function matching signature: `async fn name(user: &User, ...) -> bool`
///
/// # Operators
///
/// - `AND` / `and` / `&&` - Logical AND
/// - `OR` / `or` / `||` - Logical OR
/// - `NOT` / `not` / `!` - Logical NOT
/// - `(` `)` - Grouping for precedence
pub fn pre_authorize_impl(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(input as ItemFn);
    let args = parse_macro_input!(attrs as PreAuthorizeArgs);

    let user_param = match find_user_param(&item_fn) {
        Some(param) => param,
        None => return missing_user_param_error(&item_fn, "pre_authorize"),
    };

    // Extract handler parameters for potential #param references
    let handler_params = extract_handler_params(&item_fn);

    let attrs = &item_fn.attrs;
    let vis = &item_fn.vis;
    let sig = &item_fn.sig;
    let block = &item_fn.block;
    let fn_name = &sig.ident;
    let inputs = &sig.inputs;
    let asyncness = &sig.asyncness;
    let generics = &sig.generics;

    let original_return = match &sig.output {
        ReturnType::Default => quote! { () },
        ReturnType::Type(_, ty) => quote! { #ty },
    };

    let core_path = core_crate_path();

    let check_code = match args.check {
        PreAuthorizeCheck::Authenticated => {
            // AuthenticatedUser extractor already handles this, but we keep it for explicitness
            quote! {
                // Authentication check (handled by AuthenticatedUser extractor)
                let _ = &#user_param;
            }
        }
        PreAuthorizeCheck::Roles(roles) => {
            quote! {
                // Role check generated by #[pre_authorize(role = ...)]
                let __required_roles: &[&str] = &[#(#roles),*];
                if !#user_param.has_any_role(__required_roles) {
                    return ::std::result::Result::Err(#core_path::http::error::AuthError::Forbidden);
                }
            }
        }
        PreAuthorizeCheck::Authorities(authorities) => {
            quote! {
                // Authority check generated by #[pre_authorize(authority = ...)]
                let __required_authorities: &[&str] = &[#(#authorities),*];
                if !#user_param.has_any_authority(__required_authorities) {
                    return ::std::result::Result::Err(#core_path::http::error::AuthError::Forbidden);
                }
            }
        }
        PreAuthorizeCheck::Expression(expr_str) => {
            match compile_expression(&expr_str, &user_param) {
                Ok(parsed_expr) => {
                    let expr_code = parsed_expr.code;

                    // If expression has custom functions with param refs, generate extraction code
                    if parsed_expr.has_custom_functions && !parsed_expr.param_refs.is_empty() {
                        // Generate extraction code for each referenced parameter
                        let mut extraction_code = Vec::new();
                        for param_ref in &parsed_expr.param_refs {
                            match generate_param_extraction(param_ref, &handler_params) {
                                Ok(code) => extraction_code.push(code),
                                Err(err) => {
                                    let err_msg = format!("invalid parameter reference: {}", err);
                                    return syn::Error::new_spanned(&item_fn.sig.ident, err_msg)
                                        .to_compile_error()
                                        .into();
                                }
                            }
                        }

                        quote! {
                            // Parameter extraction for custom authorization function
                            #(#extraction_code)*
                            // Expression check generated by #[pre_authorize("...")]
                            if !(#expr_code) {
                                return ::std::result::Result::Err(#core_path::http::error::AuthError::Forbidden);
                            }
                        }
                    } else {
                        quote! {
                            // Expression check generated by #[pre_authorize("...")]
                            if !(#expr_code) {
                                return ::std::result::Result::Err(#core_path::http::error::AuthError::Forbidden);
                            }
                        }
                    }
                }
                Err(err) => {
                    let err_msg = format!("invalid security expression: {}", err);
                    return syn::Error::new_spanned(&item_fn.sig.ident, err_msg)
                        .to_compile_error()
                        .into();
                }
            }
        }
    };

    let expanded = quote! {
        #(#attrs)*
        #vis #asyncness fn #fn_name #generics(#inputs) -> ::std::result::Result<#original_return, #core_path::http::error::AuthError> {
            {
                #check_code
            }

            ::std::result::Result::Ok(#block)
        }
    };

    expanded.into()
}
