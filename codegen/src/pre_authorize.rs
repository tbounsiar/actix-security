//! The `#[pre_authorize]` macro for expression-based method security.
//!
//! # Spring Security Equivalent
//! `@PreAuthorize("...")`

use proc_macro::TokenStream;
use proc_macro2::TokenStream as TokenStream2;
use quote::quote;
use syn::parse::{Parse, ParseStream};
use syn::punctuated::Punctuated;
use syn::{parse_macro_input, Expr, ExprLit, ItemFn, Lit, ReturnType, Token};

use crate::helpers::{find_user_param, missing_user_param_error};

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
// Expression Compiler - compiles expression strings to Rust code at compile time
// =============================================================================

/// Compiles a security expression to Rust code.
/// Returns the generated code or an error message.
fn compile_expression(expr: &str, user_param: &proc_macro2::Ident) -> Result<TokenStream2, String> {
    let tokens = tokenize_expression(expr)?;
    if tokens.is_empty() {
        return Err("empty expression".to_string());
    }

    let mut parser = ExpressionParser::new(tokens);
    parser.parse_or(user_param)
}

#[derive(Debug, Clone, PartialEq)]
enum ExprToken {
    Ident(String),
    String(String),
    LParen,
    RParen,
    Comma,
    And,
    Or,
    Not,
    True,
    False,
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

struct ExpressionParser {
    tokens: Vec<ExprToken>,
    pos: usize,
}

impl ExpressionParser {
    fn new(tokens: Vec<ExprToken>) -> Self {
        ExpressionParser { tokens, pos: 0 }
    }

    fn peek(&self) -> Option<&ExprToken> {
        self.tokens.get(self.pos)
    }

    fn advance(&mut self) -> Option<ExprToken> {
        let token = self.tokens.get(self.pos).cloned();
        self.pos += 1;
        token
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

        // Parse arguments
        let mut args: Vec<String> = Vec::new();
        if !matches!(self.peek(), Some(ExprToken::RParen)) {
            loop {
                match self.peek().cloned() {
                    Some(ExprToken::String(s)) => {
                        self.advance();
                        args.push(s);
                    }
                    Some(ExprToken::Ident(s)) => {
                        self.advance();
                        args.push(s);
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

        // Generate code for built-in functions
        self.generate_function_code(name, &args, user)
    }

    fn generate_function_code(
        &self,
        name: &str,
        args: &[String],
        user: &proc_macro2::Ident,
    ) -> Result<TokenStream2, String> {
        match name {
            "hasRole" => {
                let role = args
                    .first()
                    .ok_or_else(|| "hasRole requires a role argument".to_string())?;
                Ok(quote! { #user.has_role(#role) })
            }
            "hasAnyRole" => {
                if args.is_empty() {
                    return Err("hasAnyRole requires at least one role argument".to_string());
                }
                Ok(quote! { #user.has_any_role(&[#(#args),*]) })
            }
            "hasAuthority" => {
                let authority = args
                    .first()
                    .ok_or_else(|| "hasAuthority requires an authority argument".to_string())?;
                Ok(quote! { #user.has_authority(#authority) })
            }
            "hasAnyAuthority" => {
                if args.is_empty() {
                    return Err("hasAnyAuthority requires at least one authority argument".to_string());
                }
                Ok(quote! { #user.has_any_authority(&[#(#args),*]) })
            }
            "isAuthenticated" => {
                // AuthenticatedUser extractor guarantees authentication
                Ok(quote! { true })
            }
            "permitAll" => Ok(quote! { true }),
            "denyAll" => Ok(quote! { false }),
            _ => Err(format!(
                "unknown function '{}'. Supported: hasRole, hasAnyRole, hasAuthority, hasAnyAuthority, isAuthenticated, permitAll, denyAll",
                name
            )),
        }
    }
}

/// Flexible method security annotation with SpEL-like expressions.
///
/// # Spring Security Equivalent
/// `@PreAuthorize("...")`
///
/// # Usage
/// ```ignore
/// use actix_security_core::http::security::AuthenticatedUser;
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
/// # Supported Expression Functions
///
/// - `hasRole('ROLE')` - Check if user has the specified role
/// - `hasAnyRole('ROLE1', 'ROLE2')` - Check if user has any of the roles
/// - `hasAuthority('AUTH')` - Check if user has the specified authority
/// - `hasAnyAuthority('AUTH1', 'AUTH2')` - Check if user has any authority
/// - `isAuthenticated()` - Check if user is authenticated (always true with AuthenticatedUser)
/// - `permitAll()` - Always returns true
/// - `denyAll()` - Always returns false
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
                    return ::std::result::Result::Err(::actix_security_core::http::error::AuthError::Forbidden);
                }
            }
        }
        PreAuthorizeCheck::Authorities(authorities) => {
            quote! {
                // Authority check generated by #[pre_authorize(authority = ...)]
                let __required_authorities: &[&str] = &[#(#authorities),*];
                if !#user_param.has_any_authority(__required_authorities) {
                    return ::std::result::Result::Err(::actix_security_core::http::error::AuthError::Forbidden);
                }
            }
        }
        PreAuthorizeCheck::Expression(expr_str) => {
            match compile_expression(&expr_str, &user_param) {
                Ok(expr_code) => {
                    quote! {
                        // Expression check generated by #[pre_authorize("...")]
                        if !(#expr_code) {
                            return ::std::result::Result::Err(::actix_security_core::http::error::AuthError::Forbidden);
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
        #vis #asyncness fn #fn_name #generics(#inputs) -> ::std::result::Result<#original_return, ::actix_security_core::http::error::AuthError> {
            {
                #check_code
            }

            ::std::result::Result::Ok(#block)
        }
    };

    expanded.into()
}
