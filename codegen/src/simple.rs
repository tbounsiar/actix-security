//! Simple security macros: permit_all, deny_all, roles_allowed.
//!
//! # Spring Security / Java EE Equivalents
//! - `@PermitAll` -> `#[permit_all]`
//! - `@DenyAll` -> `#[deny_all]`
//! - `@RolesAllowed({"ADMIN", "USER"})` -> `#[roles_allowed("ADMIN", "USER")]`

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, ReturnType};

use crate::helpers::core_crate_path;

/// Marks a method as publicly accessible (no authentication required).
///
/// # Spring Security / Java EE Equivalent
/// `@PermitAll`
///
/// # Note
/// This macro does NOT require an AuthenticatedUser parameter since
/// the endpoint is public. It simply passes through to the original function.
pub fn permit_all_impl(_attrs: TokenStream, input: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(input as ItemFn);

    // Simply return the original function unchanged
    // The endpoint is public - no security checks needed
    let expanded = quote! {
        #item_fn
    };

    expanded.into()
}

/// Marks a method as inaccessible (always returns 403 Forbidden).
///
/// # Spring Security / Java EE Equivalent
/// `@DenyAll`
///
/// # Usage
/// Used to temporarily disable an endpoint or mark it as under construction.
pub fn deny_all_impl(_attrs: TokenStream, input: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(input as ItemFn);

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

    // We include the original block (unreachable) to help type inference
    let expanded = quote! {
        #(#attrs)*
        #vis #asyncness fn #fn_name #generics(#inputs) -> ::std::result::Result<#original_return, #core_path::http::error::AuthError> {
            // denyAll() - always return Forbidden
            return ::std::result::Result::Err(#core_path::http::error::AuthError::Forbidden);

            // Unreachable - kept for type inference
            #[allow(unreachable_code)]
            ::std::result::Result::Ok(#block)
        }
    };

    expanded.into()
}

/// Role-based method security (Java EE standard).
///
/// # Java EE Equivalent
/// `@RolesAllowed({"ADMIN", "USER"})`
///
/// # Spring Security Equivalent
/// `@Secured({"ROLE_ADMIN", "ROLE_USER"})`
///
/// This is an alias for `#[secured]` that follows the Java EE naming convention.
pub fn roles_allowed_impl(attrs: TokenStream, input: TokenStream) -> TokenStream {
    // Delegate to the secured macro implementation
    crate::secured::secured_impl(attrs, input)
}
