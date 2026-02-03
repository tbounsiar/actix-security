//! Legacy macros kept for backward compatibility.
//!
//! These macros are deprecated and will be removed in a future version.
//! Please migrate to the new Spring Security-like macros:
//!
//! - `#[has_role]` → `#[secured]`
//! - `#[has_access]` → `#[pre_authorize(authority = "...")]`
//! - `#[authenticated]` → `#[pre_authorize(authenticated)]`

use proc_macro::TokenStream;
use quote::quote;
use syn::{parse_macro_input, ItemFn, ReturnType};

use crate::access::Access;
use crate::helpers::{core_crate_path, find_user_param, missing_user_param_error};
use crate::secured::secured_impl;

/// **Deprecated**: Use `#[secured("ROLE")]` instead.
///
/// This macro is kept for backward compatibility.
pub fn has_role_impl(attrs: TokenStream, input: TokenStream) -> TokenStream {
    secured_impl(attrs, input)
}

/// **Deprecated**: Use `#[pre_authorize(authority = "...")]` instead.
///
/// This macro is kept for backward compatibility.
pub fn has_access_impl(attrs: TokenStream, input: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(input as ItemFn);
    let access = parse_macro_input!(attrs as Access);

    let authorities = access.get_access();

    let user_param = match find_user_param(&item_fn) {
        Some(param) => param,
        None => return missing_user_param_error(&item_fn, "has_access"),
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

    let core_path = core_crate_path();

    let expanded = quote! {
        #(#attrs)*
        #vis #asyncness fn #fn_name #generics(#inputs) -> ::std::result::Result<#original_return, #core_path::http::error::AuthError> {
            {
                let __required_authorities: &[&str] = &[#(#authorities),*];
                if !#user_param.has_any_authority(__required_authorities) {
                    return ::std::result::Result::Err(#core_path::http::error::AuthError::Forbidden);
                }
            }

            ::std::result::Result::Ok(#block)
        }
    };

    expanded.into()
}

/// **Deprecated**: Use `#[pre_authorize(authenticated)]` instead.
pub fn authenticated_impl(_attrs: TokenStream, input: TokenStream) -> TokenStream {
    let item_fn = parse_macro_input!(input as ItemFn);

    if find_user_param(&item_fn).is_none() {
        return missing_user_param_error(&item_fn, "authenticated");
    }

    let expanded = quote! {
        #item_fn
    };

    expanded.into()
}
