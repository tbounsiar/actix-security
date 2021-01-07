use proc_macro::TokenStream;

use proc_macro2::Ident;
use quote::quote;
use syn::{self, AttributeArgs, ItemFn, parse_macro_input, Visibility};
use actix_security_core;

use crate::access::Access;

mod access;

#[proc_macro_attribute]
pub fn has_access(_attrs: TokenStream, _input: TokenStream) -> TokenStream {
    let mut item_fn = parse_macro_input!(_input as ItemFn);
    let args = parse_macro_input!(_attrs as AttributeArgs);
    let access = match Access::new(args) {
        Ok(access) => access,
        Err(err) => panic!("Error: {}", err),
    };
    let attrs = item_fn.clone().attrs;
    let ident = item_fn.clone().sig.ident;
    let asyncness = item_fn.clone().sig.asyncness;
    let vis = item_fn.clone().vis;
    let output = match item_fn.clone().sig.output {
        syn::ReturnType::Type(_, ty) => Some(ty),
        _ => None
    };

    if output == None {
        panic!("Output");
    }

    let inputs = item_fn.clone().sig.inputs;
    item_fn.attrs = vec![];
    item_fn.vis = Visibility::Inherited;
    item_fn.sig.asyncness = None;
    let mut params = vec![];
    for input in item_fn.clone().sig.inputs {
        match input {
            syn::FnArg::Typed(ar) => {
                params.push(ar.clone().pat);
            }
            // Other cases shouldn't happen since we parsed an `ItemFn`.
            _ => {
                continue;
            }
        };
    }

    let auths = access.get_access();
    let token = quote! {
        #(#attrs)*
        #vis #asyncness fn #ident(auth: actix_web::web::ReqData<api_core::Auth>, #inputs)
            -> Result<#output, impl actix_web::error::ResponseError> {
            if(!auth.has_authorities(vec![#(#auths, )*])){
                return Err(actix_security_core::http::error::AuthError::Forbidden);
            }
            #item_fn
            let response = #ident(#(#params,)*);
            Ok(response)
        }
    };
    token.into()
}