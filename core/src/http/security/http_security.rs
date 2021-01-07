use std::collections::HashMap;

use crate::http::auth::{Access, AccessFn};
use crate::http::security::authorize_requests::AuthorizeRequests;

pub struct Authorization {
    pub url: Option<String>,
    pub access: Access,
}

pub trait Authorize {
    fn is_authorized(self, authorization: &Authorization) -> bool;
}

pub struct HttpSecurity {}

impl HttpSecurity {
    pub fn authorize_requests() -> AuthorizeRequests {
        AuthorizeRequests::new()
    }
}