use crate::http::security::AuthorizeRequests;

pub struct HttpSecurity {}

impl HttpSecurity {
    pub fn authorize_requests() -> AuthorizeRequests {
        AuthorizeRequests::new()
    }
}