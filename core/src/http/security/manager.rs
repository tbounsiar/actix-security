use crate::http::security::web::{MemoryAuthenticator, RequestMatcherAuthorizer};

pub struct AuthenticationManager {}

impl AuthenticationManager {
    pub fn in_memory_authentication() -> MemoryAuthenticator {
        MemoryAuthenticator::new()
    }
}

pub struct AuthorizationManager {}

impl AuthorizationManager {
    pub fn request_matcher() -> RequestMatcherAuthorizer {
        RequestMatcherAuthorizer::new()
    }
}