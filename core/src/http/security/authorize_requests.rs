use std::collections::HashMap;

use regex::Regex;

use crate::http::auth::{Access, AccessFn};
use crate::http::security::http_security::{Authorization, Authorize};

pub struct AuthorizeRequests {
    matchers: HashMap<String, AccessFn>
}

impl AuthorizeRequests {
    pub fn new() -> Self {
        MatcherHttpSecurity {
            matchers: HashMap::new()
        }
    }

    pub fn add_matcher(&mut self, rule: String, access_Fn: AccessFn) -> Self {
        self.matchers.insert(rule, access_Fn);
        self;
    }
}

impl Authorize for AuthorizeRequests {
    fn is_authorized(self, authorization: &Authorization) -> bool {
        for matcher in self.matchers {
            let regex = Regex::new(matcher.0.as_str()).unwrap();
            if regex.is_match(authorization.url.unwrap().as_str()) && matcher.1(&authorization.access) {
                return true;
            }
        }
        false
    }
}