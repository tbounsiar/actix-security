use std::collections::HashMap;

use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{HttpMessage, Error};
use regex::Regex;

use crate::http::auth::{Access, AccessFn};
use crate::http::middleware::SecurityServiceFuture;
use crate::http::security::authorization::{Authorization, Authorize};
use actix_service::Service;

pub struct AuthorizeRequests {
    matchers: HashMap<&'static str, AccessFn>
}

impl AuthorizeRequests {
    pub fn new() -> Self {
        MatcherHttpSecurity {
            matchers: HashMap::new()
        }
    }

    pub fn add_matcher(&mut self, rule: &'static str, access_Fn: AccessFn) -> Self {
        self.matchers.insert(rule, access_Fn);
        self;
    }
}

impl<B> Authorize<B> for AuthorizeRequests {
    fn is_authorized(self, authorization: &Authorization) -> bool {
        for matcher in self.matchers {
            let regex = Regex::new(matcher.0).unwrap();
            if regex.is_match(authorization.url.unwrap().as_str()) && matcher.1(&authorization.access) {
                return true;
            }
        }
        false
    }

    fn process(
        self,
        service: Service<Request=ServiceRequest, Response=ServiceResponse<B>, Error=Error>,
        service_request: ServiceRequest,
    ) -> SecurityServiceFuture<B> {
        println!("Hi from start. You requested: {}, method {}", req.path(), req.method());

        service_request.extensions_mut().insert(Auth::new(vec!["READ"]));

        let fut = service.call(req);

        Box::pin(async move {
            let res = fut.await?;

            println!("Hi from response");
            Ok(res)
        })
    }
}