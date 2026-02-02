//! Request Matcher based Authorization.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager`

use std::collections::HashMap;

use actix_web::body::EitherBody;
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::{http, Error, HttpResponse};
use futures_util::future::LocalBoxFuture;
use regex::Regex;

use crate::http::security::config::Authorizer;
use crate::http::security::user::User;

#[cfg(feature = "http-basic")]
use crate::http::security::http_basic::HttpBasicConfig;

/// URL pattern-based authorization.
///
/// # Spring Security Equivalent
/// `RequestMatcher` + `AuthorizationManager`
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::authorizer::{RequestMatcherAuthorizer, Access};
///
/// let authorizer = RequestMatcherAuthorizer::new()
///     .login_url("/login")
///     .http_basic()
///     .add_matcher("/admin/.*", Access::new().roles(vec!["ADMIN"]))
///     .add_matcher("/api/.*", Access::new().authorities(vec!["api:read"]));
/// ```
pub struct RequestMatcherAuthorizer {
    login_url: &'static str,
    matchers: HashMap<String, Access>,
    #[cfg(feature = "http-basic")]
    http_basic: Option<HttpBasicConfig>,
}

impl RequestMatcherAuthorizer {
    /// Creates a new authorizer with default settings.
    pub fn new() -> Self {
        RequestMatcherAuthorizer {
            login_url: "/login",
            matchers: HashMap::new(),
            #[cfg(feature = "http-basic")]
            http_basic: None,
        }
    }

    /// Adds a URL pattern with access requirements.
    ///
    /// # Arguments
    /// * `url_regex` - A regex pattern to match URLs
    /// * `access` - The access requirements for matching URLs
    pub fn add_matcher(mut self, url_regex: &'static str, access: Access) -> Self {
        self.matchers.insert(String::from(url_regex), access);
        self
    }

    /// Sets the login URL (default: "/login").
    ///
    /// Unauthenticated users will be redirected to this URL
    /// unless HTTP Basic auth is enabled.
    pub fn login_url(mut self, url: &'static str) -> Self {
        self.login_url = url;
        self
    }

    /// Enables HTTP Basic authentication.
    ///
    /// # Spring Security Equivalent
    /// `HttpSecurity.httpBasic()`
    ///
    /// When enabled, unauthenticated requests will receive a
    /// `401 Unauthorized` response with `WWW-Authenticate: Basic realm="..."`
    /// header instead of being redirected to the login page.
    #[cfg(feature = "http-basic")]
    pub fn http_basic(mut self) -> Self {
        self.http_basic = Some(HttpBasicConfig::new());
        self
    }

    /// Enables HTTP Basic authentication with custom configuration.
    #[cfg(feature = "http-basic")]
    pub fn http_basic_with_config(mut self, config: HttpBasicConfig) -> Self {
        self.http_basic = Some(config);
        self
    }

    /// Checks if a path matches any registered pattern.
    pub fn matches(&self, path: &str) -> Option<&Access> {
        for (pattern, access) in &self.matchers {
            if let Ok(re) = Regex::new(pattern) {
                if re.is_match(path) {
                    return Some(access);
                }
            }
        }
        None
    }

    fn check_access(&self, user: &User, access: &Access) -> bool {
        user.has_authorities(&access.authorities) || user.has_roles(&access.roles)
    }
}

impl Default for RequestMatcherAuthorizer {
    fn default() -> Self {
        Self::new()
    }
}

impl<B: 'static> Authorizer<B> for RequestMatcherAuthorizer {
    fn process(
        &self,
        req: ServiceRequest,
        user: Option<&User>,
        next: impl FnOnce(ServiceRequest) -> LocalBoxFuture<'static, Result<ServiceResponse<B>, Error>>
            + 'static,
    ) -> LocalBoxFuture<'static, Result<ServiceResponse<EitherBody<B>>, Error>> {
        let path = req.path().to_string();
        let login_url = self.login_url;
        #[cfg(feature = "http-basic")]
        let http_basic = self.http_basic.clone();

        match user {
            Some(u) => {
                // Authenticated user
                if path == login_url {
                    // Redirect authenticated users away from login page
                    return Box::pin(async move {
                        Ok(req.into_response(
                            HttpResponse::Found()
                                .append_header((http::header::LOCATION, "/"))
                                .finish()
                                .map_into_right_body(),
                        ))
                    });
                }

                // Check if user has required access
                if let Some(access) = self.matches(&path) {
                    if self.check_access(u, access) {
                        // User has access, forward to inner service
                        return Box::pin(async move {
                            let res = next(req).await?;
                            Ok(res.map_into_left_body())
                        });
                    } else {
                        // User lacks required access -> 403 Forbidden
                        return Box::pin(async move {
                            Ok(req.into_response(
                                HttpResponse::Forbidden().finish().map_into_right_body(),
                            ))
                        });
                    }
                }

                // No matching pattern - allow through to handler
                // (handler may use macro-level security like #[secured])
                Box::pin(async move {
                    let res = next(req).await?;
                    Ok(res.map_into_left_body())
                })
            }
            None => {
                // Unauthenticated user
                if path == login_url {
                    // Allow access to login page
                    Box::pin(async move {
                        let res = next(req).await?;
                        Ok(res.map_into_left_body())
                    })
                } else {
                    #[cfg(feature = "http-basic")]
                    if let Some(basic_config) = http_basic {
                        // HTTP Basic Auth: Return 401 with WWW-Authenticate header
                        let www_auth = basic_config.www_authenticate_header();
                        return Box::pin(async move {
                            Ok(req.into_response(
                                HttpResponse::Unauthorized()
                                    .append_header((http::header::WWW_AUTHENTICATE, www_auth))
                                    .finish()
                                    .map_into_right_body(),
                            ))
                        });
                    }

                    // Redirect to login page (fallback when http-basic not enabled or not configured)
                    let redirect_url = login_url.to_string();
                    Box::pin(async move {
                        Ok(req.into_response(
                            HttpResponse::Found()
                                .append_header((http::header::LOCATION, redirect_url))
                                .finish()
                                .map_into_right_body(),
                        ))
                    })
                }
            }
        }
    }
}

// =============================================================================
// Access Configuration
// =============================================================================

/// Access configuration for URL patterns.
///
/// # Spring Security Equivalent
/// `AuthorizeHttpRequestsConfigurer`
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::authorizer::Access;
///
/// // Require ADMIN role
/// let admin_access = Access::new().roles(vec!["ADMIN"]);
///
/// // Require any of these authorities
/// let api_access = Access::new().authorities(vec!["api:read", "api:write"]);
///
/// // Require ADMIN or MANAGER role
/// let management_access = Access::new().roles(vec!["ADMIN", "MANAGER"]);
/// ```
#[derive(Default)]
pub struct Access {
    pub(crate) roles: Vec<String>,
    pub(crate) authorities: Vec<String>,
}

impl Access {
    /// Creates a new empty access configuration.
    pub fn new() -> Self {
        Access {
            roles: Vec::new(),
            authorities: Vec::new(),
        }
    }

    /// Requires any of the specified roles.
    ///
    /// # Spring Security Equivalent
    /// `hasAnyRole("ADMIN", "USER")`
    pub fn roles(mut self, roles: Vec<&str>) -> Self {
        for role in roles {
            let role_str = String::from(role);
            if !self.roles.contains(&role_str) {
                self.roles.push(role_str);
            }
        }
        self
    }

    /// Requires any of the specified authorities.
    ///
    /// # Spring Security Equivalent
    /// `hasAnyAuthority("users:read", "users:write")`
    pub fn authorities(mut self, authorities: Vec<&str>) -> Self {
        for authority in authorities {
            let auth_str = String::from(authority);
            if !self.authorities.contains(&auth_str) {
                self.authorities.push(auth_str);
            }
        }
        self
    }
}
