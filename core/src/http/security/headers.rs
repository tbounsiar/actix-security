//! Security headers middleware for HTTP security.
//!
//! # Spring Security Equivalent
//! `HttpSecurity.headers()` configuration
//!
//! # Overview
//! Adds security-related HTTP headers to responses:
//!
//! - `X-Content-Type-Options: nosniff` - Prevents MIME-sniffing
//! - `X-Frame-Options: DENY` - Prevents clickjacking
//! - `X-XSS-Protection: 0` - Disables XSS Auditor (deprecated but safe)
//! - `Strict-Transport-Security` - Forces HTTPS (HSTS)
//! - `Content-Security-Policy` - Controls resource loading
//! - `Referrer-Policy` - Controls referrer information
//! - `Permissions-Policy` - Controls browser features
//!
//! # Usage
//! ```ignore
//! use actix_web::{App, HttpServer};
//! use actix_security_core::http::security::headers::SecurityHeaders;
//!
//! HttpServer::new(|| {
//!     App::new()
//!         .wrap(SecurityHeaders::default())
//!         // ... routes
//! })
//! ```

use std::future::{ready, Future, Ready};
use std::pin::Pin;
use std::rc::Rc;
use std::task::{Context, Poll};

use actix_service::{Service, Transform};
use actix_web::dev::{ServiceRequest, ServiceResponse};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::Error;

/// Frame options for X-Frame-Options header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FrameOptions {
    /// Prevents the page from being framed entirely.
    Deny,
    /// Allows framing by the same origin only.
    SameOrigin,
    /// Disables X-Frame-Options header.
    Disabled,
}

impl FrameOptions {
    fn to_header_value(&self) -> Option<&'static str> {
        match self {
            FrameOptions::Deny => Some("DENY"),
            FrameOptions::SameOrigin => Some("SAMEORIGIN"),
            FrameOptions::Disabled => None,
        }
    }
}

/// Referrer policy options.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferrerPolicy {
    NoReferrer,
    NoReferrerWhenDowngrade,
    Origin,
    OriginWhenCrossOrigin,
    SameOrigin,
    StrictOrigin,
    StrictOriginWhenCrossOrigin,
    UnsafeUrl,
    Disabled,
}

impl ReferrerPolicy {
    fn to_header_value(&self) -> Option<&'static str> {
        match self {
            ReferrerPolicy::NoReferrer => Some("no-referrer"),
            ReferrerPolicy::NoReferrerWhenDowngrade => Some("no-referrer-when-downgrade"),
            ReferrerPolicy::Origin => Some("origin"),
            ReferrerPolicy::OriginWhenCrossOrigin => Some("origin-when-cross-origin"),
            ReferrerPolicy::SameOrigin => Some("same-origin"),
            ReferrerPolicy::StrictOrigin => Some("strict-origin"),
            ReferrerPolicy::StrictOriginWhenCrossOrigin => Some("strict-origin-when-cross-origin"),
            ReferrerPolicy::UnsafeUrl => Some("unsafe-url"),
            ReferrerPolicy::Disabled => None,
        }
    }
}

/// Security headers configuration.
///
/// # Spring Security Equivalent
/// `HttpSecurity.headers()`
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::headers::{SecurityHeaders, FrameOptions};
///
/// let headers = SecurityHeaders::new()
///     .frame_options(FrameOptions::SameOrigin)
///     .content_security_policy("default-src 'self'")
///     .hsts(true, 31536000); // 1 year
/// ```
#[derive(Debug, Clone)]
pub struct SecurityHeaders {
    /// X-Content-Type-Options header (default: nosniff)
    pub content_type_options: bool,
    /// X-Frame-Options header (default: DENY)
    pub frame_options: FrameOptions,
    /// X-XSS-Protection header (default: 0)
    pub xss_protection: bool,
    /// Content-Security-Policy header (default: None)
    pub content_security_policy: Option<String>,
    /// Strict-Transport-Security header (default: disabled)
    pub hsts_enabled: bool,
    /// HSTS max-age in seconds (default: 31536000 = 1 year)
    pub hsts_max_age: u64,
    /// HSTS include subdomains (default: false)
    pub hsts_include_subdomains: bool,
    /// HSTS preload (default: false)
    pub hsts_preload: bool,
    /// Referrer-Policy header (default: strict-origin-when-cross-origin)
    pub referrer_policy: ReferrerPolicy,
    /// Permissions-Policy header (default: None)
    pub permissions_policy: Option<String>,
    /// Cache-Control header for sensitive content (default: None)
    pub cache_control: Option<String>,
}

impl Default for SecurityHeaders {
    /// Creates security headers with sensible defaults.
    ///
    /// # Default Values
    /// - `X-Content-Type-Options: nosniff`
    /// - `X-Frame-Options: DENY`
    /// - `X-XSS-Protection: 0` (disabled as recommended)
    /// - `Referrer-Policy: strict-origin-when-cross-origin`
    fn default() -> Self {
        SecurityHeaders {
            content_type_options: true,
            frame_options: FrameOptions::Deny,
            xss_protection: false, // XSS Auditor is deprecated
            content_security_policy: None,
            hsts_enabled: false,
            hsts_max_age: 31536000, // 1 year
            hsts_include_subdomains: false,
            hsts_preload: false,
            referrer_policy: ReferrerPolicy::StrictOriginWhenCrossOrigin,
            permissions_policy: None,
            cache_control: None,
        }
    }
}

impl SecurityHeaders {
    /// Creates a new security headers configuration with defaults.
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a strict security headers configuration.
    ///
    /// Enables all security headers with strict values.
    pub fn strict() -> Self {
        SecurityHeaders {
            content_type_options: true,
            frame_options: FrameOptions::Deny,
            xss_protection: false,
            content_security_policy: Some("default-src 'self'".to_string()),
            hsts_enabled: true,
            hsts_max_age: 31536000,
            hsts_include_subdomains: true,
            hsts_preload: false,
            referrer_policy: ReferrerPolicy::NoReferrer,
            permissions_policy: Some("geolocation=(), microphone=(), camera=()".to_string()),
            cache_control: Some("no-cache, no-store, must-revalidate".to_string()),
        }
    }

    /// Sets the X-Frame-Options header.
    ///
    /// # Spring Security Equivalent
    /// `headers().frameOptions().deny()` or `.sameOrigin()`
    pub fn frame_options(mut self, options: FrameOptions) -> Self {
        self.frame_options = options;
        self
    }

    /// Sets the Content-Security-Policy header.
    ///
    /// # Spring Security Equivalent
    /// `headers().contentSecurityPolicy("policy")`
    ///
    /// # Example
    /// ```ignore
    /// let headers = SecurityHeaders::new()
    ///     .content_security_policy("default-src 'self'; script-src 'self' 'unsafe-inline'");
    /// ```
    pub fn content_security_policy(mut self, policy: impl Into<String>) -> Self {
        self.content_security_policy = Some(policy.into());
        self
    }

    /// Enables HTTP Strict Transport Security (HSTS).
    ///
    /// # Spring Security Equivalent
    /// `headers().httpStrictTransportSecurity()`
    ///
    /// # Arguments
    /// * `enabled` - Whether to enable HSTS
    /// * `max_age` - Max-age value in seconds
    pub fn hsts(mut self, enabled: bool, max_age: u64) -> Self {
        self.hsts_enabled = enabled;
        self.hsts_max_age = max_age;
        self
    }

    /// Sets HSTS to include subdomains.
    pub fn hsts_include_subdomains(mut self, include: bool) -> Self {
        self.hsts_include_subdomains = include;
        self
    }

    /// Sets HSTS preload flag.
    ///
    /// # Warning
    /// Only enable this if you've submitted your domain to the HSTS preload list.
    pub fn hsts_preload(mut self, preload: bool) -> Self {
        self.hsts_preload = preload;
        self
    }

    /// Sets the Referrer-Policy header.
    ///
    /// # Spring Security Equivalent
    /// `headers().referrerPolicy(ReferrerPolicy.STRICT_ORIGIN)`
    pub fn referrer_policy(mut self, policy: ReferrerPolicy) -> Self {
        self.referrer_policy = policy;
        self
    }

    /// Sets the Permissions-Policy header.
    ///
    /// # Example
    /// ```ignore
    /// let headers = SecurityHeaders::new()
    ///     .permissions_policy("geolocation=(), microphone=(), camera=()");
    /// ```
    pub fn permissions_policy(mut self, policy: impl Into<String>) -> Self {
        self.permissions_policy = Some(policy.into());
        self
    }

    /// Sets the Cache-Control header for sensitive content.
    pub fn cache_control(mut self, value: impl Into<String>) -> Self {
        self.cache_control = Some(value.into());
        self
    }

    /// Disables X-Content-Type-Options header.
    pub fn disable_content_type_options(mut self) -> Self {
        self.content_type_options = false;
        self
    }

    fn build_hsts_value(&self) -> String {
        let mut value = format!("max-age={}", self.hsts_max_age);
        if self.hsts_include_subdomains {
            value.push_str("; includeSubDomains");
        }
        if self.hsts_preload {
            value.push_str("; preload");
        }
        value
    }
}

impl<S, B> Transform<S, ServiceRequest> for SecurityHeaders
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = SecurityHeadersMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ready(Ok(SecurityHeadersMiddleware {
            service: Rc::new(service),
            config: self.clone(),
        }))
    }
}

/// Security headers middleware service.
pub struct SecurityHeadersMiddleware<S> {
    service: Rc<S>,
    config: SecurityHeaders,
}

impl<S, B> Service<ServiceRequest> for SecurityHeadersMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>>>>;

    fn poll_ready(&self, ctx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let service = Rc::clone(&self.service);
        let config = self.config.clone();

        Box::pin(async move {
            let mut response = service.call(req).await?;

            let headers = response.headers_mut();

            // X-Content-Type-Options
            if config.content_type_options {
                headers.insert(
                    HeaderName::from_static("x-content-type-options"),
                    HeaderValue::from_static("nosniff"),
                );
            }

            // X-Frame-Options
            if let Some(value) = config.frame_options.to_header_value() {
                headers.insert(
                    HeaderName::from_static("x-frame-options"),
                    HeaderValue::from_static(value),
                );
            }

            // X-XSS-Protection (disabled by default, set to 0)
            headers.insert(
                HeaderName::from_static("x-xss-protection"),
                HeaderValue::from_static(if config.xss_protection {
                    "1; mode=block"
                } else {
                    "0"
                }),
            );

            // Content-Security-Policy
            if let Some(ref csp) = config.content_security_policy {
                if let Ok(value) = HeaderValue::from_str(csp) {
                    headers.insert(HeaderName::from_static("content-security-policy"), value);
                }
            }

            // Strict-Transport-Security (HSTS)
            if config.hsts_enabled {
                let hsts_value = config.build_hsts_value();
                if let Ok(value) = HeaderValue::from_str(&hsts_value) {
                    headers.insert(HeaderName::from_static("strict-transport-security"), value);
                }
            }

            // Referrer-Policy
            if let Some(value) = config.referrer_policy.to_header_value() {
                headers.insert(
                    HeaderName::from_static("referrer-policy"),
                    HeaderValue::from_static(value),
                );
            }

            // Permissions-Policy
            if let Some(ref policy) = config.permissions_policy {
                if let Ok(value) = HeaderValue::from_str(policy) {
                    headers.insert(HeaderName::from_static("permissions-policy"), value);
                }
            }

            // Cache-Control
            if let Some(ref cache) = config.cache_control {
                if let Ok(value) = HeaderValue::from_str(cache) {
                    headers.insert(HeaderName::from_static("cache-control"), value);
                }
            }

            Ok(response)
        })
    }
}
