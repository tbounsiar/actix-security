//! Rate Limiting middleware for brute-force protection.
//!
//! Provides configurable rate limiting to protect against brute-force attacks,
//! DDoS attempts, and API abuse.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's `RateLimiter` and integration with Bucket4j.
//!
//! # Example
//!
//! ```ignore
//! use actix_security::http::security::rate_limit::{RateLimiter, RateLimitConfig};
//! use actix_web::{App, HttpServer};
//!
//! let rate_limiter = RateLimiter::new(
//!     RateLimitConfig::new()
//!         .requests_per_second(10)
//!         .burst_size(20)
//! );
//!
//! HttpServer::new(move || {
//!     App::new()
//!         .wrap(rate_limiter.clone())
//!         .route("/api/login", web::post().to(login))
//! })
//! ```

use actix_web::dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::http::header::{HeaderName, HeaderValue};
use actix_web::http::StatusCode;
use actix_web::{Error, HttpResponse};
use futures_util::future::{ok, LocalBoxFuture, Ready};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Rate limit exceeded error response.
#[derive(Debug, Clone)]
pub struct RateLimitExceeded {
    /// Retry after seconds
    pub retry_after: u64,
    /// Custom message
    pub message: String,
}

impl Default for RateLimitExceeded {
    fn default() -> Self {
        Self {
            retry_after: 60,
            message: "Too many requests. Please try again later.".to_string(),
        }
    }
}

/// Type alias for custom key extractor function.
pub type KeyExtractorFn = Arc<dyn Fn(&ServiceRequest) -> Option<String> + Send + Sync>;

/// Strategy for identifying clients for rate limiting.
#[derive(Clone, Default)]
pub enum KeyExtractor {
    /// Rate limit by IP address (default)
    #[default]
    IpAddress,
    /// Rate limit by authenticated user
    User,
    /// Rate limit by custom header
    Header(String),
    /// Rate limit by IP + endpoint combination
    IpAndEndpoint,
    /// Custom key extractor function
    Custom(KeyExtractorFn),
}

impl std::fmt::Debug for KeyExtractor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyExtractor::IpAddress => write!(f, "IpAddress"),
            KeyExtractor::User => write!(f, "User"),
            KeyExtractor::Header(h) => write!(f, "Header({})", h),
            KeyExtractor::IpAndEndpoint => write!(f, "IpAndEndpoint"),
            KeyExtractor::Custom(_) => write!(f, "Custom(<fn>)"),
        }
    }
}

impl KeyExtractor {
    /// Extract the rate limit key from a request.
    pub fn extract(&self, req: &ServiceRequest) -> Option<String> {
        match self {
            KeyExtractor::IpAddress => req
                .connection_info()
                .realip_remote_addr()
                .map(|s| s.to_string()),
            KeyExtractor::User => req
                .headers()
                .get("Authorization")
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
            KeyExtractor::Header(name) => req
                .headers()
                .get(name.as_str())
                .and_then(|h| h.to_str().ok())
                .map(|s| s.to_string()),
            KeyExtractor::IpAndEndpoint => {
                let ip = req.connection_info().realip_remote_addr()?.to_string();
                let path = req.path().to_string();
                Some(format!("{}:{}", ip, path))
            }
            KeyExtractor::Custom(f) => f(req),
        }
    }
}

/// Rate limiting algorithm.
#[derive(Debug, Clone, Default)]
pub enum RateLimitAlgorithm {
    /// Fixed window counter (simpler, less memory)
    #[default]
    FixedWindow,
    /// Sliding window log (more accurate, more memory)
    SlidingWindow,
    /// Token bucket (smooth rate limiting)
    TokenBucket,
}

/// Rate limit configuration.
#[derive(Clone)]
pub struct RateLimitConfig {
    /// Maximum requests per window
    pub max_requests: u64,
    /// Time window duration
    pub window: Duration,
    /// Burst size (for token bucket)
    pub burst_size: u64,
    /// Algorithm to use
    pub algorithm: RateLimitAlgorithm,
    /// Key extractor
    pub key_extractor: KeyExtractor,
    /// Paths to exclude from rate limiting
    pub excluded_paths: Vec<String>,
    /// Whether to add rate limit headers to response
    pub add_headers: bool,
    /// Custom error response
    pub error_response: Option<Arc<dyn Fn(RateLimitExceeded) -> HttpResponse + Send + Sync>>,
}

impl std::fmt::Debug for RateLimitConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitConfig")
            .field("max_requests", &self.max_requests)
            .field("window", &self.window)
            .field("burst_size", &self.burst_size)
            .field("algorithm", &self.algorithm)
            .field("key_extractor", &self.key_extractor)
            .field("excluded_paths", &self.excluded_paths)
            .field("add_headers", &self.add_headers)
            .field("error_response", &self.error_response.as_ref().map(|_| "<fn>"))
            .finish()
    }
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        Self {
            max_requests: 100,
            window: Duration::from_secs(60),
            burst_size: 10,
            algorithm: RateLimitAlgorithm::default(),
            key_extractor: KeyExtractor::default(),
            excluded_paths: vec![],
            add_headers: true,
            error_response: None,
        }
    }
}

impl RateLimitConfig {
    /// Create a new rate limit configuration.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum requests per window.
    pub fn max_requests(mut self, max: u64) -> Self {
        self.max_requests = max;
        self
    }

    /// Set requests per second (convenience method).
    pub fn requests_per_second(mut self, rps: u64) -> Self {
        self.max_requests = rps;
        self.window = Duration::from_secs(1);
        self
    }

    /// Set requests per minute.
    pub fn requests_per_minute(mut self, rpm: u64) -> Self {
        self.max_requests = rpm;
        self.window = Duration::from_secs(60);
        self
    }

    /// Set time window.
    pub fn window(mut self, window: Duration) -> Self {
        self.window = window;
        self
    }

    /// Set burst size for token bucket algorithm.
    pub fn burst_size(mut self, size: u64) -> Self {
        self.burst_size = size;
        self
    }

    /// Set the rate limiting algorithm.
    pub fn algorithm(mut self, algo: RateLimitAlgorithm) -> Self {
        self.algorithm = algo;
        self
    }

    /// Set the key extractor.
    pub fn key_extractor(mut self, extractor: KeyExtractor) -> Self {
        self.key_extractor = extractor;
        self
    }

    /// Exclude paths from rate limiting.
    pub fn exclude_paths(mut self, paths: Vec<&str>) -> Self {
        self.excluded_paths = paths.into_iter().map(String::from).collect();
        self
    }

    /// Whether to add rate limit headers.
    pub fn add_headers(mut self, add: bool) -> Self {
        self.add_headers = add;
        self
    }

    /// Set custom error response handler.
    pub fn error_response<F>(mut self, handler: F) -> Self
    where
        F: Fn(RateLimitExceeded) -> HttpResponse + Send + Sync + 'static,
    {
        self.error_response = Some(Arc::new(handler));
        self
    }

    /// Create a strict configuration for login endpoints.
    pub fn strict_login() -> Self {
        Self::new()
            .requests_per_minute(5)
            .burst_size(3)
            .algorithm(RateLimitAlgorithm::SlidingWindow)
    }

    /// Create a lenient configuration for API endpoints.
    pub fn lenient_api() -> Self {
        Self::new()
            .requests_per_minute(1000)
            .burst_size(100)
            .algorithm(RateLimitAlgorithm::TokenBucket)
    }
}

/// Rate limit entry for tracking requests.
#[derive(Debug, Clone)]
struct RateLimitEntry {
    /// Request count in current window
    count: u64,
    /// Window start time
    window_start: Instant,
    /// Request timestamps for sliding window
    timestamps: Vec<Instant>,
    /// Available tokens for token bucket
    tokens: f64,
    /// Last token refill time
    last_refill: Instant,
}

impl RateLimitEntry {
    fn new(config: &RateLimitConfig) -> Self {
        Self {
            count: 0,
            window_start: Instant::now(),
            timestamps: Vec::new(),
            tokens: config.burst_size as f64,
            last_refill: Instant::now(),
        }
    }
}

/// Rate limiter state.
#[derive(Clone)]
pub struct RateLimiterState {
    entries: Arc<RwLock<HashMap<String, RateLimitEntry>>>,
    config: RateLimitConfig,
}

impl RateLimiterState {
    /// Create new rate limiter state.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            entries: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Check if a request should be allowed.
    pub async fn check(&self, key: &str) -> Result<RateLimitInfo, RateLimitExceeded> {
        let mut entries = self.entries.write().await;
        let now = Instant::now();

        let entry = entries
            .entry(key.to_string())
            .or_insert_with(|| RateLimitEntry::new(&self.config));

        match self.config.algorithm {
            RateLimitAlgorithm::FixedWindow => self.check_fixed_window(entry, now),
            RateLimitAlgorithm::SlidingWindow => self.check_sliding_window(entry, now),
            RateLimitAlgorithm::TokenBucket => self.check_token_bucket(entry, now),
        }
    }

    fn check_fixed_window(
        &self,
        entry: &mut RateLimitEntry,
        now: Instant,
    ) -> Result<RateLimitInfo, RateLimitExceeded> {
        // Reset window if expired
        if now.duration_since(entry.window_start) >= self.config.window {
            entry.count = 0;
            entry.window_start = now;
        }

        if entry.count >= self.config.max_requests {
            let reset_time = entry.window_start + self.config.window;
            let retry_after = reset_time.saturating_duration_since(now).as_secs();
            return Err(RateLimitExceeded {
                retry_after,
                message: "Rate limit exceeded".to_string(),
            });
        }

        entry.count += 1;

        let reset_time = entry.window_start + self.config.window;
        Ok(RateLimitInfo {
            limit: self.config.max_requests,
            remaining: self.config.max_requests.saturating_sub(entry.count),
            reset: reset_time.saturating_duration_since(now).as_secs(),
        })
    }

    fn check_sliding_window(
        &self,
        entry: &mut RateLimitEntry,
        now: Instant,
    ) -> Result<RateLimitInfo, RateLimitExceeded> {
        // Remove expired timestamps
        let window_start = now - self.config.window;
        entry.timestamps.retain(|&t| t > window_start);

        if entry.timestamps.len() as u64 >= self.config.max_requests {
            let oldest = entry.timestamps.first().copied().unwrap_or(now);
            let retry_after = (oldest + self.config.window)
                .saturating_duration_since(now)
                .as_secs();
            return Err(RateLimitExceeded {
                retry_after,
                message: "Rate limit exceeded".to_string(),
            });
        }

        entry.timestamps.push(now);

        Ok(RateLimitInfo {
            limit: self.config.max_requests,
            remaining: self.config.max_requests.saturating_sub(entry.timestamps.len() as u64),
            reset: self.config.window.as_secs(),
        })
    }

    fn check_token_bucket(
        &self,
        entry: &mut RateLimitEntry,
        now: Instant,
    ) -> Result<RateLimitInfo, RateLimitExceeded> {
        // Refill tokens based on time elapsed
        let elapsed = now.duration_since(entry.last_refill).as_secs_f64();
        let refill_rate = self.config.max_requests as f64 / self.config.window.as_secs_f64();
        let new_tokens = elapsed * refill_rate;

        entry.tokens = (entry.tokens + new_tokens).min(self.config.burst_size as f64);
        entry.last_refill = now;

        if entry.tokens < 1.0 {
            let tokens_needed = 1.0 - entry.tokens;
            let retry_after = (tokens_needed / refill_rate).ceil() as u64;
            return Err(RateLimitExceeded {
                retry_after,
                message: "Rate limit exceeded".to_string(),
            });
        }

        entry.tokens -= 1.0;

        Ok(RateLimitInfo {
            limit: self.config.max_requests,
            remaining: entry.tokens as u64,
            reset: self.config.window.as_secs(),
        })
    }

    /// Clean up expired entries (call periodically).
    pub async fn cleanup(&self) {
        let mut entries = self.entries.write().await;
        let now = Instant::now();
        let window = self.config.window * 2; // Keep entries for 2x window

        entries.retain(|_, entry| now.duration_since(entry.window_start) < window);
    }
}

/// Rate limit information for headers.
#[derive(Debug, Clone)]
pub struct RateLimitInfo {
    /// Maximum requests allowed
    pub limit: u64,
    /// Remaining requests in current window
    pub remaining: u64,
    /// Seconds until rate limit resets
    pub reset: u64,
}

/// Rate limiter middleware.
#[derive(Clone)]
pub struct RateLimiter {
    state: RateLimiterState,
}

impl RateLimiter {
    /// Create a new rate limiter with the given configuration.
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            state: RateLimiterState::new(config),
        }
    }

    /// Create a rate limiter for login endpoints (strict).
    pub fn for_login() -> Self {
        Self::new(RateLimitConfig::strict_login())
    }

    /// Create a rate limiter for API endpoints (lenient).
    pub fn for_api() -> Self {
        Self::new(RateLimitConfig::lenient_api())
    }

    /// Get the underlying state for manual operations.
    pub fn state(&self) -> &RateLimiterState {
        &self.state
    }
}

impl<S, B> Transform<S, ServiceRequest> for RateLimiter
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Transform = RateLimiterMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(RateLimiterMiddleware {
            service,
            state: self.state.clone(),
        })
    }
}

/// Rate limiter middleware service.
pub struct RateLimiterMiddleware<S> {
    service: S,
    state: RateLimiterState,
}

impl<S, B> Service<ServiceRequest> for RateLimiterMiddleware<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: 'static,
{
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        let state = self.state.clone();
        let config = state.config.clone();

        // Check if path is excluded
        let path = req.path().to_string();
        if config.excluded_paths.iter().any(|p| path.starts_with(p)) {
            let fut = self.service.call(req);
            return Box::pin(fut);
        }

        // Extract key
        let key = match config.key_extractor.extract(&req) {
            Some(k) => k,
            None => {
                // Can't identify client, allow request
                let fut = self.service.call(req);
                return Box::pin(fut);
            }
        };

        let fut = self.service.call(req);
        let add_headers = config.add_headers;
        let error_handler = config.error_response.clone();

        Box::pin(async move {
            // Check rate limit
            match state.check(&key).await {
                Ok(info) => {
                    let mut resp = fut.await?;

                    // Add rate limit headers
                    if add_headers {
                        let headers = resp.headers_mut();
                        if let Ok(v) = HeaderValue::from_str(&info.limit.to_string()) {
                            headers.insert(
                                HeaderName::from_static("x-ratelimit-limit"),
                                v,
                            );
                        }
                        if let Ok(v) = HeaderValue::from_str(&info.remaining.to_string()) {
                            headers.insert(
                                HeaderName::from_static("x-ratelimit-remaining"),
                                v,
                            );
                        }
                        if let Ok(v) = HeaderValue::from_str(&info.reset.to_string()) {
                            headers.insert(
                                HeaderName::from_static("x-ratelimit-reset"),
                                v,
                            );
                        }
                    }

                    Ok(resp)
                }
                Err(exceeded) => {
                    // Rate limit exceeded
                    let response = if let Some(handler) = error_handler {
                        handler(exceeded.clone())
                    } else {
                        HttpResponse::build(StatusCode::TOO_MANY_REQUESTS)
                            .insert_header(("Retry-After", exceeded.retry_after.to_string()))
                            .insert_header(("X-RateLimit-Limit", config.max_requests.to_string()))
                            .insert_header(("X-RateLimit-Remaining", "0"))
                            .body(exceeded.message)
                    };

                    // We need to return the same response type
                    // This is a workaround - the response body type doesn't match
                    Err(actix_web::error::InternalError::from_response(
                        std::io::Error::new(std::io::ErrorKind::Other, "Rate limit exceeded"),
                        response,
                    )
                    .into())
                }
            }
        })
    }
}

/// Builder for endpoint-specific rate limits.
#[derive(Clone, Default)]
pub struct RateLimitBuilder {
    rules: Vec<(String, RateLimitConfig)>,
    default: Option<RateLimitConfig>,
}

impl RateLimitBuilder {
    /// Create a new rate limit builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Add a rate limit rule for a path pattern.
    pub fn add_rule(mut self, pattern: &str, config: RateLimitConfig) -> Self {
        self.rules.push((pattern.to_string(), config));
        self
    }

    /// Set the default rate limit for unmatched paths.
    pub fn default_limit(mut self, config: RateLimitConfig) -> Self {
        self.default = Some(config);
        self
    }

    /// Add strict rate limiting for login endpoints.
    pub fn protect_login(self, path: &str) -> Self {
        self.add_rule(path, RateLimitConfig::strict_login())
    }

    /// Add lenient rate limiting for API endpoints.
    pub fn protect_api(self, path: &str) -> Self {
        self.add_rule(path, RateLimitConfig::lenient_api())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fixed_window_rate_limit() {
        let config = RateLimitConfig::new().max_requests(3).window(Duration::from_secs(60));

        let state = RateLimiterState::new(config);

        // First 3 requests should succeed
        assert!(state.check("test-key").await.is_ok());
        assert!(state.check("test-key").await.is_ok());
        assert!(state.check("test-key").await.is_ok());

        // 4th request should fail
        assert!(state.check("test-key").await.is_err());
    }

    #[tokio::test]
    async fn test_sliding_window_rate_limit() {
        let config = RateLimitConfig::new()
            .max_requests(3)
            .window(Duration::from_secs(60))
            .algorithm(RateLimitAlgorithm::SlidingWindow);

        let state = RateLimiterState::new(config);

        // First 3 requests should succeed
        assert!(state.check("test-key").await.is_ok());
        assert!(state.check("test-key").await.is_ok());
        assert!(state.check("test-key").await.is_ok());

        // 4th request should fail
        assert!(state.check("test-key").await.is_err());
    }

    #[tokio::test]
    async fn test_token_bucket_rate_limit() {
        let config = RateLimitConfig::new()
            .max_requests(10)
            .window(Duration::from_secs(1))
            .burst_size(3)
            .algorithm(RateLimitAlgorithm::TokenBucket);

        let state = RateLimiterState::new(config);

        // Burst of 3 should succeed
        assert!(state.check("test-key").await.is_ok());
        assert!(state.check("test-key").await.is_ok());
        assert!(state.check("test-key").await.is_ok());

        // 4th request should fail (burst exhausted)
        assert!(state.check("test-key").await.is_err());
    }

    #[tokio::test]
    async fn test_different_keys_independent() {
        let config = RateLimitConfig::new().max_requests(2).window(Duration::from_secs(60));

        let state = RateLimiterState::new(config);

        // Key A
        assert!(state.check("key-a").await.is_ok());
        assert!(state.check("key-a").await.is_ok());
        assert!(state.check("key-a").await.is_err());

        // Key B should still have quota
        assert!(state.check("key-b").await.is_ok());
        assert!(state.check("key-b").await.is_ok());
        assert!(state.check("key-b").await.is_err());
    }

    #[test]
    fn test_rate_limit_info() {
        let info = RateLimitInfo {
            limit: 100,
            remaining: 50,
            reset: 30,
        };

        assert_eq!(info.limit, 100);
        assert_eq!(info.remaining, 50);
        assert_eq!(info.reset, 30);
    }

    #[test]
    fn test_config_builder() {
        let config = RateLimitConfig::new()
            .requests_per_minute(60)
            .burst_size(10)
            .add_headers(true)
            .exclude_paths(vec!["/health", "/metrics"]);

        assert_eq!(config.max_requests, 60);
        assert_eq!(config.burst_size, 10);
        assert!(config.add_headers);
        assert_eq!(config.excluded_paths.len(), 2);
    }

    #[test]
    fn test_strict_login_config() {
        let config = RateLimitConfig::strict_login();
        assert_eq!(config.max_requests, 5);
        assert_eq!(config.window, Duration::from_secs(60));
    }

    #[test]
    fn test_lenient_api_config() {
        let config = RateLimitConfig::lenient_api();
        assert_eq!(config.max_requests, 1000);
    }
}
