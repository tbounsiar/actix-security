//! Integration tests for rate limiting.

use actix_security::http::security::rate_limit::{
    KeyExtractor, RateLimitAlgorithm, RateLimitConfig, RateLimiter, RateLimiterState,
};
use std::time::Duration;

#[tokio::test]
async fn test_fixed_window_rate_limit() {
    let config = RateLimitConfig::new()
        .max_requests(3)
        .window(Duration::from_secs(60))
        .algorithm(RateLimitAlgorithm::FixedWindow);

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
    let config = RateLimitConfig::new()
        .max_requests(2)
        .window(Duration::from_secs(60));

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

#[test]
fn test_key_extractor_debug() {
    let extractor = KeyExtractor::IpAddress;
    assert_eq!(format!("{:?}", extractor), "IpAddress");

    let extractor = KeyExtractor::Header("X-API-Key".to_string());
    assert!(format!("{:?}", extractor).contains("Header"));
}

#[tokio::test]
async fn test_rate_limit_info() {
    let config = RateLimitConfig::new()
        .max_requests(10)
        .window(Duration::from_secs(60));

    let state = RateLimiterState::new(config);

    let info = state.check("test-key").await.unwrap();
    assert_eq!(info.limit, 10);
    assert_eq!(info.remaining, 9);
}
