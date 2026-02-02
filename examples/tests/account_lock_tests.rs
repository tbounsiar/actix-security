//! Integration tests for account locking.

use actix_security::http::security::account::{
    check_login, AccountLockManager, LockConfig, LockStatus, LoginCheckResult,
};
use std::time::Duration;

#[tokio::test]
async fn test_account_not_locked_initially() {
    let manager = AccountLockManager::with_defaults();
    assert!(!manager.is_locked("user@example.com").await);
}

#[tokio::test]
async fn test_lock_after_max_attempts() {
    let config = LockConfig::new()
        .max_attempts(3)
        .lockout_duration(Duration::from_secs(60));
    let manager = AccountLockManager::new(config);

    // First 2 attempts should not lock
    manager.record_failure("user@example.com").await;
    manager.record_failure("user@example.com").await;
    assert!(!manager.is_locked("user@example.com").await);

    // 3rd attempt should lock
    manager.record_failure("user@example.com").await;
    assert!(manager.is_locked("user@example.com").await);
}

#[tokio::test]
async fn test_reset_on_success() {
    let config = LockConfig::new().max_attempts(3).reset_on_success(true);
    let manager = AccountLockManager::new(config);

    // Record 2 failures
    manager.record_failure("user@example.com").await;
    manager.record_failure("user@example.com").await;
    assert_eq!(manager.get_failed_attempts("user@example.com").await, 2);

    // Success should reset
    manager.record_success("user@example.com").await;
    assert_eq!(manager.get_failed_attempts("user@example.com").await, 0);
}

#[tokio::test]
async fn test_manual_unlock() {
    let config = LockConfig::new()
        .max_attempts(2)
        .lockout_duration(Duration::from_secs(3600));
    let manager = AccountLockManager::new(config);

    // Lock the account
    manager.record_failure("user@example.com").await;
    manager.record_failure("user@example.com").await;
    assert!(manager.is_locked("user@example.com").await);

    // Manual unlock
    manager.unlock("user@example.com").await;
    assert!(!manager.is_locked("user@example.com").await);
}

#[tokio::test]
async fn test_remaining_attempts() {
    let config = LockConfig::new().max_attempts(5);
    let manager = AccountLockManager::new(config);

    assert_eq!(manager.get_remaining_attempts("user@example.com").await, 5);

    manager.record_failure("user@example.com").await;
    assert_eq!(manager.get_remaining_attempts("user@example.com").await, 4);

    manager.record_failure("user@example.com").await;
    manager.record_failure("user@example.com").await;
    assert_eq!(manager.get_remaining_attempts("user@example.com").await, 2);
}

#[tokio::test]
async fn test_ip_tracking() {
    let manager = AccountLockManager::with_defaults();

    manager
        .record_failure_with_ip("user@example.com", Some("192.168.1.1"))
        .await;
    manager
        .record_failure_with_ip("user@example.com", Some("10.0.0.1"))
        .await;

    let stats = manager.get_account_stats("user@example.com").await;
    assert_eq!(stats.associated_ips.len(), 2);
    assert!(stats.associated_ips.contains(&"192.168.1.1".to_string()));
    assert!(stats.associated_ips.contains(&"10.0.0.1".to_string()));
}

#[test]
fn test_lock_status() {
    let unlocked = LockStatus::Unlocked;
    assert!(!unlocked.is_locked());

    let temp_locked = LockStatus::TemporarilyLocked {
        until: std::time::Instant::now() + Duration::from_secs(60),
        reason: "test".to_string(),
    };
    assert!(temp_locked.is_locked());

    let perm_locked = LockStatus::PermanentlyLocked {
        reason: "test".to_string(),
    };
    assert!(perm_locked.is_locked());
}

#[test]
fn test_config_builder() {
    let config = LockConfig::new()
        .max_attempts(10)
        .lockout_duration(Duration::from_secs(300))
        .progressive_lockout(false);

    assert_eq!(config.max_attempts, 10);
    assert_eq!(config.lockout_duration, Duration::from_secs(300));
    assert!(!config.progressive_lockout);
}

#[test]
fn test_strict_config() {
    let config = LockConfig::strict();
    assert_eq!(config.max_attempts, 3);
    assert_eq!(config.lockout_duration, Duration::from_secs(30 * 60));
}

#[test]
fn test_lenient_config() {
    let config = LockConfig::lenient();
    assert_eq!(config.max_attempts, 10);
    assert!(!config.progressive_lockout);
}

#[tokio::test]
async fn test_check_login_allowed() {
    let manager = AccountLockManager::with_defaults();

    let result = check_login(&manager, "new_user").await;
    assert!(result.is_allowed());

    if let LoginCheckResult::Allowed { remaining_attempts } = result {
        assert_eq!(remaining_attempts, 5); // Default max_attempts
    } else {
        panic!("Expected Allowed result");
    }
}

#[tokio::test]
async fn test_check_login_blocked() {
    let config = LockConfig::new()
        .max_attempts(2)
        .lockout_duration(Duration::from_secs(60));
    let manager = AccountLockManager::new(config);

    // Lock the account
    manager.record_failure("user@example.com").await;
    manager.record_failure("user@example.com").await;

    let result = check_login(&manager, "user@example.com").await;
    assert!(!result.is_allowed());

    if let LoginCheckResult::Blocked { message, .. } = result {
        assert!(message.contains("locked"));
    } else {
        panic!("Expected Blocked result");
    }
}

#[tokio::test]
async fn test_permanent_lock() {
    let manager = AccountLockManager::with_defaults();

    manager
        .lock_permanently("bad_user", "Suspicious activity")
        .await;

    let status = manager.get_lock_status("bad_user").await;
    assert!(matches!(status, LockStatus::PermanentlyLocked { .. }));

    // Cannot unlock via record_success
    manager.record_success("bad_user").await;
    assert!(manager.is_locked("bad_user").await);
}
