//! Account locking and login attempt tracking.
//!
//! Provides protection against brute-force attacks by tracking failed login
//! attempts and temporarily locking accounts.
//!
//! # Spring Security Equivalent
//! Similar to Spring Security's `AuthenticationFailureHandler` with
//! `LockoutPolicy` and `AccountStatusUserDetailsChecker`.
//!
//! # Example
//!
//! ```ignore
//! use actix_security::http::security::account::{AccountLockManager, LockConfig};
//!
//! let lock_manager = AccountLockManager::new(
//!     LockConfig::new()
//!         .max_attempts(5)
//!         .lockout_duration(Duration::from_secs(900)) // 15 minutes
//! );
//!
//! // On login attempt
//! if lock_manager.is_locked("user@example.com").await {
//!     return Err(AuthError::AccountLocked);
//! }
//!
//! // On failed login
//! lock_manager.record_failure("user@example.com").await;
//!
//! // On successful login
//! lock_manager.record_success("user@example.com").await;
//! ```

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::sync::RwLock;

/// Account lock status.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LockStatus {
    /// Account is not locked
    Unlocked,
    /// Account is temporarily locked
    TemporarilyLocked {
        /// When the lock expires
        until: Instant,
        /// Reason for locking
        reason: String,
    },
    /// Account is permanently locked (requires admin intervention)
    PermanentlyLocked {
        /// Reason for locking
        reason: String,
    },
}

impl LockStatus {
    /// Check if the account is locked.
    pub fn is_locked(&self) -> bool {
        match self {
            LockStatus::Unlocked => false,
            LockStatus::TemporarilyLocked { until, .. } => Instant::now() < *until,
            LockStatus::PermanentlyLocked { .. } => true,
        }
    }

    /// Get remaining lock duration if temporarily locked.
    pub fn remaining_lock_duration(&self) -> Option<Duration> {
        match self {
            LockStatus::TemporarilyLocked { until, .. } => {
                let now = Instant::now();
                if now < *until {
                    Some(*until - now)
                } else {
                    None
                }
            }
            _ => None,
        }
    }
}

/// Account lock configuration.
#[derive(Debug, Clone)]
pub struct LockConfig {
    /// Maximum failed attempts before locking
    pub max_attempts: u32,
    /// Duration to lock the account
    pub lockout_duration: Duration,
    /// Window for counting failed attempts
    pub attempt_window: Duration,
    /// Whether to reset attempts after successful login
    pub reset_on_success: bool,
    /// Whether to use progressive lockout (longer each time)
    pub progressive_lockout: bool,
    /// Maximum lockout duration for progressive lockout
    pub max_lockout_duration: Duration,
    /// Number of consecutive lockouts before permanent lock
    pub permanent_lock_threshold: Option<u32>,
}

impl Default for LockConfig {
    fn default() -> Self {
        Self {
            max_attempts: 5,
            lockout_duration: Duration::from_secs(15 * 60), // 15 minutes
            attempt_window: Duration::from_secs(60 * 60),   // 1 hour
            reset_on_success: true,
            progressive_lockout: true,
            max_lockout_duration: Duration::from_secs(24 * 60 * 60), // 24 hours
            permanent_lock_threshold: Some(10),
        }
    }
}

impl LockConfig {
    /// Create a new lock configuration with default values.
    pub fn new() -> Self {
        Self::default()
    }

    /// Set maximum failed attempts before locking.
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Set lockout duration.
    pub fn lockout_duration(mut self, duration: Duration) -> Self {
        self.lockout_duration = duration;
        self
    }

    /// Set the window for counting failed attempts.
    pub fn attempt_window(mut self, window: Duration) -> Self {
        self.attempt_window = window;
        self
    }

    /// Set whether to reset attempts on successful login.
    pub fn reset_on_success(mut self, reset: bool) -> Self {
        self.reset_on_success = reset;
        self
    }

    /// Enable/disable progressive lockout.
    pub fn progressive_lockout(mut self, enabled: bool) -> Self {
        self.progressive_lockout = enabled;
        self
    }

    /// Set maximum lockout duration for progressive lockout.
    pub fn max_lockout_duration(mut self, duration: Duration) -> Self {
        self.max_lockout_duration = duration;
        self
    }

    /// Set threshold for permanent lock (None to disable).
    pub fn permanent_lock_threshold(mut self, threshold: Option<u32>) -> Self {
        self.permanent_lock_threshold = threshold;
        self
    }

    /// Create a strict configuration for sensitive applications.
    pub fn strict() -> Self {
        Self::new()
            .max_attempts(3)
            .lockout_duration(Duration::from_secs(30 * 60)) // 30 minutes
            .permanent_lock_threshold(Some(5))
    }

    /// Create a lenient configuration for user-friendly applications.
    pub fn lenient() -> Self {
        Self::new()
            .max_attempts(10)
            .lockout_duration(Duration::from_secs(5 * 60)) // 5 minutes
            .progressive_lockout(false)
            .permanent_lock_threshold(None)
    }
}

/// Failed attempt record.
#[derive(Debug, Clone)]
struct AttemptRecord {
    /// Timestamps of failed attempts
    attempts: Vec<Instant>,
    /// Number of times account has been locked
    lock_count: u32,
    /// Current lock status
    lock_status: LockStatus,
    /// IP addresses associated with failures
    ip_addresses: Vec<String>,
}

impl AttemptRecord {
    fn new() -> Self {
        Self {
            attempts: Vec::new(),
            lock_count: 0,
            lock_status: LockStatus::Unlocked,
            ip_addresses: Vec::new(),
        }
    }
}

/// Account lock manager for tracking failed attempts and locking accounts.
#[derive(Clone)]
pub struct AccountLockManager {
    records: Arc<RwLock<HashMap<String, AttemptRecord>>>,
    config: LockConfig,
}

impl AccountLockManager {
    /// Create a new account lock manager with the given configuration.
    pub fn new(config: LockConfig) -> Self {
        Self {
            records: Arc::new(RwLock::new(HashMap::new())),
            config,
        }
    }

    /// Create with default configuration.
    pub fn with_defaults() -> Self {
        Self::new(LockConfig::default())
    }

    /// Check if an account is locked.
    pub async fn is_locked(&self, identifier: &str) -> bool {
        let records = self.records.read().await;
        if let Some(record) = records.get(identifier) {
            record.lock_status.is_locked()
        } else {
            false
        }
    }

    /// Get the lock status for an account.
    pub async fn get_lock_status(&self, identifier: &str) -> LockStatus {
        let records = self.records.read().await;
        if let Some(record) = records.get(identifier) {
            record.lock_status.clone()
        } else {
            LockStatus::Unlocked
        }
    }

    /// Get the number of recent failed attempts.
    pub async fn get_failed_attempts(&self, identifier: &str) -> u32 {
        let records = self.records.read().await;
        if let Some(record) = records.get(identifier) {
            let cutoff = Instant::now() - self.config.attempt_window;
            record.attempts.iter().filter(|&&t| t > cutoff).count() as u32
        } else {
            0
        }
    }

    /// Get remaining attempts before lockout.
    pub async fn get_remaining_attempts(&self, identifier: &str) -> u32 {
        let failed = self.get_failed_attempts(identifier).await;
        self.config.max_attempts.saturating_sub(failed)
    }

    /// Record a failed login attempt.
    ///
    /// Returns the new lock status after recording the failure.
    pub async fn record_failure(&self, identifier: &str) -> LockStatus {
        self.record_failure_with_ip(identifier, None).await
    }

    /// Record a failed login attempt with IP address.
    pub async fn record_failure_with_ip(
        &self,
        identifier: &str,
        ip_address: Option<&str>,
    ) -> LockStatus {
        let mut records = self.records.write().await;
        let record = records
            .entry(identifier.to_string())
            .or_insert_with(AttemptRecord::new);

        // Check if already permanently locked
        if matches!(record.lock_status, LockStatus::PermanentlyLocked { .. }) {
            return record.lock_status.clone();
        }

        // Check if temporarily locked and lock has expired
        if let LockStatus::TemporarilyLocked { until, .. } = &record.lock_status {
            if Instant::now() >= *until {
                record.lock_status = LockStatus::Unlocked;
            }
        }

        let now = Instant::now();

        // Clean up old attempts outside the window
        let cutoff = now - self.config.attempt_window;
        record.attempts.retain(|&t| t > cutoff);

        // Record this attempt
        record.attempts.push(now);

        // Record IP if provided
        if let Some(ip) = ip_address {
            if !record.ip_addresses.contains(&ip.to_string()) {
                record.ip_addresses.push(ip.to_string());
            }
        }

        // Check if we should lock
        if record.attempts.len() as u32 >= self.config.max_attempts {
            record.lock_count += 1;

            // Check for permanent lock
            if let Some(threshold) = self.config.permanent_lock_threshold {
                if record.lock_count >= threshold {
                    record.lock_status = LockStatus::PermanentlyLocked {
                        reason: format!(
                            "Too many failed attempts ({} lockouts)",
                            record.lock_count
                        ),
                    };
                    return record.lock_status.clone();
                }
            }

            // Calculate lockout duration
            let duration = if self.config.progressive_lockout {
                let multiplier = 2u64.pow(record.lock_count.saturating_sub(1));
                let progressive = self.config.lockout_duration * multiplier as u32;
                progressive.min(self.config.max_lockout_duration)
            } else {
                self.config.lockout_duration
            };

            record.lock_status = LockStatus::TemporarilyLocked {
                until: now + duration,
                reason: format!(
                    "Too many failed login attempts ({} attempts)",
                    record.attempts.len()
                ),
            };

            // Clear attempts after locking
            record.attempts.clear();
        }

        record.lock_status.clone()
    }

    /// Record a successful login.
    ///
    /// This resets the failed attempt counter if `reset_on_success` is enabled.
    pub async fn record_success(&self, identifier: &str) {
        if !self.config.reset_on_success {
            return;
        }

        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(identifier) {
            // Only reset if not permanently locked
            if !matches!(record.lock_status, LockStatus::PermanentlyLocked { .. }) {
                record.attempts.clear();
                record.lock_status = LockStatus::Unlocked;
                // Note: we don't reset lock_count to track total lockouts
            }
        }
    }

    /// Manually unlock an account.
    pub async fn unlock(&self, identifier: &str) {
        let mut records = self.records.write().await;
        if let Some(record) = records.get_mut(identifier) {
            record.attempts.clear();
            record.lock_status = LockStatus::Unlocked;
        }
    }

    /// Manually lock an account permanently.
    pub async fn lock_permanently(&self, identifier: &str, reason: &str) {
        let mut records = self.records.write().await;
        let record = records
            .entry(identifier.to_string())
            .or_insert_with(AttemptRecord::new);
        record.lock_status = LockStatus::PermanentlyLocked {
            reason: reason.to_string(),
        };
    }

    /// Get statistics for an account.
    pub async fn get_account_stats(&self, identifier: &str) -> AccountStats {
        let records = self.records.read().await;
        if let Some(record) = records.get(identifier) {
            let cutoff = Instant::now() - self.config.attempt_window;
            let recent_attempts = record.attempts.iter().filter(|&&t| t > cutoff).count() as u32;

            AccountStats {
                total_lockouts: record.lock_count,
                recent_failed_attempts: recent_attempts,
                is_locked: record.lock_status.is_locked(),
                remaining_lock_duration: record.lock_status.remaining_lock_duration(),
                associated_ips: record.ip_addresses.clone(),
            }
        } else {
            AccountStats::default()
        }
    }

    /// Clean up expired records.
    pub async fn cleanup(&self) {
        let mut records = self.records.write().await;
        let now = Instant::now();
        let cleanup_threshold = self.config.attempt_window * 2;

        records.retain(|_, record| {
            // Keep if locked
            if record.lock_status.is_locked() {
                return true;
            }
            // Keep if has recent attempts
            if let Some(last) = record.attempts.last() {
                return now - *last < cleanup_threshold;
            }
            // Remove if no attempts and not locked
            false
        });
    }
}

impl Default for AccountLockManager {
    fn default() -> Self {
        Self::with_defaults()
    }
}

/// Account statistics.
#[derive(Debug, Clone, Default)]
pub struct AccountStats {
    /// Total number of times this account has been locked.
    pub total_lockouts: u32,
    /// Number of recent failed attempts.
    pub recent_failed_attempts: u32,
    /// Whether the account is currently locked.
    pub is_locked: bool,
    /// Remaining lock duration if temporarily locked.
    pub remaining_lock_duration: Option<Duration>,
    /// IP addresses associated with failed attempts.
    pub associated_ips: Vec<String>,
}

/// Result of a login check.
#[derive(Debug, Clone)]
pub enum LoginCheckResult {
    /// Login allowed
    Allowed {
        /// Remaining attempts before lockout
        remaining_attempts: u32,
    },
    /// Login blocked due to account lock
    Blocked {
        /// Lock status
        status: LockStatus,
        /// Message to display
        message: String,
    },
}

impl LoginCheckResult {
    /// Check if login is allowed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, LoginCheckResult::Allowed { .. })
    }
}

/// Helper function to check login and return detailed result.
pub async fn check_login(manager: &AccountLockManager, identifier: &str) -> LoginCheckResult {
    let status = manager.get_lock_status(identifier).await;

    match status {
        LockStatus::Unlocked => {
            let remaining = manager.get_remaining_attempts(identifier).await;
            LoginCheckResult::Allowed {
                remaining_attempts: remaining,
            }
        }
        LockStatus::TemporarilyLocked { until, ref reason } => {
            let remaining = until.saturating_duration_since(Instant::now());
            let minutes = remaining.as_secs() / 60;
            let message = format!(
                "Account temporarily locked: {}. Try again in {} minutes.",
                reason, minutes
            );
            LoginCheckResult::Blocked {
                status: LockStatus::TemporarilyLocked {
                    until,
                    reason: reason.clone(),
                },
                message,
            }
        }
        LockStatus::PermanentlyLocked { ref reason } => {
            let message = format!(
                "Account permanently locked: {}. Please contact support.",
                reason
            );
            LoginCheckResult::Blocked {
                status: LockStatus::PermanentlyLocked {
                    reason: reason.clone(),
                },
                message,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
    async fn test_permanent_lock() {
        let config = LockConfig::new()
            .max_attempts(2)
            .lockout_duration(Duration::from_secs(1))
            .permanent_lock_threshold(Some(2));
        let manager = AccountLockManager::new(config);

        // First lockout
        manager.record_failure("user@example.com").await;
        manager.record_failure("user@example.com").await;

        // Wait for lock to expire
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Second lockout should trigger permanent lock
        manager.record_failure("user@example.com").await;
        manager.record_failure("user@example.com").await;

        let status = manager.get_lock_status("user@example.com").await;
        assert!(matches!(status, LockStatus::PermanentlyLocked { .. }));
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
            until: Instant::now() + Duration::from_secs(60),
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
}
