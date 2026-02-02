# Account Locking

Account locking automatically locks user accounts after multiple failed login attempts, protecting against brute-force attacks.

## Enabling Account Locking

Add the `account-lock` feature to your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["account-lock"] }
```

## Basic Usage

```rust
use actix_security::http::security::{
    AccountLockManager, LockConfig, check_login
};
use std::time::Duration;

// Create lock manager
let lock_manager = AccountLockManager::new(
    LockConfig::new()
        .max_attempts(5)
        .lockout_duration(Duration::from_secs(15 * 60))
);

// In your login handler:
async fn login(
    form: web::Form<LoginForm>,
    lock_manager: web::Data<AccountLockManager>,
) -> impl Responder {
    let username = &form.username;

    // Check if account is locked
    let result = check_login(&lock_manager, username).await;
    if !result.is_allowed() {
        return HttpResponse::Forbidden().body("Account locked");
    }

    // Attempt authentication
    if authenticate(username, &form.password) {
        lock_manager.record_success(username).await;
        HttpResponse::Ok().body("Logged in")
    } else {
        lock_manager.record_failure(username).await;
        let remaining = lock_manager.get_remaining_attempts(username).await;
        HttpResponse::Unauthorized()
            .body(format!("{} attempts remaining", remaining))
    }
}
```

## Configuration Options

```rust
LockConfig::new()
    // Maximum failed attempts before lock
    .max_attempts(5)

    // How long to lock the account
    .lockout_duration(Duration::from_secs(15 * 60))

    // Reset counter on successful login
    .reset_on_success(true)

    // Progressive lockout (doubles duration each time)
    .progressive_lockout(true)
```

## Preset Configurations

```rust
// Strict: 3 attempts, 30 minute lockout
LockConfig::strict()

// Lenient: 10 attempts, 5 minute lockout
LockConfig::lenient()
```

## Lock Status

```rust
use actix_security::http::security::LockStatus;

let status = lock_manager.get_lock_status(&username).await;

match status {
    LockStatus::Unlocked => { /* Account is accessible */ }
    LockStatus::TemporarilyLocked { until, reason } => {
        // Locked until specified time
    }
    LockStatus::PermanentlyLocked { reason } => {
        // Requires admin intervention
    }
}
```

## IP Address Tracking

Track which IP addresses have attempted to access an account:

```rust
// Record failure with IP
lock_manager
    .record_failure_with_ip(&username, Some(&ip_address))
    .await;

// Get account statistics
let stats = lock_manager.get_account_stats(&username).await;
println!("Failed attempts: {}", stats.failed_attempts);
println!("Associated IPs: {:?}", stats.associated_ips);
```

## Manual Lock/Unlock

```rust
// Manually unlock an account
lock_manager.unlock(&username).await;

// Permanently lock an account
lock_manager
    .lock_permanently(&username, "Suspicious activity detected")
    .await;
```

## Check Result

The `check_login` function returns detailed information:

```rust
let result = check_login(&lock_manager, &username).await;

match result {
    LoginCheckResult::Allowed { remaining_attempts } => {
        println!("{} attempts remaining", remaining_attempts);
    }
    LoginCheckResult::Blocked { message, unlock_time } => {
        println!("Blocked: {}", message);
        if let Some(time) = unlock_time {
            println!("Unlocks at: {:?}", time);
        }
    }
}
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `LockedException` | `LockStatus::TemporarilyLocked` |
| `AccountStatusUserDetailsChecker` | `check_login()` |
| `JdbcUserDetailsManager.lockUser()` | `lock_permanently()` |
