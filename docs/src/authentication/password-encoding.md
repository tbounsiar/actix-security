# Password Encoding

Never store passwords in plain text. Actix Security provides secure password encoding out of the box.

## The PasswordEncoder Trait

```rust
pub trait PasswordEncoder: Clone + Send + Sync + 'static {
    /// Encode a raw password.
    fn encode(&self, raw_password: &str) -> String;

    /// Check if a raw password matches an encoded password.
    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool;
}
```

## Available Encoders

### Argon2PasswordEncoder (Recommended)

Uses the Argon2id algorithm, winner of the Password Hashing Competition.

```rust
use actix_security::http::security::{Argon2PasswordEncoder, PasswordEncoder};

let encoder = Argon2PasswordEncoder::new();

// Encode a password
let encoded = encoder.encode("my_secure_password");
// Output: $argon2id$v=19$m=19456,t=2,p=1$...

// Verify a password
assert!(encoder.matches("my_secure_password", &encoded));
assert!(!encoder.matches("wrong_password", &encoded));
```

**Features:**
- Memory-hard (resistant to GPU attacks)
- Configurable parameters
- Recommended by OWASP

> Requires the `argon2` feature flag (enabled by default).

### NoOpPasswordEncoder

Stores passwords in plain text. **Only use for testing!**

```rust
use actix_security::http::security::{NoOpPasswordEncoder, PasswordEncoder};

let encoder = NoOpPasswordEncoder::new();

let encoded = encoder.encode("password");
assert_eq!(encoded, "password"); // No encoding!

assert!(encoder.matches("password", "password"));
```

> ⚠️ **Warning**: Never use `NoOpPasswordEncoder` in production!

### DelegatingPasswordEncoder

Supports multiple encoding formats, useful for password migration.

```rust
use actix_security::http::security::{
    DelegatingPasswordEncoder, Argon2PasswordEncoder, NoOpPasswordEncoder, PasswordEncoder
};

let encoder = DelegatingPasswordEncoder::new()
    .with_encoder("argon2", Box::new(Argon2PasswordEncoder::new()))
    .with_encoder("noop", Box::new(NoOpPasswordEncoder::new()))
    .default_encoder("argon2");

// New passwords use argon2
let encoded = encoder.encode("password");
// Output: {argon2}$argon2id$v=19$...

// Can still verify old noop passwords
assert!(encoder.matches("old_password", "{noop}old_password"));

// Can verify new argon2 passwords
assert!(encoder.matches("password", &encoded));
```

## Best Practices

### 1. Use Argon2 for New Applications

```rust
let encoder = Argon2PasswordEncoder::new();
```

### 2. Migrate Existing Passwords

Use `DelegatingPasswordEncoder` to gradually migrate:

```rust
let encoder = DelegatingPasswordEncoder::new()
    .with_encoder("argon2", Box::new(Argon2PasswordEncoder::new()))
    .with_encoder("bcrypt", Box::new(BcryptEncoder::new())) // Your old encoder
    .default_encoder("argon2"); // New passwords use argon2
```

### 3. Never Log or Display Passwords

```rust
// Bad - logs the password
log::info!("User {} with password {}", username, password);

// Good - only log non-sensitive data
log::info!("User {} logged in", username);
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `PasswordEncoder` | `PasswordEncoder` trait |
| `BCryptPasswordEncoder` | `Argon2PasswordEncoder` |
| `NoOpPasswordEncoder` | `NoOpPasswordEncoder` |
| `DelegatingPasswordEncoder` | `DelegatingPasswordEncoder` |

**Spring Security:**
```java
@Bean
public PasswordEncoder passwordEncoder() {
    return new BCryptPasswordEncoder();
}
```

**Actix Security:**
```rust
let encoder = Argon2PasswordEncoder::new();
```

## Implementing Custom Encoders

```rust
use actix_security::http::security::PasswordEncoder;

#[derive(Clone)]
pub struct MyCustomEncoder;

impl PasswordEncoder for MyCustomEncoder {
    fn encode(&self, raw_password: &str) -> String {
        // Your encoding logic
        format!("{{custom}}{}", some_hash_function(raw_password))
    }

    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool {
        // Your verification logic
        let expected = self.encode(raw_password);
        constant_time_eq(expected.as_bytes(), encoded_password.as_bytes())
    }
}
```

## Security Considerations

1. **Use strong algorithms** - Argon2id is currently recommended
2. **Use constant-time comparison** - Prevents timing attacks
3. **Salt passwords** - Argon2 does this automatically
4. **Tune parameters** - Adjust memory/time cost based on your hardware
5. **Re-hash on login** - Upgrade old hashes when users log in
