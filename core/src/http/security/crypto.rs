//! Password encoding utilities.
//!
//! # Spring Security Equivalent
//! `org.springframework.security.crypto.password.PasswordEncoder`
//!
//! # Feature Flags
//! - `argon2`: Enables `Argon2PasswordEncoder` (recommended, default)
//! - `bcrypt`: Enables `BCryptPasswordEncoder` (widely compatible)

#[cfg(feature = "argon2")]
use argon2::password_hash::rand_core::OsRng;
#[cfg(feature = "argon2")]
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
#[cfg(feature = "argon2")]
use argon2::Argon2;

/// Trait for encoding and verifying passwords.
///
/// # Spring Security Equivalent
/// `PasswordEncoder` interface
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::crypto::{PasswordEncoder, Argon2PasswordEncoder};
///
/// let encoder = Argon2PasswordEncoder::new();
/// let hash = encoder.encode("my_password");
/// assert!(encoder.matches("my_password", &hash));
/// ```
pub trait PasswordEncoder: Send + Sync {
    /// Encode the raw password.
    ///
    /// # Spring Equivalent
    /// `PasswordEncoder.encode(CharSequence rawPassword)`
    fn encode(&self, raw_password: &str) -> String;

    /// Verify a raw password against an encoded password.
    ///
    /// # Spring Equivalent
    /// `PasswordEncoder.matches(CharSequence rawPassword, String encodedPassword)`
    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool;

    /// Returns true if the encoded password should be upgraded for better security.
    ///
    /// # Spring Equivalent
    /// `PasswordEncoder.upgradeEncoding(String encodedPassword)`
    fn upgrade_encoding(&self, _encoded_password: &str) -> bool {
        false
    }
}

/// Argon2 password encoder - the recommended encoder for new applications.
///
/// # Spring Security Equivalent
/// `Argon2PasswordEncoder`
///
/// Argon2 is the winner of the Password Hashing Competition and is recommended
/// by OWASP for password storage.
///
/// # Feature Flag
/// Requires the `argon2` feature (enabled by default).
///
/// # Example
/// ```
/// use actix_security_core::http::security::crypto::{PasswordEncoder, Argon2PasswordEncoder};
///
/// let encoder = Argon2PasswordEncoder::new();
/// let hash = encoder.encode("secret_password");
///
/// // Verify correct password
/// assert!(encoder.matches("secret_password", &hash));
///
/// // Verify wrong password
/// assert!(!encoder.matches("wrong_password", &hash));
/// ```
#[cfg(feature = "argon2")]
#[derive(Clone)]
pub struct Argon2PasswordEncoder {
    argon2: Argon2<'static>,
}

#[cfg(feature = "argon2")]
impl Argon2PasswordEncoder {
    /// Creates a new Argon2 password encoder with default settings.
    pub fn new() -> Self {
        Argon2PasswordEncoder {
            argon2: Argon2::default(),
        }
    }
}

#[cfg(feature = "argon2")]
impl Default for Argon2PasswordEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "argon2")]
impl PasswordEncoder for Argon2PasswordEncoder {
    fn encode(&self, raw_password: &str) -> String {
        let salt = SaltString::generate(&mut OsRng);
        self.argon2
            .hash_password(raw_password.as_bytes(), &salt)
            .expect("Failed to hash password")
            .to_string()
    }

    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool {
        match PasswordHash::new(encoded_password) {
            Ok(parsed_hash) => self
                .argon2
                .verify_password(raw_password.as_bytes(), &parsed_hash)
                .is_ok(),
            Err(_) => false,
        }
    }
}

/// BCrypt password encoder - widely compatible with other frameworks.
///
/// # Spring Security Equivalent
/// `BCryptPasswordEncoder`
///
/// BCrypt is a widely-used password hashing algorithm that is compatible with
/// many other frameworks (PHP, Node.js, etc.). Use this when migrating from
/// other systems or for interoperability.
///
/// # Feature Flag
/// Requires the `bcrypt` feature.
///
/// # Example
/// ```ignore
/// use actix_security_core::http::security::crypto::{PasswordEncoder, BCryptPasswordEncoder};
///
/// let encoder = BCryptPasswordEncoder::new();
/// let hash = encoder.encode("secret_password");
///
/// // Verify correct password
/// assert!(encoder.matches("secret_password", &hash));
/// ```
#[cfg(feature = "bcrypt")]
#[derive(Clone)]
pub struct BCryptPasswordEncoder {
    cost: u32,
}

#[cfg(feature = "bcrypt")]
impl BCryptPasswordEncoder {
    /// Creates a new BCrypt password encoder with default cost (12).
    pub fn new() -> Self {
        Self { cost: 12 }
    }

    /// Creates a new BCrypt password encoder with custom cost.
    ///
    /// Cost should be between 4 and 31. Higher values are more secure
    /// but slower. Default is 12.
    pub fn with_cost(cost: u32) -> Self {
        let cost = cost.clamp(4, 31);
        Self { cost }
    }

    /// Create encoder with strength level.
    ///
    /// - `weak`: cost 10 (fast, for development)
    /// - `default`: cost 12 (balanced)
    /// - `strong`: cost 14 (secure, slower)
    pub fn with_strength(strength: &str) -> Self {
        let cost = match strength {
            "weak" => 10,
            "strong" => 14,
            _ => 12,
        };
        Self { cost }
    }
}

#[cfg(feature = "bcrypt")]
impl Default for BCryptPasswordEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "bcrypt")]
impl PasswordEncoder for BCryptPasswordEncoder {
    fn encode(&self, raw_password: &str) -> String {
        bcrypt::hash(raw_password, self.cost).expect("Failed to hash password with bcrypt")
    }

    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool {
        bcrypt::verify(raw_password, encoded_password).unwrap_or(false)
    }

    fn upgrade_encoding(&self, encoded_password: &str) -> bool {
        // Check if the cost in the hash is lower than current setting
        // BCrypt hashes start with $2a$, $2b$, or $2y$ followed by cost
        if encoded_password.starts_with("$2") && encoded_password.len() > 7 {
            // Extract cost from hash (format: $2a$XX$ where XX is cost)
            if let Some(cost_str) = encoded_password.get(4..6) {
                if let Ok(hash_cost) = cost_str.parse::<u32>() {
                    return hash_cost < self.cost;
                }
            }
        }
        true // Invalid hash or unable to parse, recommend re-encoding
    }
}

/// No-op password encoder that stores passwords in plain text.
///
/// # Spring Security Equivalent
/// `NoOpPasswordEncoder`
///
/// # Warning
/// **NEVER use this in production!** This is only for testing/development.
/// Passwords are stored in plain text without any hashing.
///
/// # Example
/// ```
/// use actix_security_core::http::security::crypto::{PasswordEncoder, NoOpPasswordEncoder};
///
/// let encoder = NoOpPasswordEncoder;
/// let encoded = encoder.encode("password");
/// assert_eq!(encoded, "password"); // Plain text!
/// assert!(encoder.matches("password", &encoded));
/// ```
#[derive(Clone, Copy, Default)]
pub struct NoOpPasswordEncoder;

impl PasswordEncoder for NoOpPasswordEncoder {
    fn encode(&self, raw_password: &str) -> String {
        raw_password.to_string()
    }

    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool {
        raw_password == encoded_password
    }
}

/// Default encoding algorithm for DelegatingPasswordEncoder.
#[derive(Debug, Clone, Copy, Default)]
pub enum DefaultEncoder {
    /// Use Argon2 (recommended)
    #[default]
    Argon2,
    /// Use BCrypt (compatible)
    BCrypt,
}

/// Delegating password encoder that supports multiple encoding formats.
///
/// # Spring Security Equivalent
/// `DelegatingPasswordEncoder`
///
/// This encoder can verify passwords encoded with different algorithms
/// by detecting the encoding format from a prefix in the stored hash.
///
/// Supported formats:
/// - `{argon2}hash` - Argon2 encoded password
/// - `{bcrypt}hash` - BCrypt encoded password
/// - `{noop}plain` - Plain text (for testing only!)
///
/// # Feature Flag
/// Requires the `argon2` feature (enabled by default).
///
/// # Example
/// ```
/// use actix_security_core::http::security::crypto::{PasswordEncoder, DelegatingPasswordEncoder};
///
/// let encoder = DelegatingPasswordEncoder::new();
///
/// // Encode with default (argon2)
/// let hash = encoder.encode("password");
/// assert!(hash.starts_with("{argon2}"));
///
/// // Can verify both formats
/// assert!(encoder.matches("password", &hash));
/// assert!(encoder.matches("plain", "{noop}plain"));
/// ```
#[cfg(feature = "argon2")]
#[derive(Clone)]
pub struct DelegatingPasswordEncoder {
    argon2: Argon2PasswordEncoder,
    #[cfg(feature = "bcrypt")]
    bcrypt: BCryptPasswordEncoder,
    default_encoder: DefaultEncoder,
}

#[cfg(feature = "argon2")]
impl DelegatingPasswordEncoder {
    /// Creates a new delegating password encoder.
    /// Default encoding is Argon2.
    pub fn new() -> Self {
        DelegatingPasswordEncoder {
            argon2: Argon2PasswordEncoder::new(),
            #[cfg(feature = "bcrypt")]
            bcrypt: BCryptPasswordEncoder::new(),
            default_encoder: DefaultEncoder::Argon2,
        }
    }

    /// Set the default encoder to use for new passwords.
    pub fn default_encoder(mut self, encoder: DefaultEncoder) -> Self {
        self.default_encoder = encoder;
        self
    }

    /// Use BCrypt as the default encoder.
    #[cfg(feature = "bcrypt")]
    pub fn use_bcrypt(self) -> Self {
        self.default_encoder(DefaultEncoder::BCrypt)
    }
}

#[cfg(feature = "argon2")]
impl Default for DelegatingPasswordEncoder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "argon2")]
impl PasswordEncoder for DelegatingPasswordEncoder {
    fn encode(&self, raw_password: &str) -> String {
        match self.default_encoder {
            DefaultEncoder::Argon2 => {
                format!("{{argon2}}{}", self.argon2.encode(raw_password))
            }
            #[cfg(feature = "bcrypt")]
            DefaultEncoder::BCrypt => {
                format!("{{bcrypt}}{}", self.bcrypt.encode(raw_password))
            }
            #[cfg(not(feature = "bcrypt"))]
            DefaultEncoder::BCrypt => {
                // Fall back to argon2 if bcrypt not available
                format!("{{argon2}}{}", self.argon2.encode(raw_password))
            }
        }
    }

    fn matches(&self, raw_password: &str, encoded_password: &str) -> bool {
        if let Some(hash) = encoded_password.strip_prefix("{argon2}") {
            self.argon2.matches(raw_password, hash)
        } else if let Some(plain) = encoded_password.strip_prefix("{noop}") {
            raw_password == plain
        } else {
            #[cfg(feature = "bcrypt")]
            if let Some(hash) = encoded_password.strip_prefix("{bcrypt}") {
                return self.bcrypt.matches(raw_password, hash);
            }
            // Legacy: try bcrypt without prefix (common in migrations)
            #[cfg(feature = "bcrypt")]
            if encoded_password.starts_with("$2") {
                return self.bcrypt.matches(raw_password, encoded_password);
            }
            // Legacy: assume plain text for backward compatibility
            raw_password == encoded_password
        }
    }

    fn upgrade_encoding(&self, encoded_password: &str) -> bool {
        // Recommend upgrade if not using the preferred encoder
        match self.default_encoder {
            DefaultEncoder::Argon2 => !encoded_password.starts_with("{argon2}"),
            DefaultEncoder::BCrypt => !encoded_password.starts_with("{bcrypt}"),
        }
    }
}

#[cfg(all(test, feature = "argon2"))]
mod tests {
    use super::*;

    #[test]
    fn test_argon2_encoder() {
        let encoder = Argon2PasswordEncoder::new();
        let password = "test_password_123";

        let hash = encoder.encode(password);

        // Hash should not equal plain password
        assert_ne!(hash, password);

        // Should verify correctly
        assert!(encoder.matches(password, &hash));
        assert!(!encoder.matches("wrong_password", &hash));
    }

    #[test]
    fn test_noop_encoder() {
        let encoder = NoOpPasswordEncoder;
        let password = "plain_password";

        let encoded = encoder.encode(password);
        assert_eq!(encoded, password);
        assert!(encoder.matches(password, &encoded));
    }

    #[test]
    fn test_delegating_encoder() {
        let encoder = DelegatingPasswordEncoder::new();

        // Test argon2 encoding
        let hash = encoder.encode("password");
        assert!(hash.starts_with("{argon2}"));
        assert!(encoder.matches("password", &hash));

        // Test noop format
        assert!(encoder.matches("plain", "{noop}plain"));

        // Test upgrade recommendation
        assert!(encoder.upgrade_encoding("{noop}plain"));
        assert!(!encoder.upgrade_encoding(&hash));
    }
}
