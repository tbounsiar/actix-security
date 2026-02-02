//! Password Encoder tests.
//!
//! Tests for Argon2 and other password encoders.

use actix_security_core::http::security::{Argon2PasswordEncoder, PasswordEncoder};

#[actix_web::test]
async fn test_argon2_password_encoder() {
    let encoder = Argon2PasswordEncoder::new();
    let password = "test_password_123";

    let hash = encoder.encode(password);

    // Hash should not equal plain password
    assert_ne!(hash, password);

    // Should verify correctly
    assert!(encoder.matches(password, &hash));
    assert!(!encoder.matches("wrong_password", &hash));
}

#[actix_web::test]
async fn test_password_hashes_are_different() {
    let encoder = Argon2PasswordEncoder::new();
    let password = "same_password";

    let hash1 = encoder.encode(password);
    let hash2 = encoder.encode(password);

    // Different salts should produce different hashes
    assert_ne!(hash1, hash2);

    // Both should still verify
    assert!(encoder.matches(password, &hash1));
    assert!(encoder.matches(password, &hash2));
}
