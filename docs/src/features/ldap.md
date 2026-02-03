# LDAP Authentication

LDAP authentication allows you to authenticate users against an LDAP or Active Directory server.

## Enabling LDAP Authentication

Add the `ldap` feature to your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["ldap"] }
```

## Basic Usage

```rust
use actix_security::http::security::{LdapAuthenticator, LdapConfig, MockLdapClient};
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let ldap_config = LdapConfig::new("ldap://ldap.example.com:389")
        .base_dn("dc=example,dc=com")
        .user_search_filter("(uid={0})")
        .bind_dn("cn=admin,dc=example,dc=com")
        .bind_password("admin_password");

    // Create authenticator with a client that implements LdapOperations
    // For testing, use MockLdapClient; for production, use a real LDAP client
    let client = MockLdapClient::new();
    let authenticator = LdapAuthenticator::new(ldap_config, client);

    HttpServer::new(move || {
        App::new()
            // Configure with SecurityTransform
            // ...
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Configuration Options

```rust
LdapConfig::new("ldap://ldap.example.com:389")
    // Base DN for user searches
    .base_dn("dc=example,dc=com")

    // User search configuration
    .user_search_base("ou=users")
    .user_search_filter("(uid={0})")

    // Service account for binding
    .bind_dn("cn=admin,dc=example,dc=com")
    .bind_password("admin_password")

    // Group configuration
    .group_search_base("ou=groups")
    .group_search_filter("(member={0})")

    // Role configuration
    .role_prefix("ROLE_")
    .convert_to_uppercase(true)

    // Timeouts
    .connect_timeout(Duration::from_secs(5))
    .operation_timeout(Duration::from_secs(10))
```

## Active Directory Configuration

For Active Directory, use the preset configuration:

```rust
let config = LdapConfig::active_directory(
    "ldap://ad.company.com:389",
    "dc=company,dc=com"
)
.bind_dn("cn=service,cn=users,dc=company,dc=com")
.bind_password("service_password");
```

This configures:
- User search filter: `(sAMAccountName={0})`
- Group membership attribute: `memberOf`

## User Attributes Mapping

Configure which LDAP attributes map to user properties:

```rust
LdapConfig::new()
    .username_attribute("uid")           // Default: "uid"
    .display_name_attribute("cn")        // Display name
    .email_attribute("mail")             // Email address
    .group_attribute("memberOf")         // Group membership
```

## Group to Role Mapping

Map LDAP groups to application roles:

```rust
let config = LdapConfig::new()
    // ... base configuration
    .group_role_mapping("cn=admins,ou=groups,dc=example,dc=com", "ADMIN")
    .group_role_mapping("cn=users,ou=groups,dc=example,dc=com", "USER")
    .group_role_mapping("cn=managers,ou=groups,dc=example,dc=com", "MANAGER");
```

## Testing with MockLdapClient

For testing without a real LDAP server:

```rust
use actix_security::http::security::MockLdapClient;

let mut mock = MockLdapClient::new();

// Add test users
mock.add_user(
    "john",
    "password123",
    vec![
        ("cn".into(), vec!["John Doe".into()]),
        ("mail".into(), vec!["john@example.com".into()]),
    ],
    vec!["cn=users,ou=groups,dc=example,dc=com".into()],
);

let authenticator = LdapAuthenticator::with_client(config, mock);
```

## Error Handling

LDAP authentication can fail for various reasons:

```rust
use actix_security::http::security::LdapError;

match result {
    Err(LdapError::ConnectionFailed) => // LDAP server unreachable
    Err(LdapError::BindFailed) => // Invalid service account credentials
    Err(LdapError::UserNotFound) => // User not in directory
    Err(LdapError::AuthenticationFailed) => // Invalid password
    Err(LdapError::SearchFailed) => // LDAP search error
}
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `LdapAuthenticationProvider` | `LdapAuthenticator` |
| `LdapContextSource` | `LdapConfig` |
| `LdapUserSearch` | `.user_search_filter()` |
| `DefaultLdapAuthoritiesPopulator` | `.group_role_mapping()` |
| `ActiveDirectoryLdapAuthenticationProvider` | `LdapConfig::active_directory()` |

## Best Practices

1. **Use TLS**: Connect using `ldaps://` or STARTTLS for production
2. **Service Account**: Use a dedicated service account for binding
3. **Principle of Least Privilege**: Service account should only have read access
4. **Connection Pooling**: Consider connection pooling for high-traffic applications
5. **Timeout Configuration**: Set appropriate timeouts for LDAP operations
