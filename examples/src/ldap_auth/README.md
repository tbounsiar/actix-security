# LDAP Authentication Example

This example demonstrates LDAP authentication for enterprise directory integration.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-security = { version = "0.2", features = ["ldap"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- LDAP/Active Directory authentication
- Mock LDAP client for testing
- Group-to-role mapping
- Configurable search base and filters

## Running the Example

```bash
# From the project root
cargo run --bin ldap_auth

# Or from the examples directory
cargo run -p actix-security-examples --bin ldap_auth
```

The server will start at `http://localhost:8080`.

**Note:** This example uses a mock LDAP client. For production, configure a real LDAP server.

## Endpoints

| Endpoint | Authorization | Description |
|----------|---------------|-------------|
| `/` | Authenticated | Home page |
| `/admin` | Role: ADMINS | Admin dashboard |
| `/profile` | Authenticated | User profile |
| `/public` | None | Public endpoint |

## Test Users (Mock LDAP)

| Username | Password | Groups | Roles |
|----------|----------|--------|-------|
| john.doe | password | Users | USER |
| jane.smith | secret | Users, Developers | USER, DEVELOPER |
| admin | admin123 | Users, Admins | USER, ADMINS |

## Testing

```bash
# Public endpoint
curl http://127.0.0.1:8080/public

# Authenticated user
curl -u john.doe:password http://127.0.0.1:8080/

# User profile
curl -u jane.smith:secret http://127.0.0.1:8080/profile

# Admin access
curl -u admin:admin123 http://127.0.0.1:8080/admin

# Non-admin accessing admin (403 Forbidden)
curl -u john.doe:password http://127.0.0.1:8080/admin

# Invalid credentials (401 Unauthorized)
curl -u invalid:wrong http://127.0.0.1:8080/
```

## Code Overview

```rust
// LDAP configuration
let ldap_config = LdapConfig::new()
    .url("ldap://localhost:389")
    .base_dn("dc=example,dc=com")
    .user_dn_pattern("uid={0},ou=users")
    .user_search_filter("(uid={0})")
    .group_search_base("ou=groups")
    .group_search_filter("(member={0})")
    .group_role_attribute("cn");

// Create authenticator with mock client
let ldap_client = MockLdapClient::new()
    .with_user("john.doe", "password", vec!["Users"])
    .with_user("admin", "admin123", vec!["Users", "Admins"]);

struct LdapAuthenticator { client: MockLdapClient, config: LdapConfig }

impl Authenticator for LdapAuthenticator {
    fn get_user(&self, req: &ServiceRequest) -> Option<User> {
        let (username, password) = extract_basic_auth(req)?;
        self.client.authenticate(&username, &password, &self.config)
    }
}
```

## LDAP Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `url` | LDAP server URL | `ldap://localhost:389` |
| `base_dn` | Base DN for searches | `dc=example,dc=com` |
| `user_dn_pattern` | User DN pattern | `uid={0},ou=users` |
| `user_search_filter` | User search filter | `(uid={0})` |
| `group_search_base` | Group search base | `ou=groups` |
| `group_search_filter` | Group membership filter | `(member={0})` |
| `group_role_attribute` | Attribute for role name | `cn` |

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `LdapAuthenticationProvider` | `LdapAuthenticator` |
| `LdapAuthoritiesPopulator` | Group-to-role mapping |
| `DefaultSpringSecurityContextSource` | `LdapConfig` |
| `LdapUserDetailsService` | `LdapClient` trait |

## Production Configuration

For production use, configure a real LDAP server:

```rust
let ldap_config = LdapConfig::new()
    .url("ldaps://ldap.company.com:636")
    .base_dn("dc=company,dc=com")
    .bind_dn("cn=service,ou=apps,dc=company,dc=com")
    .bind_password("service-password")
    .user_dn_pattern("uid={0},ou=users")
    .use_tls(true);
```

## Related Examples

- [HTTP Basic Authentication](../basic_auth/README.md) - Basic auth
- [SAML Authentication](../saml_auth/README.md) - Enterprise SSO
- [Security Complete](../security_complete/README.md) - Full security setup
