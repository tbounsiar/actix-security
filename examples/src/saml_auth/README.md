# SAML 2.0 Authentication Example

This example demonstrates SAML 2.0 Single Sign-On (SSO) authentication.

## Quick Start

Add these dependencies to your `Cargo.toml`:

```toml
[dependencies]
actix-web = "4"
actix-session = { version = "0.10", features = ["cookie-session"] }
actix-security = { version = "0.2", features = ["saml"] }
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
```

## Features

- SAML 2.0 Service Provider (SP) implementation
- SP-initiated SSO flow
- Configurable authentication contexts
- Attribute mapping

## Prerequisites

Configure a SAML Identity Provider (IdP) such as:
- **Keycloak** - Open source identity management
- **Okta** - Cloud identity platform
- **Auth0** - Identity-as-a-service
- **SimpleSAMLphp** - Testing IdP
- **Azure AD** - Microsoft identity platform

## Running the Example

```bash
# Set environment variables
export SAML_ENTITY_ID=https://myapp.example.com/saml/metadata
export SAML_IDP_SSO_URL=https://idp.example.com/saml/sso
export SAML_ACS_URL=http://localhost:8080/saml/acs
export SAML_IDP_CERTIFICATE=/path/to/idp-cert.pem

# From the project root
cargo run --bin saml_auth

# Or from the examples directory
cargo run -p actix-security-examples --bin saml_auth
```

The server will start at `http://localhost:8080`.

## Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Home page |
| `/saml/login` | GET | Start SAML login flow |
| `/saml/acs` | POST | Assertion Consumer Service |
| `/saml/metadata` | GET | SP metadata XML |
| `/logout` | GET | Clear session |

## SAML Flow

1. User accesses protected resource on SP
2. SP generates AuthnRequest and redirects to IdP
3. User authenticates at IdP
4. IdP sends SAML Response to SP's ACS URL
5. SP validates response and creates session

```text
User                    SP                      IdP
 |                       |                       |
 |--Access protected---->|                       |
 |                       |--AuthnRequest-------->|
 |                       |                       |
 |<-----------Redirect to IdP login page---------|
 |                       |                       |
 |---------------Authenticate------------------>|
 |                       |                       |
 |                       |<----SAML Response-----|
 |                       |                       |
 |<--Session created-----|                       |
 |                       |                       |
```

## Configuration

```rust
let saml_config = SamlConfig::new()
    .entity_id("https://myapp.example.com/saml/metadata")
    .acs_url("http://localhost:8080/saml/acs")
    .idp_sso_url("https://idp.example.com/saml/sso")
    .idp_certificate_pem(&certificate)
    .name_id_format(NameIdFormat::EmailAddress)
    .authn_context(AuthnContextClass::PasswordProtectedTransport)
    .binding(SamlBinding::HttpPost);
```

## Configuration Options

| Option | Description | Example |
|--------|-------------|---------|
| `entity_id` | SP entity ID | `https://myapp.example.com/saml/metadata` |
| `acs_url` | Assertion Consumer Service URL | `http://localhost:8080/saml/acs` |
| `idp_sso_url` | IdP SSO URL | `https://idp.example.com/saml/sso` |
| `idp_certificate_pem` | IdP X.509 certificate | PEM-encoded certificate |
| `name_id_format` | NameID format | `EmailAddress`, `Persistent`, `Transient` |
| `authn_context` | Authentication context | `PasswordProtectedTransport` |
| `binding` | SAML binding | `HttpPost`, `HttpRedirect` |

## Testing with Keycloak

1. Create a SAML client in Keycloak:
   - Client ID: `https://myapp.example.com/saml/metadata`
   - Valid Redirect URIs: `http://localhost:8080/*`
   - ACS URL: `http://localhost:8080/saml/acs`

2. Configure attributes:
   - Map user attributes to SAML assertion

3. Export IdP metadata or certificate

## Code Overview

```rust
// SAML configuration
let saml_config = SamlConfig::new()
    .entity_id(&config.entity_id)
    .acs_url(&config.acs_url)
    .idp_sso_url(&config.idp_sso_url)
    .idp_certificate_pem(&certificate);

// Create authenticator
let saml_authenticator = SamlAuthenticator::new(saml_config.clone());

// Generate AuthnRequest
let authn_request = saml_authenticator.create_authn_request();

// Validate SAML Response
let saml_response = saml_authenticator.validate_response(&saml_response_xml)?;
let user = SamlUser {
    name_id: saml_response.name_id,
    attributes: saml_response.attributes,
    session_index: saml_response.session_index,
};
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `Saml2LoginConfigurer` | `SamlConfig` |
| `RelyingPartyRegistration` | SP configuration |
| `Saml2AuthenticationRequestFactory` | `create_authn_request()` |
| `OpenSamlAuthenticationProvider` | `SamlAuthenticator` |

## Security Best Practices

1. **Use HTTPS** - Always in production
2. **Validate signatures** - Verify IdP certificate
3. **Check assertion validity** - NotBefore/NotOnOrAfter
4. **Validate audience** - Ensure assertion is for your SP
5. **Use secure bindings** - Prefer HTTP-POST over HTTP-Redirect

## Related Examples

- [OAuth2 Google](../oauth2_google/README.md) - OAuth2 social login
- [OIDC Keycloak](../oidc_keycloak/README.md) - OpenID Connect
- [LDAP Authentication](../ldap_auth/README.md) - Directory auth
