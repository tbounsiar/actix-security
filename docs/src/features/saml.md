# SAML 2.0 Authentication

SAML 2.0 (Security Assertion Markup Language) enables Single Sign-On (SSO) with enterprise identity providers like Okta, Azure AD, ADFS, and Google Workspace.

## Enabling SAML Authentication

Add the `saml` feature to your `Cargo.toml`:

```toml
[dependencies]
actix-security = { version = "0.2", features = ["saml"] }
```

## Basic Usage

```rust
use actix_security::http::security::{SamlAuthenticator, SamlConfig};
use actix_web::{App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let saml_config = SamlConfig::new()
        .entity_id("https://myapp.example.com")
        .acs_url("https://myapp.example.com/saml/acs")
        .idp_entity_id("https://idp.example.com")
        .idp_sso_url("https://idp.example.com/sso")
        .idp_certificate(include_str!("../idp_cert.pem"));

    let authenticator = SamlAuthenticator::new(saml_config)
        .expect("Failed to create SAML authenticator");

    HttpServer::new(move || {
        App::new()
            // Configure routes for SAML
            // ...
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
```

## Provider Presets

Use preset configurations for common identity providers:

### Okta

```rust
let config = SamlConfig::okta(
    "dev-123456",                           // Okta org subdomain
    "0oa1234567890abcdef",                  // App ID
    "https://myapp.example.com",            // SP Entity ID
    "https://myapp.example.com/saml/acs",   // ACS URL
)
.idp_certificate(include_str!("okta_cert.pem"));
```

### Azure AD

```rust
let config = SamlConfig::azure_ad(
    "tenant-id-here",                       // Azure tenant ID
    "app-id-here",                          // Azure app ID
    "https://myapp.example.com",            // SP Entity ID
)
.idp_certificate(include_str!("azure_cert.pem"));
```

### Google Workspace

```rust
let config = SamlConfig::google_workspace(
    "https://myapp.example.com",            // SP Entity ID
    "https://myapp.example.com/saml/acs",   // ACS URL
)
.idp_certificate(include_str!("google_cert.pem"));
```

### ADFS

```rust
let config = SamlConfig::adfs(
    "https://adfs.company.com",             // ADFS server URL
    "https://myapp.example.com",            // SP Entity ID
    "https://myapp.example.com/saml/acs",   // ACS URL
)
.idp_certificate(include_str!("adfs_cert.pem"));
```

## Configuration Options

```rust
SamlConfig::new()
    // Service Provider (your application) settings
    .entity_id("https://myapp.example.com")
    .acs_url("https://myapp.example.com/saml/acs")
    .sls_url("https://myapp.example.com/saml/slo")  // Single Logout Service

    // Identity Provider settings
    .idp_entity_id("https://idp.example.com")
    .idp_sso_url("https://idp.example.com/sso")
    .idp_slo_url("https://idp.example.com/slo")
    .idp_certificate("-----BEGIN CERTIFICATE-----...")

    // Request settings
    .name_id_format(NameIdFormat::EmailAddress)
    .authn_context_class(AuthnContextClass::PasswordProtectedTransport)
    .sign_authn_request(false)              // Sign outgoing AuthnRequest
    .want_assertions_signed(true)           // Require signed assertions

    // Attribute mapping
    .role_attribute("groups")               // Attribute containing roles
```

## SAML Routes

You need to set up routes to handle SAML flow:

```rust
use actix_security::http::security::SamlAuthenticator;
use actix_web::{web, HttpResponse};
use serde::Deserialize;

#[derive(Deserialize)]
struct SamlResponseForm {
    #[serde(rename = "SAMLResponse")]
    saml_response: String,
}

// Initiate SAML login
async fn saml_login(saml: web::Data<SamlAuthenticator>) -> HttpResponse {
    // initiate_login creates and stores the AuthnRequest, returns redirect URL
    let redirect_url = saml.initiate_login(None);

    HttpResponse::Found()
        .insert_header(("Location", redirect_url))
        .finish()
}

// Handle SAML response (Assertion Consumer Service)
async fn saml_acs(
    saml: web::Data<SamlAuthenticator>,
    form: web::Form<SamlResponseForm>,
) -> HttpResponse {
    match saml.process_response(&form.saml_response) {
        Ok(auth_result) => {
            // auth_result contains: user, session_index, name_id, attributes
            // Store user in session
            HttpResponse::Found()
                .insert_header(("Location", "/"))
                .finish()
        }
        Err(e) => HttpResponse::Unauthorized().body(format!("SAML error: {:?}", e))
    }
}

// Configure routes
App::new()
    .route("/saml/login", web::get().to(saml_login))
    .route("/saml/acs", web::post().to(saml_acs))
```

## SP Metadata Generation

Generate SAML metadata for your IdP:

```rust
// Serve at /saml/metadata
async fn saml_metadata(saml: web::Data<SamlAuthenticator>) -> HttpResponse {
    let metadata = saml.generate_metadata();
    HttpResponse::Ok()
        .content_type("application/xml")
        .body(metadata)
}
```

## Assertion Validation

The library validates SAML assertions for:

- **Signature**: Verifies IdP signature using configured certificate
- **Audience**: Ensures assertion is intended for your SP
- **Timing**: Checks NotBefore and NotOnOrAfter conditions
- **Replay**: Validates InResponseTo matches pending request

## Error Handling

```rust
use actix_security::http::security::SamlError;

match result {
    Err(SamlError::InvalidSignature) => // Signature verification failed
    Err(SamlError::AudienceMismatch) => // Wrong SP entity ID
    Err(SamlError::AssertionExpired) => // Assertion timing invalid
    Err(SamlError::InvalidRequest) => // Malformed SAML request
    Err(SamlError::IdpError(msg)) => // IdP returned an error
}
```

## Group/Role Mapping

Map SAML groups to application roles:

```rust
let config = SamlConfig::new()
    // ... base configuration
    .roles_attribute("groups")  // Attribute containing groups
    .role_mapping("IdP-Admins", "ADMIN")
    .role_mapping("IdP-Users", "USER");
```

## Single Logout (SLO)

Support for SAML Single Logout:

```rust
// Initiate logout
async fn saml_logout(saml: web::Data<SamlAuthenticator>) -> HttpResponse {
    let logout_request = saml.create_logout_request(&user);
    let redirect_url = saml.get_slo_redirect_url(&logout_request);

    // Clear local session
    // ...

    HttpResponse::Found()
        .insert_header(("Location", redirect_url))
        .finish()
}
```

## Spring Security Comparison

| Spring Security | Actix Security |
|-----------------|----------------|
| `Saml2LoginConfigurer` | `SamlConfig` |
| `RelyingPartyRegistration` | `SamlConfig` builder methods |
| `Saml2AuthenticationRequestResolver` | `create_authn_request()` |
| `OpenSaml4AuthenticationProvider` | `SamlAuthenticator` |
| `Saml2MetadataFilter` | `generate_sp_metadata()` |

## Security Considerations

1. **Use HTTPS**: Always use HTTPS for ACS URL in production
2. **Validate Signatures**: Never disable signature validation
3. **Certificate Management**: Keep IdP certificates up to date
4. **Clock Synchronization**: Ensure servers have synchronized time
5. **Secure Storage**: Protect SP private keys if using signed requests
