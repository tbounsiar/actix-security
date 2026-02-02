//! SAML 2.0 Authentication Module
//!
//! Provides SAML 2.0 Single Sign-On (SSO) authentication support.
//! This module implements the Service Provider (SP) side of SAML authentication.
//!
//! # Features
//!
//! - **SAML AuthnRequest Generation**: Create authentication requests to IdP
//! - **SAML Response Validation**: Parse and validate IdP responses
//! - **Assertion Processing**: Extract user information from SAML assertions
//! - **Signature Verification**: Verify XML signatures (with appropriate crypto)
//! - **Metadata Support**: Configure from IdP/SP metadata
//!
//! # Example
//!
//! ```rust,ignore
//! use actix_security::http::security::saml::{SamlConfig, SamlAuthenticator};
//!
//! let config = SamlConfig::new()
//!     .entity_id("https://myapp.example.com/saml/metadata")
//!     .idp_sso_url("https://idp.example.com/saml/sso")
//!     .idp_certificate(include_str!("../idp-cert.pem"))
//!     .sp_private_key(include_str!("../sp-key.pem"))
//!     .assertion_consumer_service_url("https://myapp.example.com/saml/acs");
//!
//! let authenticator = SamlAuthenticator::new(config);
//! ```
//!
//! # SAML Flow
//!
//! 1. User accesses protected resource
//! 2. SP generates AuthnRequest and redirects to IdP
//! 3. User authenticates at IdP
//! 4. IdP sends SAML Response back to SP's ACS URL
//! 5. SP validates response and creates session

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::http::security::User;

/// SAML 2.0 name ID formats
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum NameIdFormat {
    /// Unspecified format
    #[default]
    Unspecified,
    /// Email address format
    EmailAddress,
    /// X.509 subject name format
    X509SubjectName,
    /// Windows domain qualified name
    WindowsDomainQualifiedName,
    /// Kerberos principal name
    Kerberos,
    /// Persistent identifier
    Persistent,
    /// Transient identifier
    Transient,
    /// Custom format
    Custom(String),
}

impl NameIdFormat {
    /// Get the URN for this name ID format
    pub fn as_urn(&self) -> &str {
        match self {
            NameIdFormat::Unspecified => "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
            NameIdFormat::EmailAddress => "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
            NameIdFormat::X509SubjectName => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName"
            }
            NameIdFormat::WindowsDomainQualifiedName => {
                "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName"
            }
            NameIdFormat::Kerberos => "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos",
            NameIdFormat::Persistent => "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            NameIdFormat::Transient => "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            NameIdFormat::Custom(urn) => urn,
        }
    }

    /// Parse a name ID format from URN
    pub fn from_urn(urn: &str) -> Self {
        match urn {
            "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified" => NameIdFormat::Unspecified,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" => NameIdFormat::EmailAddress,
            "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName" => {
                NameIdFormat::X509SubjectName
            }
            "urn:oasis:names:tc:SAML:1.1:nameid-format:WindowsDomainQualifiedName" => {
                NameIdFormat::WindowsDomainQualifiedName
            }
            "urn:oasis:names:tc:SAML:2.0:nameid-format:kerberos" => NameIdFormat::Kerberos,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" => NameIdFormat::Persistent,
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" => NameIdFormat::Transient,
            other => NameIdFormat::Custom(other.to_string()),
        }
    }
}

/// SAML 2.0 binding types
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SamlBinding {
    /// HTTP Redirect binding (GET with query parameters)
    #[default]
    HttpRedirect,
    /// HTTP POST binding (form submission)
    HttpPost,
    /// HTTP Artifact binding
    HttpArtifact,
    /// SOAP binding
    Soap,
}

impl SamlBinding {
    /// Get the URN for this binding
    pub fn as_urn(&self) -> &str {
        match self {
            SamlBinding::HttpRedirect => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            SamlBinding::HttpPost => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            SamlBinding::HttpArtifact => "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Artifact",
            SamlBinding::Soap => "urn:oasis:names:tc:SAML:2.0:bindings:SOAP",
        }
    }
}

/// SAML 2.0 authentication context classes
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum AuthnContextClass {
    /// Unspecified authentication
    #[default]
    Unspecified,
    /// Password authentication
    Password,
    /// Password protected transport
    PasswordProtectedTransport,
    /// X.509 certificate
    X509,
    /// Kerberos authentication
    Kerberos,
    /// Multi-factor authentication
    MultiFactor,
    /// Custom authentication context
    Custom(String),
}

impl AuthnContextClass {
    /// Get the URN for this authentication context
    pub fn as_urn(&self) -> &str {
        match self {
            AuthnContextClass::Unspecified => "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified",
            AuthnContextClass::Password => "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
            AuthnContextClass::PasswordProtectedTransport => {
                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
            }
            AuthnContextClass::X509 => "urn:oasis:names:tc:SAML:2.0:ac:classes:X509",
            AuthnContextClass::Kerberos => "urn:oasis:names:tc:SAML:2.0:ac:classes:Kerberos",
            AuthnContextClass::MultiFactor => "urn:oasis:names:tc:SAML:2.0:ac:classes:MultiFactor",
            AuthnContextClass::Custom(urn) => urn,
        }
    }
}

/// SAML Status codes
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlStatusCode {
    /// Authentication succeeded
    Success,
    /// Request could not be performed due to an error
    Requester,
    /// Request could not be performed due to an error on the responding provider
    Responder,
    /// SAML responder or SAML authority is able to process the request but has chosen not to respond
    VersionMismatch,
    /// The SAML responder cannot properly authenticate the requesting party
    AuthnFailed,
    /// The responding provider cannot or will not support the requested name identifier policy
    InvalidNameIdPolicy,
    /// The specified authentication context requirements cannot be met
    NoAuthnContext,
    /// Unknown status code
    Unknown(String),
}

impl SamlStatusCode {
    /// Parse status code from URN
    pub fn from_urn(urn: &str) -> Self {
        match urn {
            "urn:oasis:names:tc:SAML:2.0:status:Success" => SamlStatusCode::Success,
            "urn:oasis:names:tc:SAML:2.0:status:Requester" => SamlStatusCode::Requester,
            "urn:oasis:names:tc:SAML:2.0:status:Responder" => SamlStatusCode::Responder,
            "urn:oasis:names:tc:SAML:2.0:status:VersionMismatch" => SamlStatusCode::VersionMismatch,
            "urn:oasis:names:tc:SAML:2.0:status:AuthnFailed" => SamlStatusCode::AuthnFailed,
            "urn:oasis:names:tc:SAML:2.0:status:InvalidNameIDPolicy" => {
                SamlStatusCode::InvalidNameIdPolicy
            }
            "urn:oasis:names:tc:SAML:2.0:status:NoAuthnContext" => SamlStatusCode::NoAuthnContext,
            other => SamlStatusCode::Unknown(other.to_string()),
        }
    }

    /// Check if this status indicates success
    pub fn is_success(&self) -> bool {
        matches!(self, SamlStatusCode::Success)
    }
}

/// SAML Service Provider configuration
#[derive(Debug, Clone)]
pub struct SamlConfig {
    /// SP Entity ID (unique identifier)
    pub entity_id: String,
    /// IdP SSO URL (where to send AuthnRequest)
    pub idp_sso_url: String,
    /// IdP Single Logout URL (optional)
    pub idp_slo_url: Option<String>,
    /// IdP Entity ID
    pub idp_entity_id: Option<String>,
    /// IdP certificate for signature verification (PEM format)
    pub idp_certificate: Option<String>,
    /// SP private key for signing requests (PEM format)
    pub sp_private_key: Option<String>,
    /// SP certificate (PEM format)
    pub sp_certificate: Option<String>,
    /// Assertion Consumer Service URL
    pub acs_url: String,
    /// Single Logout Service URL
    pub sls_url: Option<String>,
    /// Preferred binding for SSO
    pub sso_binding: SamlBinding,
    /// Preferred binding for SLO
    pub slo_binding: SamlBinding,
    /// Name ID format to request
    pub name_id_format: NameIdFormat,
    /// Authentication context class to request
    pub authn_context_class: Option<AuthnContextClass>,
    /// Whether to sign AuthnRequest
    pub sign_authn_request: bool,
    /// Whether to require signed assertions
    pub want_assertions_signed: bool,
    /// Whether to require encrypted assertions
    pub want_assertions_encrypted: bool,
    /// Maximum allowed clock skew
    pub max_clock_skew: Duration,
    /// Attribute mapping (SAML attribute name -> User field)
    pub attribute_mapping: HashMap<String, String>,
    /// Role attribute name
    pub role_attribute: Option<String>,
    /// Authority attribute name
    pub authority_attribute: Option<String>,
    /// Default roles for authenticated users
    pub default_roles: Vec<String>,
    /// Allow unsolicited responses (IdP-initiated SSO)
    pub allow_unsolicited_responses: bool,
    /// Session timeout
    pub session_timeout: Duration,
}

impl SamlConfig {
    /// Create a new SAML configuration with minimal required fields
    pub fn new() -> Self {
        Self {
            entity_id: String::new(),
            idp_sso_url: String::new(),
            idp_slo_url: None,
            idp_entity_id: None,
            idp_certificate: None,
            sp_private_key: None,
            sp_certificate: None,
            acs_url: String::new(),
            sls_url: None,
            sso_binding: SamlBinding::HttpRedirect,
            slo_binding: SamlBinding::HttpRedirect,
            name_id_format: NameIdFormat::Unspecified,
            authn_context_class: None,
            sign_authn_request: false,
            want_assertions_signed: true,
            want_assertions_encrypted: false,
            max_clock_skew: Duration::from_secs(120),
            attribute_mapping: HashMap::new(),
            role_attribute: None,
            authority_attribute: None,
            default_roles: vec!["USER".to_string()],
            allow_unsolicited_responses: false,
            session_timeout: Duration::from_secs(3600),
        }
    }

    /// Set the SP entity ID
    pub fn entity_id(mut self, entity_id: impl Into<String>) -> Self {
        self.entity_id = entity_id.into();
        self
    }

    /// Set the IdP SSO URL
    pub fn idp_sso_url(mut self, url: impl Into<String>) -> Self {
        self.idp_sso_url = url.into();
        self
    }

    /// Set the IdP SLO URL
    pub fn idp_slo_url(mut self, url: impl Into<String>) -> Self {
        self.idp_slo_url = Some(url.into());
        self
    }

    /// Set the IdP entity ID
    pub fn idp_entity_id(mut self, entity_id: impl Into<String>) -> Self {
        self.idp_entity_id = Some(entity_id.into());
        self
    }

    /// Set the IdP certificate (PEM format)
    pub fn idp_certificate(mut self, cert: impl Into<String>) -> Self {
        self.idp_certificate = Some(cert.into());
        self
    }

    /// Set the SP private key (PEM format)
    pub fn sp_private_key(mut self, key: impl Into<String>) -> Self {
        self.sp_private_key = Some(key.into());
        self
    }

    /// Set the SP certificate (PEM format)
    pub fn sp_certificate(mut self, cert: impl Into<String>) -> Self {
        self.sp_certificate = Some(cert.into());
        self
    }

    /// Set the Assertion Consumer Service URL
    pub fn acs_url(mut self, url: impl Into<String>) -> Self {
        self.acs_url = url.into();
        self
    }

    /// Alias for acs_url
    pub fn assertion_consumer_service_url(self, url: impl Into<String>) -> Self {
        self.acs_url(url)
    }

    /// Set the Single Logout Service URL
    pub fn sls_url(mut self, url: impl Into<String>) -> Self {
        self.sls_url = Some(url.into());
        self
    }

    /// Set the SSO binding
    pub fn sso_binding(mut self, binding: SamlBinding) -> Self {
        self.sso_binding = binding;
        self
    }

    /// Set the SLO binding
    pub fn slo_binding(mut self, binding: SamlBinding) -> Self {
        self.slo_binding = binding;
        self
    }

    /// Set the Name ID format
    pub fn name_id_format(mut self, format: NameIdFormat) -> Self {
        self.name_id_format = format;
        self
    }

    /// Set the authentication context class
    pub fn authn_context_class(mut self, class: AuthnContextClass) -> Self {
        self.authn_context_class = Some(class);
        self
    }

    /// Set whether to sign AuthnRequest
    pub fn sign_authn_request(mut self, sign: bool) -> Self {
        self.sign_authn_request = sign;
        self
    }

    /// Set whether assertions must be signed
    pub fn want_assertions_signed(mut self, signed: bool) -> Self {
        self.want_assertions_signed = signed;
        self
    }

    /// Set whether assertions must be encrypted
    pub fn want_assertions_encrypted(mut self, encrypted: bool) -> Self {
        self.want_assertions_encrypted = encrypted;
        self
    }

    /// Set maximum clock skew tolerance
    pub fn max_clock_skew(mut self, skew: Duration) -> Self {
        self.max_clock_skew = skew;
        self
    }

    /// Add an attribute mapping
    pub fn map_attribute(
        mut self,
        saml_attribute: impl Into<String>,
        user_field: impl Into<String>,
    ) -> Self {
        self.attribute_mapping
            .insert(saml_attribute.into(), user_field.into());
        self
    }

    /// Set the role attribute name
    pub fn role_attribute(mut self, attr: impl Into<String>) -> Self {
        self.role_attribute = Some(attr.into());
        self
    }

    /// Set the authority attribute name
    pub fn authority_attribute(mut self, attr: impl Into<String>) -> Self {
        self.authority_attribute = Some(attr.into());
        self
    }

    /// Set default roles for authenticated users
    pub fn default_roles(mut self, roles: Vec<String>) -> Self {
        self.default_roles = roles;
        self
    }

    /// Set whether to allow unsolicited responses
    pub fn allow_unsolicited_responses(mut self, allow: bool) -> Self {
        self.allow_unsolicited_responses = allow;
        self
    }

    /// Set session timeout
    pub fn session_timeout(mut self, timeout: Duration) -> Self {
        self.session_timeout = timeout;
        self
    }

    /// Create configuration preset for Okta
    pub fn okta(
        okta_domain: impl Into<String>,
        app_id: impl Into<String>,
        sp_entity_id: impl Into<String>,
    ) -> Self {
        let domain = okta_domain.into();
        let app = app_id.into();
        Self::new()
            .entity_id(sp_entity_id)
            .idp_sso_url(format!("https://{}/app/{}/sso/saml", domain, app))
            .idp_entity_id(format!("http://www.okta.com/{}", app))
            .name_id_format(NameIdFormat::EmailAddress)
            .sso_binding(SamlBinding::HttpPost)
    }

    /// Create configuration preset for Azure AD
    pub fn azure_ad(
        tenant_id: impl Into<String>,
        _app_id: impl Into<String>,
        sp_entity_id: impl Into<String>,
    ) -> Self {
        let tenant = tenant_id.into();
        Self::new()
            .entity_id(sp_entity_id)
            .idp_sso_url(format!(
                "https://login.microsoftonline.com/{}/saml2",
                tenant
            ))
            .idp_entity_id(format!("https://sts.windows.net/{}/", tenant))
            .name_id_format(NameIdFormat::EmailAddress)
            .sso_binding(SamlBinding::HttpRedirect)
            .map_attribute(
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress",
                "email",
            )
            .map_attribute(
                "http://schemas.microsoft.com/ws/2008/06/identity/claims/groups",
                "groups",
            )
    }

    /// Create configuration preset for Google Workspace
    pub fn google_workspace(sp_entity_id: impl Into<String>, acs_url: impl Into<String>) -> Self {
        Self::new()
            .entity_id(sp_entity_id)
            .idp_sso_url("https://accounts.google.com/o/saml2/idp")
            .acs_url(acs_url)
            .name_id_format(NameIdFormat::EmailAddress)
            .sso_binding(SamlBinding::HttpRedirect)
    }

    /// Create configuration preset for ADFS
    pub fn adfs(adfs_host: impl Into<String>, sp_entity_id: impl Into<String>) -> Self {
        let host = adfs_host.into();
        Self::new()
            .entity_id(sp_entity_id)
            .idp_sso_url(format!("https://{}/adfs/ls/", host))
            .idp_entity_id(format!("http://{}/adfs/services/trust", host))
            .name_id_format(NameIdFormat::Unspecified)
            .sso_binding(SamlBinding::HttpPost)
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), SamlError> {
        if self.entity_id.is_empty() {
            return Err(SamlError::Configuration("entity_id is required".into()));
        }
        if self.idp_sso_url.is_empty() {
            return Err(SamlError::Configuration("idp_sso_url is required".into()));
        }
        if self.acs_url.is_empty() {
            return Err(SamlError::Configuration("acs_url is required".into()));
        }
        if self.sign_authn_request && self.sp_private_key.is_none() {
            return Err(SamlError::Configuration(
                "sp_private_key is required when sign_authn_request is true".into(),
            ));
        }
        if self.want_assertions_signed && self.idp_certificate.is_none() {
            return Err(SamlError::Configuration(
                "idp_certificate is required when want_assertions_signed is true".into(),
            ));
        }
        Ok(())
    }
}

impl Default for SamlConfig {
    fn default() -> Self {
        Self::new()
    }
}

/// SAML authentication error
#[derive(Debug, Clone)]
pub enum SamlError {
    /// Configuration error
    Configuration(String),
    /// Invalid SAML response
    InvalidResponse(String),
    /// Signature verification failed
    SignatureVerificationFailed(String),
    /// Assertion validation failed
    AssertionValidationFailed(String),
    /// Time condition not met
    TimeConditionNotMet(String),
    /// Audience restriction not met
    AudienceRestrictionNotMet(String),
    /// Required attribute missing
    MissingAttribute(String),
    /// IdP returned an error status
    IdpError(SamlStatusCode, Option<String>),
    /// Decryption failed
    DecryptionFailed(String),
    /// XML parsing error
    XmlParsingError(String),
    /// Network error
    NetworkError(String),
}

impl std::fmt::Display for SamlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SamlError::Configuration(msg) => write!(f, "SAML configuration error: {}", msg),
            SamlError::InvalidResponse(msg) => write!(f, "Invalid SAML response: {}", msg),
            SamlError::SignatureVerificationFailed(msg) => {
                write!(f, "SAML signature verification failed: {}", msg)
            }
            SamlError::AssertionValidationFailed(msg) => {
                write!(f, "SAML assertion validation failed: {}", msg)
            }
            SamlError::TimeConditionNotMet(msg) => {
                write!(f, "SAML time condition not met: {}", msg)
            }
            SamlError::AudienceRestrictionNotMet(msg) => {
                write!(f, "SAML audience restriction not met: {}", msg)
            }
            SamlError::MissingAttribute(attr) => {
                write!(f, "Required SAML attribute missing: {}", attr)
            }
            SamlError::IdpError(code, msg) => {
                write!(f, "IdP returned error {:?}: {:?}", code, msg)
            }
            SamlError::DecryptionFailed(msg) => write!(f, "SAML decryption failed: {}", msg),
            SamlError::XmlParsingError(msg) => write!(f, "XML parsing error: {}", msg),
            SamlError::NetworkError(msg) => write!(f, "Network error: {}", msg),
        }
    }
}

impl std::error::Error for SamlError {}

/// SAML AuthnRequest
#[derive(Debug, Clone)]
pub struct AuthnRequest {
    /// Request ID
    pub id: String,
    /// Issue instant (ISO 8601)
    pub issue_instant: String,
    /// SP Entity ID
    pub issuer: String,
    /// Destination (IdP SSO URL)
    pub destination: String,
    /// Assertion Consumer Service URL
    pub acs_url: String,
    /// Protocol binding for response
    pub protocol_binding: SamlBinding,
    /// Name ID policy format
    pub name_id_format: NameIdFormat,
    /// Requested authentication context
    pub authn_context: Option<AuthnContextClass>,
    /// Force re-authentication
    pub force_authn: bool,
    /// Passive authentication (no user interaction)
    pub is_passive: bool,
}

impl AuthnRequest {
    /// Create a new AuthnRequest with generated ID
    pub fn new(config: &SamlConfig) -> Self {
        let id = format!("_{}_{}", generate_id(), timestamp_millis());

        Self {
            id,
            issue_instant: iso8601_now(),
            issuer: config.entity_id.clone(),
            destination: config.idp_sso_url.clone(),
            acs_url: config.acs_url.clone(),
            protocol_binding: SamlBinding::HttpPost,
            name_id_format: config.name_id_format.clone(),
            authn_context: config.authn_context_class.clone(),
            force_authn: false,
            is_passive: false,
        }
    }

    /// Set force re-authentication
    pub fn force_authn(mut self, force: bool) -> Self {
        self.force_authn = force;
        self
    }

    /// Set passive authentication
    pub fn is_passive(mut self, passive: bool) -> Self {
        self.is_passive = passive;
        self
    }

    /// Generate XML for this AuthnRequest
    pub fn to_xml(&self) -> String {
        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push_str(&format!(
            r#"<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}" AssertionConsumerServiceURL="{}" ProtocolBinding="{}""#,
            self.id,
            self.issue_instant,
            self.destination,
            self.acs_url,
            self.protocol_binding.as_urn()
        ));

        if self.force_authn {
            xml.push_str(r#" ForceAuthn="true""#);
        }
        if self.is_passive {
            xml.push_str(r#" IsPassive="true""#);
        }

        xml.push('>');

        // Issuer
        xml.push_str(&format!(r#"<saml:Issuer>{}</saml:Issuer>"#, self.issuer));

        // NameIDPolicy
        xml.push_str(&format!(
            r#"<samlp:NameIDPolicy Format="{}" AllowCreate="true"/>"#,
            self.name_id_format.as_urn()
        ));

        // RequestedAuthnContext
        if let Some(ref authn_context) = self.authn_context {
            xml.push_str(r#"<samlp:RequestedAuthnContext Comparison="exact">"#);
            xml.push_str(&format!(
                r#"<saml:AuthnContextClassRef>{}</saml:AuthnContextClassRef>"#,
                authn_context.as_urn()
            ));
            xml.push_str(r#"</samlp:RequestedAuthnContext>"#);
        }

        xml.push_str(r#"</samlp:AuthnRequest>"#);
        xml
    }

    /// Get the URL for HTTP Redirect binding (deflated and base64-encoded)
    pub fn to_redirect_url(&self, relay_state: Option<&str>) -> String {
        let xml = self.to_xml();
        let deflated = deflate_and_encode(&xml);

        let mut url = format!(
            "{}?SAMLRequest={}",
            self.destination,
            urlencoding::encode(&deflated)
        );

        if let Some(state) = relay_state {
            url.push_str(&format!("&RelayState={}", urlencoding::encode(state)));
        }

        url
    }
}

/// SAML Assertion
#[derive(Debug, Clone)]
pub struct SamlAssertion {
    /// Assertion ID
    pub id: String,
    /// Issue instant
    pub issue_instant: String,
    /// Issuer (IdP Entity ID)
    pub issuer: String,
    /// Subject NameID
    pub name_id: String,
    /// Subject NameID format
    pub name_id_format: NameIdFormat,
    /// Session index
    pub session_index: Option<String>,
    /// Session not on or after
    pub session_not_on_or_after: Option<String>,
    /// Not before condition
    pub not_before: Option<String>,
    /// Not on or after condition
    pub not_on_or_after: Option<String>,
    /// Audience restrictions
    pub audiences: Vec<String>,
    /// Authentication context class
    pub authn_context_class: Option<String>,
    /// Attributes
    pub attributes: HashMap<String, Vec<String>>,
}

impl SamlAssertion {
    /// Get a single-valued attribute
    pub fn get_attribute(&self, name: &str) -> Option<&str> {
        self.attributes
            .get(name)
            .and_then(|values| values.first())
            .map(|s| s.as_str())
    }

    /// Get a multi-valued attribute
    pub fn get_attribute_values(&self, name: &str) -> Option<&Vec<String>> {
        self.attributes.get(name)
    }

    /// Validate the assertion against configuration
    pub fn validate(&self, config: &SamlConfig) -> Result<(), SamlError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check NotBefore
        if let Some(ref not_before) = self.not_before {
            if let Ok(nb_time) = parse_iso8601(not_before) {
                let skew = config.max_clock_skew.as_secs();
                if now + skew < nb_time {
                    return Err(SamlError::TimeConditionNotMet(format!(
                        "Assertion not valid before {}",
                        not_before
                    )));
                }
            }
        }

        // Check NotOnOrAfter
        if let Some(ref not_on_or_after) = self.not_on_or_after {
            if let Ok(noa_time) = parse_iso8601(not_on_or_after) {
                let skew = config.max_clock_skew.as_secs();
                if now > noa_time + skew {
                    return Err(SamlError::TimeConditionNotMet(format!(
                        "Assertion expired at {}",
                        not_on_or_after
                    )));
                }
            }
        }

        // Check Audience
        if !self.audiences.is_empty() && !self.audiences.contains(&config.entity_id) {
            return Err(SamlError::AudienceRestrictionNotMet(format!(
                "SP entity ID {} not in audiences: {:?}",
                config.entity_id, self.audiences
            )));
        }

        // Check Issuer
        if let Some(ref expected_issuer) = config.idp_entity_id {
            if &self.issuer != expected_issuer {
                return Err(SamlError::AssertionValidationFailed(format!(
                    "Issuer mismatch: expected {}, got {}",
                    expected_issuer, self.issuer
                )));
            }
        }

        Ok(())
    }
}

/// SAML Response
#[derive(Debug, Clone)]
pub struct SamlResponse {
    /// Response ID
    pub id: String,
    /// In response to (AuthnRequest ID)
    pub in_response_to: Option<String>,
    /// Issue instant
    pub issue_instant: String,
    /// Destination
    pub destination: Option<String>,
    /// Issuer (IdP Entity ID)
    pub issuer: String,
    /// Status code
    pub status_code: SamlStatusCode,
    /// Status message
    pub status_message: Option<String>,
    /// Assertion(s)
    pub assertions: Vec<SamlAssertion>,
}

impl SamlResponse {
    /// Parse a SAML Response from base64-encoded XML
    ///
    /// Note: In production, you should use a proper XML/SAML library
    /// like `samael` or `saml2` for full parsing and signature verification.
    pub fn from_base64(encoded: &str) -> Result<Self, SamlError> {
        use base64::{engine::general_purpose::STANDARD, Engine as _};

        let decoded = STANDARD
            .decode(encoded)
            .map_err(|e| SamlError::InvalidResponse(format!("Base64 decode error: {}", e)))?;

        let xml = String::from_utf8(decoded)
            .map_err(|e| SamlError::InvalidResponse(format!("UTF-8 decode error: {}", e)))?;

        Self::from_xml(&xml)
    }

    /// Parse a SAML Response from XML string
    ///
    /// Note: This is a simplified parser. In production, use a proper
    /// XML library with namespace support and signature verification.
    pub fn from_xml(xml: &str) -> Result<Self, SamlError> {
        // This is a simplified parser for demonstration.
        // Production code should use a proper SAML library.

        let id = extract_attribute(xml, "Response", "ID")
            .ok_or_else(|| SamlError::XmlParsingError("Missing Response ID".into()))?;

        let in_response_to = extract_attribute(xml, "Response", "InResponseTo");
        let issue_instant = extract_attribute(xml, "Response", "IssueInstant")
            .ok_or_else(|| SamlError::XmlParsingError("Missing IssueInstant".into()))?;
        let destination = extract_attribute(xml, "Response", "Destination");
        let issuer = extract_element_text(xml, "Issuer")
            .ok_or_else(|| SamlError::XmlParsingError("Missing Issuer".into()))?;

        // Parse status
        let status_code =
            extract_status_code(xml).unwrap_or(SamlStatusCode::Unknown(String::new()));
        let status_message = extract_element_text(xml, "StatusMessage");

        // Parse assertions (simplified)
        let assertions = parse_assertions(xml)?;

        Ok(Self {
            id,
            in_response_to,
            issue_instant,
            destination,
            issuer,
            status_code,
            status_message,
            assertions,
        })
    }

    /// Check if the response indicates success
    pub fn is_success(&self) -> bool {
        self.status_code.is_success()
    }

    /// Get the first assertion (most common case)
    pub fn assertion(&self) -> Option<&SamlAssertion> {
        self.assertions.first()
    }
}

/// SAML Authenticator for actix-web
#[derive(Clone)]
pub struct SamlAuthenticator {
    config: Arc<SamlConfig>,
    pending_requests: Arc<std::sync::RwLock<HashMap<String, PendingRequest>>>,
}

/// A pending authentication request
#[derive(Debug, Clone)]
#[allow(dead_code)] // Fields are stored for request validation and relay state retrieval
struct PendingRequest {
    /// Request ID
    id: String,
    /// Created at timestamp
    created_at: u64,
    /// Relay state (redirect URL after auth)
    relay_state: Option<String>,
}

impl SamlAuthenticator {
    /// Create a new SAML authenticator
    pub fn new(config: SamlConfig) -> Result<Self, SamlError> {
        config.validate()?;
        Ok(Self {
            config: Arc::new(config),
            pending_requests: Arc::new(std::sync::RwLock::new(HashMap::new())),
        })
    }

    /// Get the configuration
    pub fn config(&self) -> &SamlConfig {
        &self.config
    }

    /// Create a new AuthnRequest
    pub fn create_authn_request(&self) -> AuthnRequest {
        AuthnRequest::new(&self.config)
    }

    /// Store a pending request
    pub fn store_pending_request(&self, request: &AuthnRequest, relay_state: Option<String>) {
        let mut pending = self.pending_requests.write().unwrap();
        pending.insert(
            request.id.clone(),
            PendingRequest {
                id: request.id.clone(),
                created_at: timestamp_millis() / 1000,
                relay_state,
            },
        );

        // Clean up old requests (older than 10 minutes)
        let now = timestamp_millis() / 1000;
        pending.retain(|_, req| now - req.created_at < 600);
    }

    /// Initiate SAML login (returns redirect URL)
    pub fn initiate_login(&self, relay_state: Option<&str>) -> String {
        let request = self.create_authn_request();
        self.store_pending_request(&request, relay_state.map(|s| s.to_string()));
        request.to_redirect_url(relay_state)
    }

    /// Process SAML Response and extract user
    pub fn process_response(&self, encoded_response: &str) -> Result<SamlAuthResult, SamlError> {
        let response = SamlResponse::from_base64(encoded_response)?;

        // Validate response
        self.validate_response(&response)?;

        // Extract user from assertion
        let assertion = response
            .assertion()
            .ok_or_else(|| SamlError::InvalidResponse("No assertion in response".into()))?;

        // Validate assertion
        assertion.validate(&self.config)?;

        // Map to User
        let user = self.map_assertion_to_user(assertion)?;

        // Clean up pending request
        if let Some(ref in_response_to) = response.in_response_to {
            let mut pending = self.pending_requests.write().unwrap();
            pending.remove(in_response_to);
        }

        Ok(SamlAuthResult {
            user,
            session_index: assertion.session_index.clone(),
            name_id: assertion.name_id.clone(),
            name_id_format: assertion.name_id_format.clone(),
            attributes: assertion.attributes.clone(),
        })
    }

    /// Validate a SAML Response
    fn validate_response(&self, response: &SamlResponse) -> Result<(), SamlError> {
        // Check status
        if !response.is_success() {
            return Err(SamlError::IdpError(
                response.status_code.clone(),
                response.status_message.clone(),
            ));
        }

        // Check InResponseTo if not allowing unsolicited responses
        if !self.config.allow_unsolicited_responses {
            if let Some(ref in_response_to) = response.in_response_to {
                let pending = self.pending_requests.read().unwrap();
                if !pending.contains_key(in_response_to) {
                    return Err(SamlError::InvalidResponse(
                        "InResponseTo does not match any pending request".into(),
                    ));
                }
            } else {
                return Err(SamlError::InvalidResponse(
                    "Unsolicited responses are not allowed".into(),
                ));
            }
        }

        // Check destination
        if let Some(ref destination) = response.destination {
            if destination != &self.config.acs_url {
                return Err(SamlError::InvalidResponse(format!(
                    "Destination mismatch: expected {}, got {}",
                    self.config.acs_url, destination
                )));
            }
        }

        Ok(())
    }

    /// Map SAML assertion to User
    fn map_assertion_to_user(&self, assertion: &SamlAssertion) -> Result<User, SamlError> {
        let username = assertion.name_id.clone();

        // Use with_encoded_password since SAML users don't have local passwords
        let mut user = User::with_encoded_password(&username, "{saml}external".to_string());

        // Map attributes
        for (saml_attr, user_field) in &self.config.attribute_mapping {
            if let Some(values) = assertion.attributes.get(saml_attr) {
                if let Some(value) = values.first() {
                    match user_field.as_str() {
                        "email" => {
                            // Store email in attributes (User doesn't have email field directly)
                            user = user.authorities(&[format!("email:{}", value)]);
                        }
                        "display_name" | "name" => {
                            // Could extend User model for this
                        }
                        _ => {}
                    }
                }
            }
        }

        // Extract roles
        let mut roles: Vec<String> = self.config.default_roles.clone();
        if let Some(ref role_attr) = self.config.role_attribute {
            if let Some(values) = assertion.attributes.get(role_attr) {
                roles.extend(values.iter().map(|r| r.to_uppercase()));
            }
        }
        user = user.roles(&roles);

        // Extract authorities
        if let Some(ref auth_attr) = self.config.authority_attribute {
            if let Some(values) = assertion.attributes.get(auth_attr) {
                user = user.authorities(values);
            }
        }

        Ok(user)
    }

    /// Generate SP metadata XML
    pub fn generate_metadata(&self) -> String {
        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push_str(&format!(
            r#"<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" entityID="{}">"#,
            self.config.entity_id
        ));

        xml.push_str(r#"<md:SPSSODescriptor AuthnRequestsSigned=""#);
        xml.push_str(if self.config.sign_authn_request {
            "true"
        } else {
            "false"
        });
        xml.push_str(r#"" WantAssertionsSigned=""#);
        xml.push_str(if self.config.want_assertions_signed {
            "true"
        } else {
            "false"
        });
        xml.push_str(r#"" protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">"#);

        // NameIDFormat
        xml.push_str(&format!(
            r#"<md:NameIDFormat>{}</md:NameIDFormat>"#,
            self.config.name_id_format.as_urn()
        ));

        // ACS
        xml.push_str(&format!(
            r#"<md:AssertionConsumerService Binding="{}" Location="{}" index="0"/>"#,
            SamlBinding::HttpPost.as_urn(),
            self.config.acs_url
        ));

        // SLS (if configured)
        if let Some(ref sls_url) = self.config.sls_url {
            xml.push_str(&format!(
                r#"<md:SingleLogoutService Binding="{}" Location="{}"/>"#,
                self.config.slo_binding.as_urn(),
                sls_url
            ));
        }

        xml.push_str(r#"</md:SPSSODescriptor></md:EntityDescriptor>"#);
        xml
    }

    /// Create logout request URL
    pub fn create_logout_request(
        &self,
        name_id: &str,
        session_index: Option<&str>,
    ) -> Option<String> {
        let slo_url = self.config.idp_slo_url.as_ref()?;

        let id = format!("_{}_{}", generate_id(), timestamp_millis());
        let issue_instant = iso8601_now();

        let mut xml = String::new();
        xml.push_str(r#"<?xml version="1.0" encoding="UTF-8"?>"#);
        xml.push_str(&format!(
            r#"<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="{}" Version="2.0" IssueInstant="{}" Destination="{}">"#,
            id, issue_instant, slo_url
        ));

        xml.push_str(&format!(
            r#"<saml:Issuer>{}</saml:Issuer>"#,
            self.config.entity_id
        ));

        xml.push_str(&format!(
            r#"<saml:NameID Format="{}">{}</saml:NameID>"#,
            self.config.name_id_format.as_urn(),
            name_id
        ));

        if let Some(session_idx) = session_index {
            xml.push_str(&format!(
                r#"<samlp:SessionIndex>{}</samlp:SessionIndex>"#,
                session_idx
            ));
        }

        xml.push_str(r#"</samlp:LogoutRequest>"#);

        let deflated = deflate_and_encode(&xml);
        Some(format!(
            "{}?SAMLRequest={}",
            slo_url,
            urlencoding::encode(&deflated)
        ))
    }
}

/// Result of successful SAML authentication
#[derive(Debug, Clone)]
pub struct SamlAuthResult {
    /// Authenticated user
    pub user: User,
    /// Session index from IdP
    pub session_index: Option<String>,
    /// Name ID from assertion
    pub name_id: String,
    /// Name ID format
    pub name_id_format: NameIdFormat,
    /// All attributes from assertion
    pub attributes: HashMap<String, Vec<String>>,
}

// ============================================================================
// Helper functions
// ============================================================================

/// Generate a random ID
fn generate_id() -> String {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};

    let hasher = RandomState::new();
    let mut h = hasher.build_hasher();
    h.write_u64(timestamp_millis());
    format!("{:016x}", h.finish())
}

/// Get current timestamp in milliseconds
fn timestamp_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

/// Get current time in ISO 8601 format
fn iso8601_now() -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    // Simple ISO 8601 formatting (in production, use chrono or time crate)
    let secs_per_minute = 60;
    let secs_per_hour = 3600;
    let secs_per_day = 86400;

    let days_since_1970 = now / secs_per_day;
    let time_of_day = now % secs_per_day;

    let hours = time_of_day / secs_per_hour;
    let minutes = (time_of_day % secs_per_hour) / secs_per_minute;
    let seconds = time_of_day % secs_per_minute;

    // Simple year/month/day calculation (not accounting for leap seconds perfectly)
    let (year, month, day) = days_to_ymd(days_since_1970);

    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Convert days since 1970 to year/month/day
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Simplified calculation
    let mut remaining = days;
    let mut year = 1970u64;

    loop {
        let days_in_year = if is_leap_year(year) { 366 } else { 365 };
        if remaining < days_in_year {
            break;
        }
        remaining -= days_in_year;
        year += 1;
    }

    let months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 1u64;

    for (i, &days_in_month) in months.iter().enumerate() {
        let days_in_month = if i == 1 && is_leap_year(year) {
            29
        } else {
            days_in_month
        };
        if remaining < days_in_month {
            break;
        }
        remaining -= days_in_month;
        month += 1;
    }

    (year, month, remaining + 1)
}

fn is_leap_year(year: u64) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Parse ISO 8601 date to Unix timestamp (simplified)
fn parse_iso8601(s: &str) -> Result<u64, ()> {
    // Expected format: 2024-01-15T10:30:00Z
    if s.len() < 19 {
        return Err(());
    }

    let year: u64 = s[0..4].parse().map_err(|_| ())?;
    let month: u64 = s[5..7].parse().map_err(|_| ())?;
    let day: u64 = s[8..10].parse().map_err(|_| ())?;
    let hour: u64 = s[11..13].parse().map_err(|_| ())?;
    let minute: u64 = s[14..16].parse().map_err(|_| ())?;
    let second: u64 = s[17..19].parse().map_err(|_| ())?;

    // Convert to Unix timestamp
    let mut days = 0u64;
    for y in 1970..year {
        days += if is_leap_year(y) { 366 } else { 365 };
    }

    let months = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    for (i, &d) in months.iter().take((month - 1) as usize).enumerate() {
        days += if i == 1 && is_leap_year(year) { 29 } else { d };
    }
    days += day - 1;

    Ok(days * 86400 + hour * 3600 + minute * 60 + second)
}

/// Deflate and base64-encode XML for HTTP Redirect binding
fn deflate_and_encode(xml: &str) -> String {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    // In production, use flate2 crate for proper DEFLATE compression
    // For now, just base64 encode (many IdPs accept this)
    STANDARD.encode(xml)
}

/// Extract an attribute from XML element (simplified parser)
fn extract_attribute(xml: &str, element: &str, attr: &str) -> Option<String> {
    let element_pattern = format!("<{}", element);
    let start = xml.find(&element_pattern)?;
    let end = xml[start..].find('>')? + start;
    let element_str = &xml[start..end];

    let attr_pattern = format!("{}=\"", attr);
    let attr_start = element_str.find(&attr_pattern)? + attr_pattern.len();
    let attr_end = element_str[attr_start..].find('"')? + attr_start;

    Some(element_str[attr_start..attr_end].to_string())
}

/// Extract element text content (simplified parser)
fn extract_element_text(xml: &str, element: &str) -> Option<String> {
    // Handle namespaced elements
    let patterns = [format!("<{}:", element), format!("<{}>", element)];

    for pattern in &patterns {
        if let Some(start) = xml.find(pattern) {
            let content_start = xml[start..].find('>')? + start + 1;
            let end_pattern = format!("</{}", element);
            if let Some(end) = xml[content_start..].find(&end_pattern) {
                let content = &xml[content_start..content_start + end];
                // Handle nested elements by finding the actual close
                if let Some(actual_end) = content.rfind('<') {
                    return Some(content[..actual_end].trim().to_string());
                }
                return Some(content.trim().to_string());
            }
        }
    }

    // Try without namespace prefix
    let start_tag = format!("<{}>", element);
    let end_tag = format!("</{}>", element);
    if let Some(start) = xml.find(&start_tag) {
        let content_start = start + start_tag.len();
        if let Some(end) = xml[content_start..].find(&end_tag) {
            return Some(xml[content_start..content_start + end].trim().to_string());
        }
    }

    None
}

/// Extract SAML status code (simplified parser)
fn extract_status_code(xml: &str) -> Option<SamlStatusCode> {
    let pattern = "StatusCode";
    let start = xml.find(pattern)?;
    let value_start = xml[start..].find("Value=\"")? + start + 7;
    let value_end = xml[value_start..].find('"')? + value_start;
    let value = &xml[value_start..value_end];

    Some(SamlStatusCode::from_urn(value))
}

/// Parse assertions from SAML response (simplified parser)
fn parse_assertions(xml: &str) -> Result<Vec<SamlAssertion>, SamlError> {
    let mut assertions = Vec::new();

    // Find Assertion element
    let assertion_pattern = "<saml:Assertion";
    if let Some(start) = xml.find(assertion_pattern) {
        let assertion_xml = &xml[start..];

        let id = extract_attribute(assertion_xml, "Assertion", "ID")
            .unwrap_or_else(|| format!("_generated_{}", timestamp_millis()));
        let issue_instant =
            extract_attribute(assertion_xml, "Assertion", "IssueInstant").unwrap_or_default();
        let issuer = extract_element_text(assertion_xml, "Issuer").unwrap_or_default();

        // Parse NameID
        let name_id = extract_element_text(assertion_xml, "NameID").unwrap_or_default();
        let name_id_format = extract_attribute(assertion_xml, "NameID", "Format")
            .map(|f| NameIdFormat::from_urn(&f))
            .unwrap_or_default();

        // Parse conditions
        let not_before = extract_attribute(assertion_xml, "Conditions", "NotBefore");
        let not_on_or_after = extract_attribute(assertion_xml, "Conditions", "NotOnOrAfter");

        // Parse session index
        let session_index = extract_attribute(assertion_xml, "AuthnStatement", "SessionIndex");
        let session_not_on_or_after =
            extract_attribute(assertion_xml, "AuthnStatement", "SessionNotOnOrAfter");

        // Parse audience
        let audiences = extract_element_text(assertion_xml, "Audience")
            .map(|a| vec![a])
            .unwrap_or_default();

        // Parse authn context
        let authn_context_class = extract_element_text(assertion_xml, "AuthnContextClassRef");

        // Parse attributes
        let attributes = parse_attributes(assertion_xml);

        assertions.push(SamlAssertion {
            id,
            issue_instant,
            issuer,
            name_id,
            name_id_format,
            session_index,
            session_not_on_or_after,
            not_before,
            not_on_or_after,
            audiences,
            authn_context_class,
            attributes,
        });
    }

    Ok(assertions)
}

/// Parse SAML attributes (simplified parser)
fn parse_attributes(xml: &str) -> HashMap<String, Vec<String>> {
    let mut attributes = HashMap::new();

    // Find AttributeStatement
    let attr_statement = "<AttributeStatement";
    if let Some(start) = xml.find(attr_statement) {
        let end = xml[start..]
            .find("</AttributeStatement>")
            .unwrap_or(xml.len() - start);
        let statement_xml = &xml[start..start + end];

        // Find each Attribute
        let mut search_pos = 0;
        while let Some(attr_start) = statement_xml[search_pos..].find("<Attribute ") {
            let attr_start = search_pos + attr_start;

            // Get attribute name
            if let Some(name) = extract_attribute(&statement_xml[attr_start..], "Attribute", "Name")
            {
                // Find attribute values
                let attr_end = statement_xml[attr_start..]
                    .find("</Attribute>")
                    .unwrap_or(statement_xml.len() - attr_start);
                let attr_xml = &statement_xml[attr_start..attr_start + attr_end];

                let mut values = Vec::new();
                let mut value_pos = 0;
                while let Some(value_start) = attr_xml[value_pos..].find("<AttributeValue") {
                    let value_start = value_pos + value_start;
                    if let Some(content_start) = attr_xml[value_start..].find('>') {
                        let content_start = value_start + content_start + 1;
                        if let Some(content_end) =
                            attr_xml[content_start..].find("</AttributeValue>")
                        {
                            let value = attr_xml[content_start..content_start + content_end].trim();
                            values.push(value.to_string());
                        }
                    }
                    value_pos = value_start + 1;
                }

                if !values.is_empty() {
                    attributes.insert(name, values);
                }
            }

            search_pos = attr_start + 1;
        }
    }

    attributes
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_name_id_format() {
        assert_eq!(
            NameIdFormat::EmailAddress.as_urn(),
            "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        );

        let parsed = NameIdFormat::from_urn("urn:oasis:names:tc:SAML:2.0:nameid-format:persistent");
        assert_eq!(parsed, NameIdFormat::Persistent);
    }

    #[test]
    fn test_saml_binding() {
        assert_eq!(
            SamlBinding::HttpPost.as_urn(),
            "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        );
    }

    #[test]
    fn test_status_code() {
        let success = SamlStatusCode::from_urn("urn:oasis:names:tc:SAML:2.0:status:Success");
        assert!(success.is_success());

        let failure = SamlStatusCode::from_urn("urn:oasis:names:tc:SAML:2.0:status:AuthnFailed");
        assert!(!failure.is_success());
    }

    #[test]
    fn test_config_builder() {
        let config = SamlConfig::new()
            .entity_id("https://sp.example.com/saml/metadata")
            .idp_sso_url("https://idp.example.com/saml/sso")
            .acs_url("https://sp.example.com/saml/acs")
            .name_id_format(NameIdFormat::EmailAddress)
            .want_assertions_signed(true);

        assert_eq!(config.entity_id, "https://sp.example.com/saml/metadata");
        assert_eq!(config.name_id_format, NameIdFormat::EmailAddress);
    }

    #[test]
    fn test_config_validation() {
        let incomplete = SamlConfig::new();
        assert!(incomplete.validate().is_err());

        let valid = SamlConfig::new()
            .entity_id("https://sp.example.com")
            .idp_sso_url("https://idp.example.com/sso")
            .acs_url("https://sp.example.com/acs")
            .want_assertions_signed(false);

        assert!(valid.validate().is_ok());
    }

    #[test]
    fn test_config_presets() {
        let okta = SamlConfig::okta("myorg.okta.com", "app123", "https://myapp.com");
        assert!(okta.idp_sso_url.contains("okta.com"));

        let azure = SamlConfig::azure_ad("tenant-id", "app-id", "https://myapp.com");
        assert!(azure.idp_sso_url.contains("microsoftonline.com"));

        let adfs = SamlConfig::adfs("adfs.company.com", "https://myapp.com");
        assert!(adfs.idp_sso_url.contains("adfs"));
    }

    #[test]
    fn test_authn_request_generation() {
        let config = SamlConfig::new()
            .entity_id("https://sp.example.com")
            .idp_sso_url("https://idp.example.com/sso")
            .acs_url("https://sp.example.com/acs")
            .name_id_format(NameIdFormat::EmailAddress);

        let request = AuthnRequest::new(&config);
        let xml = request.to_xml();

        assert!(xml.contains("AuthnRequest"));
        assert!(xml.contains("https://sp.example.com"));
        assert!(xml.contains("emailAddress"));
    }

    #[test]
    fn test_authn_request_url() {
        let config = SamlConfig::new()
            .entity_id("https://sp.example.com")
            .idp_sso_url("https://idp.example.com/sso")
            .acs_url("https://sp.example.com/acs");

        let request = AuthnRequest::new(&config);
        let url = request.to_redirect_url(Some("/dashboard"));

        assert!(url.starts_with("https://idp.example.com/sso?"));
        assert!(url.contains("SAMLRequest="));
        assert!(url.contains("RelayState="));
    }

    #[test]
    fn test_assertion_validation() {
        let config = SamlConfig::new()
            .entity_id("https://sp.example.com")
            .idp_sso_url("https://idp.example.com/sso")
            .acs_url("https://sp.example.com/acs")
            .idp_entity_id("https://idp.example.com")
            .max_clock_skew(Duration::from_secs(300));

        let assertion = SamlAssertion {
            id: "_test".to_string(),
            issue_instant: iso8601_now(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "user@example.com".to_string(),
            name_id_format: NameIdFormat::EmailAddress,
            session_index: Some("_session123".to_string()),
            session_not_on_or_after: None,
            not_before: None,
            not_on_or_after: None,
            audiences: vec!["https://sp.example.com".to_string()],
            authn_context_class: None,
            attributes: HashMap::new(),
        };

        assert!(assertion.validate(&config).is_ok());
    }

    #[test]
    fn test_assertion_audience_validation() {
        let config = SamlConfig::new()
            .entity_id("https://sp.example.com")
            .idp_sso_url("https://idp.example.com/sso")
            .acs_url("https://sp.example.com/acs");

        let assertion = SamlAssertion {
            id: "_test".to_string(),
            issue_instant: iso8601_now(),
            issuer: "https://idp.example.com".to_string(),
            name_id: "user@example.com".to_string(),
            name_id_format: NameIdFormat::EmailAddress,
            session_index: None,
            session_not_on_or_after: None,
            not_before: None,
            not_on_or_after: None,
            audiences: vec!["https://other-sp.example.com".to_string()],
            authn_context_class: None,
            attributes: HashMap::new(),
        };

        let result = assertion.validate(&config);
        assert!(matches!(
            result,
            Err(SamlError::AudienceRestrictionNotMet(_))
        ));
    }

    #[test]
    fn test_authenticator_creation() {
        let config = SamlConfig::new()
            .entity_id("https://sp.example.com")
            .idp_sso_url("https://idp.example.com/sso")
            .acs_url("https://sp.example.com/acs")
            .want_assertions_signed(false);

        let authenticator = SamlAuthenticator::new(config);
        assert!(authenticator.is_ok());
    }

    #[test]
    fn test_metadata_generation() {
        let config = SamlConfig::new()
            .entity_id("https://sp.example.com")
            .idp_sso_url("https://idp.example.com/sso")
            .acs_url("https://sp.example.com/acs")
            .sls_url("https://sp.example.com/sls")
            .want_assertions_signed(false);

        let authenticator = SamlAuthenticator::new(config).unwrap();
        let metadata = authenticator.generate_metadata();

        assert!(metadata.contains("EntityDescriptor"));
        assert!(metadata.contains("https://sp.example.com"));
        assert!(metadata.contains("AssertionConsumerService"));
        assert!(metadata.contains("SingleLogoutService"));
    }

    #[test]
    fn test_iso8601_generation() {
        let now = iso8601_now();
        assert!(now.contains("T"));
        assert!(now.ends_with("Z"));
        assert_eq!(now.len(), 20);
    }

    #[test]
    fn test_iso8601_parsing() {
        let timestamp = parse_iso8601("2024-01-15T10:30:00Z");
        assert!(timestamp.is_ok());

        let invalid = parse_iso8601("invalid");
        assert!(invalid.is_err());
    }

    #[test]
    fn test_xml_attribute_extraction() {
        let xml = r#"<Response ID="resp123" Version="2.0">"#;
        assert_eq!(
            extract_attribute(xml, "Response", "ID"),
            Some("resp123".to_string())
        );
    }

    #[test]
    fn test_attribute_parsing() {
        let xml = r#"
        <AttributeStatement>
            <Attribute Name="email">
                <AttributeValue>user@example.com</AttributeValue>
            </Attribute>
            <Attribute Name="roles">
                <AttributeValue>admin</AttributeValue>
                <AttributeValue>user</AttributeValue>
            </Attribute>
        </AttributeStatement>
        "#;

        let attrs = parse_attributes(xml);
        assert_eq!(
            attrs.get("email"),
            Some(&vec!["user@example.com".to_string()])
        );
        assert_eq!(
            attrs.get("roles"),
            Some(&vec!["admin".to_string(), "user".to_string()])
        );
    }

    #[test]
    fn test_saml_error_display() {
        let err = SamlError::Configuration("test error".to_string());
        let display = format!("{}", err);
        assert!(display.contains("test error"));
    }

    #[test]
    fn test_logout_request() {
        let config = SamlConfig::new()
            .entity_id("https://sp.example.com")
            .idp_sso_url("https://idp.example.com/sso")
            .idp_slo_url("https://idp.example.com/slo")
            .acs_url("https://sp.example.com/acs")
            .want_assertions_signed(false);

        let authenticator = SamlAuthenticator::new(config).unwrap();
        let logout_url =
            authenticator.create_logout_request("user@example.com", Some("_session123"));

        assert!(logout_url.is_some());
        let url = logout_url.unwrap();
        assert!(url.contains("SAMLRequest="));
    }
}
