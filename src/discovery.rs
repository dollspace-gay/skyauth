//! OAuth 2.0 Discovery Engine (RFC 8414 & RFC 9728).
//!
//! Implements multi-stage discovery for the AT Protocol:
//! 1. **Protected Resource Discovery (RFC 9728)**: Discovers authorization servers
//!    guarding the user's Personal Data Server (PDS) via `/.well-known/oauth-protected-resource`.
//! 2. **Authorization Server Discovery (RFC 8414)**: Discovers OAuth endpoints through the
//!    authorization-server well-known document required by the AT Protocol profile.
//! 3. **Mandatory Security Validation**: Asserts issuer origin equality, `ES256` DPoP support,
//!    `S256` PKCE enforcement, and PAR endpoint availability.
//! 4. **End-to-End Discovery Pipeline**: Integrates identity resolution and SSRF defense
//!    into a unified discovery entry point.

use serde::{Deserialize, Serialize};
use url::Url;

use crate::error::{DiscoveryError, SsrfError};
use crate::identity::IdentityResolver;
use crate::policy::metadata_profile_accepts;
use crate::scope::ScopeSet;
use crate::ssrf::SsrfFilter;

/// RFC 9728 OAuth 2.0 Protected Resource Metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProtectedResourceMetadata {
    /// URI of the protected resource (PDS origin).
    pub resource: String,
    /// List of trusted Authorization Server URLs protecting this resource.
    pub authorization_servers: Vec<String>,
    /// Scopes supported by this protected resource (e.g. `["atproto"]`).
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Supported bearer presentation methods (e.g. `["header"]`).
    #[serde(default)]
    pub bearer_methods_supported: Vec<String>,
    /// Documentation URI for the resource.
    #[serde(default)]
    pub resource_documentation: Option<String>,
}

/// RFC 8414 OAuth 2.0 Authorization Server Metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationServerMetadata {
    /// Issuer identifier URL (MUST match discovery origin).
    pub issuer: String,
    /// URL for user authorization browser redirects.
    pub authorization_endpoint: String,
    /// URL for token exchange and refresh requests.
    pub token_endpoint: String,
    /// URL for RFC 9126 Pushed Authorization Requests.
    #[serde(default)]
    pub pushed_authorization_request_endpoint: String,
    /// Whether PAR is required by the authorization server.
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    /// Supported DPoP signing algorithms (must include `"ES256"`).
    #[serde(default)]
    pub dpop_signing_alg_values_supported: Vec<String>,
    /// Supported PKCE code challenge methods (must include `"S256"`).
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    /// Supported response types (e.g. `["code"]`).
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    /// Supported grant types (e.g. `["authorization_code", "refresh_token"]`).
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    /// Supported client authentication methods for the token endpoint.
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    /// Supported client authentication signing algorithms.
    #[serde(default)]
    pub token_endpoint_auth_signing_alg_values_supported: Vec<String>,
    /// Supported OAuth scopes (e.g. `["atproto"]`).
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    /// Whether RFC 9207 `iss` response parameter is returned.
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    /// Whether client ID metadata document resolution is supported.
    #[serde(default)]
    pub client_id_metadata_document_supported: bool,
    /// Whether request URI registration is required.
    #[serde(default)]
    pub require_request_uri_registration: Option<bool>,
}

/// AT Protocol OAuth client metadata document for a public client.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClientMetadataDocument {
    /// Exact URL identifying and locating this metadata document.
    pub client_id: String,
    /// Web or native application classification.
    #[serde(default = "default_application_type")]
    pub application_type: String,
    /// Registered redirect URIs.
    pub redirect_uris: Vec<String>,
    /// Declared OAuth grant types.
    pub grant_types: Vec<String>,
    /// Declared OAuth response types.
    pub response_types: Vec<String>,
    /// Maximum OAuth scope set the client may request.
    pub scope: String,
    /// Token endpoint authentication method.
    pub token_endpoint_auth_method: String,
    /// Whether access tokens must be DPoP-bound.
    pub dpop_bound_access_tokens: bool,
    /// Embedded public client-authentication key set.
    #[serde(default)]
    pub jwks: Option<serde_json::Value>,
    /// URL of a public client-authentication key set.
    #[serde(default)]
    pub jwks_uri: Option<String>,
}

fn default_application_type() -> String {
    "web".to_string()
}

/// Fetches and validates a public AT Protocol client metadata document.
///
/// # Errors
///
/// Returns [`DiscoveryError`] for transport, JSON, identity, redirect, or profile failures.
pub async fn fetch_client_metadata_document(
    ssrf_filter: &SsrfFilter,
    client_id: &str,
) -> Result<ClientMetadataDocument, DiscoveryError> {
    let client_url = Url::parse(client_id).map_err(|error| {
        DiscoveryError::ProfileViolation(format!("invalid client ID URL: {error}"))
    })?;
    ssrf_filter.validate_url(&client_url)?;
    if client_url.port().is_some() {
        return Err(DiscoveryError::ProfileViolation(
            "client ID URL contains a port".to_string(),
        ));
    }
    let document: ClientMetadataDocument = ssrf_filter
        .safe_get_json_exact(client_id, 1_048_576)
        .await
        .map_err(DiscoveryError::Ssrf)?;
    validate_client_metadata_document(&document, client_id)?;
    Ok(document)
}

/// Resolves a public client metadata document, including the localhost virtual profile.
///
/// # Errors
///
/// Returns [`DiscoveryError`] for invalid virtual metadata or failed remote resolution.
pub async fn resolve_client_metadata_document(
    ssrf_filter: &SsrfFilter,
    client_id: &str,
) -> Result<ClientMetadataDocument, DiscoveryError> {
    let url = Url::parse(client_id).map_err(|error| {
        DiscoveryError::ProfileViolation(format!("invalid client ID URL: {error}"))
    })?;
    if url.scheme() == "http" && url.host_str() == Some("localhost") {
        virtual_loopback_client_metadata(client_id)
    } else {
        fetch_client_metadata_document(ssrf_filter, client_id).await
    }
}

fn virtual_loopback_client_metadata(
    client_id: &str,
) -> Result<ClientMetadataDocument, DiscoveryError> {
    let url = Url::parse(client_id).map_err(|error| {
        DiscoveryError::ProfileViolation(format!("invalid localhost client ID: {error}"))
    })?;
    if url.scheme() != "http"
        || url.host_str() != Some("localhost")
        || url.port().is_some()
        || url.path() != "/"
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(DiscoveryError::ProfileViolation(
            "invalid localhost client ID".to_string(),
        ));
    }
    let mut redirects = Vec::new();
    let mut scope = None;
    for (name, value) in url.query_pairs() {
        match name.as_ref() {
            "redirect_uri" => redirects.push(value.into_owned()),
            "scope" if scope.is_none() => scope = Some(value.into_owned()),
            "scope" => {
                return Err(DiscoveryError::ProfileViolation(
                    "localhost client ID repeats scope".to_string(),
                ));
            }
            _ => {
                return Err(DiscoveryError::ProfileViolation(
                    "localhost client ID contains an unknown parameter".to_string(),
                ));
            }
        }
    }
    if redirects.is_empty() {
        redirects = vec!["http://127.0.0.1/".to_string(), "http://[::1]/".to_string()];
    }
    let document = ClientMetadataDocument {
        client_id: client_id.to_string(),
        application_type: "native".to_string(),
        redirect_uris: redirects,
        grant_types: vec![
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ],
        response_types: vec!["code".to_string()],
        scope: scope.unwrap_or_else(|| "atproto".to_string()),
        token_endpoint_auth_method: "none".to_string(),
        dpop_bound_access_tokens: true,
        jwks: None,
        jwks_uri: None,
    };
    validate_virtual_client_metadata(&document)?;
    Ok(document)
}

/// Validates a parsed AT Protocol public-client metadata document.
///
/// # Errors
///
/// Returns [`DiscoveryError`] when a mandatory profile constraint is not met.
pub fn validate_client_metadata_document(
    document: &ClientMetadataDocument,
    fetched_from: &str,
) -> Result<(), DiscoveryError> {
    if document.client_id != fetched_from {
        return Err(DiscoveryError::ProfileViolation(
            "client metadata identifier does not match its fetch URL".to_string(),
        ));
    }
    let client_url = Url::parse(fetched_from).map_err(|error| {
        DiscoveryError::ProfileViolation(format!("invalid client ID URL: {error}"))
    })?;
    if client_url.scheme() != "https"
        || client_url.host_str().is_none()
        || client_url.port().is_some()
        || !client_url.username().is_empty()
        || client_url.password().is_some()
        || client_url.fragment().is_some()
    {
        return Err(DiscoveryError::ProfileViolation(
            "client ID is not a canonical HTTPS metadata URL".to_string(),
        ));
    }
    if !matches!(document.application_type.as_str(), "web" | "native") {
        return Err(DiscoveryError::ProfileViolation(
            "unknown client application type".to_string(),
        ));
    }
    if document.redirect_uris.is_empty() {
        return Err(DiscoveryError::ProfileViolation(
            "client metadata has no redirect URI".to_string(),
        ));
    }
    for redirect in &document.redirect_uris {
        validate_client_redirect(redirect, &document.application_type, &client_url)?;
    }
    require_value(&document.grant_types, "authorization_code", "grant_types")?;
    require_value(&document.response_types, "code", "response_types")?;
    ScopeSet::parse(&document.scope).map_err(|error| {
        DiscoveryError::ProfileViolation(format!("invalid declared scope set: {error}"))
    })?;
    if !document.dpop_bound_access_tokens {
        return Err(DiscoveryError::ProfileViolation(
            "client does not require DPoP-bound access tokens".to_string(),
        ));
    }
    if document.token_endpoint_auth_method != "none" {
        return Err(DiscoveryError::ProfileViolation(
            "only public clients are supported".to_string(),
        ));
    }
    if document.jwks.is_some() || document.jwks_uri.is_some() {
        return Err(DiscoveryError::ProfileViolation(
            "public client metadata includes client-authentication keys".to_string(),
        ));
    }
    Ok(())
}

fn validate_client_redirect(
    value: &str,
    application_type: &str,
    client_id: &Url,
) -> Result<(), DiscoveryError> {
    let redirect = Url::parse(value).map_err(|error| {
        DiscoveryError::ProfileViolation(format!("invalid redirect URI: {error}"))
    })?;
    if !redirect.username().is_empty()
        || redirect.password().is_some()
        || redirect.fragment().is_some()
    {
        return Err(DiscoveryError::ProfileViolation(
            "redirect URI contains prohibited components".to_string(),
        ));
    }
    let valid = match application_type {
        "web" => redirect.scheme() == "https" && redirect.host_str().is_some(),
        "native" => {
            (redirect.scheme() == "http"
                && redirect
                    .host_str()
                    .is_some_and(|host| matches!(host, "127.0.0.1" | "::1")))
                || (redirect.scheme() == "https" && redirect.origin() == client_id.origin())
                || valid_native_custom_redirect(value, &redirect, client_id)
        }
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(DiscoveryError::ProfileViolation(
            "redirect URI does not match the application type".to_string(),
        ))
    }
}

fn valid_native_custom_redirect(value: &str, redirect: &Url, client_id: &Url) -> bool {
    let Some(host) = client_id.host_str() else {
        return false;
    };
    let expected_scheme = host.split('.').rev().collect::<Vec<_>>().join(".");
    redirect.scheme() == expected_scheme
        && redirect.host_str().is_none()
        && value.starts_with(&format!("{expected_scheme}:/"))
        && !value.starts_with(&format!("{expected_scheme}://"))
}

fn validate_virtual_client_metadata(
    document: &ClientMetadataDocument,
) -> Result<(), DiscoveryError> {
    ScopeSet::parse(&document.scope).map_err(|error| {
        DiscoveryError::ProfileViolation(format!("invalid localhost scope set: {error}"))
    })?;
    for redirect in &document.redirect_uris {
        let url = Url::parse(redirect).map_err(|error| {
            DiscoveryError::ProfileViolation(format!("invalid localhost redirect URI: {error}"))
        })?;
        if url.scheme() != "http"
            || !url
                .host_str()
                .is_some_and(|host| matches!(host, "127.0.0.1" | "::1"))
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
        {
            return Err(DiscoveryError::ProfileViolation(
                "invalid localhost redirect URI".to_string(),
            ));
        }
    }
    Ok(())
}

/// Fully discovered and validated OAuth endpoints bundle.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAuthEndpoints {
    /// Authenticated subject DID.
    pub did: String,
    /// Verified account handle, if resolved from handle.
    pub handle: Option<String>,
    /// Resolved PDS origin URL.
    pub pds_endpoint: String,
    /// Authoritative Authorization Server issuer URL.
    pub auth_server_issuer: String,
    /// RFC 9126 PAR endpoint URL.
    pub par_endpoint: String,
    /// User authorization redirect endpoint URL.
    pub authorization_endpoint: String,
    /// Token exchange endpoint URL.
    pub token_endpoint: String,
    /// Supported DPoP signing algorithms.
    pub dpop_algs: Vec<String>,
    /// Supported OAuth scopes.
    pub scopes: Vec<String>,
    /// Complete RFC 9728 Protected Resource Metadata.
    pub protected_resource_metadata: ProtectedResourceMetadata,
    /// Complete RFC 8414 Authorization Server Metadata.
    pub auth_server_metadata: AuthorizationServerMetadata,
}

/// Fetches and parses RFC 9728 Protected Resource Metadata from a PDS endpoint.
///
/// # Errors
/// - Returns [`DiscoveryError::MissingAuthorizationServers`] if the `authorization_servers` list is empty.
/// - Returns [`DiscoveryError::ProtectedResourceDiscoveryFailed`] if the HTTP request or JSON parsing fails.
pub async fn fetch_protected_resource_metadata(
    ssrf_filter: &SsrfFilter,
    pds_endpoint: &str,
) -> Result<ProtectedResourceMetadata, DiscoveryError> {
    let resource_url = Url::parse(pds_endpoint).map_err(|error| {
        DiscoveryError::ProtectedResourceDiscoveryFailed(format!(
            "Invalid protected resource identifier '{pds_endpoint}': {error}"
        ))
    })?;
    ssrf_filter.validate_url(&resource_url)?;
    let url = protected_resource_metadata_url(&resource_url);

    let meta: ProtectedResourceMetadata = ssrf_filter
        .safe_get_json_exact(url.as_str(), 1_048_576)
        .await
        .map_err(|e| match e {
            SsrfError::HttpStatus(status, msg) => DiscoveryError::ProtectedResourceDiscoveryFailed(
                format!("HTTP {status} fetching protected resource metadata from {url}: {msg}"),
            ),
            SsrfError::Json(err) => DiscoveryError::ProtectedResourceDiscoveryFailed(format!(
                "Invalid JSON in protected resource metadata from {url}: {err}"
            )),
            other => DiscoveryError::Ssrf(other),
        })?;

    let expected_resource = normalize_resource_identifier(&resource_url);
    if meta.resource != expected_resource {
        return Err(DiscoveryError::ProfileViolation(format!(
            "protected resource identifier '{}' does not match '{expected_resource}'",
            meta.resource
        )));
    }

    if meta.authorization_servers.len() != 1 {
        return Err(DiscoveryError::MissingAuthorizationServers(
            pds_endpoint.to_string(),
        ));
    }

    validate_origin_identifier_with_local(
        &meta.authorization_servers[0],
        ssrf_filter.allow_insecure_localhost,
    )?;

    Ok(meta)
}

/// Fetches and parses RFC 8414 Authorization Server Metadata.
///
/// # Invariants
/// 1. Fetches `<auth_server>/.well-known/oauth-authorization-server`.
/// 2. Validates mandatory security invariants: `issuer` matching, `ES256` DPoP support,
///    `S256` PKCE challenge method, and non-empty PAR, token, and authorization endpoints.
///
/// # Errors
/// - Returns [`DiscoveryError::IssuerMismatch`] if `issuer` does not match `auth_server_url`.
/// - Returns [`DiscoveryError::MissingDpopAlgorithm`] if `ES256` is missing.
/// - Returns [`DiscoveryError::MissingPkceMethod`] if `S256` is missing.
/// - Returns [`DiscoveryError::MissingParEndpoint`] if PAR endpoint is missing.
pub async fn fetch_auth_server_metadata(
    ssrf_filter: &SsrfFilter,
    auth_server_url: &str,
) -> Result<AuthorizationServerMetadata, DiscoveryError> {
    let base = validate_origin_identifier_with_local(
        auth_server_url,
        ssrf_filter.allow_insecure_localhost,
    )?;
    let primary_url = format!("{base}/.well-known/oauth-authorization-server");

    let meta: AuthorizationServerMetadata = ssrf_filter
        .safe_get_json_exact(&primary_url, 1_048_576)
        .await
        .map_err(|e| match e {
            SsrfError::HttpStatus(status, msg) => DiscoveryError::AuthServerDiscoveryFailed(
                format!("HTTP {status} fetching authorization server metadata from {primary_url}: {msg}"),
            ),
            SsrfError::Json(err) => DiscoveryError::AuthServerDiscoveryFailed(format!(
                "Invalid JSON in authorization server metadata from {primary_url}: {err}"
            )),
            other => DiscoveryError::Ssrf(other),
        })?;

    validate_auth_server_capabilities_with_local(
        &meta,
        auth_server_url,
        ssrf_filter.allow_insecure_localhost,
    )?;
    Ok(meta)
}

/// Validates security capabilities and invariant compliance on Authorization Server Metadata.
pub fn validate_auth_server_capabilities(
    meta: &AuthorizationServerMetadata,
    auth_server_url: &str,
) -> Result<(), DiscoveryError> {
    validate_auth_server_capabilities_with_local(meta, auth_server_url, false)
}

fn validate_auth_server_capabilities_with_local(
    meta: &AuthorizationServerMetadata,
    auth_server_url: &str,
    allow_insecure_localhost: bool,
) -> Result<(), DiscoveryError> {
    let expected_norm =
        validate_origin_identifier_with_local(auth_server_url, allow_insecure_localhost)?;
    let actual_norm =
        validate_origin_identifier_with_local(&meta.issuer, allow_insecure_localhost)?;
    if expected_norm != actual_norm {
        return Err(DiscoveryError::IssuerMismatch {
            expected: auth_server_url.to_string(),
            actual: meta.issuer.clone(),
        });
    }

    if meta.pushed_authorization_request_endpoint.trim().is_empty() {
        return Err(DiscoveryError::MissingParEndpoint(
            auth_server_url.to_string(),
        ));
    }
    validate_endpoint_url(
        &meta.pushed_authorization_request_endpoint,
        "PAR",
        allow_insecure_localhost,
    )?;

    if meta.token_endpoint.trim().is_empty() {
        return Err(DiscoveryError::MissingTokenEndpoint(
            auth_server_url.to_string(),
        ));
    }
    validate_endpoint_url(&meta.token_endpoint, "token", allow_insecure_localhost)?;

    if meta.authorization_endpoint.trim().is_empty() {
        return Err(DiscoveryError::MissingAuthorizationEndpoint(
            auth_server_url.to_string(),
        ));
    }
    validate_endpoint_url(
        &meta.authorization_endpoint,
        "authorization",
        allow_insecure_localhost,
    )?;

    if !meta
        .dpop_signing_alg_values_supported
        .iter()
        .any(|alg| alg == "ES256")
    {
        return Err(DiscoveryError::MissingDpopAlgorithm(
            auth_server_url.to_string(),
        ));
    }

    if !meta
        .code_challenge_methods_supported
        .iter()
        .any(|method| method == "S256")
    {
        return Err(DiscoveryError::MissingPkceMethod(
            auth_server_url.to_string(),
        ));
    }

    require_value(
        &meta.response_types_supported,
        "code",
        "response_types_supported",
    )?;
    require_value(
        &meta.grant_types_supported,
        "authorization_code",
        "grant_types_supported",
    )?;
    require_value(
        &meta.grant_types_supported,
        "refresh_token",
        "grant_types_supported",
    )?;
    require_value(
        &meta.token_endpoint_auth_methods_supported,
        "none",
        "token_endpoint_auth_methods_supported",
    )?;
    require_value(
        &meta.token_endpoint_auth_methods_supported,
        "private_key_jwt",
        "token_endpoint_auth_methods_supported",
    )?;
    require_value(
        &meta.token_endpoint_auth_signing_alg_values_supported,
        "ES256",
        "token_endpoint_auth_signing_alg_values_supported",
    )?;
    if meta
        .token_endpoint_auth_signing_alg_values_supported
        .iter()
        .any(|value| value == "none")
    {
        return Err(DiscoveryError::ProfileViolation(
            "token endpoint signing algorithms include 'none'".to_string(),
        ));
    }
    require_value(&meta.scopes_supported, "atproto", "scopes_supported")?;
    if !meta.authorization_response_iss_parameter_supported {
        return Err(DiscoveryError::ProfileViolation(
            "authorization response issuer parameter is not supported".to_string(),
        ));
    }
    if !meta.require_pushed_authorization_requests {
        return Err(DiscoveryError::ProfileViolation(
            "pushed authorization requests are not required".to_string(),
        ));
    }
    if !meta.client_id_metadata_document_supported {
        return Err(DiscoveryError::ProfileViolation(
            "client ID metadata documents are not supported".to_string(),
        ));
    }
    if meta.require_request_uri_registration == Some(false) {
        return Err(DiscoveryError::ProfileViolation(
            "request URI registration is disabled".to_string(),
        ));
    }

    let accepted = metadata_profile_accepts(
        expected_norm == actual_norm,
        true,
        meta.dpop_signing_alg_values_supported
            .iter()
            .any(|value| value == "ES256"),
        meta.code_challenge_methods_supported
            .iter()
            .any(|value| value == "S256"),
        meta.response_types_supported
            .iter()
            .any(|value| value == "code"),
        meta.grant_types_supported
            .iter()
            .any(|value| value == "authorization_code"),
        meta.grant_types_supported
            .iter()
            .any(|value| value == "refresh_token"),
        ["none", "private_key_jwt"].iter().all(|required| {
            meta.token_endpoint_auth_methods_supported
                .iter()
                .any(|value| value == required)
        }),
        meta.token_endpoint_auth_signing_alg_values_supported
            .iter()
            .any(|value| value == "ES256")
            && !meta
                .token_endpoint_auth_signing_alg_values_supported
                .iter()
                .any(|value| value == "none"),
        meta.scopes_supported.iter().any(|value| value == "atproto"),
        meta.authorization_response_iss_parameter_supported,
        meta.require_pushed_authorization_requests,
        meta.client_id_metadata_document_supported,
        meta.require_request_uri_registration.unwrap_or(true),
    );
    if !accepted {
        return Err(DiscoveryError::ProfileViolation(
            "authorization server metadata does not satisfy the AT Protocol profile".to_string(),
        ));
    }

    Ok(())
}

fn protected_resource_metadata_url(resource: &Url) -> Url {
    let mut metadata_url = resource.clone();
    let resource_path = resource.path().trim_start_matches('/');
    let metadata_path = if resource_path.is_empty() {
        "/.well-known/oauth-protected-resource".to_string()
    } else {
        format!("/.well-known/oauth-protected-resource/{resource_path}")
    };
    metadata_url.set_path(&metadata_path);
    metadata_url
}

fn normalize_resource_identifier(resource: &Url) -> String {
    let serialized = resource.as_str();
    if resource.path() == "/" && resource.query().is_none() {
        serialized.trim_end_matches('/').to_string()
    } else {
        serialized.to_string()
    }
}

fn validate_origin_identifier_with_local(
    value: &str,
    allow_insecure_localhost: bool,
) -> Result<String, DiscoveryError> {
    let url = Url::parse(value).map_err(|error| {
        DiscoveryError::InvalidEndpointUrl(format!("Invalid origin '{value}': {error}"))
    })?;
    let is_local_http = allow_insecure_localhost
        && url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if (url.scheme() != "https" && !is_local_http)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(DiscoveryError::InvalidEndpointUrl(format!(
            "Expected an HTTPS origin, got '{value}'"
        )));
    }
    let origin = url.origin().ascii_serialization();
    if value.trim().trim_end_matches('/') != origin {
        return Err(DiscoveryError::InvalidEndpointUrl(format!(
            "Origin is not canonical: '{value}'"
        )));
    }
    Ok(origin)
}

fn validate_endpoint_url(
    value: &str,
    name: &str,
    allow_insecure_localhost: bool,
) -> Result<(), DiscoveryError> {
    let url = Url::parse(value).map_err(|error| {
        DiscoveryError::InvalidEndpointUrl(format!("Invalid {name} endpoint '{value}': {error}"))
    })?;
    let is_local_http = allow_insecure_localhost
        && url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1"));
    if (url.scheme() != "https" && !is_local_http)
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
    {
        return Err(DiscoveryError::InvalidEndpointUrl(format!(
            "Invalid {name} endpoint '{value}'"
        )));
    }
    Ok(())
}

fn require_value(values: &[String], required: &str, field: &str) -> Result<(), DiscoveryError> {
    if values.iter().any(|value| value == required) {
        Ok(())
    } else {
        Err(DiscoveryError::ProfileViolation(format!(
            "{field} is missing '{required}'"
        )))
    }
}

/// Executes the complete AT Protocol discovery pipeline for a user handle or DID.
///
/// # Multi-Stage Execution:
/// 1. Resolves identity (Handle -> DID -> DID Document, or DID -> DID Document).
/// 2. Verifies bidirectional handle linkage if a handle was provided.
/// 3. Extracts the authoritative `#atproto_pds` service endpoint.
/// 4. Fetches RFC 9728 Protected Resource Metadata from `<pds>/.well-known/oauth-protected-resource`.
/// 5. Selects the primary Authorization Server URL from `authorization_servers[0]`.
/// 6. Fetches and validates RFC 8414 Authorization Server Metadata.
/// 7. Returns fully assembled [`DiscoveredAuthEndpoints`].
pub async fn discover_oauth_endpoints(
    resolver: &IdentityResolver,
    did_or_handle: &str,
) -> Result<DiscoveredAuthEndpoints, DiscoveryError> {
    // 1. Identity Resolution & Bidirectional Verification
    let identity = resolver.resolve_ident(did_or_handle).await?;

    // 2. Protected Resource Discovery
    let pds_meta =
        fetch_protected_resource_metadata(resolver.ssrf_filter(), &identity.pds_endpoint).await?;

    let auth_server_url = &pds_meta.authorization_servers[0];

    // 3. Authorization Server Metadata Discovery
    let as_meta = fetch_auth_server_metadata(resolver.ssrf_filter(), auth_server_url).await?;

    Ok(DiscoveredAuthEndpoints {
        did: identity.did,
        handle: identity.handle,
        pds_endpoint: identity.pds_endpoint,
        auth_server_issuer: as_meta.issuer.clone(),
        par_endpoint: as_meta.pushed_authorization_request_endpoint.clone(),
        authorization_endpoint: as_meta.authorization_endpoint.clone(),
        token_endpoint: as_meta.token_endpoint.clone(),
        dpop_algs: as_meta.dpop_signing_alg_values_supported.clone(),
        scopes: if !as_meta.scopes_supported.is_empty() {
            as_meta.scopes_supported.clone()
        } else if !pds_meta.scopes_supported.is_empty() {
            pds_meta.scopes_supported.clone()
        } else {
            vec!["atproto".to_string()]
        },
        protected_resource_metadata: pds_meta,
        auth_server_metadata: as_meta,
    })
}

impl IdentityResolver {
    /// Executes the full OAuth discovery pipeline for a user handle or DID.
    pub async fn discover_oauth_endpoints(
        &self,
        did_or_handle: &str,
    ) -> Result<DiscoveredAuthEndpoints, DiscoveryError> {
        discover_oauth_endpoints(self, did_or_handle).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_auth_server_capabilities_valid() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/oauth/authorize".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            pushed_authorization_request_endpoint: "https://auth.example.com/oauth/par".to_string(),
            require_pushed_authorization_requests: true,
            dpop_signing_alg_values_supported: vec!["ES256".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec![
                "authorization_code".to_string(),
                "refresh_token".to_string(),
            ],
            token_endpoint_auth_methods_supported: vec![
                "none".to_string(),
                "private_key_jwt".to_string(),
            ],
            token_endpoint_auth_signing_alg_values_supported: vec!["ES256".to_string()],
            scopes_supported: vec!["atproto".to_string()],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
            require_request_uri_registration: Some(true),
        };

        assert!(validate_auth_server_capabilities(&meta, "https://auth.example.com").is_ok());
    }

    #[test]
    fn test_validate_auth_server_capabilities_missing_es256() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/oauth/authorize".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            pushed_authorization_request_endpoint: "https://auth.example.com/oauth/par".to_string(),
            require_pushed_authorization_requests: true,
            dpop_signing_alg_values_supported: vec!["RS256".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            token_endpoint_auth_methods_supported: vec![],
            token_endpoint_auth_signing_alg_values_supported: vec![],
            scopes_supported: vec!["atproto".to_string()],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
            require_request_uri_registration: Some(true),
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::MissingDpopAlgorithm(_))
        ));
    }

    #[test]
    fn test_validate_auth_server_capabilities_missing_s256_pkce() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://auth.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/oauth/authorize".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            pushed_authorization_request_endpoint: "https://auth.example.com/oauth/par".to_string(),
            require_pushed_authorization_requests: true,
            dpop_signing_alg_values_supported: vec!["ES256".to_string()],
            code_challenge_methods_supported: vec!["plain".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            token_endpoint_auth_methods_supported: vec![],
            token_endpoint_auth_signing_alg_values_supported: vec![],
            scopes_supported: vec!["atproto".to_string()],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
            require_request_uri_registration: Some(true),
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::MissingPkceMethod(_))
        ));
    }

    #[test]
    fn test_validate_auth_server_capabilities_issuer_mismatch() {
        let meta = AuthorizationServerMetadata {
            issuer: "https://attacker.example.com".to_string(),
            authorization_endpoint: "https://auth.example.com/oauth/authorize".to_string(),
            token_endpoint: "https://auth.example.com/oauth/token".to_string(),
            pushed_authorization_request_endpoint: "https://auth.example.com/oauth/par".to_string(),
            require_pushed_authorization_requests: true,
            dpop_signing_alg_values_supported: vec!["ES256".to_string()],
            code_challenge_methods_supported: vec!["S256".to_string()],
            response_types_supported: vec!["code".to_string()],
            grant_types_supported: vec!["authorization_code".to_string()],
            token_endpoint_auth_methods_supported: vec![],
            token_endpoint_auth_signing_alg_values_supported: vec![],
            scopes_supported: vec!["atproto".to_string()],
            authorization_response_iss_parameter_supported: true,
            client_id_metadata_document_supported: true,
            require_request_uri_registration: Some(true),
        };

        assert!(matches!(
            validate_auth_server_capabilities(&meta, "https://auth.example.com"),
            Err(DiscoveryError::IssuerMismatch { .. })
        ));
    }
}
