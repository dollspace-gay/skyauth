//! Server-Side Request Forgery (SSRF) boundary filtering and DNS rebinding defense.
//!
//! This module provides strict IP address filtering and socket
//! connection pinning to prevent SSRF and DNS rebinding attacks across all outbound
//! identity and discovery network requests in `atproto-oauth`.
//!
//! ## Threat Model & Defense Strategy
//!
//! 1. **Exhaustive IP Range Filtering**: Evaluates every resolved IP against RFC 1918,
//!    loopback (RFC 1122), link-local / cloud metadata (RFC 3927), CGNAT (RFC 6598),
//!    documentation prefixes (RFC 5737, RFC 3849), IPv6 ULA (RFC 4193), multicast,
//!    and unpacked IPv4-mapped IPv6 addresses (RFC 4291).
//! 2. **DNS Rebinding Prevention**: Resolves DNS records ahead-of-time, validates
//!    *all* returned addresses, and pins the HTTP socket connection to a verified IP.
//! 3. **Redirect Depth & Scope Bounding**: Intercepts HTTP redirects (301/302/307/308),
//!    validating target URLs and IPs at each hop with bounded depth.
//! 4. **Response Size Capping**: Limits stream reads to prevent memory exhaustion
//!    or decompression bombs.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use reqwest::header::{HeaderMap, CONTENT_LENGTH, CONTENT_TYPE};
use url::Url;

use crate::error::SsrfError;
use crate::policy::{ipv4_is_restricted, ipv6_is_restricted};

const MAX_RESPONSE_HEADER_BYTES: usize = 65_536;

trait AddressResolver: std::fmt::Debug + Send + Sync + 'static {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, SsrfError>> + Send + 'a>>;
}

#[derive(Debug)]
struct SystemAddressResolver;

impl AddressResolver for SystemAddressResolver {
    fn resolve<'a>(
        &'a self,
        host: &'a str,
        port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, SsrfError>> + Send + 'a>> {
        Box::pin(async move {
            tokio::net::lookup_host((host, port))
                .await
                .map(|addresses| addresses.collect())
                .map_err(|error| SsrfError::DnsResolutionFailed(format!("{host}: {error}")))
        })
    }
}

/// Determines if an IPv4 address belongs to a restricted, private, or special-purpose range.
///
/// # Filtered Ranges (RFC Compliance):
/// - `0.0.0.0/8`: Current network / broadcast ("This host") (RFC 1122)
/// - `10.0.0.0/8`: Private-Use (RFC 1918)
/// - `100.64.0.0/10`: Shared Address Space / CGNAT (RFC 6598)
/// - `127.0.0.0/8`: Loopback (RFC 1122)
/// - `169.254.0.0/16`: Link-Local, includes AWS/GCP/Azure metadata `169.254.169.254` (RFC 3927)
/// - `172.16.0.0/12`: Private-Use (RFC 1918: `172.16.0.0` - `172.31.255.255`)
/// - `192.0.0.0/24`: IETF Protocol Assignments (RFC 6890)
/// - `192.0.2.0/24`: Documentation TEST-NET-1 (RFC 5737)
/// - `192.31.196.0/24`: AS112-v4 (RFC 7535)
/// - `192.52.193.0/24`: AMT (RFC 7450)
/// - `192.88.99.0/24`: 6to4 Relay Anycast (RFC 7526)
/// - `192.168.0.0/16`: Private-Use (RFC 1918)
/// - `192.175.48.0/24`: Direct Delegation AS112 Service (RFC 7534)
/// - `198.18.0.0/15`: Benchmarking (RFC 2544: `198.18.0.0` - `198.19.255.255`)
/// - `198.51.100.0/24`: Documentation TEST-NET-2 (RFC 5737)
/// - `203.0.113.0/24`: Documentation TEST-NET-3 (RFC 5737)
/// - `224.0.0.0/4`: Multicast (RFC 5771)
/// - `240.0.0.0/4`: Reserved / Class E, includes limited broadcast `255.255.255.255` (RFC 1112)
#[must_use]
pub fn is_restricted_ipv4(ip: &Ipv4Addr) -> bool {
    let octets = ip.octets();
    ipv4_is_restricted(octets[0], octets[1], octets[2], octets[3])
}

/// Determines if an IPv6 address belongs to a restricted, private, or special-purpose range.
///
/// # Filtered Ranges (RFC Compliance):
/// - `::/128`: Unspecified address (RFC 4291)
/// - `::1/128`: Loopback address (RFC 4291)
/// - `::ffff:0:0/96`: IPv4-mapped IPv6 (RFC 4291) — unpacked and re-evaluated via [`is_restricted_ipv4`]
/// - `::ffff:0:0:0/96`: IPv4-translated (RFC 6052)
/// - `64:ff9b::/96`: Well-Known IPv4/IPv6 translation prefix (RFC 6052)
/// - `64:ff9b:1::/48`: Local-use translation prefix (RFC 8215)
/// - `100::/64`: Discard-only (RFC 6666)
/// - `100:0:0:1::/64`: Dummy prefix (RFC 9780)
/// - `2001::/23`: IETF protocol assignments (RFC 2928)
/// - `2002::/16`: 6to4 (RFC 3056)
/// - `2620:4f:8000::/48`: Direct Delegation AS112 Service (RFC 7534)
/// - `3fff::/20`: Documentation prefix (RFC 9637)
/// - `5f00::/16`: Segment Routing SIDs (RFC 9602)
/// - `fc00::/7`: Unique Local Address (ULA) (RFC 4193: `fc00::/8`, `fd00::/8`)
/// - `fe80::/10`: Link-Local Unicast (RFC 4291)
/// - `fec0::/10`: Deprecated Site-Local Unicast (RFC 3879)
/// - `ff00::/8`: Multicast (RFC 4291)
#[must_use]
pub fn is_restricted_ipv6(ip: &Ipv6Addr) -> bool {
    let seg = ip.segments();
    ipv6_is_restricted(
        seg[0], seg[1], seg[2], seg[3], seg[4], seg[5], seg[6], seg[7],
    )
}

/// Determines if an IP address (IPv4 or IPv6) belongs to a restricted/private range.
#[must_use]
pub fn is_restricted_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_restricted_ipv4(&v4),
        IpAddr::V6(v6) => is_restricted_ipv6(&v6),
    }
}

/// Checks if a hostname matches any cloud metadata or internal hostnames.
#[must_use]
pub fn is_blocked_hostname(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    let trimmed = lower.trim_end_matches('.');
    trimmed == "metadata.google.internal"
        || trimmed == "instance-data"
        || trimmed == "metadata.internal"
        || trimmed == "169.254.169.254"
        || trimmed.ends_with(".internal")
        || trimmed.ends_with(".local")
        || trimmed.ends_with(".localhost")
}

/// Configurable SSRF boundary filter for outbound HTTP and DNS requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SsrfFilter {
    /// Whether insecure HTTP and loopback addresses (`127.0.0.1`, `::1`, `localhost`)
    /// are permitted for local integration testing. Defaults to `false` (strictly enforced).
    pub allow_insecure_localhost: bool,
}

impl SsrfFilter {
    /// Creates a new SSRF filter.
    #[must_use]
    pub const fn new(allow_insecure_localhost: bool) -> Self {
        Self {
            allow_insecure_localhost,
        }
    }

    /// Checks whether an IP address is restricted under the current filter configuration.
    #[must_use]
    pub fn is_ip_restricted(&self, ip: IpAddr) -> bool {
        if self.allow_insecure_localhost && ip.is_loopback() {
            return false;
        }
        is_restricted_ip(ip)
    }

    /// Validates that an IP address is not restricted.
    ///
    /// # Errors
    /// Returns [`SsrfError::BlockedIp`] if the IP address is in a restricted range.
    pub fn validate_ip(&self, ip: IpAddr) -> Result<(), SsrfError> {
        if self.is_ip_restricted(ip) {
            Err(SsrfError::BlockedIp(ip.to_string()))
        } else {
            Ok(())
        }
    }

    /// Validates a URL against scheme, hostname, and SSRF restrictions.
    ///
    /// # Errors
    /// - Returns [`SsrfError::InsecureScheme`] if the scheme is not `https` (or `http` on localhost in test mode).
    /// - Returns [`SsrfError::BlockedHost`] if the hostname is a blocked internal/cloud metadata name.
    /// - Returns [`SsrfError::BlockedIp`] if the hostname is an IP literal in a restricted range.
    pub fn validate_url(&self, url: &Url) -> Result<(), SsrfError> {
        let scheme = url.scheme();
        let host = url
            .host_str()
            .ok_or_else(|| SsrfError::InvalidUrl("Missing hostname in URL".to_string()))?;

        if !url.username().is_empty() || url.password().is_some() {
            return Err(SsrfError::InvalidUrl(
                "URL user information is not permitted".to_string(),
            ));
        }

        if url.fragment().is_some() {
            return Err(SsrfError::InvalidUrl(
                "URL fragments are not permitted".to_string(),
            ));
        }

        if host.ends_with('.') {
            return Err(SsrfError::InvalidUrl(
                "Trailing-dot hostnames are not canonical".to_string(),
            ));
        }

        if scheme != "https" {
            if scheme == "http" {
                if !self.allow_insecure_localhost {
                    return Err(SsrfError::InsecureScheme(url.to_string()));
                }
                let is_local =
                    host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
                if !is_local {
                    return Err(SsrfError::InsecureScheme(url.to_string()));
                }
            } else {
                return Err(SsrfError::InsecureScheme(url.to_string()));
            }
        }

        if !self.allow_insecure_localhost && is_blocked_hostname(host) {
            return Err(SsrfError::BlockedHost(host.to_string()));
        }

        if !self.allow_insecure_localhost {
            if let Some(port) = url.port() {
                return Err(SsrfError::DisallowedPort(port));
            }
        }

        // If host is an IP literal, validate immediately
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.validate_ip(ip)?;
        }

        Ok(())
    }

    /// Resolves the hostname in `url` to IP addresses, validates all resolved IPs against
    /// SSRF rules, and returns a validated [`SocketAddr`] along with the target host header.
    ///
    /// # Security Invariant
    /// If ANY resolved IP address for the hostname is restricted, the entire resolution
    /// fails immediately with [`SsrfError::BlockedIp`], neutralizing multi-homed DNS
    /// rebinding attacks.
    pub async fn resolve_and_pin(&self, url: &Url) -> Result<(SocketAddr, String), SsrfError> {
        self.resolve_and_pin_with(url, &SystemAddressResolver).await
    }

    async fn resolve_and_pin_with(
        &self,
        url: &Url,
        resolver: &dyn AddressResolver,
    ) -> Result<(SocketAddr, String), SsrfError> {
        self.validate_url(url)?;

        let host = url
            .host_str()
            .ok_or_else(|| SsrfError::InvalidUrl("Missing host in URL".to_string()))?;
        let port = url
            .port_or_known_default()
            .ok_or_else(|| SsrfError::InvalidUrl(format!("URL scheme has no known port: {url}")))?;
        let host_header = if let Some(p) = url.port() {
            format!("{host}:{p}")
        } else {
            host.to_string()
        };

        // If host is an IP literal
        if let Ok(ip) = host.parse::<IpAddr>() {
            self.validate_ip(ip)?;
            return Ok((SocketAddr::new(ip, port), host_header));
        }

        let mut addrs = resolver.resolve(host, port).await?;

        if addrs.is_empty() {
            return Err(SsrfError::DnsResolutionFailed(format!(
                "No DNS records returned for {host}"
            )));
        }

        // Validate EVERY returned address to prevent multi-IP rebinding
        for addr in &addrs {
            self.validate_ip(addr.ip())?;
        }

        // When insecure localhost is permitted (for tests/dev), prefer IPv4 (127.0.0.1)
        // since wiremock and local test servers typically bind to IPv4.
        if self.allow_insecure_localhost {
            addrs.sort_by_key(|a| if a.is_ipv4() { 0 } else { 1 });
        }

        Ok((addrs[0], host_header))
    }

    /// Executes a safe HTTP GET request with SSRF validation, DNS pinning, redirect depth bounding,
    /// and response size limits.
    ///
    /// # Arguments
    /// - `url_str`: The target URL string.
    /// - `max_bytes`: Maximum allowed response body size in bytes.
    pub async fn safe_get(&self, url_str: &str, max_bytes: usize) -> Result<Vec<u8>, SsrfError> {
        let mut current_url = Url::parse(url_str)
            .map_err(|e| SsrfError::InvalidUrl(format!("Failed to parse URL '{url_str}': {e}")))?;

        let mut redirects_remaining = 3usize;
        let client = SafeHttpClient::new(*self);

        loop {
            let resp = client
                .send(
                    reqwest::Method::GET,
                    current_url.as_str(),
                    HeaderMap::new(),
                    None,
                )
                .await?;

            let status = resp.status();
            if status.is_redirection() {
                if redirects_remaining == 0 {
                    return Err(SsrfError::TooManyRedirects);
                }
                redirects_remaining = redirects_remaining.saturating_sub(1);

                let location = resp
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .ok_or_else(|| SsrfError::Http("Redirect missing Location header".to_string()))?
                    .to_str()
                    .map_err(|e| SsrfError::Http(format!("Invalid Location header: {e}")))?;

                let next_url = current_url.join(location).map_err(|e| {
                    SsrfError::InvalidUrl(format!("Invalid redirect location '{location}': {e}"))
                })?;

                if next_url.origin() != current_url.origin() {
                    return Err(SsrfError::CrossOriginRedirect);
                }

                current_url = next_url;
                continue;
            }

            if !status.is_success() {
                return Err(SsrfError::HttpStatus(
                    status.as_u16(),
                    format!("HTTP status {status} from {current_url}"),
                ));
            }

            return collect_limited(resp, max_bytes).await;
        }
    }

    /// Fetches a non-redirecting JSON document with an exact HTTP 200 response.
    ///
    /// # Errors
    ///
    /// Returns an error when transport validation, response metadata, size limits, or JSON
    /// decoding fails.
    pub async fn safe_get_json_exact<T: serde::de::DeserializeOwned>(
        &self,
        url_str: &str,
        max_bytes: usize,
    ) -> Result<T, SsrfError> {
        let response = SafeHttpClient::new(*self)
            .send(reqwest::Method::GET, url_str, HeaderMap::new(), None)
            .await?;

        if response.status() != reqwest::StatusCode::OK {
            return Err(SsrfError::HttpStatus(
                response.status().as_u16(),
                format!("HTTP status {} from {url_str}", response.status()),
            ));
        }

        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        if !content_type
            .split(';')
            .next()
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("application/json"))
        {
            return Err(SsrfError::Http(format!(
                "Expected application/json from {url_str}, received '{content_type}'"
            )));
        }

        let bytes = collect_limited(response, max_bytes).await?;
        serde_json::from_slice(&bytes).map_err(|e| SsrfError::Json(e.to_string()))
    }

    /// Fetches JSON from a URL with full SSRF safety checks.
    ///
    /// # Arguments
    /// - `url_str`: The target URL string.
    /// - `max_bytes`: Maximum permitted response byte size.
    pub async fn safe_get_json<T: serde::de::DeserializeOwned>(
        &self,
        url_str: &str,
        max_bytes: usize,
    ) -> Result<T, SsrfError> {
        let bytes = self.safe_get(url_str, max_bytes).await?;
        serde_json::from_slice(&bytes).map_err(|e| SsrfError::Json(e.to_string()))
    }
}

#[derive(Debug, Clone)]
pub(crate) struct SafeHttpClient {
    filter: SsrfFilter,
    connect_timeout: Duration,
    request_timeout: Duration,
    resolver: Arc<dyn AddressResolver>,
}

impl SafeHttpClient {
    pub(crate) fn new(filter: SsrfFilter) -> Self {
        Self {
            filter,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            resolver: Arc::new(SystemAddressResolver),
        }
    }

    #[cfg(test)]
    fn with_resolver(filter: SsrfFilter, resolver: Arc<dyn AddressResolver>) -> Self {
        Self {
            filter,
            connect_timeout: Duration::from_secs(5),
            request_timeout: Duration::from_secs(15),
            resolver,
        }
    }

    pub(crate) async fn send(
        &self,
        method: reqwest::Method,
        url_str: &str,
        headers: HeaderMap,
        body: Option<Vec<u8>>,
    ) -> Result<reqwest::Response, SsrfError> {
        let url = Url::parse(url_str)
            .map_err(|e| SsrfError::InvalidUrl(format!("Failed to parse URL '{url_str}': {e}")))?;
        let (pinned_addr, _) = self
            .filter
            .resolve_and_pin_with(&url, self.resolver.as_ref())
            .await?;
        let host = url
            .host_str()
            .ok_or_else(|| SsrfError::InvalidUrl("Missing hostname in URL".to_string()))?;

        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(self.connect_timeout)
            .timeout(self.request_timeout)
            .pool_max_idle_per_host(0)
            .no_proxy();
        if host.parse::<IpAddr>().is_err() {
            builder = builder.resolve(host, pinned_addr);
        }

        let client = builder
            .build()
            .map_err(|e| SsrfError::Http(e.to_string()))?;
        let mut request = client.request(method, url).headers(headers);
        if let Some(bytes) = body {
            request = request.body(bytes);
        }

        let response = request
            .send()
            .await
            .map_err(|e| SsrfError::Http(e.to_string()))?;
        validate_response_headers(&response)?;
        Ok(response)
    }
}

fn validate_response_headers(response: &reqwest::Response) -> Result<(), SsrfError> {
    let total = response
        .headers()
        .iter()
        .fold(0usize, |size, (name, value)| {
            size.saturating_add(name.as_str().len())
                .saturating_add(value.as_bytes().len())
                .saturating_add(4)
        });
    if total > MAX_RESPONSE_HEADER_BYTES {
        return Err(SsrfError::HeadersTooLarge {
            max_bytes: MAX_RESPONSE_HEADER_BYTES,
        });
    }
    if response
        .headers()
        .get(reqwest::header::CONTENT_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| !value.eq_ignore_ascii_case("identity"))
    {
        return Err(SsrfError::UnsupportedContentEncoding);
    }
    Ok(())
}

pub(crate) async fn collect_limited(
    mut response: reqwest::Response,
    max_bytes: usize,
) -> Result<Vec<u8>, SsrfError> {
    if let Some(content_length) = response.headers().get(CONTENT_LENGTH) {
        if let Ok(content_length) = content_length.to_str() {
            if let Ok(content_length) = content_length.parse::<usize>() {
                if content_length > max_bytes {
                    return Err(SsrfError::ResponseTooLarge {
                        max_bytes,
                        actual_bytes: content_length,
                    });
                }
            }
        }
    }

    let mut bytes = Vec::with_capacity(max_bytes.min(16_384));
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|e| SsrfError::Http(e.to_string()))?
    {
        let next_len = bytes.len().saturating_add(chunk.len());
        if next_len > max_bytes {
            return Err(SsrfError::ResponseTooLarge {
                max_bytes,
                actual_bytes: next_len,
            });
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[derive(Debug)]
    struct SequencedResolver {
        calls: AtomicUsize,
        answers: Vec<Vec<SocketAddr>>,
    }

    impl SequencedResolver {
        fn new(answers: Vec<Vec<SocketAddr>>) -> Self {
            Self {
                calls: AtomicUsize::new(0),
                answers,
            }
        }

        fn calls(&self) -> usize {
            self.calls.load(Ordering::SeqCst)
        }
    }

    impl AddressResolver for SequencedResolver {
        fn resolve<'a>(
            &'a self,
            _host: &'a str,
            _port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<SocketAddr>, SsrfError>> + Send + 'a>> {
            let index = self.calls.fetch_add(1, Ordering::SeqCst);
            let answer = self.answers.get(index).cloned().unwrap_or_default();
            Box::pin(async move { Ok(answer) })
        }
    }

    #[test]
    fn test_loopback_ipv4() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 255, 255, 254))));

        let local_filter = SsrfFilter::new(true);
        assert!(!local_filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))));
    }

    #[test]
    fn test_rfc1918_private_ipv4() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(10, 255, 255, 255))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 16, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 31, 255, 255))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 168, 255, 255))));

        // 172.32.0.1 is public
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(172, 32, 0, 1))));
    }

    #[test]
    fn test_link_local_and_cloud_metadata() {
        let filter = SsrfFilter::new(false);
        // 169.254.169.254
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254))));
        // 169.254.170.2
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2))));
    }

    #[test]
    fn test_cgnat_shared_space() {
        let filter = SsrfFilter::new(false);
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 127, 255, 254))));
        // 100.63.255.255 is not CGNAT
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(100, 63, 255, 255))));
    }

    #[test]
    fn test_documentation_and_benchmarking_ranges() {
        let filter = SsrfFilter::new(false);
        // TEST-NET-1 192.0.2.1
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))));
        // TEST-NET-2 198.51.100.1
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1))));
        // TEST-NET-3 203.0.113.1
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))));
        // Benchmarking 198.18.0.1
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))));
        // 6to4 Relay 192.88.99.1
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(192, 88, 99, 1))));
    }

    #[test]
    fn test_multicast_and_reserved_class_e() {
        let filter = SsrfFilter::new(false);
        // 0.0.0.0
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0))));
        // 224.0.0.1 multicast
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 1))));
        // 240.0.0.1 Class E
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(240, 0, 0, 1))));
        // 255.255.255.255
        assert!(filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255))));
    }

    #[test]
    fn test_ipv6_ranges() {
        let filter = SsrfFilter::new(false);
        // Loopback
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        // Unspecified
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::UNSPECIFIED)));
        // ULA fc00::/7
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1))));
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfd12, 0, 0, 0, 0, 0, 0, 1))));
        // Link-Local fe80::/10
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))));
        // Documentation 2001:db8::/32
        assert!(
            filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 1)))
        );
        // Multicast ff02::1
        assert!(filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_ipv4_mapped_ipv6() {
        let filter = SsrfFilter::new(false);
        // ::ffff:127.0.0.1
        let mapped_loopback = IpAddr::V6(Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped());
        assert!(filter.is_ip_restricted(mapped_loopback));

        // ::ffff:169.254.169.254
        let mapped_metadata = IpAddr::V6(Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped());
        assert!(filter.is_ip_restricted(mapped_metadata));

        // ::ffff:10.0.0.1
        let mapped_private = IpAddr::V6(Ipv4Addr::new(10, 0, 0, 1).to_ipv6_mapped());
        assert!(filter.is_ip_restricted(mapped_private));

        // ::ffff:8.8.8.8 (public)
        let mapped_public = IpAddr::V6(Ipv4Addr::new(8, 8, 8, 8).to_ipv6_mapped());
        assert!(!filter.is_ip_restricted(mapped_public));
    }

    #[test]
    fn test_public_ips_allowed() {
        let filter = SsrfFilter::new(false);
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))));
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))));
        assert!(!filter.is_ip_restricted(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))));
        assert!(!filter.is_ip_restricted(IpAddr::V6(Ipv6Addr::new(
            0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111
        ))));
    }

    #[tokio::test]
    async fn mixed_dns_answers_fail_as_a_set() {
        let resolver = SequencedResolver::new(vec![vec![
            SocketAddr::from(([93, 184, 216, 34], 443)),
            SocketAddr::from(([10, 0, 0, 1], 443)),
        ]]);
        let url = Url::parse("https://example.com/resource").unwrap();
        let result = SsrfFilter::new(false)
            .resolve_and_pin_with(&url, &resolver)
            .await;
        assert!(matches!(result, Err(SsrfError::BlockedIp(_))));
        assert_eq!(resolver.calls(), 1);
    }

    #[tokio::test]
    async fn validated_address_is_pinned_for_the_connection() {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .await
                .unwrap();
        });
        let resolver = Arc::new(SequencedResolver::new(vec![
            vec![address],
            vec![SocketAddr::from(([10, 0, 0, 1], address.port()))],
        ]));
        let client = SafeHttpClient::with_resolver(
            SsrfFilter::new(true),
            resolver.clone() as Arc<dyn AddressResolver>,
        );
        let response = client
            .send(
                reqwest::Method::GET,
                &format!("http://localhost:{}/resource", address.port()),
                HeaderMap::new(),
                None,
            )
            .await
            .unwrap();
        assert_eq!(collect_limited(response, 2).await.unwrap(), b"ok");
        assert_eq!(resolver.calls(), 1);
        server.await.unwrap();
    }

    #[test]
    fn test_validate_url() {
        let filter = SsrfFilter::new(false);
        assert!(filter
            .validate_url(&Url::parse("https://bsky.social").unwrap())
            .is_ok());
        assert!(filter
            .validate_url(&Url::parse("http://bsky.social").unwrap())
            .is_err());
        assert!(filter
            .validate_url(&Url::parse("ftp://example.com").unwrap())
            .is_err());
        assert!(filter
            .validate_url(&Url::parse("https://127.0.0.1").unwrap())
            .is_err());
        assert!(filter
            .validate_url(&Url::parse("https://169.254.169.254").unwrap())
            .is_err());
        assert!(filter
            .validate_url(&Url::parse("https://metadata.google.internal").unwrap())
            .is_err());

        let local_filter = SsrfFilter::new(true);
        assert!(local_filter
            .validate_url(&Url::parse("http://localhost:8080").unwrap())
            .is_ok());
        assert!(local_filter
            .validate_url(&Url::parse("http://127.0.0.1:8080").unwrap())
            .is_ok());
        assert!(local_filter
            .validate_url(&Url::parse("http://10.0.0.1:8080").unwrap())
            .is_err());
    }
}
