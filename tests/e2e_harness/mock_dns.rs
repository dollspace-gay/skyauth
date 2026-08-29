//! Mock DNS resolver harness for AT Protocol handle resolution.
//!
//! Models RFC 1464 DNS TXT record resolution for `_atproto.<handle>` with
//! fault injection, ambiguity detection, and format validation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// Result of a mock DNS TXT lookup.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MockDnsResult {
    /// DNS lookup succeeded with the given TXT records.
    Records(Vec<String>),
    /// Domain name does not exist (NXDOMAIN).
    NxDomain,
    /// DNS server error (SERVFAIL).
    ServFail,
    /// Query timed out.
    Timeout,
}

/// In-memory mock DNS resolver for handle verification.
#[derive(Debug, Clone, Default)]
pub struct MockDnsResolver {
    records: Arc<Mutex<HashMap<String, MockDnsResult>>>,
}

impl MockDnsResolver {
    /// Creates a new empty mock DNS resolver.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Registers standard `_atproto.<handle>` TXT records for a handle.
    pub fn register_handle_did(&self, handle: &str, did: &str) {
        let query_name = format!("_atproto.{}", handle.to_ascii_lowercase());
        let record = format!("did={did}");
        self.records
            .lock()
            .expect("lock acquired")
            .insert(query_name, MockDnsResult::Records(vec![record]));
    }

    /// Registers multiple TXT records for a handle (e.g. mixed SPF and DID records).
    pub fn register_multiple_records(&self, handle: &str, txt_records: Vec<String>) {
        let query_name = format!("_atproto.{}", handle.to_ascii_lowercase());
        self.records
            .lock()
            .expect("lock acquired")
            .insert(query_name, MockDnsResult::Records(txt_records));
    }

    /// Configures a DNS NXDOMAIN response for a handle.
    pub fn register_nxdomain(&self, handle: &str) {
        let query_name = format!("_atproto.{}", handle.to_ascii_lowercase());
        self.records
            .lock()
            .expect("lock acquired")
            .insert(query_name, MockDnsResult::NxDomain);
    }

    /// Configures a DNS SERVFAIL response for a handle.
    pub fn register_servfail(&self, handle: &str) {
        let query_name = format!("_atproto.{}", handle.to_ascii_lowercase());
        self.records
            .lock()
            .expect("lock acquired")
            .insert(query_name, MockDnsResult::ServFail);
    }

    /// Resolves TXT records for a query name (e.g. `_atproto.alice.bsky.social`).
    #[must_use]
    pub fn query_txt(&self, query_name: &str) -> MockDnsResult {
        let normalized = query_name.to_ascii_lowercase();
        self.records
            .lock()
            .expect("lock acquired")
            .get(&normalized)
            .cloned()
            .unwrap_or(MockDnsResult::NxDomain)
    }

    /// Resolves a handle to its DID using ATProto DNS TXT precedence rules.
    ///
    /// # Rules:
    /// - Prepends `_atproto.` to normalized handle.
    /// - Filters TXT records starting with `did=`.
    /// - If 0 `did=` records: returns `None` (triggers HTTPS fallback).
    /// - If 1 `did=` record: returns `Some(did)`.
    /// - If multiple identical `did=` records: returns `Some(did)`.
    /// - If multiple conflicting `did=` records: returns `Err(Ambiguous)`.
    pub fn resolve_handle_txt(&self, handle: &str) -> Result<Option<String>, String> {
        let query_name = format!("_atproto.{}", handle.to_ascii_lowercase());
        match self.query_txt(&query_name) {
            MockDnsResult::Records(records) => {
                let dids: Vec<String> = records
                    .into_iter()
                    .filter(|r| r.starts_with("did="))
                    .map(|r| r.strip_prefix("did=").unwrap_or("").to_string())
                    .collect();

                if dids.is_empty() {
                    return Ok(None);
                }

                let first_did = &dids[0];
                for did in &dids[1..] {
                    if did != first_did {
                        return Err(format!(
                            "Ambiguous DNS resolution: conflicting DIDs '{first_did}' vs '{did}'"
                        ));
                    }
                }

                Ok(Some(first_did.clone()))
            }
            MockDnsResult::NxDomain => Ok(None),
            MockDnsResult::ServFail => Err("DNS SERVFAIL".to_string()),
            MockDnsResult::Timeout => Err("DNS Timeout".to_string()),
        }
    }
}

impl skyauth::identity::DnsTxtResolver for MockDnsResolver {
    fn resolve_txt<'a>(
        &'a self,
        query_name: &'a str,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<Output = Result<Vec<String>, skyauth::error::IdentityError>>
                + Send
                + 'a,
        >,
    > {
        let result = self.query_txt(query_name);
        Box::pin(async move {
            match result {
                MockDnsResult::Records(r) => Ok(r),
                MockDnsResult::NxDomain => Ok(Vec::new()),
                MockDnsResult::ServFail => {
                    Err(skyauth::error::IdentityError::Dns("SERVFAIL".to_string()))
                }
                MockDnsResult::Timeout => {
                    Err(skyauth::error::IdentityError::Dns("Timeout".to_string()))
                }
            }
        })
    }
}
