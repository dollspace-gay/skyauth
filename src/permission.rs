//! Authenticated Lexicon permission-set resolution and caching.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use parking_lot::RwLock;
use serde::Deserialize;

use crate::error::ScopeError;
use crate::scope::{PermissionResource, PermissionScope, ScopeSet};

/// Recommended permission-set stale lifetime.
pub const DEFAULT_PERMISSION_SET_STALE: Duration = Duration::from_secs(24 * 60 * 60);
/// Recommended permission-set expiration lifetime for new sessions.
pub const DEFAULT_PERMISSION_SET_EXPIRY: Duration = Duration::from_secs(90 * 24 * 60 * 60);
/// Default maximum number of cached permission sets.
pub const DEFAULT_PERMISSION_SET_CAPACITY: usize = 1_024;

/// Asynchronous authenticated Lexicon resolution operation.
pub type LexiconResolutionFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AuthenticatedLexiconRecord, ScopeError>> + Send + 'a>>;

/// Adapter boundary for cryptographically authenticated Lexicon repository resolution.
pub trait AuthenticatedLexiconResolver: std::fmt::Debug + Send + Sync + 'static {
    /// Resolves `nsid` through its DNS authority and verifies the repository record and commit.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError`] when authority, DID, repository, CID, or signature checks fail.
    fn resolve_authenticated(&self, nsid: &str) -> LexiconResolutionFuture<'_>;
}

/// A Lexicon record authenticated by a configured resolver.
#[derive(Debug, Clone)]
pub struct AuthenticatedLexiconRecord {
    document: serde_json::Value,
    authority_did: String,
    record_cid: String,
}

impl AuthenticatedLexiconRecord {
    /// Constructs the result of a completed repository-authentication pipeline.
    ///
    /// Resolver implementations must call this only after validating DNS authority, the DID
    /// document, repository commit signature, Merkle path, collection, record key, and CID.
    #[must_use]
    pub fn from_verified_repository(
        document: serde_json::Value,
        authority_did: impl Into<String>,
        record_cid: impl Into<String>,
    ) -> Self {
        Self {
            document,
            authority_did: authority_did.into(),
            record_cid: record_cid.into(),
        }
    }
}

/// Provenance retained with a resolved permission set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PermissionSetProvenance {
    nsid: String,
    authority_did: String,
    record_cid: String,
    resolved_at: SystemTime,
}

impl PermissionSetProvenance {
    /// Returns the permission-set NSID.
    #[must_use]
    pub fn nsid(&self) -> &str {
        &self.nsid
    }

    /// Returns the authenticated repository DID.
    #[must_use]
    pub fn authority_did(&self) -> &str {
        &self.authority_did
    }

    /// Returns the authenticated record CID.
    #[must_use]
    pub fn record_cid(&self) -> &str {
        &self.record_cid
    }

    /// Returns when the record was authenticated.
    #[must_use]
    pub const fn resolved_at(&self) -> SystemTime {
        self.resolved_at
    }
}

/// Concrete permissions and provenance derived from one permission-set reference.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedPermissionSet {
    permissions: Vec<PermissionScope>,
    provenance: PermissionSetProvenance,
    stale: bool,
}

impl ResolvedPermissionSet {
    /// Returns the understood concrete permissions.
    #[must_use]
    pub fn permissions(&self) -> &[PermissionScope] {
        &self.permissions
    }

    /// Returns authenticated resolution provenance.
    #[must_use]
    pub const fn provenance(&self) -> &PermissionSetProvenance {
        &self.provenance
    }

    /// Returns whether a stale cached value was used after refresh failed.
    #[must_use]
    pub const fn is_stale(&self) -> bool {
        self.stale
    }
}

/// Asynchronous operation resolving every permission-set reference in a scope set.
pub type PermissionSetFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<ResolvedPermissionSet>, ScopeError>> + Send + 'a>>;

/// Object-safe permission-set provider used by the OAuth client lifecycle.
pub trait PermissionSetResolver: std::fmt::Debug + Send + Sync + 'static {
    /// Resolves all `include:` references in `scopes`.
    ///
    /// # Errors
    ///
    /// Returns [`ScopeError`] if a required set cannot be authenticated or interpreted.
    fn resolve_scope_sets(&self, scopes: &ScopeSet) -> PermissionSetFuture<'_>;
}

#[derive(Debug, Clone)]
struct CachedPermissionSet {
    value: ResolvedPermissionSet,
    inserted_secs: u64,
}

/// Bounded permission-set cache with independent stale and expiration lifetimes.
#[derive(Debug)]
pub struct PermissionSetCache<R> {
    resolver: Arc<R>,
    entries: RwLock<HashMap<String, CachedPermissionSet>>,
    stale_after: Duration,
    expire_after: Duration,
    capacity: usize,
}

impl<R> PermissionSetCache<R>
where
    R: AuthenticatedLexiconResolver,
{
    /// Creates a cache using the protocol's recommended lifetimes.
    #[must_use]
    pub fn new(resolver: Arc<R>) -> Self {
        Self::with_policy(
            resolver,
            DEFAULT_PERMISSION_SET_STALE,
            DEFAULT_PERMISSION_SET_EXPIRY,
            DEFAULT_PERMISSION_SET_CAPACITY,
        )
    }

    /// Creates a cache with explicit lifetimes and capacity.
    #[must_use]
    pub fn with_policy(
        resolver: Arc<R>,
        stale_after: Duration,
        expire_after: Duration,
        capacity: usize,
    ) -> Self {
        Self {
            resolver,
            entries: RwLock::new(HashMap::new()),
            stale_after,
            expire_after,
            capacity,
        }
    }

    async fn resolve_one(
        &self,
        include: &PermissionScope,
    ) -> Result<ResolvedPermissionSet, ScopeError> {
        let nsid = include
            .positional()
            .ok_or(ScopeError::InvalidPermissionSet)?;
        let now_secs = unix_seconds(SystemTime::now());
        let cached = self.entries.read().get(nsid).cloned();
        if let Some(cached) = cached.as_ref() {
            let age = now_secs.saturating_sub(cached.inserted_secs);
            if age < self.stale_after.as_secs() {
                return Ok(cached.value.clone());
            }
        }

        match self.resolver.resolve_authenticated(nsid).await {
            Ok(record) => {
                let value = parse_permission_set(nsid, include.parameter("aud"), record)?;
                let mut entries = self.entries.write();
                if !entries.contains_key(nsid) && entries.len() >= self.capacity {
                    return Err(ScopeError::CacheCapacity);
                }
                entries.insert(
                    nsid.to_string(),
                    CachedPermissionSet {
                        value: value.clone(),
                        inserted_secs: now_secs,
                    },
                );
                Ok(value)
            }
            Err(_) => {
                let Some(cached) = cached else {
                    return Err(ScopeError::ResolutionFailed);
                };
                let age = now_secs.saturating_sub(cached.inserted_secs);
                if age >= self.expire_after.as_secs() {
                    return Err(ScopeError::ResolutionFailed);
                }
                let mut stale = cached.value;
                stale.stale = true;
                Ok(stale)
            }
        }
    }
}

impl<R> PermissionSetResolver for PermissionSetCache<R>
where
    R: AuthenticatedLexiconResolver,
{
    fn resolve_scope_sets(&self, scopes: &ScopeSet) -> PermissionSetFuture<'_> {
        let includes: Vec<PermissionScope> = scopes
            .items()
            .iter()
            .filter_map(|item| match item {
                crate::scope::ScopeItem::Permission(permission)
                    if permission.resource() == PermissionResource::Include =>
                {
                    Some(permission.clone())
                }
                _ => None,
            })
            .collect();
        Box::pin(async move {
            let mut resolved = Vec::with_capacity(includes.len());
            for include in &includes {
                resolved.push(self.resolve_one(include).await?);
            }
            Ok(resolved)
        })
    }
}

#[derive(Deserialize)]
struct LexiconDocument {
    lexicon: u64,
    id: String,
    defs: BTreeMap<String, serde_json::Value>,
}

fn parse_permission_set(
    requested_nsid: &str,
    include_audience: Option<&[String]>,
    record: AuthenticatedLexiconRecord,
) -> Result<ResolvedPermissionSet, ScopeError> {
    let document: LexiconDocument =
        serde_json::from_value(record.document).map_err(|_| ScopeError::InvalidPermissionSet)?;
    if document.lexicon != 1 || document.id != requested_nsid {
        return Err(ScopeError::InvalidPermissionSet);
    }
    let main = document
        .defs
        .get("main")
        .and_then(serde_json::Value::as_object)
        .ok_or(ScopeError::InvalidPermissionSet)?;
    if main.get("type").and_then(serde_json::Value::as_str) != Some("permission-set") {
        return Err(ScopeError::InvalidPermissionSet);
    }
    let declarations = main
        .get("permissions")
        .and_then(serde_json::Value::as_array)
        .ok_or(ScopeError::InvalidPermissionSet)?;
    let inherited_audience = include_audience.and_then(|values| {
        if values.len() == 1 {
            values.first().map(String::as_str)
        } else {
            None
        }
    });
    let mut permissions = Vec::new();
    for declaration in declarations {
        if let Some(permission) = parse_declaration(requested_nsid, inherited_audience, declaration)
        {
            permissions.push(permission);
        }
    }
    Ok(ResolvedPermissionSet {
        permissions,
        provenance: PermissionSetProvenance {
            nsid: requested_nsid.to_string(),
            authority_did: record.authority_did,
            record_cid: record.record_cid,
            resolved_at: SystemTime::now(),
        },
        stale: false,
    })
}

fn parse_declaration(
    set_nsid: &str,
    inherited_audience: Option<&str>,
    value: &serde_json::Value,
) -> Option<PermissionScope> {
    let object = value.as_object()?;
    if object.get("type")?.as_str()? != "permission" {
        return None;
    }
    match object.get("resource")?.as_str()? {
        "repo" => parse_repo_declaration(set_nsid, object),
        "rpc" => parse_rpc_declaration(set_nsid, inherited_audience, object),
        _ => None,
    }
}

fn parse_repo_declaration(
    set_nsid: &str,
    object: &serde_json::Map<String, serde_json::Value>,
) -> Option<PermissionScope> {
    if object
        .keys()
        .any(|key| !matches!(key.as_str(), "type" | "resource" | "collection" | "action"))
    {
        return None;
    }
    let collections = unique_strings(object.get("collection")?)?;
    if collections.is_empty()
        || collections
            .iter()
            .any(|value| value == "*" || !within_set_namespace(set_nsid, value))
    {
        return None;
    }
    let actions = match object.get("action") {
        Some(value) => unique_strings(value)?,
        None => Vec::new(),
    };
    if actions
        .iter()
        .any(|action| !matches!(action.as_str(), "create" | "update" | "delete"))
    {
        return None;
    }
    let mut scope = String::from("repo?");
    append_parameters(&mut scope, "collection", &collections);
    append_parameters(&mut scope, "action", &actions);
    PermissionScope::parse(&scope).ok()
}

fn parse_rpc_declaration(
    set_nsid: &str,
    inherited_audience: Option<&str>,
    object: &serde_json::Map<String, serde_json::Value>,
) -> Option<PermissionScope> {
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "type" | "resource" | "lxm" | "aud" | "inheritAud"
        )
    }) {
        return None;
    }
    let methods = unique_strings(object.get("lxm")?)?;
    if methods.is_empty()
        || methods
            .iter()
            .any(|value| value == "*" || !within_set_namespace(set_nsid, value))
    {
        return None;
    }
    let inherit = match object.get("inheritAud") {
        Some(value) => value.as_bool()?,
        None => false,
    };
    let declared_audience = object.get("aud").and_then(serde_json::Value::as_str);
    let audience = match (inherit, declared_audience) {
        (true, None) => inherited_audience?,
        (false, Some("*")) => "*",
        _ => return None,
    };
    let mut scope = String::from("rpc?");
    append_parameters(&mut scope, "lxm", &methods);
    append_parameters(&mut scope, "aud", &[audience.to_string()]);
    PermissionScope::parse(&scope).ok()
}

fn unique_strings(value: &serde_json::Value) -> Option<Vec<String>> {
    let values = value.as_array()?;
    let mut seen = BTreeSet::new();
    let mut output = Vec::with_capacity(values.len());
    for value in values {
        let value = value.as_str()?.to_string();
        if !seen.insert(value.clone()) {
            return None;
        }
        output.push(value);
    }
    Some(output)
}

fn within_set_namespace(set_nsid: &str, resource_nsid: &str) -> bool {
    let Some((group, _)) = set_nsid.rsplit_once('.') else {
        return false;
    };
    resource_nsid
        .strip_prefix(group)
        .is_some_and(|suffix| suffix.starts_with('.'))
}

fn append_parameters(output: &mut String, name: &str, values: &[String]) {
    for value in values {
        if !output.ends_with('?') {
            output.push('&');
        }
        output.push_str(name);
        output.push('=');
        output.push_str(&encode_component(value));
    }
}

fn encode_component(value: &str) -> String {
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'*' | b'/') {
            encoded.push(char::from(byte));
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

fn unix_seconds(time: SystemTime) -> u64 {
    time.duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]
mod tests {
    use std::collections::VecDeque;

    use parking_lot::Mutex;

    use super::*;

    #[derive(Debug)]
    struct FixtureResolver {
        responses: Mutex<VecDeque<Result<AuthenticatedLexiconRecord, ScopeError>>>,
    }

    impl FixtureResolver {
        fn new(responses: Vec<Result<AuthenticatedLexiconRecord, ScopeError>>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
            }
        }
    }

    impl AuthenticatedLexiconResolver for FixtureResolver {
        fn resolve_authenticated(&self, _nsid: &str) -> LexiconResolutionFuture<'_> {
            let response = self
                .responses
                .lock()
                .pop_front()
                .unwrap_or(Err(ScopeError::ResolutionFailed));
            Box::pin(async move { response })
        }
    }

    fn record() -> AuthenticatedLexiconRecord {
        AuthenticatedLexiconRecord::from_verified_repository(
            serde_json::json!({
                "lexicon": 1,
                "id": "app.example.authFull",
                "defs": {
                    "main": {
                        "type": "permission-set",
                        "permissions": [
                            {
                                "type": "permission",
                                "resource": "repo",
                                "collection": ["app.example.post"],
                                "action": ["create", "delete"]
                            },
                            {
                                "type": "permission",
                                "resource": "rpc",
                                "lxm": ["app.example.getFeed"],
                                "inheritAud": true
                            },
                            {
                                "type": "permission",
                                "resource": "repo",
                                "collection": ["chat.other.message"]
                            },
                            {
                                "type": "permission",
                                "resource": "repo",
                                "collection": ["app.example.like"],
                                "futureAttenuation": true
                            }
                        ]
                    }
                }
            }),
            "did:plc:authority123",
            "bafyrecordcid",
        )
    }

    #[tokio::test]
    async fn resolves_understood_permissions_and_enforces_namespace() {
        let resolver = Arc::new(FixtureResolver::new(vec![Ok(record())]));
        let cache = PermissionSetCache::new(resolver);
        let scopes = ScopeSet::parse(
            "atproto include:app.example.authFull?aud=did:web:api.example.com%23svc_appview",
        )
        .unwrap();
        let sets = cache.resolve_scope_sets(&scopes).await.unwrap();
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].permissions().len(), 2);
        assert_eq!(sets[0].provenance().record_cid(), "bafyrecordcid");
        assert_eq!(
            sets[0].permissions()[1].parameter("aud").unwrap(),
            &["did:web:api.example.com#svc_appview".to_string()]
        );
    }

    #[tokio::test]
    async fn stale_authenticated_value_survives_resolution_outage() {
        let resolver = Arc::new(FixtureResolver::new(vec![
            Ok(record()),
            Err(ScopeError::ResolutionFailed),
        ]));
        let cache =
            PermissionSetCache::with_policy(resolver, Duration::ZERO, Duration::from_secs(60), 4);
        let scopes = ScopeSet::parse(
            "atproto include:app.example.authFull?aud=did:web:api.example.com%23svc_appview",
        )
        .unwrap();
        assert!(!cache.resolve_scope_sets(&scopes).await.unwrap()[0].is_stale());
        assert!(cache.resolve_scope_sets(&scopes).await.unwrap()[0].is_stale());
    }
}
