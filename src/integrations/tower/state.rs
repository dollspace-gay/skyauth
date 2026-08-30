use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use parking_lot::Mutex;
use rand::RngCore;

use crate::crypto::{base64url_encode, constant_time_eq};
use crate::error::DPoPError;
use crate::policy::{nonce_accepts, replay_insert_accepts};

const STATE_SHARDS: usize = 64;

/// Atomic storage for accepted DPoP proof identifiers.
pub trait DPoPReplayStore: std::fmt::Debug + Send + Sync + 'static {
    /// Records an accepted proof unless its identifier is already live.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] when the proof was already accepted or storage is unavailable.
    fn insert_once(
        &self,
        issuer: &str,
        token_identifier: &str,
        thumbprint: &str,
        proof_identifier: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<(), DPoPError>;
}

/// Bounded, sharded in-memory DPoP replay store.
#[derive(Debug, Clone)]
pub struct InMemoryDPoPReplayStore {
    shards: Arc<[Mutex<HashMap<ReplayKey, u64>>; STATE_SHARDS]>,
    shard_capacities: Arc<[usize; STATE_SHARDS]>,
}

impl InMemoryDPoPReplayStore {
    /// Creates a replay store with the requested total entry bound.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] when the bound cannot allocate at least one entry per shard.
    pub fn new(max_entries: usize) -> Result<Self, DPoPError> {
        if max_entries < STATE_SHARDS {
            return Err(DPoPError::ReplayStoreUnavailable);
        }
        let base = max_entries / STATE_SHARDS;
        let remainder = max_entries % STATE_SHARDS;
        Ok(Self {
            shards: Arc::new(std::array::from_fn(|_| Mutex::new(HashMap::new()))),
            shard_capacities: Arc::new(std::array::from_fn(|index| {
                base + usize::from(index < remainder)
            })),
        })
    }
}

impl DPoPReplayStore for InMemoryDPoPReplayStore {
    fn insert_once(
        &self,
        issuer: &str,
        token_identifier: &str,
        thumbprint: &str,
        proof_identifier: &str,
        now: u64,
        expires_at: u64,
    ) -> Result<(), DPoPError> {
        let key = ReplayKey::new(issuer, token_identifier, thumbprint, proof_identifier);
        let shard_index = shard_index(&key);
        let mut shard = self.shards[shard_index].lock();
        shard.retain(|_, expiry| *expiry > now);
        let already_live = shard.contains_key(&key);
        let capacity_available = shard.len() < self.shard_capacities[shard_index];
        if !replay_insert_accepts(already_live, capacity_available) && already_live {
            return Err(DPoPError::ReplayDetected);
        }
        if !replay_insert_accepts(already_live, capacity_available) {
            return Err(DPoPError::ReplayStoreUnavailable);
        }
        shard.insert(key, expires_at);
        Ok(())
    }
}

/// Result of atomically evaluating a DPoP nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DPoPNonceDecision {
    /// The request may proceed and the returned nonce is required next.
    Accepted(String),
    /// The request must be retried with the returned nonce.
    Challenge(String),
}

/// Atomic storage for rotating DPoP nonces.
pub trait DPoPNonceStore: std::fmt::Debug + Send + Sync + 'static {
    /// Evaluates a nonce and rotates the stored value.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] when nonce state cannot be checked.
    fn evaluate_and_rotate(
        &self,
        issuer: &str,
        token_identifier: &str,
        thumbprint: &str,
        presented_nonce: Option<&str>,
        require_initial_nonce: bool,
        now: u64,
    ) -> Result<DPoPNonceDecision, DPoPError>;
}

/// Bounded, sharded in-memory DPoP nonce store.
#[derive(Debug, Clone)]
pub struct InMemoryDPoPNonceStore {
    shards: Arc<[Mutex<HashMap<NonceKey, NonceRecord>>; STATE_SHARDS]>,
    shard_capacities: Arc<[usize; STATE_SHARDS]>,
    ttl: Duration,
}

impl InMemoryDPoPNonceStore {
    /// Creates a nonce store with total entry and lifetime bounds.
    ///
    /// # Errors
    ///
    /// Returns [`DPoPError`] for an unusable bound or zero lifetime.
    pub fn new(max_entries: usize, ttl: Duration) -> Result<Self, DPoPError> {
        if max_entries < STATE_SHARDS || ttl.is_zero() {
            return Err(DPoPError::NonceStoreUnavailable);
        }
        let base = max_entries / STATE_SHARDS;
        let remainder = max_entries % STATE_SHARDS;
        Ok(Self {
            shards: Arc::new(std::array::from_fn(|_| Mutex::new(HashMap::new()))),
            shard_capacities: Arc::new(std::array::from_fn(|index| {
                base + usize::from(index < remainder)
            })),
            ttl,
        })
    }
}

impl DPoPNonceStore for InMemoryDPoPNonceStore {
    fn evaluate_and_rotate(
        &self,
        issuer: &str,
        token_identifier: &str,
        thumbprint: &str,
        presented_nonce: Option<&str>,
        require_initial_nonce: bool,
        now: u64,
    ) -> Result<DPoPNonceDecision, DPoPError> {
        let key = NonceKey::new(issuer, token_identifier, thumbprint);
        let shard_index = shard_index(&key);
        let mut shard = self.shards[shard_index].lock();
        shard.retain(|_, record| record.expires_at > now);

        let current = shard.get(&key);
        let nonce_matches = current.is_some_and(|record| {
            presented_nonce.is_some_and(|presented| {
                constant_time_eq(presented.as_bytes(), record.value.as_bytes())
            })
        });
        let accepted = nonce_accepts(
            current.is_some(),
            presented_nonce.is_some(),
            nonce_matches,
            require_initial_nonce,
        );
        if !shard.contains_key(&key) && shard.len() >= self.shard_capacities[shard_index] {
            return Err(DPoPError::NonceStoreUnavailable);
        }

        let nonce = random_nonce();
        shard.insert(
            key,
            NonceRecord {
                value: nonce.clone(),
                expires_at: now.saturating_add(self.ttl.as_secs()),
            },
        );
        if accepted {
            Ok(DPoPNonceDecision::Accepted(nonce))
        } else {
            Ok(DPoPNonceDecision::Challenge(nonce))
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct ReplayKey {
    issuer: String,
    token_identifier: String,
    thumbprint: String,
    proof_identifier: String,
}

impl ReplayKey {
    fn new(issuer: &str, token_identifier: &str, thumbprint: &str, proof_identifier: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            token_identifier: token_identifier.to_string(),
            thumbprint: thumbprint.to_string(),
            proof_identifier: proof_identifier.to_string(),
        }
    }
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
struct NonceKey {
    issuer: String,
    token_identifier: String,
    thumbprint: String,
}

impl NonceKey {
    fn new(issuer: &str, token_identifier: &str, thumbprint: &str) -> Self {
        Self {
            issuer: issuer.to_string(),
            token_identifier: token_identifier.to_string(),
            thumbprint: thumbprint.to_string(),
        }
    }
}

#[derive(Debug, Clone)]
struct NonceRecord {
    value: String,
    expires_at: u64,
}

fn shard_index<T: std::hash::Hash>(value: &T) -> usize {
    use std::hash::Hasher;

    let mut hasher = ahash::AHasher::default();
    value.hash(&mut hasher);
    (hasher.finish() as usize) % STATE_SHARDS
}

fn random_nonce() -> String {
    let mut bytes = [0_u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    base64url_encode(&bytes)
}
