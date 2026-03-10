//! Storage abstraction for single-use, time-limited account recovery tokens.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Storage for single-use, time-limited recovery tokens.
///
/// During account recovery, a verified challenge response produces a recovery
/// token that authorizes re-registration for a specific credential. This trait
/// defines the storage operations for those tokens.
///
/// Implementations must be thread-safe.
///
/// # Token Lifecycle
///
/// 1. Token is created by [`store`](RecoveryTokenStore::store) after challenge verification
/// 2. Token is validated (without consuming) by [`peek`](RecoveryTokenStore::peek)
///    during registration start
/// 3. Token is consumed by [`remove`](RecoveryTokenStore::remove) during
///    registration finish
///
/// # Clustering
///
/// The default [`InMemoryRecoveryTokenStore`] is suitable for single-node
/// deployments only. For multi-node clusters, implement with a distributed
/// backend (e.g. Redis with TTL).
pub trait RecoveryTokenStore: Send + Sync {
    /// Stores a recovery token associated with a credential identifier.
    ///
    /// Returns `Err` if the store has reached its capacity limit.
    fn store(&self, token: &str, credential_identifier: &str) -> Result<(), String>;

    /// Retrieves the credential identifier for a recovery token without consuming it.
    ///
    /// Returns `None` if the token is not found or has expired.
    fn peek(&self, token: &str) -> Option<String>;

    /// Retrieves and atomically removes a recovery token (consume-once semantics).
    ///
    /// Returns `None` if the token is not found or has expired.
    fn remove(&self, token: &str) -> Option<String>;
}

/// Entry stored in the in-memory token store.
struct TokenEntry {
    credential_identifier: String,
    created_at: Instant,
}

/// Non-persistent in-memory [`RecoveryTokenStore`].
///
/// Backed by a `Mutex<HashMap>`. Expired tokens are cleaned up lazily on
/// each operation. All tokens are lost on process restart.
///
/// # Defaults
///
/// - TTL: 10 minutes (600 seconds)
/// - Max tokens: 10,000
///
/// # Thread Safety
///
/// All operations hold a lock for the duration of the operation. This is
/// sufficient for typical server workloads but not optimized for extremely
/// high concurrency. For production clusters, use a Redis-backed implementation.
pub struct InMemoryRecoveryTokenStore {
    ttl: Duration,
    max_tokens: usize,
    tokens: Mutex<HashMap<String, TokenEntry>>,
}

impl InMemoryRecoveryTokenStore {
    /// Default TTL for recovery tokens: 10 minutes.
    pub const DEFAULT_TTL_SECS: u64 = 600;

    /// Default maximum concurrent recovery tokens.
    pub const DEFAULT_MAX_TOKENS: usize = 10_000;

    /// Creates a store with default TTL (10 minutes) and capacity (10,000).
    pub fn new() -> Self {
        Self::with_config(
            Duration::from_secs(Self::DEFAULT_TTL_SECS),
            Self::DEFAULT_MAX_TOKENS,
        )
    }

    /// Creates a store with custom TTL and capacity.
    pub fn with_config(ttl: Duration, max_tokens: usize) -> Self {
        Self {
            ttl,
            max_tokens,
            tokens: Mutex::new(HashMap::new()),
        }
    }

    /// Removes expired entries from the store. Called lazily on each operation.
    fn cleanup(tokens: &mut HashMap<String, TokenEntry>, ttl: Duration) {
        let cutoff = Instant::now() - ttl;
        tokens.retain(|_, entry| entry.created_at > cutoff);
    }

    /// Checks if a token entry is still valid (not expired).
    fn is_valid(entry: &TokenEntry, ttl: Duration) -> bool {
        entry.created_at.elapsed() < ttl
    }
}

impl Default for InMemoryRecoveryTokenStore {
    fn default() -> Self {
        Self::new()
    }
}

impl RecoveryTokenStore for InMemoryRecoveryTokenStore {
    fn store(&self, token: &str, credential_identifier: &str) -> Result<(), String> {
        let mut tokens = self.tokens.lock().unwrap();
        Self::cleanup(&mut tokens, self.ttl);
        if tokens.len() >= self.max_tokens {
            return Err("Too many pending recovery tokens".to_string());
        }
        tokens.insert(
            token.to_string(),
            TokenEntry {
                credential_identifier: credential_identifier.to_string(),
                created_at: Instant::now(),
            },
        );
        Ok(())
    }

    fn peek(&self, token: &str) -> Option<String> {
        let mut tokens = self.tokens.lock().unwrap();
        Self::cleanup(&mut tokens, self.ttl);
        tokens.get(token)
            .filter(|entry| Self::is_valid(entry, self.ttl))
            .map(|entry| entry.credential_identifier.clone())
    }

    fn remove(&self, token: &str) -> Option<String> {
        let mut tokens = self.tokens.lock().unwrap();
        tokens.remove(token)
            .filter(|entry| Self::is_valid(entry, self.ttl))
            .map(|entry| entry.credential_identifier)
    }
}
