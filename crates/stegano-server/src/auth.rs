//! API key authentication and rate limiting for SteganoHero server.
//!
//! Design:
//! - API keys stored in SQLite (sha256-hashed, never plaintext)
//! - Rate limiting: in-memory token bucket per API key
//! - The forensic endpoint is FREE (no auth required)
//! - All other endpoints require a valid API key via `X-Api-Key` header

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Instant;

use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::{IntoResponse, Response},
};
use sha2::{Digest, Sha256};

// ─── API Key Store (SQLite) ─────────────────────────────────

/// Manages API keys in SQLite. Keys are stored as SHA-256 hashes.
/// Wrapped in Mutex because rusqlite::Connection is not Send+Sync.
pub struct ApiKeyStore {
    conn: Mutex<rusqlite::Connection>,
}

impl ApiKeyStore {
    /// Open (or create) the API key database.
    pub fn open(path: &str) -> Result<Self, rusqlite::Error> {
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS api_keys (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                name        TEXT NOT NULL,
                key_hash    TEXT NOT NULL UNIQUE,
                tier        TEXT NOT NULL DEFAULT 'free',
                rate_limit  INTEGER NOT NULL DEFAULT 60,
                created_at  TEXT NOT NULL DEFAULT (datetime('now')),
                active      INTEGER NOT NULL DEFAULT 1
            );"
        )?;
        Ok(Self { conn: Mutex::new(conn) })
    }

    /// Open an in-memory database (for testing).
    // Kept intentionally: a test-support constructor exercised by the store
    // tests, not called by the running binary (invariant 1: retained, not
    // deleted).
    #[allow(dead_code)]
    pub fn open_memory() -> Result<Self, rusqlite::Error> {
        Self::open(":memory:")
    }

    /// Create a new API key. Returns the raw key (only shown once).
    pub fn create_key(&self, name: &str, tier: &str, rate_limit: u32) -> Result<String, rusqlite::Error> {
        let raw_key = generate_api_key();
        let key_hash = hash_key(&raw_key);
        let conn = self.conn.lock().unwrap();

        conn.execute(
            "INSERT INTO api_keys (name, key_hash, tier, rate_limit) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![name, key_hash, tier, rate_limit],
        )?;

        Ok(raw_key)
    }

    /// Validate an API key. Returns (tier, rate_limit) if valid.
    pub fn validate_key(&self, raw_key: &str) -> Option<(String, u32)> {
        let key_hash = hash_key(raw_key);
        let conn = self.conn.lock().unwrap();

        conn.query_row(
            "SELECT tier, rate_limit FROM api_keys WHERE key_hash = ?1 AND active = 1",
            rusqlite::params![key_hash],
            |row| {
                let tier: String = row.get(0)?;
                let rate_limit: u32 = row.get(1)?;
                Ok((tier, rate_limit))
            },
        )
        .ok()
    }

    /// Revoke an API key by name.
    // Kept intentionally: the key-store revoke operation, proven by
    // `revoke_key_works`, reserved for the key-management surface and not yet
    // wired to a route (invariant 1: retained, not deleted).
    #[allow(dead_code)]
    pub fn revoke_key(&self, name: &str) -> Result<usize, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let changed = conn.execute(
            "UPDATE api_keys SET active = 0 WHERE name = ?1 AND active = 1",
            rusqlite::params![name],
        )?;
        Ok(changed)
    }

    /// List all active keys (name, tier, rate_limit, created_at).
    pub fn list_keys(&self) -> Result<Vec<KeyInfo>, rusqlite::Error> {
        let conn = self.conn.lock().unwrap();
        let mut stmt = conn.prepare(
            "SELECT name, tier, rate_limit, created_at FROM api_keys WHERE active = 1 ORDER BY created_at"
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(KeyInfo {
                name: row.get(0)?,
                tier: row.get(1)?,
                rate_limit: row.get(2)?,
                created_at: row.get(3)?,
            })
        })?;
        rows.collect()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct KeyInfo {
    pub name: String,
    pub tier: String,
    pub rate_limit: u32,
    pub created_at: String,
}

// ─── Rate Limiter (Token Bucket) ────────────────────────────

/// In-memory rate limiter using token bucket algorithm.
/// Each API key gets its own bucket.
pub struct RateLimiter {
    buckets: Mutex<HashMap<String, TokenBucket>>,
}

struct TokenBucket {
    tokens: f64,
    max_tokens: f64,
    refill_rate: f64, // tokens per second
    last_refill: Instant,
}

impl RateLimiter {
    pub fn new() -> Self {
        Self {
            buckets: Mutex::new(HashMap::new()),
        }
    }

    /// Try to consume a token. Returns true if allowed.
    pub fn check(&self, key_hash: &str, rate_limit: u32) -> bool {
        let mut buckets = self.buckets.lock().unwrap();
        let bucket = buckets.entry(key_hash.to_string()).or_insert_with(|| {
            TokenBucket {
                tokens: rate_limit as f64,
                max_tokens: rate_limit as f64,
                refill_rate: rate_limit as f64 / 60.0, // per second (rate_limit = per minute)
                last_refill: Instant::now(),
            }
        });

        // Refill tokens based on elapsed time
        let now = Instant::now();
        let elapsed = now.duration_since(bucket.last_refill).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * bucket.refill_rate).min(bucket.max_tokens);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

// ─── Shared Application State ───────────────────────────────

/// Shared state accessible from middleware and handlers.
pub struct AppState {
    pub key_store: ApiKeyStore,
    pub rate_limiter: RateLimiter,
}

// ─── Axum Middleware ─────────────────────────────────────────

/// Authentication middleware.
/// - Passes through requests to /api/v1/health and /api/v1/forensic (free endpoints)
/// - Requires valid X-Api-Key header for all other endpoints
/// - Enforces rate limiting per key
pub async fn auth_middleware(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path();

    // Free endpoints: no auth required
    if path == "/api/v1/health" || path == "/api/v1/forensic" {
        return next.run(req).await;
    }

    // Extract API key from header
    let api_key = match req.headers().get("x-api-key").and_then(|v| v.to_str().ok()) {
        Some(key) => key.to_string(),
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("content-type", "application/json")],
                r#"{"error":"missing X-Api-Key header"}"#,
            ).into_response();
        }
    };

    // Validate key
    let (tier, rate_limit) = match state.key_store.validate_key(&api_key) {
        Some(info) => info,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                [("content-type", "application/json")],
                r#"{"error":"invalid API key"}"#,
            ).into_response();
        }
    };

    // Rate limiting
    let key_hash = hash_key(&api_key);
    if !state.rate_limiter.check(&key_hash, rate_limit) {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("content-type", "application/json"),
                ("retry-after", "60"),
            ],
            format!(r#"{{"error":"rate limit exceeded","tier":"{tier}","limit":{rate_limit}}}"#),
        ).into_response();
    }

    next.run(req).await
}

// ─── Helpers ────────────────────────────────────────────────

fn generate_api_key() -> String {
    let bytes: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    format!("sh_{}", hex::encode(&bytes))
}

fn hash_key(raw_key: &str) -> String {
    let hash = Sha256::digest(raw_key.as_bytes());
    hex::encode(&hash[..])
}

// We use our own hex encode since we don't want to add the `hex` crate
mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

// ─── Tests ──────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_validate_key() {
        let store = ApiKeyStore::open_memory().unwrap();
        let key = store.create_key("test-app", "standard", 100).unwrap();

        assert!(key.starts_with("sh_"));
        assert_eq!(key.len(), 3 + 64); // "sh_" + 32 bytes hex

        let (tier, rate) = store.validate_key(&key).unwrap();
        assert_eq!(tier, "standard");
        assert_eq!(rate, 100);
    }

    #[test]
    fn invalid_key_returns_none() {
        let store = ApiKeyStore::open_memory().unwrap();
        assert!(store.validate_key("sh_nonexistent").is_none());
    }

    #[test]
    fn revoke_key_works() {
        let store = ApiKeyStore::open_memory().unwrap();
        let key = store.create_key("revoke-me", "free", 10).unwrap();

        assert!(store.validate_key(&key).is_some());

        let revoked = store.revoke_key("revoke-me").unwrap();
        assert_eq!(revoked, 1);

        assert!(store.validate_key(&key).is_none());
    }

    #[test]
    fn list_keys_works() {
        let store = ApiKeyStore::open_memory().unwrap();
        store.create_key("app-1", "free", 10).unwrap();
        store.create_key("app-2", "pro", 1000).unwrap();

        let keys = store.list_keys().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0].name, "app-1");
        assert_eq!(keys[1].name, "app-2");
    }

    #[test]
    fn rate_limiter_allows_within_limit() {
        let limiter = RateLimiter::new();
        // 60 requests per minute
        for _ in 0..60 {
            assert!(limiter.check("test-key", 60));
        }
    }

    #[test]
    fn rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new();
        // Exhaust all tokens
        for _ in 0..60 {
            limiter.check("test-key", 60);
        }
        // Next request should be blocked
        assert!(!limiter.check("test-key", 60));
    }

    #[test]
    fn api_key_format() {
        let key = generate_api_key();
        assert!(key.starts_with("sh_"));
        // 32 random bytes = 64 hex chars
        assert_eq!(key.len(), 67);
    }

    #[test]
    fn hash_is_deterministic() {
        let h1 = hash_key("sh_test123");
        let h2 = hash_key("sh_test123");
        assert_eq!(h1, h2);
    }

    #[test]
    fn different_keys_different_hashes() {
        let h1 = hash_key("sh_key1");
        let h2 = hash_key("sh_key2");
        assert_ne!(h1, h2);
    }
}
