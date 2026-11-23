//! The recommendation engine's HTTP surface.
//!
//! This is a library as well as a binary: the core service mounts [`core_router`] in
//! process, so a deployment that wants recommendations needs no second listener and no
//! address to discover.

#![forbid(unsafe_code)]

pub mod auth;
pub mod config;
pub mod cursor;
pub mod error;
pub mod host;
pub mod og;
pub mod routes;
pub mod state;

pub use crate::routes::{core_router, router};

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use nodus_store::crypto::TokenSealer;
use sqlx::PgPool;

/// Where the engine keeps its tables when it runs inside another service's database.
pub const SCHEMA: &str = nodus_store::ENGINE_SCHEMA;

/// State for the in-process mount, built from the core service's own pool.
///
/// The shared cache backend exists so several replicas agree on which tokens they
/// verified. One process needs none, so the in-process map is used and `replicas`
/// says so by construction.
///
/// # Panics
///
/// Panics only when the HTTP client cannot be built, which is a TLS misconfiguration
/// worth failing at boot.
#[must_use]
pub fn in_process(
    pool: PgPool,
    base_url: &str,
    max_connections: u32,
    token_enc_key: Option<TokenSealer>,
) -> state::AppState {
    let base = base_url.trim_end_matches('/').to_owned();
    let config = config::Config {
        database_url: String::new(),
        listen_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
        web_origins: vec![base.clone()],
        public_base_url: base,
        sync_enabled: false,
        max_connections,
        replicas: 1,
        redis_url: None,
        verify_cache_seconds: 600,
        verify_cache_capacity: 10_000,
        og_cache_seconds: 86_400,
        connect_timeout: Duration::from_secs(10),
        token_enc_key,
    };
    state::AppState::new(pool, config, Arc::new(nodus_cache::InMemoryCache::new()))
}

/// A pool that reads the engine's tables first and the host's second.
///
/// The engine's `account` and `status` are its own mirrors, not the host's rows, so every
/// connection resolves unqualified names inside [`SCHEMA`] before `public`.
///
/// # Errors
///
/// Returns the database error if the schema cannot be applied or the pool cannot connect.
pub async fn prepare(database_url: &str, max_connections: u32) -> Result<PgPool, sqlx::Error> {
    nodus_store::engine_pool(database_url, max_connections, SCHEMA).await
}

/// Apply the engine's schema and hand back its routes, ready to mount in a host process.
///
/// # Errors
///
/// Returns the database error from [`prepare`]; a host should keep serving without the
/// feed routes rather than stop over them.
pub async fn mount(
    database_url: &str,
    base_url: &str,
    max_connections: u32,
    token_enc_key: Option<TokenSealer>,
) -> Result<axum::Router, sqlx::Error> {
    let pool = prepare(database_url, max_connections).await?;
    Ok(core_router(in_process(
        pool,
        base_url,
        max_connections,
        token_enc_key,
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lazy_pool() -> PgPool {
        sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://nodus@localhost/nodus")
            .expect("a lazily connected pool is valid")
    }

    /// Regression: `in_process` used to hardcode `token_enc_key: None`, so a deployment
    /// that set `TOKEN_ENC_KEY` still answered every `/api/v1/sync/*` call with 503
    /// `sync_disabled`. The parameter is required so the key cannot be dropped again.
    #[test]
    fn a_supplied_sealer_reaches_the_state() {
        let sealer = TokenSealer::from_key_bytes(&[7_u8; 32]).expect("a 32-byte key is valid");
        let state = build_state(Some(sealer));
        assert!(state.config.token_enc_key.is_some());
    }

    #[test]
    fn no_sealer_stays_disabled() {
        let state = build_state(None);
        assert!(state.config.token_enc_key.is_none());
    }

    /// `connect_lazy` needs a Tokio context even though the test never queries.
    fn build_state(token_enc_key: Option<TokenSealer>) -> state::AppState {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("a test runtime")
            .block_on(
                async move { in_process(lazy_pool(), "https://nodus.example", 1, token_enc_key) },
            )
    }
}
