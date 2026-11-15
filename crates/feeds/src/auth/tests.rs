//! Tests for credential parsing and host validation.

use axum::http::{HeaderMap, HeaderValue, header};
use std::sync::Arc;
use std::time::Duration;

use super::authenticate;
use super::credentials::Credentials;
use super::headers::is_plausible_host;
use crate::config::Config;
use crate::state::{AppState, Identity};

fn headers(entries: &[(&str, &str)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in entries {
        map.insert(
            axum::http::HeaderName::from_bytes(name.as_bytes()).expect("valid name"),
            HeaderValue::from_str(value).expect("valid value"),
        );
    }
    map
}

#[test]
fn a_bearer_token_and_a_host_are_accepted() {
    let credentials = Credentials::from_headers(&headers(&[
        ("authorization", "Bearer tok-123"),
        ("x-instance-host", "Mastodon.Social"),
    ]))
    .expect("credentials parse");
    assert_eq!(credentials.instance_host, "mastodon.social");
    assert_eq!(credentials.token.expose(), "tok-123");
    assert!(format!("{:?}", credentials.token).contains("redacted"));
}

#[test]
fn a_missing_authorization_header_is_named() {
    let error = Credentials::from_headers(&headers(&[("x-instance-host", "a.example")]))
        .expect_err("no credentials");
    assert_eq!(error.code(), "missing_credentials");
}

#[test]
fn a_non_bearer_scheme_is_rejected() {
    let error = Credentials::from_headers(&headers(&[
        ("authorization", "Basic dXNlcjpwYXNz"),
        ("x-instance-host", "a.example"),
    ]))
    .expect_err("wrong scheme");
    assert_eq!(error.code(), "missing_credentials");
}

#[test]
fn a_missing_instance_header_is_named() {
    let error =
        Credentials::from_headers(&headers(&[("authorization", "Bearer t")])).expect_err("no host");
    assert_eq!(error.code(), "missing_instance_header");
}

#[test]
fn a_host_that_could_escape_the_url_is_rejected() {
    for host in [
        "https://evil.example",
        "evil.example/path",
        "user@evil.example",
        "evil example",
    ] {
        let error = Credentials::from_headers(&headers(&[
            ("authorization", "Bearer t"),
            ("x-instance-host", host),
        ]))
        .expect_err("host must be rejected");
        assert_eq!(error.code(), "invalid_instance_header", "{host}");
    }
}

#[test]
fn plausible_hosts_are_accepted() {
    for host in ["mastodon.social", "localhost:3000", "social.example.org"] {
        assert!(is_plausible_host(host), "{host}");
    }
}

#[test]
fn the_authorization_header_name_is_used_from_the_http_crate() {
    assert_eq!(header::AUTHORIZATION.as_str(), "authorization");
}

fn test_config() -> Config {
    Config {
        database_url: String::new(),
        listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
        web_origins: Vec::new(),
        public_base_url: "http://127.0.0.1:3000".to_owned(),
        sync_enabled: false,
        max_connections: 1,
        replicas: 1,
        redis_url: None,
        verify_cache_seconds: 600,
        verify_cache_capacity: 64,
        og_cache_seconds: 600,
        connect_timeout: Duration::from_secs(5),
        token_enc_key: None,
    }
}

fn unused_local_host() -> String {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local addr");
    drop(listener);
    addr.to_string()
}

async fn assert_rejected_with_cached_identity(
    pool: sqlx::PgPool,
    victim_host: &str,
    token: &str,
    cache_key: [u8; 32],
    cached_host: &str,
) {
    let state = AppState::new(
        pool.clone(),
        test_config(),
        Arc::new(nodus_cache::InMemoryCache::new()),
    );
    state
        .identities
        .insert(
            cache_key,
            Identity {
                instance_host: cached_host.to_owned(),
                mastodon_account_id: 109_384,
                acct: "victim".to_owned(),
            },
        )
        .await;

    let creds = Credentials::from_headers(&headers(&[
        ("authorization", &format!("Bearer {token}")),
        ("x-instance-host", victim_host),
    ]))
    .expect("valid headers");
    let result = authenticate(&state, creds).await;
    assert!(
        result.is_err(),
        "cross-instance cache hit must be rejected; got {result:?}"
    );

    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM app_user WHERE instance_host = $1")
        .bind(victim_host)
        .fetch_one(&pool)
        .await
        .expect("count query");
    assert_eq!(count, 0, "rejected auth must not create an app_user row");
}

#[sqlx::test(migrations = "../store/migrations")]
async fn cached_identity_from_evil_instance_cannot_authenticate_on_another_instance(
    pool: sqlx::PgPool,
) {
    let token = "attacker-controlled-token";
    let victim_host = unused_local_host();
    // Simulate step 2 of the exploit: evil.example verified `token` as victim 109384.
    let evil_key = nodus_store::crypto::verification_fingerprint("evil.example", token);
    assert_rejected_with_cached_identity(pool, &victim_host, token, evil_key, "evil.example").await;
}

#[sqlx::test(migrations = "../store/migrations")]
async fn cached_identity_with_mismatched_instance_host_under_same_key_is_rejected(
    pool: sqlx::PgPool,
) {
    let token = "attacker-controlled-token";
    let victim_host = unused_local_host();
    // Defense-in-depth: even if the cache entry under the victim's key claims a
    // different instance_host, authenticate() must refuse it and re-verify.
    let victim_key = nodus_store::crypto::verification_fingerprint(&victim_host, token);
    assert_rejected_with_cached_identity(pool, &victim_host, token, victim_key, "evil.example")
        .await;
}

#[sqlx::test(migrations = "../store/migrations")]
async fn cached_identity_for_matching_instance_host_authenticates(pool: sqlx::PgPool) {
    let state = AppState::new(
        pool,
        test_config(),
        Arc::new(nodus_cache::InMemoryCache::new()),
    );
    let token = "legitimate-token";
    let instance_host = unused_local_host();

    let key = nodus_store::crypto::verification_fingerprint(&instance_host, token);
    state
        .identities
        .insert(
            key,
            Identity {
                instance_host: instance_host.clone(),
                mastodon_account_id: 109_384,
                acct: "victim".to_owned(),
            },
        )
        .await;

    let creds = Credentials::from_headers(&headers(&[
        ("authorization", &format!("Bearer {token}")),
        ("x-instance-host", &instance_host.to_ascii_uppercase()),
    ]))
    .expect("valid headers");
    let authenticated = authenticate(&state, creds)
        .await
        .expect("matching host cache hit should authenticate");
    assert_eq!(authenticated.user.instance_host, instance_host);
    assert_eq!(authenticated.user.mastodon_account_id, 109_384);
    assert_eq!(authenticated.user.acct, "victim");
}
