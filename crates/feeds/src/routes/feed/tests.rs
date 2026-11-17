//! Tests for the guards and the page split.

use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, HeaderValue, header};
use nodus_shared::MIN_CONTRACT_VERSION;
use nodus_store::accounts;
use nodus_store::models::NewAccount;
use nodus_store::users;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration as StdDuration;
use time::{Duration, OffsetDateTime};

use super::params::{FeedParams, contract_gate, degraded_flag, parse_version, split};
use super::{accounts, refresh};
use crate::config::Config;
use crate::error::ApiError;
use crate::state::{AppState, Identity};

#[test]
fn versions_compare_numerically() {
    assert!(parse_version("0.2.0") > parse_version("0.1.9"));
    assert!(parse_version("1.0.0") > parse_version("0.99.99"));
    assert_eq!(parse_version("0"), (0, 0, 0));
    assert_eq!(parse_version("0.1.0-rc1"), (0, 1, 0));
}

#[test]
fn a_missing_header_passes_the_gate() {
    assert!(contract_gate(&HeaderMap::new()).is_ok());
}

#[test]
fn an_older_client_is_rejected() {
    let mut headers = HeaderMap::new();
    headers.insert("x-contract-version", "0.0.1".parse().unwrap());
    assert!(matches!(
        contract_gate(&headers),
        Err(ApiError::ClientTooOld { .. })
    ));
}

#[test]
fn a_current_client_passes() {
    let mut headers = HeaderMap::new();
    headers.insert("x-contract-version", MIN_CONTRACT_VERSION.parse().unwrap());
    assert!(contract_gate(&headers).is_ok());
}

#[test]
fn a_limit_plus_one_read_reports_more() {
    let (page, more) = split(vec![1, 2, 3], 2);
    assert_eq!(page, vec![1, 2]);
    assert!(more);
    let (page, more) = split(vec![1, 2], 2);
    assert_eq!(page, vec![1, 2]);
    assert!(!more);
}

#[test]
fn degradation_prefers_the_cause_over_the_symptom() {
    assert_eq!(
        degraded_flag(false, None).as_deref(),
        Some("no_server_sync")
    );
    assert_eq!(degraded_flag(true, None).as_deref(), Some("cold_start"));
    assert_eq!(
        degraded_flag(true, Some(72.0)).as_deref(),
        Some("stale_similarity")
    );
    assert_eq!(degraded_flag(true, Some(2.0)), None);
}

fn test_config() -> Config {
    Config {
        database_url: String::new(),
        listen_addr: "127.0.0.1:0".parse().expect("valid addr"),
        web_origins: Vec::new(),
        public_base_url: "http://127.0.0.1:3000".to_owned(),
        sync_enabled: true,
        max_connections: 1,
        replicas: 1,
        redis_url: None,
        verify_cache_seconds: 600,
        verify_cache_capacity: 64,
        og_cache_seconds: 600,
        connect_timeout: StdDuration::from_secs(5),
        token_enc_key: None,
    }
}

fn new_account(host: &str, remote_id: i64, acct: &str) -> NewAccount {
    NewAccount {
        instance_host: host.to_owned(),
        remote_id: remote_id.to_string(),
        acct: acct.to_owned(),
        display_name: None,
        followers_count: 100,
        bot: false,
        locked: false,
        discoverable: None,
        indexable: None,
        noindex: None,
    }
}

async fn authenticated_state_and_headers(
    pool: PgPool,
    host: &str,
    acct: &str,
) -> (AppState, HeaderMap, nodus_store::models::AppUser) {
    let state = AppState::new(
        pool.clone(),
        test_config(),
        Arc::new(nodus_cache::InMemoryCache::new()),
    );
    let token = "test-feed-token";
    let key = nodus_store::crypto::verification_fingerprint(host, token);
    state
        .identities
        .insert(
            key,
            Identity {
                instance_host: host.to_owned(),
                instance_account_id: "1".to_owned(),
                acct: acct.to_owned(),
            },
        )
        .await;
    users::ensure_instance(&pool, host).await.unwrap();
    let user = users::upsert(&pool, host, "1", acct).await.unwrap();
    let mut map = HeaderMap::new();
    map.insert(
        header::AUTHORIZATION,
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    map.insert("x-instance-host", HeaderValue::from_str(host).unwrap());
    (state, map, user)
}

async fn insert_affinity(pool: &PgPool, user_id: uuid::Uuid, account_id: i64, affinity: f32) {
    sqlx::query(
        "INSERT INTO account_affinity (user_id, account_id, affinity, support, sources, expires_at) \
         VALUES ($1, $2, $3, 1, ARRAY['similar_user']::text[], now() + interval '1 day')",
    )
    .bind(user_id)
    .bind(account_id)
    .bind(affinity)
    .execute(pool)
    .await
    .unwrap();
}

#[sqlx::test(migrations = "../store/migrations")]
async fn accounts_scores_and_sorts_candidates_before_page_selection(pool: PgPool) {
    let (state, headers, user) =
        authenticated_state_and_headers(pool.clone(), "home.test", "me").await;
    users::ensure_instance(&pool, "remote.test").await.unwrap();

    accounts::upsert_many(
        &pool,
        &[
            new_account("home.test", 1, "me"),
            new_account("remote.test", 10, "dismissed@remote.test"),
            new_account("remote.test", 11, "fatigued@remote.test"),
            new_account("remote.test", 12, "plain_high@remote.test"),
            new_account("remote.test", 13, "plain_mid@remote.test"),
            new_account("home.test", 14, "local_fresh_lift"),
            new_account("home.test", 15, "local_fresh"),
        ],
    )
    .await
    .unwrap();

    let dismissed = accounts::find_id(&pool, "remote.test", "10")
        .await
        .unwrap()
        .unwrap();
    let fatigued = accounts::find_id(&pool, "remote.test", "11")
        .await
        .unwrap()
        .unwrap();
    let plain_high = accounts::find_id(&pool, "remote.test", "12")
        .await
        .unwrap()
        .unwrap();
    let plain_mid = accounts::find_id(&pool, "remote.test", "13")
        .await
        .unwrap()
        .unwrap();
    let local_fresh_lift = accounts::find_id(&pool, "home.test", "14")
        .await
        .unwrap()
        .unwrap();
    let local_fresh = accounts::find_id(&pool, "home.test", "15")
        .await
        .unwrap()
        .unwrap();

    let now = OffsetDateTime::now_utc();
    for id in [local_fresh_lift, local_fresh] {
        sqlx::query("UPDATE account SET last_status_at = $2 WHERE id = $1")
            .bind(id)
            .bind(now - Duration::hours(1))
            .execute(&pool)
            .await
            .unwrap();
    }

    // `dismissed` has 3 impressions + a fresh dismiss -> strong negative penalty.
    let dismissed_item = sqlx::query_scalar::<_, i64>(
        "INSERT INTO recommendation_item (user_id, account_id, kind, score, model_version, served_at) \
         VALUES ($1, $2, 'account', 0.9, 0, now() - interval '10 days') RETURNING id",
    )
    .bind(user.id)
    .bind(dismissed)
    .fetch_one(&pool)
    .await
    .unwrap();
    for key in 1_u8..=3 {
        sqlx::query(
            "INSERT INTO interaction_event (user_id, item_id, kind, client_ts, idempotency_key) \
             VALUES ($1, $2, 'impression', now() - interval '10 days', $3)",
        )
        .bind(user.id)
        .bind(dismissed_item)
        .bind(vec![key; 32])
        .execute(&pool)
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO interaction_event (user_id, item_id, kind, client_ts, server_ts, idempotency_key) \
         VALUES ($1, $2, 'dismiss', now(), now(), $3)",
    )
    .bind(user.id)
    .bind(dismissed_item)
    .bind(vec![99_u8; 32])
    .execute(&pool)
    .await
    .unwrap();

    // `fatigued` has 5 recent unmeasured impressions -> seen_attention_7d = 5 -> -1.50.
    let fatigued_item = sqlx::query_scalar::<_, i64>(
        "INSERT INTO recommendation_item (user_id, account_id, kind, score, model_version, served_at) \
         VALUES ($1, $2, 'account', 0.9, 0, now() - interval '8 days') RETURNING id",
    )
    .bind(user.id)
    .bind(fatigued)
    .fetch_one(&pool)
    .await
    .unwrap();
    for key in 10_u8..15 {
        sqlx::query(
            "INSERT INTO interaction_event (user_id, item_id, kind, client_ts, server_ts, idempotency_key) \
             VALUES ($1, $2, 'impression', now() - interval '1 day', now() - interval '1 day', $3)",
        )
        .bind(user.id)
        .bind(fatigued_item)
        .bind(vec![key; 32])
        .execute(&pool)
        .await
        .unwrap();
    }

    // `local_fresh_lift` has strong follow-through lift (4.0x).
    sqlx::query(
        "INSERT INTO account_follow_through (account_id, impressions, follows, expected_rate) \
         VALUES ($1, 25, 10, 0.05)",
    )
    .bind(local_fresh_lift)
    .execute(&pool)
    .await
    .unwrap();

    // Raw affinity puts dismissed/fatigued first and `local_fresh_lift` / `local_fresh`
    // beyond `limit + 1` (4).
    insert_affinity(&pool, user.id, dismissed, 0.95).await;
    insert_affinity(&pool, user.id, fatigued, 0.90).await;
    insert_affinity(&pool, user.id, plain_high, 0.85).await;
    insert_affinity(&pool, user.id, plain_mid, 0.80).await;
    insert_affinity(&pool, user.id, local_fresh_lift, 0.60).await;
    insert_affinity(&pool, user.id, local_fresh, 0.65).await;

    let response = accounts(
        State(state),
        headers,
        Query(FeedParams {
            limit: Some(3),
            cursor: None,
            refresh: Some(true),
        }),
    )
    .await
    .expect("feed accounts succeeds")
    .0;

    let accts: Vec<&str> = response
        .items
        .iter()
        .map(|item| item.account.acct.as_str())
        .collect();
    assert_eq!(
        accts,
        vec!["local_fresh_lift", "local_fresh", "plain_high@remote.test",],
        "expected score()-ranked candidates from full pool, got {accts:?}"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn accounts_enforces_instance_diversity_cap(pool: PgPool) {
    let (state, headers, user) =
        authenticated_state_and_headers(pool.clone(), "home.test", "me").await;
    users::ensure_instance(&pool, "crowded.test").await.unwrap();

    let mut new_accounts = vec![new_account("home.test", 1, "me")];
    for i in 0..15_i64 {
        new_accounts.push(new_account(
            "crowded.test",
            100 + i,
            &format!("c{i}@crowded.test"),
        ));
    }
    for i in 0..50_i64 {
        let host = format!("alt{i:02}.test");
        users::ensure_instance(&pool, &host).await.unwrap();
        new_accounts.push(new_account(&host, 200 + i, &format!("u{i}@{host}")));
    }
    accounts::upsert_many(&pool, &new_accounts).await.unwrap();

    let mut host_by_account_id = HashMap::new();
    for i in 0..15_i64 {
        let id = accounts::find_id(&pool, "crowded.test", &format!("{}", 100 + i))
            .await
            .unwrap()
            .unwrap();
        host_by_account_id.insert(id.to_string(), "crowded.test".to_owned());
        #[expect(clippy::cast_precision_loss, reason = "small test index")]
        let aff = 0.99 - (i as f32) * 0.005;
        insert_affinity(&pool, user.id, id, aff).await;
    }
    for i in 0..50_i64 {
        let host = format!("alt{i:02}.test");
        let id = accounts::find_id(&pool, &host, &format!("{}", 200 + i))
            .await
            .unwrap()
            .unwrap();
        host_by_account_id.insert(id.to_string(), host);
        #[expect(clippy::cast_precision_loss, reason = "small test index")]
        let aff = 0.80 - (i as f32) * 0.005;
        insert_affinity(&pool, user.id, id, aff).await;
    }

    let response = accounts(
        State(state),
        headers,
        Query(FeedParams {
            limit: Some(20),
            cursor: None,
            refresh: Some(true),
        }),
    )
    .await
    .expect("feed accounts succeeds")
    .0;

    assert_eq!(response.items.len(), 20);
    let hosts: Vec<&str> = response
        .items
        .iter()
        .map(|item| host_by_account_id[&item.account.id].as_str())
        .collect();

    for (start, window) in hosts
        .windows(nodus_core::diversity::INSTANCE_WINDOW)
        .enumerate()
    {
        let mut counts: HashMap<&str, usize> = HashMap::new();
        for host in window {
            *counts.entry(*host).or_insert(0) += 1;
        }
        for (host, count) in counts {
            assert!(
                count <= nodus_core::diversity::MAX_PER_INSTANCE,
                "window starting at {start} had {count} accounts from {host}: {hosts:?}"
            );
        }
    }
}

#[sqlx::test(migrations = "../store/migrations")]
async fn accounts_and_refresh_return_active_model_version(pool: PgPool) {
    let (state, headers, user) =
        authenticated_state_and_headers(pool.clone(), "home.test", "me").await;
    users::ensure_instance(&pool, "remote.test").await.unwrap();

    sqlx::query(
        "INSERT INTO model_version (version, weights, active) VALUES (7, '{}'::jsonb, true)",
    )
    .execute(&pool)
    .await
    .unwrap();

    accounts::upsert_many(
        &pool,
        &[
            new_account("home.test", 1, "me"),
            new_account("remote.test", 10, "alice@remote.test"),
            new_account("remote.test", 11, "bob@remote.test"),
        ],
    )
    .await
    .unwrap();
    for m_id in [10, 11] {
        let id = accounts::find_id(&pool, "remote.test", &m_id.to_string())
            .await
            .unwrap()
            .unwrap();
        insert_affinity(&pool, user.id, id, 0.8).await;
    }

    // Fresh page.
    let fresh = accounts(
        State(state.clone()),
        headers.clone(),
        Query(FeedParams {
            limit: Some(10),
            cursor: None,
            refresh: None,
        }),
    )
    .await
    .expect("fresh page succeeds")
    .0;
    assert_eq!(
        fresh.model_version, 7,
        "fresh page must report active model_version"
    );

    // Reused live snapshot.
    let reused = accounts(
        State(state.clone()),
        headers.clone(),
        Query(FeedParams {
            limit: Some(10),
            cursor: None,
            refresh: None,
        }),
    )
    .await
    .expect("reused snapshot succeeds")
    .0;
    assert_eq!(reused.feed_id, fresh.feed_id);
    assert_eq!(
        reused.model_version, 7,
        "reused snapshot must report active model_version"
    );

    // Explicit refresh endpoint.
    let refreshed = refresh::refresh(
        State(state.clone()),
        headers.clone(),
        Path(fresh.feed_id),
        Query(FeedParams {
            limit: Some(10),
            cursor: None,
            refresh: None,
        }),
    )
    .await
    .expect("refresh endpoint succeeds")
    .0;
    assert_eq!(
        refreshed.model_version, 7,
        "refresh must report active model_version"
    );

    // Cursor continuation page.
    let second_page_feed_id = uuid::Uuid::now_v7();
    let persisted = nodus_store::feed::persist(
        &pool,
        user.id,
        second_page_feed_id,
        7,
        &[
            nodus_store::feed::NewItem {
                account_id: accounts::find_id(&pool, "remote.test", "10").await.unwrap().unwrap(),
                score: 0.9,
                reason: serde_json::json!({"code": "similar_user", "support": 1, "sample_followers": []}),
            },
            nodus_store::feed::NewItem {
                account_id: accounts::find_id(&pool, "remote.test", "11").await.unwrap().unwrap(),
                score: 0.8,
                reason: serde_json::json!({"code": "similar_user", "support": 1, "sample_followers": []}),
            },
        ],
    )
    .await
    .unwrap();
    let cursor = crate::cursor::encode(second_page_feed_id, persisted[0].0);
    let continued = accounts(
        State(state),
        headers,
        Query(FeedParams {
            limit: Some(10),
            cursor: Some(cursor),
            refresh: None,
        }),
    )
    .await
    .expect("cursor page succeeds")
    .0;
    assert_eq!(
        continued.model_version, 7,
        "cursor page must report active model_version"
    );
}
