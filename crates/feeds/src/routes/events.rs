//! `POST /api/v1/events` — batched interaction telemetry.
//!
//! Batching exists so a client that scrolled through a screen sends one request rather
//! than thirty; the endpoint is idempotent, so the client may retry a batch freely
//! without inflating the counts the ranking model is trained on. The whole batch is
//! rejected when it is too large or malformed, because a partially applied batch is
//! harder to reason about than a retried one.
//!
//! Consent is enforced here rather than negotiated with the client: a user who has not
//! opted into telemetry gets `204` and their events are discarded, so the client has no
//! branch to get wrong and opt-out remains a server-side property.

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use nodus_shared::{EventBatch, EventKind, MIN_CONTRACT_VERSION};
use nodus_store::events::{idempotency_key, kind_text, mark_followed, owned_item_accounts, record};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use uuid::Uuid;

use crate::auth::{Credentials, authenticate};
use crate::error::ApiError;
use crate::state::AppState;

/// Largest batch a single request may carry.
const MAX_EVENTS: usize = 100;

/// `POST /api/v1/events`
///
/// Takes an [`EventBatch`] and answers `204 No Content`; the response carries nothing
/// the client can act on, and in particular does not say how many events were stored.
///
/// # Errors
///
/// - [`ApiError::ClientTooOld`] when the caller's contract is below
///   [`MIN_CONTRACT_VERSION`].
/// - [`ApiError::Unauthorized`] when the token or the instance header is missing or
///   the instance rejects the token.
/// - [`ApiError::BadRequest`] with `batch_too_large` above `MAX_EVENTS`, with
///   `invalid_feed_id` for a feed id this service did not mint, or with
///   `invalid_client_ts` for a timestamp that is not RFC 3339.
/// - [`ApiError::Internal`] when the write fails.
pub async fn collect(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(batch): Json<EventBatch>,
) -> Result<StatusCode, ApiError> {
    contract_gate(&headers)?;
    let credentials = Credentials::from_headers(&headers)?;
    let caller = authenticate(&state, credentials).await?;

    // Opted out: accept and discard. The response is identical to the stored case so
    // the client cannot (and need not) behave differently.
    if !caller.user.telemetry_opt_in {
        return Ok(StatusCode::NO_CONTENT);
    }

    if batch.events.len() > MAX_EVENTS {
        return Err(ApiError::bad_request(
            "batch_too_large",
            format!("a batch may carry at most {MAX_EVENTS} events"),
        ));
    }

    let feed_id = Uuid::parse_str(&batch.feed_id).map_err(|_| {
        ApiError::bad_request("invalid_feed_id", "feed_id was not issued by this service")
    })?;

    let mut prepared = Vec::with_capacity(batch.events.len());
    let mut follow_item_ids = Vec::new();
    for event in batch.events {
        let client_ts = OffsetDateTime::parse(&event.client_ts, &Rfc3339).map_err(|_| {
            ApiError::bad_request(
                "invalid_client_ts",
                "client_ts must be an RFC 3339 timestamp",
            )
        })?;
        if event.kind == EventKind::Follow {
            follow_item_ids.push(event.item_id);
        }
        let key = idempotency_key(event.item_id, kind_text(event.kind), client_ts);
        prepared.push((event, key));
    }

    record(&state.pool, caller.user.id, feed_id, &prepared).await?;
    for account_id in owned_item_accounts(&state.pool, caller.user.id, &follow_item_ids).await? {
        mark_followed(&state.pool, caller.user.id, account_id).await?;
    }
    Ok(StatusCode::NO_CONTENT)
}

/// Rejects a client whose contract version predates ours.
///
/// A missing header is allowed: curl and the first integration tests do not send one.
/// A header we cannot understand is not.
fn contract_gate(headers: &HeaderMap) -> Result<(), ApiError> {
    let Some(client) = headers
        .get("x-contract-version")
        .and_then(|value| value.to_str().ok())
    else {
        return Ok(());
    };
    let client = client.trim();
    if version(client) < version(MIN_CONTRACT_VERSION) {
        return Err(ApiError::ClientTooOld {
            client: client.to_owned(),
            min: MIN_CONTRACT_VERSION.to_owned(),
        });
    }
    Ok(())
}

/// Parses `major.minor.patch`, ignoring anything after the patch number.
fn version(text: &str) -> (u32, u32, u32) {
    let mut parts = text.split('.').map(|part| {
        part.chars()
            .take_while(char::is_ascii_digit)
            .collect::<String>()
            .parse()
            .unwrap_or(0)
    });
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;
    use nodus_shared::{EventKind, InteractionEvent};
    use nodus_store::models::NewAccount;
    use nodus_store::{accounts, users};
    use std::sync::Arc;
    use std::time::Duration;

    use crate::config::Config;
    use crate::state::Identity;

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

    async fn authed_state_and_headers(
        pool: sqlx::PgPool,
        host: &str,
        remote_id: i64,
        acct: &str,
    ) -> (AppState, HeaderMap, Uuid) {
        users::ensure_instance(&pool, host)
            .await
            .expect("ensure instance");
        let user = users::upsert(&pool, host, &remote_id.to_string(), acct)
            .await
            .expect("upsert user");
        users::set_telemetry_opt_in(&pool, user.id, true)
            .await
            .expect("opt in");

        let token = format!("tok-{acct}");
        let state = AppState::new(
            pool,
            test_config(),
            Arc::new(nodus_cache::InMemoryCache::new()),
        );
        let key = nodus_store::crypto::verification_fingerprint(host, &token);
        state
            .identities
            .insert(
                key,
                Identity {
                    instance_host: host.to_owned(),
                    instance_account_id: remote_id.to_string(),
                    acct: acct.to_owned(),
                },
            )
            .await;

        let mut headers = HeaderMap::new();
        headers.insert(
            axum::http::header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("header"),
        );
        headers.insert(
            axum::http::HeaderName::from_static("x-instance-host"),
            HeaderValue::from_str(host).expect("header"),
        );
        (state, headers, user.id)
    }

    fn new_account(host: &str, remote_id: i64, acct: &str) -> NewAccount {
        NewAccount {
            instance_host: host.to_owned(),
            remote_id: remote_id.to_string(),
            acct: acct.to_owned(),
            display_name: None,
            followers_count: 0,
            bot: false,
            locked: false,
            discoverable: None,
            indexable: None,
            noindex: None,
        }
    }

    #[test]
    fn versions_compare_numerically() {
        assert!(version("0.2.0") > version("0.1.9"));
        assert_eq!(version("0.1.0-rc1"), (0, 1, 0));
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

    #[sqlx::test(migrations = "../store/migrations")]
    async fn follow_event_clears_affinity_and_enqueues_sync_user(pool: sqlx::PgPool) {
        let (state, headers, user_id) =
            authed_state_and_headers(pool.clone(), "home.test", 1, "me").await;
        users::ensure_instance(&pool, "remote.test")
            .await
            .expect("ensure remote");
        let other = users::upsert(&pool, "home.test", "2", "other")
            .await
            .expect("upsert other");

        accounts::upsert_many(
            &pool,
            &[
                new_account("remote.test", 10, "alice"),
                new_account("remote.test", 11, "bob"),
                new_account("remote.test", 12, "carol"),
            ],
        )
        .await
        .expect("seed accounts");
        let alice = accounts::find_id(&pool, "remote.test", "10")
            .await
            .expect("find alice")
            .expect("alice");
        let bob = accounts::find_id(&pool, "remote.test", "11")
            .await
            .expect("find bob")
            .expect("bob");
        let carol = accounts::find_id(&pool, "remote.test", "12")
            .await
            .expect("find carol")
            .expect("carol");

        for account_id in [alice, bob, carol] {
            sqlx::query(
                "INSERT INTO account_affinity (user_id, account_id, affinity, support) \
                 VALUES ($1, $2, 0.8, 2)",
            )
            .bind(user_id)
            .bind(account_id)
            .execute(&pool)
            .await
            .expect("seed affinity");
        }

        // Account recommendation owned by caller (alice), impression-only item (bob),
        // and foreign item owned by another user (carol).
        let alice_item: i64 = sqlx::query_scalar(
            "INSERT INTO recommendation_item \
                 (user_id, account_id, kind, score, reason, model_version) \
             VALUES ($1, $2, 'account', 0.8, '{}'::jsonb, 0) RETURNING id",
        )
        .bind(user_id)
        .bind(alice)
        .fetch_one(&pool)
        .await
        .expect("insert alice item");
        let bob_item: i64 = sqlx::query_scalar(
            "INSERT INTO recommendation_item \
                 (user_id, account_id, kind, score, reason, model_version) \
             VALUES ($1, $2, 'account', 0.7, '{}'::jsonb, 0) RETURNING id",
        )
        .bind(user_id)
        .bind(bob)
        .fetch_one(&pool)
        .await
        .expect("insert bob item");
        let foreign_carol_item: i64 = sqlx::query_scalar(
            "INSERT INTO recommendation_item \
                 (user_id, account_id, kind, score, reason, model_version) \
             VALUES ($1, $2, 'account', 0.6, '{}'::jsonb, 0) RETURNING id",
        )
        .bind(other.id)
        .bind(carol)
        .fetch_one(&pool)
        .await
        .expect("insert foreign carol item");

        let batch = EventBatch {
            feed_id: Uuid::new_v4().to_string(),
            events: vec![
                InteractionEvent {
                    item_id: alice_item,
                    kind: EventKind::Follow,
                    client_ts: "2026-01-01T00:00:00Z".to_owned(),
                    dwell_ms: None,
                },
                InteractionEvent {
                    item_id: bob_item,
                    kind: EventKind::Impression,
                    client_ts: "2026-01-01T00:00:01Z".to_owned(),
                    dwell_ms: Some(1200),
                },
                InteractionEvent {
                    item_id: foreign_carol_item,
                    kind: EventKind::Follow,
                    client_ts: "2026-01-01T00:00:02Z".to_owned(),
                    dwell_ms: None,
                },
            ],
        };

        let status = collect(State(state), headers, Json(batch))
            .await
            .expect("collect succeeds");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let remaining_affinity: Vec<i64> = sqlx::query_scalar(
            "SELECT account_id FROM account_affinity WHERE user_id = $1 ORDER BY account_id",
        )
        .bind(user_id)
        .fetch_all(&pool)
        .await
        .expect("read remaining affinity");
        assert_eq!(
            remaining_affinity,
            vec![bob, carol],
            "only the owned followed account's affinity must be deleted"
        );

        let sync_jobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM job \
             WHERE kind = 'sync_user' AND priority = 0 \
               AND subject_kind = 'user' AND subject_id = $1 AND status = 'pending'",
        )
        .bind(user_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("count sync_user jobs");
        assert_eq!(sync_jobs, 1, "a P0 sync_user job must be queued");
    }

    #[sqlx::test(migrations = "../store/migrations")]
    async fn follow_event_for_foreign_item_alone_does_not_enqueue_sync_user(pool: sqlx::PgPool) {
        let (state, headers, user_id) =
            authed_state_and_headers(pool.clone(), "home.test", 1, "me").await;
        users::ensure_instance(&pool, "remote.test")
            .await
            .expect("ensure remote");
        let other = users::upsert(&pool, "home.test", "2", "other")
            .await
            .expect("upsert other");

        accounts::upsert_many(&pool, &[new_account("remote.test", 10, "alice")])
            .await
            .expect("seed account");
        let alice = accounts::find_id(&pool, "remote.test", "10")
            .await
            .expect("find alice")
            .expect("alice");

        sqlx::query(
            "INSERT INTO account_affinity (user_id, account_id, affinity, support) \
             VALUES ($1, $2, 0.8, 2)",
        )
        .bind(user_id)
        .bind(alice)
        .execute(&pool)
        .await
        .expect("seed affinity");

        let foreign_item: i64 = sqlx::query_scalar(
            "INSERT INTO recommendation_item \
                 (user_id, account_id, kind, score, reason, model_version) \
             VALUES ($1, $2, 'account', 0.8, '{}'::jsonb, 0) RETURNING id",
        )
        .bind(other.id)
        .bind(alice)
        .fetch_one(&pool)
        .await
        .expect("insert foreign item");

        let batch = EventBatch {
            feed_id: Uuid::new_v4().to_string(),
            events: vec![InteractionEvent {
                item_id: foreign_item,
                kind: EventKind::Follow,
                client_ts: "2026-01-01T00:00:00Z".to_owned(),
                dwell_ms: None,
            }],
        };

        let status = collect(State(state), headers, Json(batch))
            .await
            .expect("collect succeeds");
        assert_eq!(status, StatusCode::NO_CONTENT);

        let affinity_count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM account_affinity WHERE user_id = $1 AND account_id = $2",
        )
        .bind(user_id)
        .bind(alice)
        .fetch_one(&pool)
        .await
        .expect("count affinity");
        assert_eq!(affinity_count, 1);

        let sync_jobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM job WHERE kind = 'sync_user' AND subject_id = $1",
        )
        .bind(user_id.to_string())
        .fetch_one(&pool)
        .await
        .expect("count jobs");
        assert_eq!(sync_jobs, 0);
    }
}
