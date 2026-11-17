//! `POST /api/v1/browse` — let a reader's visit ask for the slower crawl.
//!
//! Reading a shared post or profile is the strongest signal that its author and
//! conversation matter. The response is a receipt, not the data: the client already
//! has the page it asked for, and the crawl continues in the calculator.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use nodus_store::jobs::{self, NewJob};
use nodus_store::models::NewAccount;
use nodus_store::{accounts, users};
use serde::Deserialize;

use crate::auth::{Credentials, authenticate};
use crate::error::ApiError;
use crate::host::is_plausible_host;
use crate::state::AppState;

/// What the reader opened.
#[derive(Debug, Deserialize)]
pub struct Browse {
    /// `status` or `profile`.
    pub kind: String,
    /// The instance that owns the id.
    pub host: String,
    /// The instance-local account or status id.
    pub id: String,
    /// The account handle, for a profile the recommender has not met.
    pub acct: Option<String>,
}

/// The number of jobs this visit created.
#[derive(Debug, serde::Serialize)]
pub struct Receipt {
    /// Jobs enqueued, after deduplication.
    pub queued: usize,
}

#[derive(Debug, PartialEq, Eq)]
enum BrowseKind {
    Profile { acct: Option<String> },
    Status,
}

#[derive(Debug, PartialEq, Eq)]
struct ValidatedBrowse {
    kind: BrowseKind,
    host: String,
    /// Kept as text: Mastodon prints numbers and nodus prints ULIDs, and the value is
    /// only ever echoed back to the instance that minted it.
    id: String,
}

/// Record a visit as crawl work.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] or [`ApiError::BadRequest`] when caller credentials
/// fail verification; [`ApiError::BadRequest`] when the target is malformed;
/// otherwise database failures.
pub async fn browse(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<Browse>,
) -> Result<Json<Receipt>, ApiError> {
    let credentials = Credentials::from_headers(&headers)?;
    let _caller = authenticate(&state, credentials).await?;

    let target = validate(&body)?;

    let account_id = match target.kind {
        BrowseKind::Profile { acct } => {
            Some(ensure_account(&state, &target.host, &target.id, acct.as_deref()).await?)
        }
        BrowseKind::Status => {
            let found: Option<i64> = sqlx::query_scalar(
                "SELECT account_id FROM status WHERE instance_host = $1 AND remote_id = $2",
            )
            .bind(&target.host)
            .bind(&target.id)
            .fetch_optional(&state.pool)
            .await?;
            found
        }
    };

    let mut queued = 0;
    if let Some(account_id) = account_id {
        let subject = account_id.to_string();
        for (kind, priority) in [("refresh_account", 2), ("refresh_profile", 3)] {
            if jobs::enqueue(
                &state.pool,
                &NewJob::pending(kind, priority, "account", Some(subject.clone())),
            )
            .await?
            .is_some()
            {
                queued += 1;
            }
        }
    }
    Ok(Json(Receipt { queued }))
}

fn validate(body: &Browse) -> Result<ValidatedBrowse, ApiError> {
    let id = body.id.trim();
    if id.is_empty() || id.len() > 64 || !id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(ApiError::bad_request(
            "bad_target",
            format!("`{id}` is not an instance id"),
        ));
    }
    let id = id.to_owned();
    let host = body.host.trim();
    if !is_plausible_host(host) {
        return Err(ApiError::bad_request(
            "bad_target",
            format!("`{host}` is not a valid instance host"),
        ));
    }
    let host = host.to_ascii_lowercase();

    let kind = match body.kind.as_str() {
        "profile" => {
            let acct = body
                .acct
                .as_deref()
                .map(str::trim)
                .filter(|acct| !acct.is_empty())
                .map(|acct| normalize_acct(acct, &host))
                .transpose()?;
            BrowseKind::Profile { acct }
        }
        "status" => BrowseKind::Status,
        other => {
            return Err(ApiError::bad_request(
                "bad_kind",
                format!("`{other}` is not `status` or `profile`"),
            ));
        }
    };

    Ok(ValidatedBrowse { kind, host, id })
}

fn normalize_acct(acct: &str, default_host: &str) -> Result<String, ApiError> {
    let (user, origin) = match acct.split_once('@') {
        Some((user, origin)) => {
            let origin = origin.trim();
            if !is_plausible_host(origin) {
                return Err(ApiError::bad_request(
                    "bad_target",
                    format!("`{origin}` is not a valid instance host"),
                ));
            }
            (user.trim(), origin.to_ascii_lowercase())
        }
        None => (acct, default_host.to_owned()),
    };
    if !is_plausible_username(user) {
        return Err(ApiError::bad_request(
            "bad_target",
            format!("`{acct}` is not a valid account handle"),
        ));
    }
    Ok(format!("{user}@{origin}"))
}

fn is_plausible_username(user: &str) -> bool {
    !user.is_empty()
        && user.len() <= 255
        && user.chars().all(|c| {
            !c.is_whitespace()
                && !c.is_control()
                && !matches!(c, '@' | '/' | '\\' | '?' | '#' | ':')
        })
}

async fn ensure_account(
    state: &AppState,
    host: &str,
    id: &str,
    acct: Option<&str>,
) -> Result<i64, ApiError> {
    if let Some(found) = accounts::find_id(&state.pool, host, id).await? {
        return Ok(found);
    }
    let Some(acct) = acct else {
        return Err(ApiError::bad_request(
            "unknown_account",
            "a profile the recommender has not met needs its acct",
        ));
    };
    users::ensure_instance(&state.pool, host).await?;
    accounts::upsert_many(
        &state.pool,
        &[NewAccount {
            instance_host: host.to_owned(),
            remote_id: id.to_owned(),
            acct: acct.to_owned(),
            display_name: None,
            followers_count: 0,
            bot: false,
            locked: false,
            discoverable: None,
            indexable: None,
            noindex: None,
        }],
    )
    .await?;
    accounts::find_id(&state.pool, host, id)
        .await?
        .ok_or(ApiError::NotFound)
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use axum::http::{HeaderName, HeaderValue};

    use super::*;
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

    fn make_headers(entries: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in entries {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        map
    }

    async fn authenticated_state(pool: sqlx::PgPool) -> (AppState, HeaderMap) {
        let state = AppState::new(
            pool,
            test_config(),
            Arc::new(nodus_cache::InMemoryCache::new()),
        );
        let host = "caller.example";
        let token = "valid-test-token";
        let key = nodus_store::crypto::verification_fingerprint(host, token);
        state
            .identities
            .insert(
                key,
                Identity {
                    instance_host: host.to_owned(),
                    instance_account_id: "1".to_owned(),
                    acct: "caller".to_owned(),
                },
            )
            .await;
        let headers = make_headers(&[
            ("authorization", &format!("Bearer {token}")),
            ("x-instance-host", host),
        ]);
        (state, headers)
    }

    #[test]
    fn validate_normalizes_valid_profile_targets() {
        let parsed = validate(&Browse {
            kind: "profile".to_owned(),
            host: " Mastodon.Social ".to_owned(),
            id: " 42 ".to_owned(),
            acct: Some("alice@Fosstodon.Org".to_owned()),
        })
        .expect("valid profile browse");
        assert_eq!(
            parsed,
            ValidatedBrowse {
                kind: BrowseKind::Profile {
                    acct: Some("alice@fosstodon.org".to_owned()),
                },
                host: "mastodon.social".to_owned(),
                id: "42".to_owned(),
            }
        );

        let local_acct = validate(&Browse {
            kind: "profile".to_owned(),
            host: "Mastodon.Social".to_owned(),
            id: "7".to_owned(),
            acct: Some("alice".to_owned()),
        })
        .expect("local acct gets normalized host");
        assert_eq!(
            local_acct.kind,
            BrowseKind::Profile {
                acct: Some("alice@mastodon.social".to_owned()),
            }
        );
    }

    #[test]
    fn validate_rejects_ssrf_hosts_and_acct_origins() {
        for bad_host in [
            "",
            "localhost",
            "localhost:8080",
            "169.254.169.254",
            "127.0.0.1:6379/internal",
            "redis.nodus.svc:6379",
            "redis.nodus.svc",
            "metadata.google.internal",
            "printer.local",
            "api.cluster.local",
            "10.0.0.1",
            "[::1]",
        ] {
            let error = validate(&Browse {
                kind: "profile".to_owned(),
                host: bad_host.to_owned(),
                id: "1".to_owned(),
                acct: Some("alice".to_owned()),
            })
            .expect_err("ssrf host must be rejected");
            assert_eq!(error.code(), "bad_target", "{bad_host}");
        }

        for bad_acct in [
            "alice@169.254.169.254",
            "alice@127.0.0.1:6379/internal",
            "alice@redis.nodus.svc:6379",
            "alice@redis.nodus.svc",
            "alice@localhost",
            "alice@metadata.google.internal",
            "alice@printer.local",
            "@alice@mastodon.social",
            "alice@bob@mastodon.social",
            "alice/../../etc",
        ] {
            let error = validate(&Browse {
                kind: "profile".to_owned(),
                host: "mastodon.social".to_owned(),
                id: "1".to_owned(),
                acct: Some(bad_acct.to_owned()),
            })
            .expect_err("ssrf acct must be rejected");
            assert_eq!(error.code(), "bad_target", "{bad_acct}");
        }
    }

    #[sqlx::test(migrations = "../store/migrations")]
    async fn unauthenticated_browse_is_rejected_without_polluting_tables(pool: sqlx::PgPool) {
        let state = AppState::new(
            pool.clone(),
            test_config(),
            Arc::new(nodus_cache::InMemoryCache::new()),
        );

        for (hdrs, expected_status) in [
            (make_headers(&[]), axum::http::StatusCode::BAD_REQUEST),
            (
                make_headers(&[("x-instance-host", "mastodon.social")]),
                axum::http::StatusCode::BAD_REQUEST,
            ),
            (
                make_headers(&[
                    ("authorization", "Bearer forged"),
                    ("x-instance-host", "localhost:8080"),
                ]),
                axum::http::StatusCode::BAD_REQUEST,
            ),
            (
                make_headers(&[
                    ("authorization", "Bearer forged"),
                    ("x-instance-host", "calculator.nodus.svc:8080"),
                ]),
                axum::http::StatusCode::BAD_REQUEST,
            ),
            (
                make_headers(&[
                    ("authorization", "Bearer forged"),
                    ("x-instance-host", "169.254.169.254"),
                ]),
                axum::http::StatusCode::BAD_REQUEST,
            ),
            (
                make_headers(&[
                    ("authorization", "Bearer forged"),
                    ("x-instance-host", "unseen.invalid"),
                ]),
                axum::http::StatusCode::SERVICE_UNAVAILABLE,
            ),
        ] {
            let err = browse(
                State(state.clone()),
                hdrs,
                Json(Browse {
                    kind: "profile".to_owned(),
                    host: "mastodon.social".to_owned(),
                    id: "123".to_owned(),
                    acct: Some("alice@mastodon.social".to_owned()),
                }),
            )
            .await
            .expect_err("unauthenticated browse must fail");
            assert_eq!(err.status(), expected_status);
        }

        let instances: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM instance")
            .fetch_one(&pool)
            .await
            .expect("count instance");
        let accounts_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account")
            .fetch_one(&pool)
            .await
            .expect("count account");
        let jobs_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM job")
            .fetch_one(&pool)
            .await
            .expect("count job");
        assert_eq!(instances, 0);
        assert_eq!(accounts_count, 0);
        assert_eq!(jobs_count, 0);
    }

    #[sqlx::test(migrations = "../store/migrations")]
    async fn authenticated_browse_rejects_ssrf_targets_and_accepts_valid_profile(
        pool: sqlx::PgPool,
    ) {
        let (state, headers) = authenticated_state(pool.clone()).await;

        let bad_host_err = browse(
            State(state.clone()),
            headers.clone(),
            Json(Browse {
                kind: "profile".to_owned(),
                host: "169.254.169.254".to_owned(),
                id: "42".to_owned(),
                acct: Some("admin".to_owned()),
            }),
        )
        .await
        .expect_err("SSRF host must fail");
        assert_eq!(bad_host_err.code(), "bad_target");

        let bad_acct_err = browse(
            State(state.clone()),
            headers.clone(),
            Json(Browse {
                kind: "profile".to_owned(),
                host: "mastodon.social".to_owned(),
                id: "42".to_owned(),
                acct: Some("admin@redis.nodus.svc".to_owned()),
            }),
        )
        .await
        .expect_err("SSRF acct origin must fail");
        assert_eq!(bad_acct_err.code(), "bad_target");

        let status_miss = browse(
            State(state.clone()),
            headers.clone(),
            Json(Browse {
                kind: "status".to_owned(),
                host: "unseen.example".to_owned(),
                id: "999".to_owned(),
                acct: None,
            }),
        )
        .await
        .expect("unknown status returns 0 queued");
        assert_eq!(status_miss.0.queued, 0);

        let unseen_count: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM instance WHERE host = 'unseen.example'")
                .fetch_one(&pool)
                .await
                .expect("count unseen instance");
        assert_eq!(unseen_count, 0);

        let receipt = browse(
            State(state),
            headers,
            Json(Browse {
                kind: "profile".to_owned(),
                host: "Mastodon.Social".to_owned(),
                id: "42".to_owned(),
                acct: Some("alice@Fosstodon.Org".to_owned()),
            }),
        )
        .await
        .expect("valid authenticated browse succeeds");
        assert_eq!(receipt.0.queued, 2);

        let stored_acct: String = sqlx::query_scalar(
            "SELECT acct::text FROM account WHERE instance_host = 'mastodon.social' AND remote_id = '42'",
        )
        .fetch_one(&pool)
        .await
        .expect("stored account");
        assert_eq!(stored_acct, "alice@fosstodon.org");
    }
}
