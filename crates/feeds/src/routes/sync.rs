//! `PUT` and `DELETE /api/v1/sync/token` — the consent surface.
//!
//! Background sync is the only thing in this service that holds a secret, so it is
//! the only thing a user has to opt into explicitly, and the only thing they can
//! switch off with one call that provably destroys the copy we hold. Telemetry is a
//! separate switch on purpose: a user may want their feed improved without wanting
//! their clicks stored.

use axum::Json;
use axum::extract::State;
use axum::http::HeaderMap;
use nodus_shared::{MeResponse, SyncSettings, SyncTokenRequest};

use crate::auth::{Credentials, authenticate};
use crate::error::ApiError;
use crate::state::AppState;
use nodus_store::crypto::{fingerprint, verification_fingerprint};

/// Start holding an encrypted copy of the caller's token and queue their first sync.
///
/// # Errors
///
/// [`ApiError::Unavailable`] with `sync_disabled` when this deployment has no
/// encryption key, `instance_unreachable`/`instance_rate_limited` when the token
/// cannot be verified, and [`ApiError::Unauthorized`] when the instance rejects it.
pub async fn put_sync_token(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<SyncTokenRequest>,
) -> Result<Json<SyncSettings>, ApiError> {
    let credentials = Credentials::from_headers(&headers)?;
    if !body.enable {
        return stop_sync(&state, credentials, body.telemetry_opt_in).await;
    }
    let sealer = state
        .config
        .token_enc_key
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("sync_disabled", 3600))?;
    let caller = authenticate(&state, credentials).await?;
    let encrypted = sealer
        .seal(caller.credentials.token.expose())
        .map_err(|error| {
            tracing::error!(error = %error, "sealing a token failed");
            ApiError::Internal(crate::error::anyhow_detail::Detail(error.to_string()))
        })?;
    let token_fingerprint = fingerprint(caller.credentials.token.expose());
    let scopes = vec![SYNC_SCOPE.to_owned()];
    let stored = nodus_store::users::set_sync_token(
        &state.pool,
        caller.user.id,
        &encrypted,
        &scopes,
        &token_fingerprint,
    )
    .await?;
    if !stored {
        return Err(ApiError::NotFound);
    }
    nodus_store::users::set_telemetry_opt_in(&state.pool, caller.user.id, body.telemetry_opt_in)
        .await?;
    nodus_store::jobs::enqueue(
        &state.pool,
        &nodus_store::jobs::NewJob::sync_user(&caller.user.id),
    )
    .await?;
    tracing::info!(user = %caller.user.acct, "background sync enabled");
    Ok(Json(SyncSettings {
        sync_enabled: true,
        telemetry_opt_in: body.telemetry_opt_in,
    }))
}

/// Stop holding the token and forget what was derived from it.
///
/// The feed does not stop working: it degrades to what can be computed from the
/// caller's own token on each request.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] when the instance rejects the token,
/// [`ApiError::Internal`] for database failures.
pub async fn delete_sync_token(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SyncSettings>, ApiError> {
    let credentials = Credentials::from_headers(&headers)?;
    stop_sync(&state, credentials, false).await
}

/// `GET /api/v1/me` — who the service thinks the caller is, and what it holds.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] when the token is rejected, [`ApiError::Internal`] for
/// database failures.
pub async fn get_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<MeResponse>, ApiError> {
    let credentials = Credentials::from_headers(&headers)?;
    let caller = authenticate(&state, credentials).await?;
    Ok(Json(MeResponse {
        acct: caller.user.acct.clone(),
        instance_host: caller.user.instance_host.clone(),
        sync_enabled: caller.user.sync_enabled,
        telemetry_opt_in: caller.user.telemetry_opt_in,
        contract: nodus_shared::CONTRACT_VERSION.to_owned(),
    }))
}

/// `DELETE /api/v1/me` — forget this user entirely.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] when the token is rejected, [`ApiError::Internal`] for
/// database failures.
pub async fn delete_me(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SyncSettings>, ApiError> {
    let credentials = Credentials::from_headers(&headers)?;
    let caller = authenticate(&state, credentials).await?;
    nodus_store::users::delete_account(&state.pool, caller.user.id).await?;
    evict_identity(&state, &caller.credentials).await;
    tracing::info!(user = %caller.user.acct, "user deleted");
    Ok(Json(SyncSettings {
        sync_enabled: false,
        telemetry_opt_in: false,
    }))
}

async fn stop_sync(
    state: &AppState,
    credentials: Credentials,
    telemetry_opt_in: bool,
) -> Result<Json<SyncSettings>, ApiError> {
    let caller = authenticate(state, credentials).await?;
    nodus_store::users::revoke_sync(&state.pool, caller.user.id, !telemetry_opt_in).await?;
    evict_identity(state, &caller.credentials).await;
    tracing::info!(user = %caller.user.acct, "background sync disabled");
    Ok(Json(SyncSettings {
        sync_enabled: false,
        telemetry_opt_in: telemetry_opt_in && caller.user.telemetry_opt_in,
    }))
}

async fn evict_identity(state: &AppState, credentials: &Credentials) {
    let key = verification_fingerprint(&credentials.instance_host, credentials.token.expose());
    state.identities.forget(&key).await;
}

/// What the client needs in order to send the user to their instance.
#[derive(Debug, serde::Serialize)]
pub struct SyncAuthorization {
    /// The instance's authorize URL for our own application.
    pub url: String,
}

/// The query string the instance sends back.
#[derive(Debug, serde::Deserialize)]
pub struct CallbackParams {
    /// The authorization code.
    pub code: String,
    /// The `state` we minted when the user started.
    pub state: String,
}

/// How long a started authorization may take to come back.
const STATE_TTL_MINUTES: i32 = 10;

/// The only scope background sync needs: it reads, it never writes.
const SYNC_SCOPE: &str = "read";

/// `POST /api/v1/sync/authorize` — start authorizing Nodus itself on the caller's
/// instance.
///
/// Background sync does not borrow the web client's token (D37). The client asks here,
/// the user approves on their instance, and the token that arrives at the callback is
/// scoped to what the service actually does: read.
///
/// # Errors
///
/// [`ApiError::Unauthorized`] when the caller's own token is rejected,
/// [`ApiError::Unavailable`] when the instance cannot be reached or refuses to register
/// the application, [`ApiError::Internal`] for database or sealing failures.
pub async fn start_sync_authorization(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<SyncAuthorization>, ApiError> {
    let credentials = Credentials::from_headers(&headers)?;
    let caller = authenticate(&state, credentials).await?;
    let host = caller.user.instance_host.clone();
    let app = app_for(&state, &host).await?;
    let minted = uuid::Uuid::new_v4().simple().to_string();
    nodus_store::sync_auth::start(
        &state.pool,
        &minted,
        &caller.user.id,
        &host,
        STATE_TTL_MINUTES,
    )
    .await?;
    let url = format!(
        "https://{host}/oauth/authorize?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}",
        encode_component(&app.client_id),
        encode_component(&app.redirect_uri),
        encode_component(SYNC_SCOPE),
        encode_component(&minted),
    );
    tracing::info!(user = %caller.user.acct, "background sync authorization started");
    Ok(Json(SyncAuthorization { url }))
}

/// `GET /api/v1/sync/callback` — the instance's answer, turned into a stored token.
///
/// Public by necessity: the redirect carries no bearer token, so the `state` is the
/// credential. It is single-use and expires (see `nodus_store::sync_auth::take`), and
/// it only ever names a user — the session is not created here, it is *continued*.
///
/// # Errors
///
/// [`ApiError::BadRequest`] with `unknown_state` for a `state` we did not mint or one
/// that expired, [`ApiError::Unavailable`] when the exchange fails, [`ApiError::Internal`]
/// for database or sealing failures.
pub async fn sync_callback(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<CallbackParams>,
) -> Result<axum::response::Redirect, ApiError> {
    let Some((user_id, host)) = nodus_store::sync_auth::take(&state.pool, &params.state).await?
    else {
        return Err(ApiError::bad_request(
            "unknown_state",
            "This authorization link has expired or was already used. Start it again from settings.",
        ));
    };
    let sealer = state
        .config
        .token_enc_key
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("sync_disabled", 3600))?;
    let app = app_for(&state, &host).await?;
    let client_secret = sealer.open(&app.client_secret).map_err(|error| {
        tracing::error!(error = %error, "opening the application secret failed");
        ApiError::Internal(crate::error::anyhow_detail::Detail(error.to_string()))
    })?;
    let token = exchange_code(&host, &app, &client_secret, &params.code).await?;
    let encrypted = sealer.seal(&token).map_err(|error| {
        tracing::error!(error = %error, "sealing a token failed");
        ApiError::Internal(crate::error::anyhow_detail::Detail(error.to_string()))
    })?;
    let scopes = vec![SYNC_SCOPE.to_owned()];
    let stored = nodus_store::users::set_sync_token(
        &state.pool,
        user_id,
        &encrypted,
        &scopes,
        &fingerprint(&token),
    )
    .await?;
    if !stored {
        return Err(ApiError::NotFound);
    }
    nodus_store::jobs::enqueue(&state.pool, &nodus_store::jobs::NewJob::sync_user(&user_id))
        .await?;
    tracing::info!(%host, "background sync authorized");
    let origin = state
        .config
        .web_origins
        .first()
        .cloned()
        .unwrap_or_else(|| state.config.public_base_url.clone());
    Ok(axum::response::Redirect::to(&format!(
        "{origin}/settings?sync=authorized"
    )))
}

/// The application for `host`, registering one when there is none.
///
/// Registration is per instance and cached forever: the secret is not rotatable from
/// our side, so re-registering on every click would leak applications the user never
/// approved.
async fn app_for(
    state: &AppState,
    host: &str,
) -> Result<nodus_store::sync_auth::InstanceApp, ApiError> {
    if let Some(app) = nodus_store::sync_auth::app(&state.pool, host).await? {
        return Ok(app);
    }
    let sealer = state
        .config
        .token_enc_key
        .as_ref()
        .ok_or_else(|| ApiError::unavailable("sync_disabled", 3600))?;
    let redirect_uri = format!("{}/api/v1/sync/callback", state.config.public_base_url);
    let registered = register_app(host, &redirect_uri).await?;
    let sealed_secret = sealer.seal(&registered.client_secret).map_err(|error| {
        tracing::error!(error = %error, "sealing the application secret failed");
        ApiError::Internal(crate::error::anyhow_detail::Detail(error.to_string()))
    })?;
    nodus_store::sync_auth::put_app(
        &state.pool,
        host,
        &registered.client_id,
        &sealed_secret,
        &redirect_uri,
    )
    .await?;
    Ok(nodus_store::sync_auth::InstanceApp {
        client_id: registered.client_id,
        client_secret: sealed_secret,
        redirect_uri,
    })
}

/// What `POST /api/v1/apps` answers.
#[derive(Debug, serde::Deserialize)]
struct RegisteredApp {
    client_id: String,
    client_secret: String,
}

/// What `POST /oauth/token` answers.
#[derive(Debug, serde::Deserialize)]
struct IssuedToken {
    access_token: String,
}

/// Registers Nodus as an application on `host`.
async fn register_app(host: &str, redirect_uri: &str) -> Result<RegisteredApp, ApiError> {
    let form = [
        ("client_name", "Nodus".to_owned()),
        ("redirect_uris", redirect_uri.to_owned()),
        ("scopes", SYNC_SCOPE.to_owned()),
        ("website", "https://github.com/nodus-social".to_owned()),
    ];
    let response = reqwest::Client::new()
        .post(format!("https://{host}/api/v1/apps"))
        .header(reqwest::header::CONTENT_TYPE, FORM_CONTENT_TYPE)
        .body(urlencode(&form))
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%host, %error, "registering the application failed");
            ApiError::unavailable("instance_unreachable", 60)
        })?;
    if !response.status().is_success() {
        tracing::warn!(%host, status = %response.status(), "the instance refused the application");
        return Err(ApiError::unavailable("instance_refused_app", 3600));
    }
    response.json::<RegisteredApp>().await.map_err(|error| {
        tracing::warn!(%host, %error, "the application answer did not parse");
        ApiError::unavailable("instance_bad_response", 60)
    })
}

/// Exchanges an authorization code for the token background sync will use.
async fn exchange_code(
    host: &str,
    app: &nodus_store::sync_auth::InstanceApp,
    client_secret: &str,
    code: &str,
) -> Result<String, ApiError> {
    let form = [
        ("grant_type", "authorization_code".to_owned()),
        ("code", code.to_owned()),
        ("client_id", app.client_id.clone()),
        ("client_secret", client_secret.to_owned()),
        ("redirect_uri", app.redirect_uri.clone()),
        ("scope", SYNC_SCOPE.to_owned()),
    ];
    let response = reqwest::Client::new()
        .post(format!("https://{host}/oauth/token"))
        .header(reqwest::header::CONTENT_TYPE, FORM_CONTENT_TYPE)
        .body(urlencode(&form))
        .send()
        .await
        .map_err(|error| {
            tracing::warn!(%host, %error, "exchanging the code failed");
            ApiError::unavailable("instance_unreachable", 60)
        })?;
    if !response.status().is_success() {
        tracing::warn!(%host, status = %response.status(), "the token exchange was refused");
        return Err(ApiError::bad_request(
            "code_rejected",
            "The instance refused the authorization code.",
        ));
    }
    response
        .json::<IssuedToken>()
        .await
        .map(|issued| issued.access_token)
        .map_err(|error| {
            tracing::warn!(%host, %error, "the token answer did not parse");
            ApiError::unavailable("instance_bad_response", 60)
        })
}

/// The content type of every form this file sends.
const FORM_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

/// Joins a form into a request body.
fn urlencode(form: &[(&str, String)]) -> String {
    form.iter()
        .map(|(key, value)| format!("{}={}", encode_component(key), encode_component(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Percent-encodes one query-string component.
///
/// Hand-written because this file needs exactly one encoding rule (RFC 3986 unreserved
/// characters pass through, everything else is `%XX`) and a URL library for one
/// function would be a dependency the rest of the service does not use.
fn encode_component(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(byte));
            }
            other => {
                const HEX: &[u8; 16] = b"0123456789ABCDEF";
                out.push('%');
                out.push(char::from(HEX[usize::from(other >> 4)]));
                out.push(char::from(HEX[usize::from(other & 0x0f)]));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::state::Identity;
    use axum::http::{HeaderValue, header};
    use nodus_store::models::NewAccount;
    use nodus_store::{accounts, jobs, users};
    use sqlx::PgPool;
    use std::sync::Arc;
    use std::time::Duration;
    use uuid::Uuid;

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
            connect_timeout: Duration::from_secs(5),
            token_enc_key: None,
        }
    }

    async fn seed_derived_rows(pool: &PgPool, user_id: Uuid, peer_id: Uuid, host: &str) {
        accounts::upsert_many(
            pool,
            &[NewAccount {
                instance_host: host.to_owned(),
                mastodon_id: 500,
                remote_id: None,
                acct: "candidate".to_owned(),
                display_name: None,
                followers_count: 10,
                bot: false,
                locked: false,
                discoverable: None,
                indexable: None,
                noindex: None,
            }],
        )
        .await
        .expect("seed candidate account");
        let candidate_id = accounts::find_id(pool, host, 500)
            .await
            .expect("find candidate")
            .expect("candidate exists");

        sqlx::query(
            "INSERT INTO account_affinity (user_id, account_id, affinity, support) \
             VALUES ($1, $2, 0.9, 1)",
        )
        .bind(user_id)
        .bind(candidate_id)
        .execute(pool)
        .await
        .expect("seed affinity");

        sqlx::query(
            "INSERT INTO user_similarity \
                 (user_id, other_user_id, similarity, co_follow, co_fav, co_reply, reciprocity) \
             VALUES ($1, $2, 0.5, 0.5, 0.0, 0.0, 0.0), \
                    ($2, $1, 0.5, 0.5, 0.0, 0.0, 0.0)",
        )
        .bind(user_id)
        .bind(peer_id)
        .execute(pool)
        .await
        .expect("seed user_similarity");

        sqlx::query(
            "INSERT INTO reference_similarity (user_id, account_id, similarity, co_follow, coverage) \
             VALUES ($1, $2, 0.6, 0.6, 0.9)",
        )
        .bind(user_id)
        .bind(candidate_id)
        .execute(pool)
        .await
        .expect("seed reference_similarity");

        let item_id: i64 = sqlx::query_scalar(
            "INSERT INTO recommendation_item \
                 (user_id, account_id, kind, score, reason, model_version) \
             VALUES ($1, $2, 'account', 0.9, '{}'::jsonb, 0) RETURNING id",
        )
        .bind(user_id)
        .bind(candidate_id)
        .fetch_one(pool)
        .await
        .expect("seed item");

        sqlx::query(
            "INSERT INTO interaction_event \
                 (user_id, item_id, kind, client_ts, idempotency_key) \
             VALUES ($1, $2, 'click', now(), $3)",
        )
        .bind(user_id)
        .bind(item_id)
        .bind(vec![1_u8; 32])
        .execute(pool)
        .await
        .expect("seed interaction_event");

        jobs::enqueue(pool, &jobs::NewJob::sync_user(&user_id))
            .await
            .expect("enqueue job");
    }

    async fn seed_user_with_derived_state(
        pool: &PgPool,
        host: &str,
        mastodon_id: i64,
        acct: &str,
        token: &str,
    ) -> (AppState, HeaderMap, Uuid, [u8; 32]) {
        users::ensure_instance(pool, host).await.expect("instance");
        let user = users::upsert(pool, host, mastodon_id, acct)
            .await
            .expect("user");
        let peer = users::upsert(pool, host, mastodon_id + 1, "peer")
            .await
            .expect("peer");
        users::set_sync_token(
            pool,
            user.id,
            b"sealed-token",
            &["read".to_owned()],
            &fingerprint(token),
        )
        .await
        .expect("set_sync_token");
        users::set_telemetry_opt_in(pool, user.id, true)
            .await
            .expect("opt in");

        seed_derived_rows(pool, user.id, peer.id, host).await;

        let state = AppState::new(
            pool.clone(),
            test_config(),
            Arc::new(nodus_cache::InMemoryCache::new()),
        );
        let key = verification_fingerprint(host, token);
        state
            .identities
            .insert(
                key,
                Identity {
                    instance_host: host.to_owned(),
                    mastodon_account_id: mastodon_id,
                    acct: acct.to_owned(),
                },
            )
            .await;

        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {token}")).expect("auth header"),
        );
        headers.insert(
            axum::http::HeaderName::from_static("x-instance-host"),
            HeaderValue::from_str(host).expect("host header"),
        );

        (state, headers, user.id, key)
    }

    async fn assert_user_derived_data_purged(
        pool: &PgPool,
        state: &AppState,
        user_id: Uuid,
        identity_key: &[u8; 32],
    ) {
        let affinity: i64 =
            sqlx::query_scalar("SELECT count(*) FROM account_affinity WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(pool)
                .await
                .expect("count affinity");
        assert_eq!(affinity, 0);

        let user_sim: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM user_similarity WHERE user_id = $1 OR other_user_id = $1",
        )
        .bind(user_id)
        .fetch_one(pool)
        .await
        .expect("count user_similarity");
        assert_eq!(user_sim, 0);

        let ref_sim: i64 =
            sqlx::query_scalar("SELECT count(*) FROM reference_similarity WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(pool)
                .await
                .expect("count reference_similarity");
        assert_eq!(ref_sim, 0);

        let events: i64 =
            sqlx::query_scalar("SELECT count(*) FROM interaction_event WHERE user_id = $1")
                .bind(user_id)
                .fetch_one(pool)
                .await
                .expect("count interaction_event");
        assert_eq!(events, 0);

        let pending_jobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM job \
             WHERE subject_kind = 'user' AND subject_id = $1 AND status = 'pending'",
        )
        .bind(user_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count pending jobs");
        assert_eq!(pending_jobs, 0);

        let cancelled_jobs: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM job \
             WHERE subject_kind = 'user' AND subject_id = $1 AND status = 'cancelled'",
        )
        .bind(user_id.to_string())
        .fetch_one(pool)
        .await
        .expect("count cancelled jobs");
        assert_eq!(cancelled_jobs, 1);

        assert!(
            state.identities.get(identity_key).await.is_none(),
            "cached identity must be evicted"
        );
    }

    #[sqlx::test(migrations = "../store/migrations")]
    async fn delete_me_purges_derived_tables_cancels_jobs_and_evicts_identity(pool: PgPool) {
        let (state, headers, user_id, key) =
            seed_user_with_derived_state(&pool, "home.example", 10, "me", "tok-delete-me").await;

        let Json(resp) = delete_me(State(state.clone()), headers)
            .await
            .expect("delete_me succeeds");
        assert!(!resp.sync_enabled);
        assert!(!resp.telemetry_opt_in);

        let deleted_at: Option<time::OffsetDateTime> =
            sqlx::query_scalar("SELECT deleted_at FROM app_user WHERE id = $1")
                .bind(user_id)
                .fetch_one(&pool)
                .await
                .expect("read deleted_at");
        assert!(deleted_at.is_some());

        assert_user_derived_data_purged(&pool, &state, user_id, &key).await;
    }

    #[sqlx::test(migrations = "../store/migrations")]
    async fn delete_sync_token_purges_derived_tables_cancels_jobs_and_evicts_identity(
        pool: PgPool,
    ) {
        let (state, headers, user_id, key) =
            seed_user_with_derived_state(&pool, "home.example", 20, "me2", "tok-stop-sync").await;

        let Json(resp) = delete_sync_token(State(state.clone()), headers)
            .await
            .expect("delete_sync_token succeeds");
        assert!(!resp.sync_enabled);
        assert!(!resp.telemetry_opt_in);

        let (deleted_at, sync_enabled, telemetry_opt_in): (
            Option<time::OffsetDateTime>,
            bool,
            bool,
        ) = sqlx::query_as(
            "SELECT deleted_at, sync_enabled, telemetry_opt_in FROM app_user WHERE id = $1",
        )
        .bind(user_id)
        .fetch_one(&pool)
        .await
        .expect("read app_user");
        assert!(deleted_at.is_none());
        assert!(!sync_enabled);
        assert!(!telemetry_opt_in);

        assert_user_derived_data_purged(&pool, &state, user_id, &key).await;
    }
}
