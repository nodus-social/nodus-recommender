//! Regression tests proving that `RefreshProfile`, `RefreshPublic`, and
//! `RefreshAccount` share the per-host [`Budget`], honor `request_interval` /
//! `budget_fraction`, record 429 cooldown holds, and apply `post_retention_days`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use nodus_cache::{Budget, InMemoryBudget};
use nodus_calculator::handlers::{
    Handler, JobError, RefreshAccount, RefreshConfig, RefreshProfile, RefreshPublic, SyncConfig,
};
use nodus_store::crypto::{TokenSealer, fingerprint};
use nodus_store::models::{Job, NewAccount};
use nodus_store::{accounts, jobs, users};
use sqlx::PgPool;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn sealer() -> Arc<TokenSealer> {
    Arc::new(TokenSealer::from_base64(KEY_B64).expect("valid test key"))
}

fn bucket_hex(token: &str) -> String {
    let mut hex = String::with_capacity(64);
    for byte in fingerprint(token) {
        use std::fmt::Write as _;
        write!(hex, "{byte:02x}").ok();
    }
    hex
}

fn account_json(id: i64, acct: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id.to_string(),
        "acct": acct,
        "display_name": format!("Person {id}"),
        "note": "",
        "avatar": "",
        "header": "",
        "bot": false,
        "locked": false,
        "followers_count": 10,
        "following_count": 1,
        "statuses_count": 1,
        "last_status_at": null,
    })
}

fn status_json(id: &str, author_id: i64, author_acct: &str, host: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "created_at": "2026-11-10T12:00:00.000Z",
        "content": format!("<p>post {id}</p>"),
        "visibility": "public",
        "account": account_json(author_id, author_acct),
        "favourites_count": 1,
        "reblogs_count": 0,
        "replies_count": 0,
        "favourited": false,
        "reblogged": false,
        "bookmarked": false,
        "url": format!("https://{host}/@{author_acct}/{id}"),
        "sensitive": false,
        "spoiler_text": "",
        "media_attachments": [],
        "mentions": [],
        "tags": [],
        "emojis": []
    })
}

fn new_account(host: &str, mastodon_id: i64, acct: &str) -> NewAccount {
    NewAccount {
        instance_host: host.to_owned(),
        mastodon_id,
        remote_id: None,
        acct: acct.to_owned(),
        display_name: None,
        followers_count: 10,
        bot: false,
        locked: false,
        discoverable: None,
        indexable: None,
        noindex: None,
    }
}

async fn seed_token(pool: &PgPool, sealer: &TokenSealer, host: &str, raw_token: &str) {
    let envelope = sealer.seal(raw_token).expect("seal token");
    users::ensure_instance(pool, host).await.expect("instance");
    let user = users::upsert(pool, host, 1, "seeder")
        .await
        .expect("seeder user");
    users::set_sync_token(
        pool,
        user.id,
        &envelope,
        &["read:follows".to_owned(), "read:statuses".to_owned()],
        &fingerprint(raw_token),
    )
    .await
    .expect("store token");
}

async fn enqueue_and_claim(pool: &PgPool, kind: &str, subject_kind: &str, subject_id: &str) -> Job {
    let job = jobs::NewJob::pending(kind, 1, subject_kind, Some(subject_id.to_owned()));
    jobs::enqueue(pool, &job).await.expect("enqueue");
    let mut claimed = jobs::claim(pool, "test-worker", 1).await.expect("claim");
    assert_eq!(claimed.len(), 1);
    claimed.pop().expect("claimed job")
}

#[sqlx::test(migrations = "../store/migrations")]
async fn refresh_profile_enforces_budget_pacing_and_429_holds(pool: PgPool) {
    let server = MockServer::start().await;
    let host = server.uri().trim_start_matches("http://").to_owned();
    let sealer = sealer();
    seed_token(&pool, &sealer, &host, "profile-token").await;
    accounts::upsert_many(&pool, &[new_account(&host, 42, "alice")])
        .await
        .expect("alice");
    let alice_id = accounts::find_id(&pool, &host, 42)
        .await
        .expect("lookup")
        .expect("alice id");

    // 1) Exhausted budget prevents any outbound request.
    let zero_budget: Arc<dyn Budget> = Arc::new(InMemoryBudget::with_rate(0.0, 0));
    let blocked = RefreshProfile::new(
        pool.clone(),
        SyncConfig::new(sealer.clone(), 100.0)
            .with_scheme("http")
            .with_budget(zero_budget),
    );
    let job = enqueue_and_claim(&pool, "refresh_profile", "account", &alice_id.to_string()).await;
    let err = blocked
        .run(&job)
        .await
        .expect_err("exhausted budget must reschedule");
    assert!(matches!(err, JobError::Retry { .. }));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty(),
        "no HTTP request may be sent when budget refuses"
    );
    jobs::complete(&pool, job.id).await.expect("complete job");

    // 2) Active budget paces `following` and `followers` by `request_interval`.
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/following"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([account_json(101, "bob")])),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/followers"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([account_json(102, "carol")])),
        )
        .mount(&server)
        .await;

    // effective_rps = 25.0 * 0.5 = 12.5 => 80ms interval between requests.
    let paced_budget: Arc<dyn Budget> = Arc::new(InMemoryBudget::with_rate(100.0, 5));
    let paced = RefreshProfile::new(
        pool.clone(),
        SyncConfig::new(sealer.clone(), 25.0)
            .with_budget_fraction(0.5)
            .with_scheme("http")
            .with_budget(paced_budget),
    );
    let started = Instant::now();
    let job = enqueue_and_claim(&pool, "refresh_profile", "account", &alice_id.to_string()).await;
    paced.run(&job).await.expect("paced profile crawl succeeds");
    assert!(
        started.elapsed() >= Duration::from_millis(70),
        "expected request_interval delay between following and followers, took {:?}",
        started.elapsed()
    );
    jobs::complete(&pool, job.id).await.expect("complete job");

    // 3) 429 records a host-wide hold in the shared budget.
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/following"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "20"))
        .mount(&server)
        .await;

    let hold_budget: Arc<dyn Budget> = Arc::new(InMemoryBudget::with_rate(100.0, 5));
    let holder = RefreshProfile::new(
        pool.clone(),
        SyncConfig::new(sealer, 100.0)
            .with_scheme("http")
            .with_budget(hold_budget.clone()),
    );
    let job = enqueue_and_claim(&pool, "refresh_profile", "account", &alice_id.to_string()).await;
    let err = holder.run(&job).await.expect_err("429 retries");
    assert!(matches!(err, JobError::Retry { .. }));
    assert!(
        !hold_budget
            .acquire(&host, &bucket_hex("profile-token"))
            .await
            .expect("acquire"),
        "429 must park host in shared budget"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn refresh_public_enforces_budget_holds_on_429_and_sets_post_retention_days(pool: PgPool) {
    let server = MockServer::start().await;
    let host = server.uri().trim_start_matches("http://").to_owned();
    let sealer = sealer();
    seed_token(&pool, &sealer, &host, "public-token").await;

    // 1) Exhausted budget blocks outbound federated timeline fetch.
    let zero_budget: Arc<dyn Budget> = Arc::new(InMemoryBudget::with_rate(0.0, 0));
    let blocked = RefreshPublic::new(
        pool.clone(),
        RefreshConfig::new(sealer.clone(), 100.0)
            .with_scheme("http")
            .with_budget(zero_budget),
    );
    let job = enqueue_and_claim(&pool, "refresh_public", "instance", &host).await;
    let err = blocked.run(&job).await.expect_err("zero budget retries");
    assert!(matches!(err, JobError::Retry { .. }));
    assert!(
        server
            .received_requests()
            .await
            .expect("requests")
            .is_empty(),
        "no HTTP request may be sent when budget refuses"
    );
    jobs::complete(&pool, job.id).await.expect("complete job");

    // 2) Valid run applies configured `post_retention_days` (45 days).
    Mock::given(method("GET"))
        .and(path("/api/v1/timelines/public"))
        .and(header("authorization", "Bearer public-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([status_json("900", 77, "dan", &host)])),
        )
        .mount(&server)
        .await;

    let budget: Arc<dyn Budget> = Arc::new(InMemoryBudget::with_rate(100.0, 5));
    let handler = RefreshPublic::new(
        pool.clone(),
        RefreshConfig::new(sealer.clone(), 100.0)
            .with_scheme("http")
            .with_post_retention_days(45)
            .with_budget(budget),
    );
    let job = enqueue_and_claim(&pool, "refresh_public", "instance", &host).await;
    handler.run(&job).await.expect("refresh_public succeeds");
    jobs::complete(&pool, job.id).await.expect("complete job");

    let expiry_days: f64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM (expires_at - fetched_at)) / 86400.0)::float8
         FROM status WHERE instance_host = $1 AND remote_id = '900'",
    )
    .bind(&host)
    .fetch_one(&pool)
    .await
    .expect("read status expiry window");
    assert!((expiry_days - 45.0).abs() < 0.01, "got {expiry_days}");

    // 3) 429 records hold in shared budget.
    server.reset().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/timelines/public"))
        .respond_with(ResponseTemplate::new(429).insert_header("Retry-After", "25"))
        .mount(&server)
        .await;

    let hold_budget: Arc<dyn Budget> = Arc::new(InMemoryBudget::with_rate(100.0, 5));
    let holder = RefreshPublic::new(
        pool.clone(),
        RefreshConfig::new(sealer, 100.0)
            .with_scheme("http")
            .with_budget(hold_budget.clone()),
    );
    let job = enqueue_and_claim(&pool, "refresh_public", "instance", &host).await;
    let err = holder.run(&job).await.expect_err("429 retries");
    assert!(matches!(err, JobError::Retry { .. }));
    assert!(
        !hold_budget
            .acquire(&host, &bucket_hex("public-token"))
            .await
            .expect("acquire"),
        "429 must park host in shared budget"
    );
}

#[sqlx::test(migrations = "../store/migrations")]
async fn refresh_account_shares_budget_across_concurrent_jobs_and_applies_post_days(pool: PgPool) {
    let server = MockServer::start().await;
    let host = server.uri().trim_start_matches("http://").to_owned();
    let sealer = sealer();
    seed_token(&pool, &sealer, &host, "account-token").await;

    accounts::upsert_many(
        &pool,
        &[
            new_account(&host, 10, "author_one"),
            new_account(&host, 11, "author_two"),
        ],
    )
    .await
    .expect("seed authors");
    let first_id = accounts::find_id(&pool, &host, 10)
        .await
        .expect("lookup 1")
        .expect("first id");
    let second_id = accounts::find_id(&pool, &host, 11)
        .await
        .expect("lookup 2")
        .expect("second id");

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/10/statuses"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([status_json(
                "1001",
                10,
                "author_one",
                &host
            )])),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/11/statuses"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(serde_json::json!([status_json(
                "1101",
                11,
                "author_two",
                &host
            )])),
        )
        .mount(&server)
        .await;

    // Exactly 1 request slot total in the shared budget (burst = 1, rate = 0.0).
    let shared_budget: Arc<dyn Budget> = Arc::new(InMemoryBudget::with_rate(0.0, 1));
    let handler_a = RefreshAccount::new(
        pool.clone(),
        RefreshConfig::new(sealer.clone(), 100.0)
            .with_scheme("http")
            .with_post_retention_days(45)
            .with_budget(shared_budget.clone()),
    );
    let handler_b = RefreshAccount::new(
        pool.clone(),
        RefreshConfig::new(sealer, 100.0)
            .with_scheme("http")
            .with_post_retention_days(45)
            .with_budget(shared_budget),
    );

    jobs::enqueue(
        &pool,
        &jobs::NewJob::pending("refresh_account", 2, "account", Some(first_id.to_string())),
    )
    .await
    .expect("enqueue 1");
    jobs::enqueue(
        &pool,
        &jobs::NewJob::pending("refresh_account", 2, "account", Some(second_id.to_string())),
    )
    .await
    .expect("enqueue 2");
    let claimed = jobs::claim(&pool, "worker-concurrent", 2)
        .await
        .expect("claim both");
    assert_eq!(claimed.len(), 2);

    let (res_a, res_b) = tokio::join!(handler_a.run(&claimed[0]), handler_b.run(&claimed[1]));
    let successes = [res_a.is_ok(), res_b.is_ok()]
        .into_iter()
        .filter(|ok| *ok)
        .count();
    let retries = [res_a, res_b]
        .into_iter()
        .filter(|res| matches!(res, Err(JobError::Retry { .. })))
        .count();
    assert_eq!(successes, 1, "only one concurrent worker gets the 1 slot");
    assert_eq!(retries, 1, "second worker must be rescheduled by budget");

    let requests = server.received_requests().await.expect("requests");
    assert_eq!(
        requests.len(),
        1,
        "shared budget must cap total outbound requests across concurrent handlers"
    );

    let expiry_days: f64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM (expires_at - fetched_at)) / 86400.0)::float8
         FROM status WHERE instance_host = $1",
    )
    .bind(&host)
    .fetch_one(&pool)
    .await
    .expect("read expiry window");
    assert!((expiry_days - 45.0).abs() < 0.01, "got {expiry_days}");
}
