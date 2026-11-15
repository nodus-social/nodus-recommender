//! Integration tests for `refresh_profile`.
//!
//! Covers both local-instance crawls (using a pooled token) and remote-origin
//! crawls (resolving the origin ID via `account_lookup`, creating missing
//! `instance` rows, upserting followers/following under the origin host, and
//! resolving edge IDs against the origin host).

use std::sync::Arc;

use nodus_calculator::handlers::{Handler, JobError, RefreshProfile, SyncConfig};
use nodus_store::crypto::TokenSealer;
use nodus_store::models::{Job, NewAccount};
use nodus_store::profiles::{self, EdgeKind};
use nodus_store::{accounts, jobs, users};
use sqlx::PgPool;
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

const KEY_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

fn sealer() -> Arc<TokenSealer> {
    Arc::new(TokenSealer::from_base64(KEY_B64).expect("valid test key"))
}

fn account_json(id: i64, acct: &str, followers: u32) -> serde_json::Value {
    serde_json::json!({
        "id": id.to_string(),
        "acct": acct,
        "display_name": format!("Person {id}"),
        "note": "",
        "avatar": "",
        "header": "",
        "bot": false,
        "locked": false,
        "followers_count": followers,
        "following_count": 1,
        "statuses_count": 3,
        "last_status_at": null,
    })
}

fn new_account(host: &str, mastodon_id: i64, remote_id: Option<&str>, acct: &str) -> NewAccount {
    NewAccount {
        instance_host: host.to_owned(),
        mastodon_id,
        remote_id: remote_id.map(str::to_owned),
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

async fn enqueue_and_claim(pool: &PgPool, account_id: i64) -> Job {
    let job = jobs::NewJob::pending(
        "refresh_profile",
        1,
        "account",
        Some(account_id.to_string()),
    );
    jobs::enqueue(pool, &job).await.expect("enqueue");
    let mut claimed = jobs::claim(pool, "test-worker", 1).await.expect("claim");
    assert_eq!(claimed.len(), 1);
    claimed.pop().expect("claimed job")
}

#[sqlx::test(migrations = "../store/migrations")]
async fn local_account_crawl_decodes_citext_and_records_edges(pool: PgPool) {
    let home = MockServer::start().await;
    let home_host = home.uri().trim_start_matches("http://").to_owned();

    let sealer = sealer();
    let envelope = sealer.seal("pool-token").expect("sealing works");
    users::ensure_instance(&pool, &home_host)
        .await
        .expect("instance");
    let user = users::upsert(&pool, &home_host, 1, "me")
        .await
        .expect("user");
    users::set_sync_token(
        &pool,
        user.id,
        &envelope,
        &["read:follows".to_owned()],
        &nodus_store::crypto::fingerprint("pool-token"),
    )
    .await
    .expect("token stored");

    accounts::upsert_many(&pool, &[new_account(&home_host, 42, None, "alice")])
        .await
        .expect("alice account");
    let alice_id = accounts::find_id(&pool, &home_host, 42)
        .await
        .expect("lookup")
        .expect("alice exists");

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/following"))
        .and(header("authorization", "Bearer pool-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([account_json(101, "bob", 50)])),
        )
        .mount(&home)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/followers"))
        .and(header("authorization", "Bearer pool-token"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([account_json(102, "carol", 20)])),
        )
        .mount(&home)
        .await;

    let handler = RefreshProfile::new(
        pool.clone(),
        SyncConfig::new(sealer, 1_000.0).with_scheme("http"),
    );
    let job = enqueue_and_claim(&pool, alice_id).await;
    handler
        .run(&job)
        .await
        .expect("local profile crawl succeeds");

    let bob_id = accounts::find_id(&pool, &home_host, 101)
        .await
        .expect("lookup")
        .expect("bob upserted");
    let carol_id = accounts::find_id(&pool, &home_host, 102)
        .await
        .expect("lookup")
        .expect("carol upserted");
    assert_ne!(carol_id, 0);

    let edges = profiles::targets(&pool, alice_id, EdgeKind::Follow)
        .await
        .expect("targets");
    assert_eq!(edges, vec![bob_id]);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn remote_account_resolves_origin_id_creates_instance_and_maps_origin_edges(pool: PgPool) {
    let origin = MockServer::start().await;
    let origin_host = origin.uri().trim_start_matches("http://").to_owned();
    let home_host = "home.test";

    // Only `home.test` exists in `instance`; `origin_host` does NOT exist yet.
    users::ensure_instance(&pool, home_host)
        .await
        .expect("home instance");

    // Seed target on home.test with shadow mastodon_id = 999 and remote_id = None,
    // plus a decoy account on home.test sharing mastodon_id = 201 with an origin followee.
    let remote_acct = format!("alice@{origin_host}");
    accounts::upsert_many(
        &pool,
        &[
            new_account(home_host, 999, None, &remote_acct),
            new_account(home_host, 201, None, "decoy"),
        ],
    )
    .await
    .expect("seed accounts");
    let alice_id = accounts::find_id(&pool, home_host, 999)
        .await
        .expect("lookup")
        .expect("alice exists");
    let decoy_id = accounts::find_id(&pool, home_host, 201)
        .await
        .expect("lookup")
        .expect("decoy exists");

    // Origin knows alice as id 42, NOT 999.
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/lookup"))
        .and(query_param("acct", "alice"))
        .respond_with(ResponseTemplate::new(200).set_body_json(account_json(42, "alice", 100)))
        .mount(&origin)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/following"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([
            account_json(201, "bob", 50),
            account_json(202, "carol@third.test", 75),
        ])))
        .mount(&origin)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/followers"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([account_json(301, "dave", 15)])),
        )
        .mount(&origin)
        .await;
    // Guardrail: the home shadow id must never be queried on origin.
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/999/following"))
        .respond_with(ResponseTemplate::new(404))
        .expect(0)
        .mount(&origin)
        .await;

    let handler = RefreshProfile::new(
        pool.clone(),
        SyncConfig::new(sealer(), 1_000.0).with_scheme("http"),
    );
    let job = enqueue_and_claim(&pool, alice_id).await;
    handler
        .run(&job)
        .await
        .expect("remote profile crawl succeeds");

    // 1. remote_id was learned and persisted.
    let stored = accounts::get(&pool, alice_id)
        .await
        .expect("get")
        .expect("alice");
    assert_eq!(stored.remote_id.as_deref(), Some("42"));

    // 2. Origin instance row was ensured, and crawled followees/followers live under origin_host.
    let bob_id = accounts::find_id(&pool, &origin_host, 201)
        .await
        .expect("lookup")
        .expect("bob upserted under origin_host");
    let carol_id = accounts::find_id(&pool, &origin_host, 202)
        .await
        .expect("lookup")
        .expect("carol upserted under origin_host");
    let dave_id = accounts::find_id(&pool, &origin_host, 301)
        .await
        .expect("lookup")
        .expect("dave (follower) upserted under origin_host");
    assert_ne!(bob_id, decoy_id);
    assert_ne!(dave_id, 0);
    assert!(
        accounts::find_id(&pool, home_host, 301)
            .await
            .expect("lookup")
            .is_none(),
        "origin followers must not be filed under target.instance_host"
    );

    // 3. Follow edges resolve to origin_host accounts, never the home decoy.
    let edges = profiles::targets(&pool, alice_id, EdgeKind::Follow)
        .await
        .expect("targets");
    let mut expected = vec![bob_id, carol_id];
    expected.sort_unstable();
    assert_eq!(edges, expected);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn remote_account_with_cached_remote_id_skips_lookup(pool: PgPool) {
    let origin = MockServer::start().await;
    let origin_host = origin.uri().trim_start_matches("http://").to_owned();
    let home_host = "home.test";
    users::ensure_instance(&pool, home_host)
        .await
        .expect("home instance");

    let remote_acct = format!("alice@{origin_host}");
    accounts::upsert_many(
        &pool,
        &[new_account(home_host, 999, Some("42"), &remote_acct)],
    )
    .await
    .expect("seed account");
    let alice_id = accounts::find_id(&pool, home_host, 999)
        .await
        .expect("lookup")
        .expect("alice exists");

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/lookup"))
        .respond_with(ResponseTemplate::new(500))
        .expect(0)
        .mount(&origin)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/following"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(serde_json::json!([account_json(201, "bob", 50)])),
        )
        .mount(&origin)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/42/followers"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .mount(&origin)
        .await;

    let handler = RefreshProfile::new(
        pool.clone(),
        SyncConfig::new(sealer(), 1_000.0).with_scheme("http"),
    );
    let job = enqueue_and_claim(&pool, alice_id).await;
    handler
        .run(&job)
        .await
        .expect("cached remote_id crawl succeeds");

    let bob_id = accounts::find_id(&pool, &origin_host, 201)
        .await
        .expect("lookup")
        .expect("bob upserted");
    let edges = profiles::targets(&pool, alice_id, EdgeKind::Follow)
        .await
        .expect("targets");
    assert_eq!(edges, vec![bob_id]);
}

#[sqlx::test(migrations = "../store/migrations")]
async fn missing_remote_lookup_never_falls_back_to_local_shadow_id(pool: PgPool) {
    let origin = MockServer::start().await;
    let origin_host = origin.uri().trim_start_matches("http://").to_owned();
    let home_host = "home.test";
    users::ensure_instance(&pool, home_host)
        .await
        .expect("home instance");

    let remote_acct = format!("ghost@{origin_host}");
    accounts::upsert_many(&pool, &[new_account(home_host, 999, None, &remote_acct)])
        .await
        .expect("seed account");
    let ghost_id = accounts::find_id(&pool, home_host, 999)
        .await
        .expect("lookup")
        .expect("ghost exists");

    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/lookup"))
        .and(query_param("acct", "ghost"))
        .respond_with(ResponseTemplate::new(404).set_body_json(serde_json::json!({
            "error": "Record not found"
        })))
        .mount(&origin)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/accounts/999/following"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!([])))
        .expect(0)
        .mount(&origin)
        .await;

    let handler = RefreshProfile::new(
        pool.clone(),
        SyncConfig::new(sealer(), 1_000.0).with_scheme("http"),
    );
    let job = enqueue_and_claim(&pool, ghost_id).await;
    let error = handler
        .run(&job)
        .await
        .expect_err("404 lookup must fail without falling back to shadow id");
    assert!(
        matches!(error, JobError::Permanent(_)),
        "expected permanent failure on 404 lookup, got {error:?}"
    );
}
