//! Integration tests for `statuses::upsert_many` constraint and deduplication behavior.

use nodus_store::statuses::{self, NewStatus};
use nodus_store::{accounts, users};
use sqlx::PgPool;
use time::OffsetDateTime;

fn sample_status(host: &str, account_id: i64, remote_id: &str) -> NewStatus {
    NewStatus {
        instance_host: host.to_owned(),
        remote_id: remote_id.to_owned(),
        account_id,
        content: format!("<p>post {remote_id}</p>"),
        visibility: "public".to_owned(),
        favourites_count: 1,
        reblogs_count: 0,
        replies_count: 0,
        language: None,
        published_at: OffsetDateTime::now_utc(),
        url: Some(format!("https://{host}/notes/{remote_id}")),
        media: Vec::new(),
        sensitive: false,
        spoiler_text: String::new(),
        emojis: Vec::new(),
    }
}

async fn seed_author(pool: &PgPool, host: &str) -> i64 {
    users::ensure_instance(pool, host).await.expect("instance");
    accounts::upsert_many(
        pool,
        &[nodus_store::models::NewAccount {
            instance_host: host.to_owned(),
            remote_id: "1".to_owned(),
            acct: "alice".to_owned(),
            display_name: Some("Alice".to_owned()),
            followers_count: 10,
            bot: false,
            locked: false,
            discoverable: None,
            indexable: None,
            noindex: None,
        }],
    )
    .await
    .expect("upsert author");
    accounts::find_id(pool, host, "1")
        .await
        .expect("find author")
        .expect("author exists")
}

#[sqlx::test(migrations = "./migrations")]
async fn upsert_many_keeps_opaque_instance_ids(pool: PgPool) {
    let host = "nodus.example";
    let author = seed_author(&pool, host).await;

    // ULID-shaped ids, the kind a non-Mastodon origin prints. They used to be hashed
    // into a bigint and only the extra `remote_id` column kept the two apart.
    let first = sample_status(host, author, "01M7GK5K46EA1TNQRY7N0N61YW");
    let second = sample_status(host, author, "01M7GK5K46EA1TNQRY7N0N61YX");

    let written = statuses::upsert_many(&pool, &[first, second])
        .await
        .expect("two opaque ids in one batch must both persist");
    assert_eq!(written, 2);

    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM status WHERE instance_host = $1")
        .bind(host)
        .fetch_one(&pool)
        .await
        .expect("count statuses");
    assert_eq!(count, 2);
}

#[sqlx::test(migrations = "./migrations")]
async fn upsert_many_deduplicates_duplicate_remote_ids_in_same_batch(pool: PgPool) {
    let host = "mastodon.example";
    let author = seed_author(&pool, host).await;

    let mut first = sample_status(host, author, "100");
    first.favourites_count = 1;
    let mut duplicate = sample_status(host, author, "100");
    duplicate.favourites_count = 5;

    let written = statuses::upsert_many(&pool, &[first, duplicate])
        .await
        .expect("duplicate (instance_host, remote_id) in one batch must succeed");
    assert_eq!(written, 1);

    let favs: i32 = sqlx::query_scalar(
        "SELECT favourites_count FROM status WHERE instance_host = $1 AND remote_id = '100'",
    )
    .bind(host)
    .fetch_one(&pool)
    .await
    .expect("read favourites_count");
    assert_eq!(favs, 5);
}

#[sqlx::test(migrations = "./migrations")]
async fn upsert_and_update_for_days_honor_configured_post_retention_days(pool: PgPool) {
    let host = "retention-days.example";
    let author = seed_author(&pool, host).await;
    let status = sample_status(host, author, "200");

    let written = statuses::upsert_many_for_days(&pool, &[status], 45)
        .await
        .expect("upsert with 45-day retention");
    assert_eq!(written, 1);

    let initial_days: f64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM (expires_at - fetched_at)) / 86400.0)::float8
         FROM status WHERE instance_host = $1 AND remote_id = '200'",
    )
    .bind(host)
    .fetch_one(&pool)
    .await
    .expect("read initial expiry window");
    assert!((initial_days - 45.0).abs() < 0.01, "got {initial_days}");

    let mut updated_row = sample_status(host, author, "200");
    updated_row.content = "<p>updated</p>".to_owned();
    updated_row.favourites_count = 3;
    let updated = statuses::update_by_url_for_days(&pool, &updated_row, 7)
        .await
        .expect("update with 7-day retention");
    assert!(updated);

    let updated_days: f64 = sqlx::query_scalar(
        "SELECT (EXTRACT(EPOCH FROM (expires_at - fetched_at)) / 86400.0)::float8
         FROM status WHERE instance_host = $1 AND remote_id = '200'",
    )
    .bind(host)
    .fetch_one(&pool)
    .await
    .expect("read updated expiry window");
    assert!((updated_days - 7.0).abs() < 0.01, "got {updated_days}");
}
