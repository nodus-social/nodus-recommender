//! Integration tests for retention policies (`POST_RETENTION_DAYS` and 30-day user purge).

use nodus_store::models::NewAccount;
use nodus_store::retention::{self, RetentionPolicy};
use nodus_store::{accounts, users};
use sqlx::PgPool;

#[sqlx::test(migrations = "./migrations")]
async fn retain_batch_enforces_post_days_on_existing_statuses(pool: PgPool) {
    let host = "posts.example";
    users::ensure_instance(&pool, host).await.expect("instance");
    accounts::upsert_many(
        &pool,
        &[NewAccount {
            instance_host: host.to_owned(),
            remote_id: "1".to_owned(),
            acct: "alice".to_owned(),
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
    .expect("author");
    let author = accounts::find_id(&pool, host, "1")
        .await
        .expect("find")
        .expect("exists");

    // Stale post fetched 10 days ago with an expires_at 4 days in the future (from a 14-day stamp),
    // and a fresh post fetched 2 days ago.
    sqlx::query(
        "INSERT INTO status (instance_host, remote_id, account_id, content, \
             visibility, created_at, fetched_at, expires_at) \
         VALUES \
             ($1, '1', $2, 'stale', 'public', now() - interval '10 days', \
              now() - interval '10 days', now() + interval '4 days'), \
             ($1, '2', $2, 'fresh', 'public', now() - interval '2 days', \
              now() - interval '2 days', now() + interval '12 days')",
    )
    .bind(host)
    .bind(author)
    .execute(&pool)
    .await
    .expect("seed statuses");

    let policy = RetentionPolicy {
        post_days: 7,
        event_days: 90,
    };
    let report = retention::retain_batch(&pool, &policy, 100)
        .await
        .expect("retain_batch");
    assert_eq!(report.statuses, 1);

    let remaining: Vec<String> =
        sqlx::query_scalar("SELECT remote_id FROM status ORDER BY remote_id")
            .fetch_all(&pool)
            .await
            .expect("remaining");
    assert_eq!(remaining, vec!["2"]);
}

#[sqlx::test(migrations = "./migrations")]
async fn retain_batch_hard_deletes_soft_deleted_users_after_30_days(pool: PgPool) {
    let host = "users.example";
    users::ensure_instance(&pool, host).await.expect("instance");
    let old_deleted = users::upsert(&pool, host, "1", "old_deleted")
        .await
        .expect("old deleted");
    let recent_deleted = users::upsert(&pool, host, "2", "recent_deleted")
        .await
        .expect("recent deleted");
    let active = users::upsert(&pool, host, "3", "active")
        .await
        .expect("active");

    sqlx::query("UPDATE app_user SET deleted_at = now() - interval '31 days' WHERE id = $1")
        .bind(old_deleted.id)
        .execute(&pool)
        .await
        .expect("backdate old_deleted");
    sqlx::query("UPDATE app_user SET deleted_at = now() - interval '10 days' WHERE id = $1")
        .bind(recent_deleted.id)
        .execute(&pool)
        .await
        .expect("backdate recent_deleted");

    let report = retention::retain_batch(&pool, &RetentionPolicy::default(), 100)
        .await
        .expect("retain_batch");
    assert_eq!(report.users, 1);

    let remaining: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM app_user ORDER BY instance_account_id")
            .fetch_all(&pool)
            .await
            .expect("remaining users");
    assert_eq!(remaining, vec![recent_deleted.id, active.id]);
}
