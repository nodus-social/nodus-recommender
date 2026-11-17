//! Integration tests for [`nodus_store::profiles`].

use nodus_store::models::NewAccount;
use nodus_store::{accounts, profiles, users};
use sqlx::PgPool;

fn new_account(host: &str, remote_id: i64, acct: &str) -> NewAccount {
    NewAccount {
        instance_host: host.to_owned(),
        remote_id: remote_id.to_string(),
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

#[sqlx::test(migrations = "./migrations")]
async fn needing_graph_decodes_citext_instance_host(pool: PgPool) {
    users::ensure_instance(&pool, "home.test").await.unwrap();
    users::ensure_instance(&pool, "remote.test").await.unwrap();
    users::upsert(&pool, "home.test", "1", "me").await.unwrap();

    accounts::upsert_many(
        &pool,
        &[
            new_account("home.test", 1, "me"),
            new_account("remote.test", 42, "alice@remote.test"),
        ],
    )
    .await
    .unwrap();

    let me = accounts::find_id(&pool, "home.test", "1")
        .await
        .unwrap()
        .expect("own account exists");
    let alice = accounts::find_id(&pool, "remote.test", "42")
        .await
        .unwrap()
        .expect("followed account exists");

    accounts::replace_follows(&pool, me, &[alice], "server_sync")
        .await
        .unwrap();

    let targets = profiles::needing_graph(&pool, 10)
        .await
        .expect("needing_graph must decode citext instance_host");
    assert_eq!(targets.len(), 1);
    assert_eq!(targets[0].id, alice);
    assert_eq!(targets[0].instance_host, "remote.test");
    assert_eq!(targets[0].remote_id, "42");
}
