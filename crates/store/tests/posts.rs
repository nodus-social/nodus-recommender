//! Integration tests for the post feed: candidates, snapshot write, cursor read.
//! They run against real Postgres because each rule is a predicate of one query.

use nodus_core::post::POST_MAX_AGE_DAYS;
use nodus_store::accounts;
use nodus_store::feed::posts::{self, NewPostItem};
use nodus_store::users;
use sqlx::PgPool;
use time::Duration;
use uuid::Uuid;

const HOME: &str = "home.test";
const REMOTE: &str = "remote.test";

/// Inserts (or finds) a local account row and returns its id.
async fn account(pool: &PgPool, host: &str, remote_id: i64, acct: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO account (instance_host, remote_id, acct) VALUES ($1, $2, $3) \
         ON CONFLICT (instance_host, remote_id) DO UPDATE SET acct = EXCLUDED.acct RETURNING id",
    )
    .bind(host)
    .bind(remote_id)
    .bind(acct)
    .fetch_one(pool)
    .await
    .expect("upsert the account row")
}

/// One signed-in user with their local account row, plus both instances.
async fn seed_me(pool: &PgPool) -> (Uuid, i64) {
    users::ensure_instance(pool, HOME).await.expect("home");
    users::ensure_instance(pool, REMOTE).await.expect("remote");
    let user = users::upsert(pool, HOME, "1", "me").await.expect("user");
    let me = account(pool, HOME, 1, "me").await;
    (user.id, me)
}

/// A remote author with an affinity row for `user_id`; `expired` backdates it.
async fn candidate_author(
    pool: &PgPool,
    user_id: Uuid,
    remote_id: i64,
    acct: &str,
    weight: f32,
    expired: bool,
) -> i64 {
    let id = account(pool, REMOTE, remote_id, acct).await;
    sqlx::query(
        "INSERT INTO account_affinity (user_id, account_id, affinity, expires_at) \
         VALUES ($1, $2, $3, \
             now() + CASE WHEN $4 THEN interval '-1 hour' ELSE interval '1 day' END)",
    )
    .bind(user_id)
    .bind(id)
    .bind(weight)
    .bind(expired)
    .execute(pool)
    .await
    .expect("insert the account_affinity row");
    id
}

/// Inserts one status and returns its local id.
async fn post(
    pool: &PgPool,
    remote_id: i64,
    account_id: i64,
    visibility: &str,
    age: Duration,
) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "INSERT INTO status (instance_host, remote_id, account_id, content, visibility, created_at) \
         VALUES ($1, $2, $3, 'post ' || $2, $4, now() - ($5 * interval '1 second')) RETURNING id",
    )
    .bind(REMOTE)
    .bind(remote_id)
    .bind(account_id)
    .bind(visibility)
    .bind(age.whole_seconds())
    .fetch_one(pool)
    .await
    .expect("insert the status")
}

/// Records an author dismissal; the event points at an `account` item because
/// `recommendation_item_target_matches_kind` forbids a `post` item from carrying the
/// `account_id` the dismissal filter joins on.
async fn dismiss_author(pool: &PgPool, user_id: Uuid, account_id: i64, key: u8) {
    sqlx::query(
        "WITH new_item AS ( \
             INSERT INTO recommendation_item (user_id, account_id, kind, score, model_version) \
             VALUES ($1, $2, 'account', 0.5, 0) RETURNING id \
         ) \
         INSERT INTO interaction_event (user_id, item_id, kind, client_ts, idempotency_key) \
         SELECT $1, id, 'dismiss', now(), $3 FROM new_item",
    )
    .bind(user_id)
    .bind(account_id)
    .bind(vec![key; 32])
    .execute(pool)
    .await
    .expect("record the dismissal of an author");
}

fn item(status_id: i64, score: f64) -> NewPostItem {
    NewPostItem {
        status_id,
        score,
        reason: serde_json::json!({"code": "affinity"}),
    }
}

#[sqlx::test(migrations = "./migrations")]
async fn old_and_followed_authors_are_not_post_candidates(pool: PgPool) {
    let (user_id, me) = seed_me(&pool).await;
    let alice = candidate_author(&pool, user_id, 10, "alice", 0.5, false).await;
    let bob = candidate_author(&pool, user_id, 11, "bob", 0.9, false).await;
    let carol = candidate_author(&pool, user_id, 12, "carol", 0.95, false).await;

    let fresh = post(&pool, 100, alice, "public", Duration::days(1)).await;
    let old = Duration::days(i64::from(POST_MAX_AGE_DAYS) + 3);
    post(&pool, 101, bob, "public", old).await;
    post(&pool, 102, carol, "public", Duration::days(1)).await;
    accounts::replace_follows(&pool, me, &[carol], "server_sync")
        .await
        .expect("record the follow edge");

    // bob's post is ten days old and carol is followed, yet both outrank alice.
    let candidates = posts::candidates(&pool, user_id, 10)
        .await
        .expect("read the post candidates");
    let ids: Vec<i64> = candidates.iter().map(|row| row.status_id).collect();
    assert_eq!(ids, vec![fresh], "unexpected candidates: {ids:?}");
    assert_eq!(candidates[0].account_acct, "alice");
    assert_eq!(candidates[0].content, "post 100");
    assert!((candidates[0].affinity - 0.5).abs() < 1e-6);
    assert!(
        posts::candidates(&pool, user_id, 0)
            .await
            .expect("read an empty candidate pool")
            .is_empty()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn unlisted_posts_are_candidates(pool: PgPool) {
    let (user_id, _) = seed_me(&pool).await;
    let alice = candidate_author(&pool, user_id, 10, "alice", 0.7, false).await;

    // `status_visibility_retained` admits only 'public' and 'unlisted', so the
    // private case is unrepresentable: this asserts the half the schema can hold.
    let id = post(&pool, 200, alice, "unlisted", Duration::days(2)).await;

    let candidates = posts::candidates(&pool, user_id, 10)
        .await
        .expect("read the post candidates");
    assert_eq!(candidates[0].status_id, id);
}

#[sqlx::test(migrations = "./migrations")]
async fn a_dismissed_author_and_an_expired_affinity_contribute_nothing(pool: PgPool) {
    let (user_id, _) = seed_me(&pool).await;
    let alice = candidate_author(&pool, user_id, 10, "alice", 0.99, false).await;
    let bob = candidate_author(&pool, user_id, 11, "bob", 0.98, true).await;
    let carol = candidate_author(&pool, user_id, 12, "carol", 0.4, false).await;

    post(&pool, 300, alice, "public", Duration::hours(1)).await;
    post(&pool, 301, bob, "public", Duration::hours(1)).await;
    let carol_post = post(&pool, 302, carol, "public", Duration::hours(1)).await;
    dismiss_author(&pool, user_id, alice, 3).await;

    // alice is the strongest match but dismissed; bob's affinity has expired.
    let candidates = posts::candidates(&pool, user_id, 10)
        .await
        .expect("read the post candidates");
    let ids: Vec<i64> = candidates.iter().map(|row| row.status_id).collect();
    assert_eq!(ids, vec![carol_post], "unexpected candidates: {ids:?}");
    assert_eq!(candidates[0].account_acct, "carol");
}

#[sqlx::test(migrations = "./migrations")]
async fn persist_keeps_input_order_and_page_continues_by_item_id(pool: PgPool) {
    let (user_id, _) = seed_me(&pool).await;
    let alice = candidate_author(&pool, user_id, 10, "alice", 0.8, false).await;
    let bob = candidate_author(&pool, user_id, 11, "bob", 0.6, false).await;
    let first_post = post(&pool, 400, alice, "public", Duration::hours(1)).await;
    let second_post = post(&pool, 401, alice, "public", Duration::hours(2)).await;
    let bob_post = post(&pool, 402, bob, "public", Duration::hours(3)).await;

    let items = [
        item(first_post, 0.9),
        item(second_post, 0.8),
        item(bob_post, 0.7),
    ];
    let feed_id = Uuid::now_v7();
    let written = posts::persist(&pool, user_id, feed_id, 0, &items)
        .await
        .expect("persist the post snapshot");
    let zipped: Vec<i64> = written.iter().map(|(_, status_id)| *status_id).collect();
    let expected: Vec<i64> = items.iter().map(|row| row.status_id).collect();
    assert_eq!(zipped, expected, "rows keep the input order");
    assert!(written.windows(2).all(|p| p[0].0 < p[1].0), "{written:?}");

    let first = posts::page(&pool, user_id, feed_id, 0, 2)
        .await
        .expect("read the first page");
    let first_ids: Vec<i64> = first.iter().map(|row| row.id).collect();
    assert_eq!(first_ids, vec![written[0].0, written[1].0]);
    assert_eq!(first[0].reason["code"], "affinity");
    assert!((first[0].score - 0.9_f32).abs() < 1e-6);

    let rest = posts::page(&pool, user_id, feed_id, first[1].id, 10)
        .await
        .expect("read the next page");
    let rest_ids: Vec<i64> = rest.iter().map(|row| row.id).collect();
    assert_eq!(rest_ids, vec![written[2].0], "no repeat past the cursor");
    assert_eq!(rest[0].content, "post 402");
    assert!(
        posts::page(&pool, user_id, feed_id, written[2].0, 10)
            .await
            .expect("read past the end of the snapshot")
            .is_empty()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn a_snapshot_belongs_to_one_user(pool: PgPool) {
    let (user_id, _) = seed_me(&pool).await;
    let alice = candidate_author(&pool, user_id, 10, "alice", 0.8, false).await;
    let post_id = post(&pool, 500, alice, "public", Duration::hours(1)).await;

    let feed_id = Uuid::now_v7();
    posts::persist(&pool, user_id, feed_id, 0, &[item(post_id, 0.6)])
        .await
        .expect("persist the post snapshot");
    let mine = posts::page(&pool, user_id, feed_id, 0, 10)
        .await
        .expect("read the owner's page");
    assert_eq!(mine.len(), 1, "the snapshot is readable by its owner");

    let other = users::upsert(&pool, HOME, "2", "other").await.expect("u2");
    assert!(
        posts::page(&pool, other.id, feed_id, 0, 10)
            .await
            .expect("read the second user's page")
            .is_empty(),
        "a feed id from another user's snapshot yields nothing"
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn followed_posts_fill_an_empty_affinity_pool(pool: PgPool) {
    let (user_id, me) = seed_me(&pool).await;
    let carol = candidate_author(&pool, user_id, 12, "carol", 0.9, false).await;
    let followed = post(&pool, 500, carol, "public", Duration::hours(1)).await;
    accounts::replace_follows(&pool, me, &[carol], "server_sync")
        .await
        .expect("record the follow edge");

    assert!(
        posts::candidates(&pool, user_id, 10)
            .await
            .expect("read the personal pool")
            .is_empty(),
        "a followed author is not a personal candidate"
    );
    let fallback = posts::fallback_candidates(&pool, user_id, 10)
        .await
        .expect("read the cold-start pool");
    let ids: Vec<i64> = fallback.iter().map(|row| row.status_id).collect();
    assert_eq!(ids, vec![followed]);
    assert!((fallback[0].affinity - 0.5).abs() < f64::EPSILON);
}

#[sqlx::test(migrations = "./migrations")]
async fn exploration_walks_past_the_people_the_user_follows(pool: PgPool) {
    let (user_id, me) = seed_me(&pool).await;
    let alice = account(&pool, REMOTE, 20, "alice").await;
    let dave = account(&pool, REMOTE, 21, "dave").await;
    accounts::replace_follows(&pool, me, &[alice], "server_sync")
        .await
        .expect("me follows alice");
    accounts::replace_follows(&pool, alice, &[dave], "expansion")
        .await
        .expect("alice follows dave");
    let fresh = post(&pool, 200, dave, "public", Duration::hours(2)).await;

    let rows = posts::exploration_candidates(&pool, user_id, 10)
        .await
        .expect("walk two hops out");
    let ids: Vec<i64> = rows.iter().map(|row| row.status_id).collect();
    assert_eq!(ids, vec![fresh], "unexpected exploration: {ids:?}");
    assert!((rows[0].affinity - 0.34).abs() < 1e-6);
}

#[sqlx::test(migrations = "./migrations")]
async fn trending_prefers_attention_per_hour(pool: PgPool) {
    let (user_id, _me) = seed_me(&pool).await;
    let alice = account(&pool, REMOTE, 30, "alice").await;
    let bob = account(&pool, REMOTE, 31, "bob").await;
    let old_but_loved = post(&pool, 300, alice, "public", Duration::days(2)).await;
    let fresh = post(&pool, 301, bob, "public", Duration::hours(1)).await;
    for (id, favourites, reblogs) in [(old_but_loved, 200, 50), (fresh, 50, 20)] {
        sqlx::query("UPDATE status SET favourites_count = $2, reblogs_count = $3 WHERE id = $1")
            .bind(id)
            .bind(favourites)
            .bind(reblogs)
            .execute(&pool)
            .await
            .expect("set engagement");
    }

    let rows = posts::trending_candidates(&pool, user_id, 10)
        .await
        .expect("read trending");
    let ids: Vec<i64> = rows.iter().map(|row| row.status_id).collect();
    assert_eq!(ids.first(), Some(&fresh), "unexpected trending: {ids:?}");
}

#[sqlx::test(migrations = "./migrations")]
async fn hidden_accounts_stay_out_of_every_pool(pool: PgPool) {
    let (user_id, _me) = seed_me(&pool).await;
    let hidden = account(&pool, REMOTE, 40, "hidden").await;
    sqlx::query("UPDATE account SET discoverable = false WHERE id = $1")
        .bind(hidden)
        .execute(&pool)
        .await
        .expect("hide the account");
    post(&pool, 400, hidden, "public", Duration::hours(1)).await;

    assert!(
        posts::trending_candidates(&pool, user_id, 10)
            .await
            .expect("trending")
            .is_empty()
    );
    assert!(
        posts::fallback_candidates(&pool, user_id, 10)
            .await
            .expect("fallback")
            .is_empty()
    );
}

#[sqlx::test(migrations = "./migrations")]
async fn personal_candidates_decodes_shared_and_acted_authors(pool: PgPool) {
    let (user_id, me) = seed_me(&pool).await;
    let peer_one = account(&pool, REMOTE, 50, "peer1").await;
    let peer_two = account(&pool, REMOTE, 51, "peer2").await;
    let shared_author = account(&pool, REMOTE, 52, "shared").await;
    let acted_author = account(&pool, REMOTE, 53, "acted").await;

    sqlx::query(
        "UPDATE account \
         SET remote_id = 'origin-52', display_name = 'Shared Author', \
             avatar_url = 'https://remote.test/avatar.png', followers_count = 420 \
         WHERE id = $1",
    )
    .bind(shared_author)
    .execute(&pool)
    .await
    .expect("enrich shared_author");

    // `me` follows two peers who both follow `shared_author`.
    accounts::replace_follows(&pool, me, &[peer_one, peer_two], "server_sync")
        .await
        .expect("me follows peers");
    accounts::replace_follows(&pool, peer_one, &[shared_author], "expansion")
        .await
        .expect("peer_one follows shared_author");
    accounts::replace_follows(&pool, peer_two, &[shared_author], "expansion")
        .await
        .expect("peer_two follows shared_author");

    // Three posts from shared_author (position <= 2 keeps the two newest).
    let shared_oldest = post(&pool, 600, shared_author, "public", Duration::hours(5)).await;
    let shared_mid = post(&pool, 601, shared_author, "public", Duration::hours(3)).await;
    let shared_newest = post(&pool, 602, shared_author, "unlisted", Duration::hours(1)).await;
    sqlx::query(
        "UPDATE status \
         SET remote_id = 'note-602', in_reply_to_id = 999, url = 'https://remote.test/@shared/602', \
             favourites_count = 7, reblogs_count = 3, replies_count = 2, sensitive = true, \
             spoiler_text = 'cw' \
         WHERE id = $1",
    )
    .bind(shared_newest)
    .execute(&pool)
    .await
    .expect("enrich shared_newest");

    // User boosted a post by `acted_author` (keep nullable account fields NULL).
    let acted_post = post(&pool, 610, acted_author, "public", Duration::hours(2)).await;
    sqlx::query(
        "WITH new_item AS ( \
             INSERT INTO recommendation_item (user_id, status_id, kind, score, model_version) \
             VALUES ($1, $2, 'post', 0.5, 0) RETURNING id \
         ) \
         INSERT INTO interaction_event (user_id, item_id, kind, client_ts, idempotency_key) \
         SELECT $1, id, 'boost', now(), $3 FROM new_item",
    )
    .bind(user_id)
    .bind(acted_post)
    .bind(vec![7_u8; 32])
    .execute(&pool)
    .await
    .expect("record boost event");

    let rows = posts::personal_candidates(&pool, user_id, 10)
        .await
        .expect("decode personal_candidates rows");

    let ids: Vec<i64> = rows.iter().map(|row| row.status_id).collect();
    // `acted_author` has affinity 0.55 > `shared_author` 0.41; `shared_oldest` is dropped by position <= 2.
    assert_eq!(ids, vec![acted_post, shared_newest, shared_mid]);
    assert!(!ids.contains(&shared_oldest));

    let acted_row = &rows[0];
    assert!((acted_row.affinity - 0.55).abs() < 1e-6);
    assert_eq!(acted_row.account_id, acted_author);
    assert_eq!(acted_row.account_acct, "acted");
    assert_eq!(acted_row.account_display_name, None);
    assert_eq!(acted_row.account_avatar_url, None);
    assert_eq!(acted_row.account_followers_count, 0);
    assert_eq!(acted_row.account_instance_host, REMOTE);
    assert_eq!(acted_row.account_remote_id, "53");
    assert_eq!(acted_row.instance_host, REMOTE);
    assert_eq!(acted_row.status_remote_id, "610");
    assert!(!acted_row.is_reply);

    let shared_row = &rows[1];
    assert!((shared_row.affinity - 0.41).abs() < 1e-6);
    assert_eq!(shared_row.status_remote_id, "note-602");
    assert_eq!(shared_row.account_id, shared_author);
    assert_eq!(shared_row.account_remote_id, "origin-52");
    assert_eq!(shared_row.content, "post 602");
    assert_eq!(shared_row.favourites_count, 7);
    assert_eq!(shared_row.reblogs_count, 3);
    assert_eq!(shared_row.replies_count, 2);
    assert!(shared_row.is_reply);
    assert_eq!(shared_row.account_acct, "shared");
    assert_eq!(
        shared_row.account_display_name.as_deref(),
        Some("Shared Author")
    );
    assert_eq!(
        shared_row.account_avatar_url.as_deref(),
        Some("https://remote.test/avatar.png")
    );
    assert_eq!(shared_row.account_followers_count, 420);
    assert_eq!(shared_row.account_instance_host, REMOTE);
    assert_eq!(shared_row.account_remote_id, "origin-52");
    assert_eq!(shared_row.instance_host, REMOTE);
    assert_eq!(
        shared_row.url.as_deref(),
        Some("https://remote.test/@shared/602")
    );
    assert_eq!(shared_row.media, serde_json::json!([]));
    assert!(shared_row.sensitive);
    assert_eq!(shared_row.spoiler_text, "cw");
    assert_eq!(shared_row.emojis, serde_json::json!([]));
}
