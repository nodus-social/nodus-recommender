//! Reads and writes for [`AppUser`].
//!
//! Every function takes a pool rather than a connection: the feed path issues a
//! handful of independent reads and does not need them in one transaction, while the
//! sync path does its bookkeeping per statement. Anything that must be atomic is
//! written as a single statement, which is also why most of these are one query.
//!
//! The directory keeps the row-level writes with the row vocabulary: this file
//! holds the column list and the plain `app_user` statements, [`sync`] holds the
//! sync material and the two statements that turn background sync on and off,
//! and [`token_pool`] holds the claim that schedules one token per instance. All
//! of it is re-exported here, so `users::…` callers did not move.

use crate::models::AppUser;
use sqlx::PgPool;
use uuid::Uuid;

mod sync;
mod token_pool;

pub use sync::{SyncMaterial, clear_sync_token, set_sync_token, sync_material};
pub use token_pool::{PooledToken, pick_token};

/// Columns of [`AppUser`], with `citext` narrowed to `text` for sqlx.
const USER_COLUMNS: &str = "id, instance_host::text AS instance_host, instance_account_id, \
     acct::text AS acct, sync_enabled, telemetry_opt_in, created_at, last_seen_at, deleted_at";

/// Make sure the `instance` row exists, so account and user rows can reference it.
///
/// # Errors
///
/// Propagates [`sqlx::Error`].
pub async fn ensure_instance(pool: &PgPool, host: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO instance (host, last_contact_at) VALUES ($1, now()) \
         ON CONFLICT (host) DO UPDATE SET last_contact_at = now()",
    )
    .bind(host)
    .execute(pool)
    .await?;
    Ok(())
}

/// Insert the user if unknown, otherwise refresh `acct` and `last_seen_at`.
///
/// The unique key is `(instance_host, instance_account_id)`, not the handle: people
/// rename themselves, and a rename must not fork their recommendation history.
///
/// # Errors
///
/// Propagates [`sqlx::Error`]; a missing `instance` row is a foreign-key violation
/// and therefore a caller bug.
pub async fn upsert(
    pool: &PgPool,
    instance_host: &str,
    instance_account_id: &str,
    acct: &str,
) -> Result<AppUser, sqlx::Error> {
    let sql = format!(
        "INSERT INTO app_user (instance_host, instance_account_id, acct) VALUES ($1, $2, $3) \
         ON CONFLICT (instance_host, instance_account_id) \
         DO UPDATE SET acct = EXCLUDED.acct, last_seen_at = now() \
         RETURNING {USER_COLUMNS}"
    );
    sqlx::query_as::<_, AppUser>(&sql)
        .bind(instance_host)
        .bind(instance_account_id)
        .bind(acct)
        .fetch_one(pool)
        .await
}

/// Look a user up by the fingerprint of the bearer token presented on a request.
///
/// This is the hot path of every authenticated call, so it is a single indexed
/// comparison; the plaintext token is never stored, and the fingerprint is a prefix
/// of its SHA-256 so a leaked database cannot be replayed against an instance.
///
/// # Errors
///
/// Propagates [`sqlx::Error`].
pub async fn find_by_token_fingerprint(
    pool: &PgPool,
    fingerprint: &[u8],
) -> Result<Option<AppUser>, sqlx::Error> {
    let sql = format!(
        "SELECT {USER_COLUMNS} FROM app_user \
         WHERE token_fingerprint = $1 AND deleted_at IS NULL"
    );
    sqlx::query_as::<_, AppUser>(&sql)
        .bind(fingerprint)
        .fetch_optional(pool)
        .await
}

/// Record a telemetry decision. Consent and sync are independent switches.
///
/// # Errors
///
/// Propagates [`sqlx::Error`].
pub async fn set_telemetry_opt_in(
    pool: &PgPool,
    user_id: Uuid,
    opt_in: bool,
) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE app_user SET telemetry_opt_in = $2, \
             telemetry_opt_in_at = CASE WHEN $2 THEN now() ELSE NULL END \
         WHERE id = $1",
    )
    .bind(user_id)
    .bind(opt_in)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Soft delete: the row survives for the grace period, the data does not.
///
/// Derived rows (`user_similarity`, `account_affinity`, queued jobs) are removed by
/// the caller's deletion job in the same transaction it uses for the rest.
///
/// # Errors
///
/// Propagates [`sqlx::Error`].
pub async fn soft_delete(pool: &PgPool, user_id: Uuid) -> Result<bool, sqlx::Error> {
    let result = sqlx::query(
        "UPDATE app_user SET deleted_at = now(), access_token_enc = NULL, \
             token_scopes = NULL, token_fingerprint = NULL, sync_enabled = false \
         WHERE id = $1 AND deleted_at IS NULL",
    )
    .bind(user_id)
    .execute(pool)
    .await?;
    Ok(result.rows_affected() > 0)
}

/// Soft-delete a user and purge all derived similarity, affinity, telemetry,
/// authorization state, and pending jobs in one transaction.
///
/// # Errors
///
/// Propagates [`sqlx::Error`].
pub async fn delete_account(pool: &PgPool, user_id: Uuid) -> Result<(), sqlx::Error> {
    purge_user_state(pool, user_id, true, true).await
}

/// Clear a user's stored sync token, purge derived similarity/affinity rows and
/// pending user jobs, and optionally clear telemetry opt-in and events.
///
/// # Errors
///
/// Propagates [`sqlx::Error`].
pub async fn revoke_sync(
    pool: &PgPool,
    user_id: Uuid,
    clear_telemetry: bool,
) -> Result<(), sqlx::Error> {
    purge_user_state(pool, user_id, false, clear_telemetry).await
}

async fn purge_user_state(
    pool: &PgPool,
    user_id: Uuid,
    soft_delete_user: bool,
    clear_telemetry: bool,
) -> Result<(), sqlx::Error> {
    let mut tx = pool.begin().await?;
    if soft_delete_user {
        sqlx::query(
            "UPDATE app_user SET deleted_at = COALESCE(deleted_at, now()), \
                 access_token_enc = NULL, token_scopes = NULL, token_fingerprint = NULL, \
                 sync_enabled = false, telemetry_opt_in = false, telemetry_opt_in_at = NULL \
             WHERE id = $1",
        )
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    } else {
        sqlx::query(
            "UPDATE app_user SET access_token_enc = NULL, token_scopes = NULL, \
                 token_fingerprint = NULL, sync_enabled = false, \
                 telemetry_opt_in = CASE WHEN $2 THEN false ELSE telemetry_opt_in END, \
                 telemetry_opt_in_at = CASE WHEN $2 THEN NULL ELSE telemetry_opt_in_at END \
             WHERE id = $1",
        )
        .bind(user_id)
        .bind(clear_telemetry)
        .execute(&mut *tx)
        .await?;
    }

    sqlx::query("DELETE FROM account_affinity WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM user_similarity WHERE user_id = $1 OR other_user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM reference_similarity WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    if soft_delete_user || clear_telemetry {
        sqlx::query("DELETE FROM interaction_event WHERE user_id = $1")
            .bind(user_id)
            .execute(&mut *tx)
            .await?;
    }
    sqlx::query("DELETE FROM sync_authorization WHERE user_id = $1")
        .bind(user_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE job SET status = 'cancelled', finished_at = now(), updated_at = now() \
         WHERE subject_kind = 'user' AND subject_id = $1::text AND status = 'pending'",
    )
    .bind(user_id)
    .execute(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(())
}
