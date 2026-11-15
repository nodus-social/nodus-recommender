//! Shared per-host rate-limiting and budget helpers for crawl handlers.

use std::fmt::Write as _;
use std::sync::Arc;
use std::time::Duration;

use nodus_cache::{Budget, InMemoryBudget};
use nodus_client_core::Error as InstanceError;
use nodus_store::crypto::fingerprint as token_fingerprint;
use tracing::warn;

use super::JobError;

/// Default burst for the in-process token bucket so a small initial batch can
/// run immediately while sustained traffic obeys the configured rate.
pub(super) const DEFAULT_BURST: u32 = 5;

/// Upper bound on derived sleep intervals when `SYNC_MAX_RPS_PER_HOST` is tiny.
const MAX_REQUEST_INTERVAL: Duration = Duration::from_secs(86_400);

/// Shared bucket label for unauthenticated requests to an origin instance.
pub(super) const PUBLIC_BUCKET: &str = "public";

/// Formats a 32-byte SHA-256 token fingerprint as the 64-char hex bucket key.
pub(super) fn fingerprint_bucket(fingerprint: &[u8; 32]) -> String {
    let mut hex = String::with_capacity(64);
    for byte in fingerprint {
        write!(hex, "{byte:02x}").ok();
    }
    hex
}

/// Derives the budget bucket name from a decrypted token, or [`PUBLIC_BUCKET`]
/// when making unauthenticated requests.
pub(super) fn secret_bucket(secret: &str) -> String {
    if secret.is_empty() {
        return PUBLIC_BUCKET.to_owned();
    }
    fingerprint_bucket(&token_fingerprint(secret))
}

/// Scales the configured per-host RPS cap by `SYNC_BUDGET_FRACTION`.
pub(super) fn effective_rps(base_rps: f64, budget_fraction: f64) -> f64 {
    let base = if base_rps.is_finite() && base_rps > 0.0 {
        base_rps
    } else {
        1.0
    };
    let fraction = if budget_fraction.is_finite() && budget_fraction > 0.0 && budget_fraction <= 1.0
    {
        budget_fraction
    } else {
        1.0
    };
    base * fraction
}

/// Converts an effective RPS rate into the whole-number budget backend rate.
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
pub(super) fn budget_rate(effective_rps: f64) -> u32 {
    (effective_rps.ceil() as u32).max(1)
}

/// Computes the inter-request sleep interval corresponding to `effective_rps`.
pub(super) fn request_interval(effective_rps: f64) -> Duration {
    let rate = if effective_rps.is_finite() && effective_rps > 0.0 {
        effective_rps
    } else {
        1.0
    };
    let secs = (1.0 / rate).min(MAX_REQUEST_INTERVAL.as_secs_f64());
    Duration::from_secs_f64(secs)
}

/// Resolves the shared budget when configured, or creates one in-process bucket
/// for a single handler instance.
pub(super) fn resolve_budget(
    configured: Option<Arc<dyn Budget>>,
    effective_rps: f64,
) -> Arc<dyn Budget> {
    if let Some(budget) = configured {
        return budget;
    }
    warn!(
        "no shared request budget configured; per-host budgets are per replica \
         (set REDIS_URL to share them)"
    );
    Arc::new(InMemoryBudget::with_rate(effective_rps, DEFAULT_BURST))
}

/// Acquires one request slot from `budget` for `(host, bucket)`, returning a
/// retryable [`JobError`] when exhausted or when the cache backend errors.
pub(super) async fn acquire(budget: &dyn Budget, host: &str, bucket: &str) -> Result<(), JobError> {
    match budget.acquire(host, bucket).await {
        Ok(true) => Ok(()),
        Ok(false) => {
            let delay = budget
                .retry_hint(host, bucket)
                .max(Duration::from_millis(100));
            Err(JobError::retry(
                delay,
                format!("request budget for {host} is spent; rescheduling"),
            ))
        }
        Err(error) => {
            let delay = budget.retry_hint(host, bucket).max(Duration::from_secs(1));
            warn!(%error, host, "request budget unavailable");
            Err(JobError::retry(
                delay,
                format!("request budget unavailable: {error}"),
            ))
        }
    }
}

/// Records a host-wide 429 cooldown in `budget`, logging if the backend fails.
pub(super) async fn hold(budget: &dyn Budget, host: &str, delay: Duration) {
    if let Err(error) = budget.hold(host, delay).await {
        warn!(%error, host, "could not record the host cooldown");
    }
}

/// Records a host-wide cooldown in `budget` when `error` is a `429 RateLimited`.
pub(super) async fn hold_if_rate_limited(budget: &dyn Budget, host: &str, error: &InstanceError) {
    if let InstanceError::RateLimited { retry_after_s } = error {
        hold(
            budget,
            host,
            Duration::from_secs(u64::from((*retry_after_s).max(1))),
        )
        .await;
    }
}
