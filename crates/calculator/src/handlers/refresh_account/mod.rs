//! `refresh_account` — P2/P3, the recent public posts of one tracked account.
//!
//! The queue names a local `account.id`, never a user (D20): two people who follow
//! the same author must not produce two copies of that author's posts. That is also
//! why the fetcher spends a token from the host's pool rather than a subject's own
//! consent — and why it may only read public statuses. A pooled token rotates, and
//! a private read has to be made with the owner's token.
//!
//! Three properties are deliberate:
//!
//! * **Public and unlisted only.** The `status` table's `CHECK` constraint admits
//!   nothing else, and [`fetch::map_status`] drops the rest before the write.
//! * **The page walk is bounded.** Ranking needs recent posts, so [`RefreshConfig`]
//!   stops at three pages of twenty; a prolific account is truncated rather than
//!   allowed to spend the host's budget on one author.
//! * **`last_fetched_at` is stamped even for an empty page.** The refresh sweep
//!   reads that column to schedule the next tick; an account that posted nothing
//!   would otherwise be fetched on every round.
//!
//! [`RefreshConfig`] grew from [`SyncConfig`](super::SyncConfig), but it carries
//! only the pacing a status read needs: a page size, a page cap and the interval
//! between requests. The per-host request budget belongs to the P0 crawl; this
//! handler paces itself and hands a 429 back to the queue with the instance's own
//! `Retry-After`.

use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use nodus_cache::Budget;
use nodus_store::crypto::TokenSealer;
use nodus_store::models::Job;
use nodus_store::statuses::DEFAULT_POST_RETENTION_DAYS;
use sqlx::PgPool;

use super::{Handler, JobError, budget};

pub(crate) mod fetch;

#[cfg(test)]
mod tests;

/// How a status refresh behaves: page size, page cap and request spacing.
///
/// The cap is the quality boundary from `docs/04-ingestion.md`: the ranker only
/// scores recent posts, and an account that posted a hundred times today is still
/// represented by its most recent three pages.
#[derive(Debug, Clone)]
pub struct RefreshConfig {
    /// The sealing key, shared with `nodus-feeds`.
    pub sealer: Arc<TokenSealer>,
    /// Statuses per request; the default is one sweep's worth of a normal account.
    pub page_size: u16,
    /// Hard cap on pages per run.
    pub max_pages: usize,
    /// Unscaled per-host request cap from `SYNC_MAX_RPS_PER_HOST`.
    pub requests_per_second: f64,
    /// Fraction of the per-host RPS cap this crawler may consume (`SYNC_BUDGET_FRACTION`).
    pub budget_fraction: f64,
    /// Pause between two pages, derived from `SYNC_MAX_RPS_PER_HOST` and `SYNC_BUDGET_FRACTION`.
    pub request_interval: Duration,
    /// Shared per-host request budget (`REDIS_URL`), or `None` for per-process fallback.
    pub budget: Option<Arc<dyn Budget>>,
    /// Retention window in days applied to newly fetched/updated statuses (`POST_RETENTION_DAYS`).
    pub post_retention_days: u32,
    /// Scheme used to reach an instance: `https`, except for a development
    /// instance that serves plain HTTP on localhost.
    pub scheme: String,
}

impl RefreshConfig {
    /// A config sized for the post feed: 20 statuses, at most 3 pages.
    #[must_use]
    pub fn new(sealer: Arc<TokenSealer>, max_rps: f64) -> Self {
        let rps = if max_rps > 0.0 { max_rps } else { 1.0 };
        let budget_fraction = 1.0;
        let effective = budget::effective_rps(rps, budget_fraction);
        Self {
            sealer,
            page_size: 20,
            max_pages: 3,
            requests_per_second: rps,
            budget_fraction,
            request_interval: budget::request_interval(effective),
            budget: None,
            post_retention_days: DEFAULT_POST_RETENTION_DAYS,
            scheme: "https".to_owned(),
        }
    }

    /// Scales the per-host RPS cap by `budget_fraction` (`SYNC_BUDGET_FRACTION`)
    /// and updates `request_interval` to match.
    #[must_use]
    pub fn with_budget_fraction(mut self, budget_fraction: f64) -> Self {
        self.budget_fraction = budget_fraction;
        self.request_interval = budget::request_interval(self.effective_rps());
        self
    }

    /// Uses `budget` as the shared per-host request budget.
    #[must_use]
    pub fn with_budget(mut self, budget: Arc<dyn Budget>) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Sets how many days fetched statuses remain active (`POST_RETENTION_DAYS`).
    #[must_use]
    pub const fn with_post_retention_days(mut self, days: u32) -> Self {
        self.post_retention_days = days;
        self
    }

    /// Effective per-host RPS after applying `budget_fraction`.
    #[must_use]
    pub fn effective_rps(&self) -> f64 {
        budget::effective_rps(self.requests_per_second, self.budget_fraction)
    }

    /// Whole requests per second for configuring shared budget backends.
    #[must_use]
    pub fn budget_rate(&self) -> u32 {
        budget::budget_rate(self.effective_rps())
    }

    /// Override the page size, for an instance whose cap is lower than the default.
    #[must_use]
    pub const fn with_page_size(mut self, page_size: u16) -> Self {
        self.page_size = page_size;
        self
    }

    /// Talk to instances over `scheme` instead of `https`.
    ///
    /// Only a development instance serving plain HTTP needs this. It is
    /// process-wide on purpose: a scheme that could be chosen per user, or carried
    /// on a job, would be a way to point our pooled token at an attacker's server.
    #[must_use]
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = scheme.into();
        self
    }
}

/// The P2/P3 handler.
#[derive(Debug)]
pub struct RefreshAccount {
    pool: PgPool,
    config: RefreshConfig,
    budget: Arc<dyn Budget>,
}

impl RefreshAccount {
    /// A handler bound to one pool and one pacing config.
    #[must_use]
    pub fn new(pool: PgPool, config: RefreshConfig) -> Self {
        let budget = budget::resolve_budget(config.budget.clone(), config.effective_rps());
        Self {
            pool,
            config,
            budget,
        }
    }
}

impl Handler for RefreshAccount {
    fn kind(&self) -> &'static str {
        "refresh_account"
    }

    fn run<'a>(
        &'a self,
        job: &'a Job,
    ) -> Pin<Box<dyn Future<Output = Result<(), JobError>> + Send + 'a>> {
        Box::pin(async move {
            if job.subject_kind != "account" {
                // The id below is an `account.id`; a user or instance id would
                // resolve to a different row or none, and retrying cannot fix it.
                return Err(JobError::permanent(format!(
                    "refresh_account expects an `account` subject, got `{}`",
                    job.subject_kind
                )));
            }
            let Some(raw) = job.subject_id.as_deref() else {
                return Err(JobError::permanent("refresh_account has no subject_id"));
            };
            let account_id = raw.parse::<i64>().map_err(|error| {
                JobError::permanent(format!("subject_id `{raw}` is not an account id: {error}"))
            })?;
            fetch::run(&self.pool, &self.config, &*self.budget, account_id).await?;
            Ok(())
        })
    }
}
