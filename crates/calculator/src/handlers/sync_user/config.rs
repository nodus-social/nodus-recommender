//! Pacing of one crawl.
//!
//! [`SyncConfig`] is the whole knob surface the calculator hands a handler, and
//! [`BURST`] fixes the in-process budget's starting depth. Nothing here performs
//! I/O; the values are consumed by [`super::SyncUser::new`] and by the token loop.

use std::sync::Arc;
use std::time::Duration;

use nodus_cache::Budget;
use nodus_store::crypto::TokenSealer;

use crate::handlers::budget;

/// How a crawl behaves: request spacing, page size and a hard page cap.
///
/// The cap is not paranoia — one account following 20 000 people would otherwise
/// spend the whole instance budget on a single user. When it trips, the graph is
/// truncated and logged, and the next run starts from the top of the list again.
#[derive(Debug, Clone)]
pub struct SyncConfig {
    /// The sealing key, shared with `nodus-feeds`.
    pub sealer: Arc<TokenSealer>,
    /// Accounts per request; Mastodon caps this at 80.
    pub page_size: u16,
    /// Hard cap on pages per run.
    pub max_pages: usize,
    /// The configured rate, from `SYNC_MAX_RPS_PER_HOST`.
    pub requests_per_second: f64,
    /// Fraction of the per-host RPS cap this crawler may consume (`SYNC_BUDGET_FRACTION`).
    pub budget_fraction: f64,
    /// The per-host request budget, once one is shared (Redis); `None` means the
    /// handler builds the in-process one on construction.
    ///
    /// It lives here rather than in a new state struct because `SyncConfig` is
    /// already what `Registry::standard` hands to every handler, and this port is
    /// the only shared state a crawl needs beyond the pool. A struct wrapping
    /// `pool` + `config` would add a layer without changing what is shared.
    pub budget: Option<Arc<dyn Budget>>,
    /// Scheme used to reach an instance: `https`, except for a development instance
    /// that serves plain HTTP on localhost.
    pub scheme: String,
}

impl SyncConfig {
    /// A config with Mastodon's documented page size and our default pacing.
    #[must_use]
    pub fn new(sealer: Arc<TokenSealer>, max_rps: f64) -> Self {
        let rps = if max_rps > 0.0 { max_rps } else { 1.0 };
        Self {
            sealer,
            page_size: 80,
            max_pages: 250,
            requests_per_second: rps,
            budget_fraction: 1.0,
            budget: None,
            scheme: "https".to_owned(),
        }
    }

    /// Scales the per-host RPS cap by `budget_fraction` (`SYNC_BUDGET_FRACTION`).
    #[must_use]
    pub const fn with_budget_fraction(mut self, budget_fraction: f64) -> Self {
        self.budget_fraction = budget_fraction;
        self
    }

    /// Override the page size, for an instance whose cap is lower than the default.
    #[must_use]
    pub const fn with_page_size(mut self, page_size: u16) -> Self {
        self.page_size = page_size;
        self
    }

    /// Talk to instances over `scheme` instead of `https`.
    ///
    /// Only a development instance serving plain HTTP needs this; federation in
    /// production is HTTPS-only, and a scheme that could be set per user would be a
    /// way to point our token at an attacker's server.
    #[must_use]
    pub fn with_scheme(mut self, scheme: impl Into<String>) -> Self {
        self.scheme = scheme.into();
        self
    }

    /// Use `budget` as the shared per-host request budget.
    ///
    /// Without this the handler falls back to [`nodus_cache::InMemoryBudget`], which is correct
    /// for one replica and wrong for several: each replica would get its own bucket
    /// and the effective rate would be the configured rate times the replica count.
    #[must_use]
    pub fn with_budget(mut self, budget: Arc<dyn Budget>) -> Self {
        self.budget = Some(budget);
        self
    }

    /// Effective per-host RPS after applying `budget_fraction`.
    #[must_use]
    pub fn effective_rps(&self) -> f64 {
        budget::effective_rps(self.requests_per_second, self.budget_fraction)
    }

    /// Minimum pause between sequential requests to the same host.
    #[must_use]
    pub fn request_interval(&self) -> Duration {
        budget::request_interval(self.effective_rps())
    }

    /// The configured rate as whole requests per second, for the budget backends.
    ///
    /// Both implementations take `u32`, while the configured rate is a fraction
    /// (0.5 means one request every two seconds). The bucket is sized by the ceiling
    /// and the token's own spend pattern supplies the fractional pacing.
    /// Float-to-int casts saturate in Rust, so a huge rate lands at `u32::MAX`,
    /// `NaN` at 0, and the floor of one keeps the bucket usable.
    #[must_use]
    pub fn budget_rate(&self) -> u32 {
        budget::budget_rate(self.effective_rps())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY_B64: &str = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";

    #[test]
    fn budget_fraction_scales_effective_rps_interval_and_budget_rate() {
        let sealer = Arc::new(TokenSealer::from_base64(KEY_B64).expect("key"));
        let config = SyncConfig::new(sealer, 10.0).with_budget_fraction(0.25);
        assert!((config.effective_rps() - 2.5).abs() < 1e-9);
        assert_eq!(config.budget_rate(), 3);
        assert_eq!(config.request_interval(), Duration::from_millis(400));
    }
}
