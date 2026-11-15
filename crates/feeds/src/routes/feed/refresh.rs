//! Asking for a new snapshot instead of the one you were reading.
//!
//! A first page is normally answered from the live snapshot for ten minutes (see
//! [`super::reuse_live_snapshot`]): two tabs a minute apart must show the same list.
//! A refresh is the caller saying "I know what I was looking at, rank again" — the
//! old snapshot stays continuable until its own lifetime ends, so the reader's scroll
//! position is never invalidated by someone else pressing refresh in another tab.
//!
//! This file owns both halves of "rank a fresh page": the shared ranking/recording
//! body, and the endpoint that names the snapshot being superseded.

use super::page;
use super::params::{
    DEFAULT_LIMIT, FeedParams, MAX_LIMIT, MIN_LIMIT, contract_gate, degraded_flag,
};
use super::ranking::{reason_for, score};
use super::response::{envelope, feed_account};
use super::{ensure_continuable, seed_of, without_fresh_rejections};
use crate::auth::authenticate;
use crate::cursor;
use crate::error::ApiError;
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use nodus_core::diversity::{
    Diversifiable, INSTANCE_WINDOW, MAX_PER_INSTANCE, MMR_LAMBDA, mmr_select,
};
use nodus_core::explore::{EXPLORE_FIRST_RANK, EXPLORE_LAST_RANK};
use nodus_core::ranking::RankingWeights;
use nodus_core::similarity::CANDIDATE_LIMIT;
use nodus_shared::{AccountFeed, AccountItem};
use nodus_store::feed::{self, Candidate, NewItem};
use nodus_store::models::AppUser;
use std::collections::{HashMap, HashSet};
use time::OffsetDateTime;
use uuid::Uuid;

/// Ranks a new snapshot, records it, and returns it.
///
/// Shared by the first page of [`super::accounts`] and by [`refresh`]: the two differ
/// only in whether the caller was allowed to skip the reuse window.
pub(super) async fn fresh_page(
    state: &AppState,
    user: &AppUser,
    limit: i64,
    age: Option<f64>,
    degraded: Option<String>,
) -> Result<AccountFeed, ApiError> {
    // One query per request: the baseline is a property of the reader, not of the
    // candidate, and every candidate's fatigue is expressed in it. A failure is not
    // worth failing the page for — fatigue then counts plain impressions, which is
    // what it did before attention was measured.
    let baseline = feed::baseline_ms(&state.pool, user.id)
        .await
        .unwrap_or_else(|error| {
            tracing::warn!(%error, "dwell baseline unavailable; fatigue counts impressions");
            None
        });
    let model_version = feed::active_model_version(&state.pool).await?;
    let now = OffsetDateTime::now_utc();
    // Fetch the full materialised candidate pool so scoring, diversity filtering,
    // and exploration (ranks 51..200) operate over all eligible candidates rather
    // than only the top `limit + 1` by raw affinity.
    let candidate_limit = i64::try_from(CANDIDATE_LIMIT).unwrap_or(500).max(limit + 1);
    let mut candidates = without_fresh_rejections(
        feed::candidates(&state.pool, user.id, candidate_limit, baseline).await?,
        now,
    );
    if candidates.is_empty() {
        // No affinity has been materialised for this user yet: serve the
        // instance-popular rung instead of an empty first page. One ranking pass
        // covers both, so scores and ordering keep the same shape either way.
        candidates = feed::popular_candidates(&state.pool, user.id, candidate_limit).await?;
    }

    let feed_id = Uuid::now_v7();
    let page_limit = usize::try_from(limit).unwrap_or(0);
    let (ranked, more) = select_page(
        candidates,
        &user.instance_host,
        page_limit,
        seed_of(feed_id),
        now,
    );

    let new_items = ranked
        .iter()
        .map(|(value, candidate)| NewItem {
            account_id: candidate.account_id,
            score: *value,
            reason: serde_json::to_value(reason_for(candidate)).unwrap_or_default(),
        })
        .collect::<Vec<_>>();
    let persisted = feed::persist(&state.pool, user.id, feed_id, model_version, &new_items).await?;
    let by_account: HashMap<i64, i64> = persisted
        .into_iter()
        .map(|(id, account)| (account, id))
        .collect();

    let items = ranked
        .into_iter()
        .filter_map(|(_, candidate)| {
            let item_id = *by_account.get(&candidate.account_id)?;
            Some(AccountItem {
                item_id,
                account: feed_account(&candidate),
                reason: reason_for(&candidate),
            })
        })
        .collect::<Vec<_>>();
    let next_cursor =
        more.then(|| cursor::encode(feed_id, items.last().map_or(0, |item| item.item_id)));
    Ok(envelope(
        model_version,
        age,
        degraded,
        feed_id,
        items,
        next_cursor,
    ))
}

/// Scores, sorts, diversifies, and plans one page of candidates.
fn select_page(
    candidates: Vec<Candidate>,
    home_instance: &str,
    limit: usize,
    seed: u64,
    now: OffsetDateTime,
) -> (Vec<(f64, Candidate)>, bool) {
    if candidates.is_empty() || limit == 0 {
        return (Vec::new(), !candidates.is_empty());
    }

    let weights = RankingWeights::default();
    let mut scored: Vec<(f64, Candidate)> = candidates
        .into_iter()
        .map(|candidate| (score(&candidate, weights, home_instance, now), candidate))
        .collect();
    // Score and sort all candidates before diversity and page planning so freshness,
    // local preference, stability, fatigue, rejection decay, and lift determine
    // which candidates make the page and in what order.
    scored.sort_by(|a, b| {
        b.0.total_cmp(&a.0)
            .then_with(|| a.1.account_id.cmp(&b.1.account_id))
    });

    let diversifiable: Vec<Diversifiable> = scored
        .iter()
        .map(|(value, candidate)| Diversifiable {
            id: u64::try_from(candidate.account_id).unwrap_or(0),
            score: *value,
            instance_host: hash_instance_host(&candidate.instance_host),
            embedding: Vec::new(),
        })
        .collect();
    let diverse_order = mmr_select(
        &diversifiable,
        MMR_LAMBDA,
        MAX_PER_INSTANCE,
        INSTANCE_WINDOW,
        diversifiable.len(),
    );

    let mut slots: Vec<Option<(f64, Candidate)>> = scored.into_iter().map(Some).collect();
    let diversified: Vec<(f64, Candidate)> = diverse_order
        .into_iter()
        .filter_map(|index| slots.get_mut(index).and_then(Option::take))
        .collect();

    // The page is planned over the scored, diversified list because exploration is
    // about positions (D26 needs explore slots from below the head to keep producing
    // evidence about accounts the ranking has given up on).
    let mut plan = page::plan(diversified.len(), limit, seed);
    let _ = page::promote_recovery(&mut plan, &diversified, |(_, candidate)| {
        recovering(candidate, now)
    });
    enforce_explore_instance_cap(&mut plan, &diversified);

    let more = plan.more;
    let selected = page::select(&diversified, &plan)
        .into_iter()
        .cloned()
        .collect();
    (selected, more)
}

/// Ensures appended explore slots also respect the per-instance window cap.
///
/// `mmr_select` guarantees `diversified[..plan.head]` satisfies `MAX_PER_INSTANCE`
/// within `INSTANCE_WINDOW`. Explore slots drawn from deeper ranks could otherwise
/// push the trailing window over the cap; replace any violating slot with the next
/// eligible candidate in the explore pool (or drop it if none fits).
fn enforce_explore_instance_cap(plan: &mut page::Plan, diversified: &[(f64, Candidate)]) {
    if plan.explore.is_empty() {
        return;
    }
    let mut picked: Vec<usize> = (0..plan.head).collect();
    let mut used: HashSet<usize> = picked.iter().copied().collect();
    let pool_start = EXPLORE_FIRST_RANK.max(plan.head).min(diversified.len());
    let pool_end = EXPLORE_LAST_RANK.min(diversified.len());
    let mut adjusted = Vec::with_capacity(plan.explore.len());

    for &slot in &plan.explore {
        if let Some(chosen) = pick_explore_slot(
            slot,
            plan.head,
            &picked,
            &used,
            pool_start,
            pool_end,
            diversified,
        ) {
            picked.push(chosen);
            used.insert(chosen);
            adjusted.push(chosen);
        }
    }
    plan.explore = adjusted;
}

fn pick_explore_slot(
    slot: usize,
    head: usize,
    picked: &[usize],
    used: &HashSet<usize>,
    pool_start: usize,
    pool_end: usize,
    diversified: &[(f64, Candidate)],
) -> Option<usize> {
    if !used.contains(&slot)
        && fits_instance_cap(picked, &diversified[slot].1.instance_host, diversified)
    {
        return Some(slot);
    }
    (pool_start..pool_end)
        .chain(head..diversified.len())
        .find(|&candidate_idx| {
            !used.contains(&candidate_idx)
                && fits_instance_cap(
                    picked,
                    &diversified[candidate_idx].1.instance_host,
                    diversified,
                )
        })
}

fn fits_instance_cap(picked: &[usize], host: &str, diversified: &[(f64, Candidate)]) -> bool {
    let tail_start = picked
        .len()
        .saturating_sub(INSTANCE_WINDOW.saturating_sub(1));
    let count = picked[tail_start..]
        .iter()
        .filter(|&&idx| diversified[idx].1.instance_host.eq_ignore_ascii_case(host))
        .count();
    count < MAX_PER_INSTANCE
}

/// Deterministic FNV-1a 64-bit hash of an instance host (case-insensitive to match `citext`).
fn hash_instance_host(host: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in host.as_bytes() {
        hash ^= u64::from(byte.to_ascii_lowercase());
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

/// Whether an account has served its penalty and deserves one more look.
///
/// Two conditions, both required: the penalty has decayed below half (so the rejection
/// is old relative to its half-life) and the account has not been shown for a week (so
/// the re-exposure is a real test rather than another impression of a list the user
/// already skipped).
fn recovering(candidate: &nodus_store::feed::Candidate, now: OffsetDateTime) -> bool {
    const FADED: f64 = 0.5;
    const QUIET_DAYS: i64 = 7;

    if candidate.rejected_kind.is_none() {
        return false;
    }
    if super::ranking::penalty(candidate, now) >= FADED {
        return false;
    }
    candidate.last_shown_at.is_none_or(|shown| {
        let quiet = now - shown;
        quiet.whole_days() >= QUIET_DAYS
    })
}

/// `POST /api/v1/feed/{feed_id}/refresh`
///
/// # Errors
///
/// - [`ApiError::ClientTooOld`] when the caller's contract is below
///   [`nodus_shared::MIN_CONTRACT_VERSION`].
/// - [`ApiError::Unauthorized`] when the token or the instance header is missing.
/// - [`ApiError::BadRequest`] when `feed_id` is not a uuid.
/// - [`ApiError::Gone`] when the named snapshot is already expired, which is reported
///   rather than ignored so a client with a stale tab learns why.
/// - [`ApiError::Database`] when a query fails.
pub async fn refresh(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(feed_id): Path<String>,
    Query(params): Query<FeedParams>,
) -> Result<Json<AccountFeed>, ApiError> {
    contract_gate(&headers)?;
    let credentials = crate::auth::Credentials::from_headers(&headers)?;
    let authenticated = authenticate(&state, credentials).await?;
    let user = &authenticated.user;

    let superseded = Uuid::parse_str(&feed_id).map_err(|_| {
        ApiError::bad_request(
            "invalid_feed_id",
            "feed_id must be the uuid this service issued",
        )
    })?;
    // The snapshot being left behind must belong to this reader and must still be
    // continuable; refreshing a stranger's id would otherwise create a snapshot from
    // someone else's scroll position.
    ensure_continuable(&state, user.id, superseded).await?;

    let limit = params
        .limit
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(MIN_LIMIT, MAX_LIMIT);
    let age = feed::similarity_age_hours(&state.pool, user.id).await?;
    let degraded = degraded_flag(user.sync_enabled, age);
    let feed = fresh_page(&state, user, limit, age, degraded).await?;
    Ok(Json(feed))
}

#[cfg(test)]
mod tests {
    use super::{enforce_explore_instance_cap, select_page};
    use crate::routes::feed::page::Plan;
    use nodus_core::diversity::{INSTANCE_WINDOW, MAX_PER_INSTANCE};
    use nodus_store::feed::Candidate;
    use std::collections::HashMap;
    use time::{Duration, OffsetDateTime};

    fn make_candidate(
        account_id: i64,
        affinity: f64,
        host: &str,
        now: OffsetDateTime,
    ) -> Candidate {
        Candidate {
            account_id,
            affinity,
            support: 1,
            sources: vec!["similar_user".to_owned()],
            computed_at: now,
            last_shown_at: None,
            seen_attention_7d: 0.0,
            rejected_kind: None,
            rejected_at: None,
            impressions: 0,
            follow_through_shown: None,
            follow_through_followed: None,
            expected_follow_rate: None,
            acct: format!("u{account_id}@{host}"),
            display_name: None,
            note: None,
            avatar_url: None,
            followers_count: 10,
            bot: false,
            last_status_at: None,
            instance_host: host.to_owned(),
        }
    }

    #[test]
    fn select_page_orders_by_all_ranking_signals_and_respects_sliding_window_cap() {
        let now = OffsetDateTime::now_utc();
        let mut candidates = Vec::new();
        // 5 high-affinity candidates from the same instance; only 2 may appear in any
        // 10-item window, and the instance can reappear once 10 items have passed.
        for i in 0..5_i64 {
            #[expect(clippy::cast_precision_loss, reason = "small test index")]
            let aff = 0.99 - (i as f64) * 0.01;
            candidates.push(make_candidate(i + 1, aff, "crowded.test", now));
        }
        // 12 candidates from distinct instances with lower raw affinity.
        for i in 0..12_i64 {
            #[expect(clippy::cast_precision_loss, reason = "small test index")]
            let aff = 0.70 - (i as f64) * 0.01;
            let host = format!("other{i:02}.test");
            candidates.push(make_candidate(100 + i, aff, &host, now));
        }
        // A candidate with low raw affinity boosted by home instance, freshness, and stability.
        let mut boosted = make_candidate(999, 0.50, "home.test", now);
        boosted.last_status_at = Some(now - Duration::hours(1));
        boosted.last_shown_at = Some(now - Duration::hours(2));
        candidates.push(boosted);

        let (selected, more) = select_page(candidates, "home.test", 15, 42, now);
        assert!(more);
        assert_eq!(selected.len(), 15);
        // `boosted` scored 0.50 + ~0.20 (fresh) + 0.10 (local) + ~0.15 (stability) + support > 0.99?
        // Wait: 0.50 + 0.20 + 0.10 + 0.15 = 0.95 (below 0.99 and 0.98, above 0.70!).
        assert_eq!(selected[0].1.account_id, 1);
        assert_eq!(selected[1].1.account_id, 2);
        assert_eq!(selected[2].1.account_id, 999);

        // No 10-item window may exceed 2 items from the same instance, yet crowded.test
        // reappears after 10 items have elapsed.
        for window in selected.windows(INSTANCE_WINDOW) {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for (_, c) in window {
                *counts.entry(c.instance_host.as_str()).or_insert(0) += 1;
            }
            for (host, count) in counts {
                assert!(count <= MAX_PER_INSTANCE, "{host} appeared {count} times");
            }
        }
        let crowded_count = selected
            .iter()
            .filter(|(_, c)| c.instance_host == "crowded.test")
            .count();
        assert!(
            crowded_count > MAX_PER_INSTANCE,
            "sliding window should let crowded.test reappear after 10 items, got {crowded_count}"
        );
    }

    #[test]
    fn enforce_explore_instance_cap_replaces_conflicting_explore_slot() {
        let now = OffsetDateTime::now_utc();
        let mut diversified = Vec::new();
        for i in 0..60_i64 {
            let host = if i == 17 || i == 18 || i == 55 {
                "dup.test".to_owned()
            } else {
                format!("inst{i:02}.test")
            };
            #[expect(clippy::cast_precision_loss, reason = "small test index")]
            let score = 1.0 - (i as f64) * 0.005;
            diversified.push((score, make_candidate(i + 1, score, &host, now)));
        }
        let mut plan = Plan {
            head: 19,
            explore: vec![55],
            more: true,
        };
        enforce_explore_instance_cap(&mut plan, &diversified);
        assert_eq!(plan.explore.len(), 1);
        assert_ne!(
            plan.explore[0], 55,
            "conflicting dup.test explore slot must be replaced"
        );
    }

    #[test]
    fn enforce_explore_instance_cap_preserves_validated_order_across_multiple_slots() {
        use crate::routes::feed::page;

        let now = OffsetDateTime::now_utc();
        let mut hosts: Vec<String> = (0..29).map(|i| format!("head{i:02}.test")).collect();
        hosts.extend(
            [
                "a.test", "b.test", "b.test", "c.test", "c.test", "d.test", "d.test", "e.test",
                "a.test",
            ]
            .into_iter()
            .map(str::to_owned),
        );
        hosts.extend((38..50).map(|i| format!("mid{i:02}.test")));
        hosts.extend(
            [
                "a.test", "a.test", "b.test", "b.test", "c.test", "c.test", "d.test", "d.test",
                "f.test",
            ]
            .into_iter()
            .map(str::to_owned),
        );

        let diversified: Vec<(f64, Candidate)> = hosts
            .into_iter()
            .enumerate()
            .map(|(i, host)| {
                #[expect(clippy::cast_precision_loss, reason = "small test index")]
                let score = 1.0 - (i as f64) * 0.005;
                let id = i64::try_from(i + 1).expect("small test index");
                (score, make_candidate(id, score, &host, now))
            })
            .collect();

        let mut plan = Plan {
            head: 38,
            explore: vec![50, 51],
            more: true,
        };
        enforce_explore_instance_cap(&mut plan, &diversified);
        assert_eq!(
            plan.explore,
            vec![58, 51],
            "replacement slot 58 must remain ahead of 51 so 51 stays outside the 29..=37 window"
        );

        let selected = page::select(&diversified, &plan);
        assert_eq!(selected.len(), 40);
        for (start, window) in selected.windows(INSTANCE_WINDOW).enumerate() {
            let mut counts: HashMap<&str, usize> = HashMap::new();
            for (_, c) in window {
                *counts.entry(c.instance_host.as_str()).or_insert(0) += 1;
            }
            for (host, count) in counts {
                assert!(
                    count <= MAX_PER_INSTANCE,
                    "window starting at {start} had {count} accounts from {host}"
                );
            }
        }
    }
}
