//! `refresh_profile` — a crawled follow graph, and the similarity it makes possible.
//!
//! The recommender compares *profiles*, not users ([`nodus_store::profiles`]). One page
//! of a public follow list is enough to place an account among its peers, and the result
//! is worth having even when the account is not one of ours: it becomes a neighbour, and
//! its follows become candidates for the user who does hold it.
//!
//! Three bounds keep this inside the operator's comfort zone, because a crawler that can
//! walk the fediverse breadth-first will eventually do exactly that:
//!
//! 1. **One page per run.** [`PageParams::first`] stops at the configured page size; the
//!    next pass starts again rather than following the cursor into somebody's 4 000
//!    follows.
//! 2. **Only accounts somebody needs.** The enqueue side reads
//!    [`profiles::needing_graph`], which asks for accounts a user we serve already
//!    follows or already carries affinity for.
//! 3. **A private graph is answered once.** `hide_collections` accounts are marked
//!    fetched on the attempt, so they are not asked again for a week.
//!
//! Similarity here is plain cosine over the three public signals, with the weights
//! [`nodus_client_core::similarity`] already assumes. It deliberately skips that module's IDF
//! weighting: IDF needs a corpus-wide frequency table, and this pass sees one page.

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use nodus_cache::Budget;
use nodus_client_core::model::{Account as InstanceAccount, LocalId, PageParams};
use nodus_client_core::{Error as InstanceError, Instance, InstanceApi, SyncApi};
use nodus_mastodon::HttpInstance;
use nodus_store::models::{Job, NewAccount};
use nodus_store::profiles::{self, EdgeKind, EdgeSource, SimilarityRow};
use nodus_store::{accounts, affinity, users};
use sqlx::PgPool;
use tracing::{debug, info, warn};

use super::{Handler, JobError, SyncConfig, budget};

/// How many accounts sharing an edge are compared in one pass.
const PEER_LIMIT: i64 = 200;
/// How many neighbours are stored per account.
const MAX_SIMILAR: usize = 50;
/// Below this, two accounts that share one follow are noise, not neighbours.
const MIN_SIMILARITY: f32 = 0.05;
/// How many candidates one profile pass may contribute.
const CANDIDATE_LIMIT: usize = 200;
/// The weights [`nodus_client_core::similarity`] uses, minus the signals a crawl cannot see.
const W_CO_FOLLOW: f32 = 0.55;
const W_CO_BOOST: f32 = 0.15;
const W_CO_REPLY: f32 = 0.10;
/// How long to wait when the instance asked us to slow down.
const BACKOFF: Duration = Duration::from_secs(300);
/// How long to wait when the database itself was the problem.
const DATABASE_BACKOFF: Duration = Duration::from_secs(60);

/// A database failure that says nothing about the work: retry rather than give up.
fn database(error: &sqlx::Error) -> JobError {
    JobError::retry(
        DATABASE_BACKOFF,
        format!("the database rejected the pass: {error}"),
    )
}

/// Crawls one account's public follow graph and re-derives its neighbours.
#[derive(Debug)]
pub struct RefreshProfile {
    pool: PgPool,
    config: SyncConfig,
    budget: Arc<dyn Budget>,
}

/// The account row this handler needs, and nothing else.
#[derive(Debug, sqlx::FromRow)]
struct Target {
    instance_host: String,
    /// The id `instance_host` printed for the account: what the graph joins match on.
    remote_id: String,
    /// The id on the account's own instance, once a lookup has learned it.
    origin_id: Option<String>,
    acct: String,
    follows_private: bool,
}

impl RefreshProfile {
    /// A handler bound to one pool and one pacing config.
    #[must_use]
    pub fn new(pool: PgPool, config: SyncConfig) -> Self {
        let budget = budget::resolve_budget(config.budget.clone(), config.effective_rps());
        Self {
            pool,
            config,
            budget,
        }
    }

    /// Reads the account, or `None` when it has been deleted since the job was queued.
    async fn target(&self, account_id: i64) -> Result<Option<Target>, sqlx::Error> {
        sqlx::query_as::<_, Target>(
            "SELECT instance_host::text AS instance_host, remote_id, origin_id, \
             acct::text AS acct, follows_private FROM account WHERE id = $1",
        )
        .bind(account_id)
        .fetch_optional(&self.pool)
        .await
    }

    /// Resolves the account id to query on `origin`, persisting a newly looked-up `remote_id`.
    /// Returns `(remote_id, made_network_request)`.
    async fn resolve_remote_id(
        &self,
        api: &HttpInstance,
        host: &str,
        bucket: &str,
        account_id: i64,
        user: &str,
        cached: Option<&str>,
    ) -> Result<(String, bool), JobError> {
        if let Some(remote_id) = cached.map(str::trim).filter(|id| !id.is_empty()) {
            return Ok((remote_id.to_owned(), false));
        }
        budget::acquire(&*self.budget, host, bucket).await?;
        let remote = match api.account_lookup(user).await {
            Ok(remote) => remote,
            Err(error) => {
                budget::hold_if_rate_limited(&*self.budget, host, &error).await;
                return Err(classify_origin_lookup(error));
            }
        };
        accounts::set_origin_id(&self.pool, account_id, &remote.id)
            .await
            .map_err(|error| database(&error))?;
        Ok((remote.id, true))
    }

    /// Picks the host, HTTP client, budget bucket, and account id for crawling `target`.
    async fn open_crawl_target(
        &self,
        target: &Target,
        account_id: i64,
    ) -> Result<(String, HttpInstance, String, LocalId, bool, bool), JobError> {
        let remote = remote_acct(&target.acct);
        let (host, secret) = if let Some((_, origin)) = remote {
            (origin.to_owned(), String::new())
        } else {
            let Some(pooled) = users::pick_token(&self.pool, &target.instance_host, &[])
                .await
                .map_err(|error| database(&error))?
            else {
                return Err(JobError::retry(
                    BACKOFF,
                    format!(
                        "no token is available for `{}`; the profile crawl waits",
                        target.instance_host
                    ),
                ));
            };
            let secret = self
                .config
                .sealer
                .open(&pooled.access_token_enc)
                .map_err(|error| {
                    JobError::retry(
                        BACKOFF,
                        format!("a pooled token cannot be decrypted: {error}"),
                    )
                })?;
            (target.instance_host.clone(), secret)
        };

        let bucket = budget::secret_bucket(&secret);
        let authority = format!("{}://{host}", self.config.scheme);
        let instance = Instance::parse(&authority).map_err(|error| {
            JobError::permanent(format!("`{host}` is not a usable instance: {error}"))
        })?;
        let api = HttpInstance::new(&instance, secret);
        let (me_id, did_lookup) = if let Some((user, _)) = remote {
            self.resolve_remote_id(
                &api,
                &host,
                &bucket,
                account_id,
                user,
                target.origin_id.as_deref(),
            )
            .await?
        } else {
            (target.remote_id.clone(), false)
        };
        Ok((
            host,
            api,
            bucket,
            LocalId(me_id),
            remote.is_some(),
            did_lookup,
        ))
    }

    /// One page of the subject's follow list, as local edge targets.
    async fn crawl(&self, target: &Target, account_id: i64) -> Result<Vec<i64>, JobError> {
        let (host, api, bucket, me, is_remote, did_lookup) =
            self.open_crawl_target(target, account_id).await?;
        let interval = self.config.request_interval();

        if did_lookup {
            tokio::time::sleep(interval).await;
        }
        budget::acquire(&*self.budget, &host, &bucket).await?;

        let page = match api
            .following(&me, PageParams::first(self.config.page_size))
            .await
        {
            Ok(page) => page,
            Err(InstanceError::Unauthorized) => {
                if is_remote {
                    return Err(JobError::permanent(
                        "the origin instance requires authentication for follow lists",
                    ));
                }
                return Err(JobError::retry(
                    BACKOFF,
                    "the instance rejected the pooled token; another will be used",
                ));
            }
            Err(InstanceError::RateLimited { retry_after_s }) => {
                let delay = Duration::from_secs(u64::from(retry_after_s.max(1)));
                budget::hold(&*self.budget, &host, delay).await;
                return Err(JobError::retry(delay, "the instance asked us to slow down"));
            }
            Err(error) => {
                return Err(JobError::retry(
                    BACKOFF,
                    format!("the follow list could not be read: {error}"),
                ));
            }
        };

        tokio::time::sleep(interval).await;
        let followers = if matches!(self.budget.acquire(&host, &bucket).await, Ok(true)) {
            match api
                .account_followers(&me, PageParams::first(self.config.page_size))
                .await
            {
                Ok(page) => Some(page),
                Err(error) => {
                    budget::hold_if_rate_limited(&*self.budget, &host, &error).await;
                    None
                }
            }
        } else {
            None
        };
        let batch: Vec<NewAccount> = page
            .items
            .iter()
            .filter_map(|account| to_new_account(&host, account))
            .collect();

        users::ensure_instance(&self.pool, &host)
            .await
            .map_err(|error| database(&error))?;
        accounts::upsert_many(&self.pool, &batch)
            .await
            .map_err(|error| database(&error))?;

        if let Some(followers) = followers {
            let newcomers: Vec<NewAccount> = followers
                .items
                .iter()
                .filter_map(|account| to_new_account(&host, account))
                .collect();
            accounts::upsert_many(&self.pool, &newcomers)
                .await
                .map_err(|error| database(&error))?;
        }

        let remote_ids: Vec<String> = batch.iter().map(|account| account.remote_id.clone()).collect();
        let resolved = accounts::resolve_ids(&self.pool, &host, &remote_ids)
            .await
            .map_err(|error| database(&error))?;

        Ok(resolved
            .into_iter()
            .map(|(local, _)| local)
            .filter(|local| *local != account_id)
            .collect())
    }

    /// Compares the subject against the accounts that share an edge with it.
    async fn neighbours(&self, account_id: i64) -> Result<Vec<SimilarityRow>, JobError> {
        let mine = self.sets(account_id).await?;
        let mut rows = Vec::new();

        for peer in profiles::peers_sharing(&self.pool, account_id, PEER_LIMIT)
            .await
            .map_err(|error| database(&error))?
        {
            let theirs = self.sets(peer).await?;
            let co_follow = cosine(&mine[0], &theirs[0]);
            let co_boost = cosine(&mine[1], &theirs[1]);
            let co_reply = cosine(&mine[2], &theirs[2]);
            // Normalised by the weights that apply, so an account with no visible boosts
            // is not punished for a signal it never had the chance to show.
            let score = (W_CO_FOLLOW * co_follow + W_CO_BOOST * co_boost + W_CO_REPLY * co_reply)
                / (W_CO_FOLLOW + W_CO_BOOST + W_CO_REPLY);
            if score >= MIN_SIMILARITY {
                rows.push(SimilarityRow {
                    peer_id: peer,
                    score,
                    co_follow,
                    co_boost,
                    co_reply,
                });
            }
        }

        rows.sort_by(|left, right| {
            right
                .score
                .total_cmp(&left.score)
                .then_with(|| left.peer_id.cmp(&right.peer_id))
        });
        rows.truncate(MAX_SIMILAR);
        Ok(rows)
    }

    /// One account's edges, as `[follows, boosts, replies]`.
    async fn sets(&self, account_id: i64) -> Result<[HashSet<i64>; 3], JobError> {
        let follows = profiles::targets(&self.pool, account_id, EdgeKind::Follow)
            .await
            .map_err(|error| database(&error))?;
        let boosts = profiles::targets(&self.pool, account_id, EdgeKind::Boost)
            .await
            .map_err(|error| database(&error))?;
        let replies = profiles::targets(&self.pool, account_id, EdgeKind::Reply)
            .await
            .map_err(|error| database(&error))?;
        Ok([
            follows.into_iter().collect(),
            boosts.into_iter().collect(),
            replies.into_iter().collect(),
        ])
    }

    /// Turns the neighbours' follows into candidates for whoever holds this account.
    ///
    /// A crawled account has no owner and contributes nothing here; it still becomes a
    /// neighbour for the accounts that are ours, which is the whole point.
    async fn contribute(&self, account_id: i64, rows: &[SimilarityRow]) -> Result<u64, JobError> {
        let Some(user_id) = profiles::owner(&self.pool, account_id)
            .await
            .map_err(|error| database(&error))?
        else {
            return Ok(0);
        };
        if rows.is_empty() {
            return Ok(0);
        }

        let own: HashSet<i64> = self.sets(account_id).await?[0].clone();
        let mut weights: HashMap<i64, f32> = HashMap::new();
        for row in rows {
            let follows = profiles::targets(&self.pool, row.peer_id, EdgeKind::Follow)
                .await
                .map_err(|error| database(&error))?;
            for target in follows {
                if target == account_id || own.contains(&target) {
                    continue;
                }
                *weights.entry(target).or_insert(0.0) += row.score;
            }
        }
        if weights.is_empty() {
            return Ok(0);
        }

        let mut candidates: Vec<affinity::AffinityRow> = weights
            .into_iter()
            .map(|(account_id, weight)| affinity::AffinityRow {
                account_id,
                // Several neighbours following the same account is evidence, not a
                // reason to exceed one: the score is a share, not a sum.
                affinity: weight.min(1.0),
                support: 1,
                sources: vec!["similar_user".to_owned()],
            })
            .collect();
        candidates.sort_by(|left, right| {
            right
                .affinity
                .total_cmp(&left.affinity)
                .then_with(|| left.account_id.cmp(&right.account_id))
        });
        candidates.truncate(CANDIDATE_LIMIT);

        affinity::merge_for_user(&self.pool, user_id, &candidates)
            .await
            .map_err(|error| database(&error))
    }
}

impl Handler for RefreshProfile {
    fn kind(&self) -> &'static str {
        "refresh_profile"
    }

    fn run<'a>(
        &'a self,
        job: &'a Job,
    ) -> Pin<Box<dyn Future<Output = Result<(), JobError>> + Send + 'a>> {
        Box::pin(async move {
            let Some(raw) = job.subject_id.as_deref() else {
                return Err(JobError::permanent("refresh_profile has no subject_id"));
            };
            let account_id = raw.parse::<i64>().map_err(|error| {
                JobError::permanent(format!("subject_id `{raw}` is not an account id: {error}"))
            })?;

            let Some(target) = self
                .target(account_id)
                .await
                .map_err(|error| database(&error))?
            else {
                return Err(JobError::permanent(format!(
                    "account {account_id} no longer exists"
                )));
            };

            if target.follows_private {
                // A permanent answer: marking it stops the next pass from spending a
                // request to learn the same thing.
                profiles::mark_fetched(&self.pool, account_id)
                    .await
                    .map_err(|error| database(&error))?;
                debug!(
                    account = account_id,
                    "the follow graph is private; nothing to crawl"
                );
                return Ok(());
            }

            let edges = self.crawl(&target, account_id).await?;
            let written = profiles::replace_edges(
                &self.pool,
                account_id,
                EdgeSource::PublicFollow,
                &edges
                    .iter()
                    .map(|target| (EdgeKind::Follow, *target))
                    .collect::<Vec<_>>(),
            )
            .await
            .map_err(|error| database(&error))?;
            profiles::mark_fetched(&self.pool, account_id)
                .await
                .map_err(|error| database(&error))?;

            let rows = self.neighbours(account_id).await?;
            profiles::replace_similarity(&self.pool, account_id, &rows)
                .await
                .map_err(|error| database(&error))?;
            let candidates = self.contribute(account_id, &rows).await?;

            info!(
                account = account_id,
                edges = written,
                neighbours = rows.len(),
                candidates,
                "profile refreshed"
            );
            Ok(())
        })
    }
}

/// The `user@host` an account actually lives on, when it is not local.
fn remote_acct(acct: &str) -> Option<(&str, &str)> {
    acct.split_once('@')
        .filter(|(user, host)| !user.is_empty() && !host.is_empty())
}

/// Maps an unauthenticated `account_lookup` failure on a remote origin onto `JobError`.
fn classify_origin_lookup(error: InstanceError) -> JobError {
    match error {
        InstanceError::RateLimited { retry_after_s } => JobError::retry(
            Duration::from_secs(u64::from(retry_after_s.max(1))),
            "the instance asked us to slow down",
        ),
        InstanceError::Unauthorized => {
            JobError::permanent("401 from the instance: remote lookup rejected")
        }
        InstanceError::Status {
            status: status @ (403 | 404),
            message,
        } => JobError::permanent(format!(
            "{status} from the instance: remote account cannot be resolved: {message}"
        )),
        InstanceError::Unsupported(feature) => {
            JobError::permanent(format!("unsupported operation: {feature}"))
        }
        InstanceError::Status { .. } | InstanceError::Transport(_) | InstanceError::Decode(_) => {
            JobError::retry(
                BACKOFF,
                format!("the remote account could not be resolved: {error}"),
            )
        }
    }
}

/// Maps a crawled instance account into a store upsert row under `host`.
fn to_new_account(host: &str, account: &InstanceAccount) -> Option<NewAccount> {
    let remote_id = account.id.trim();
    if remote_id.is_empty() {
        warn!(acct = %account.acct, "skipping an account with an empty id");
        return None;
    }
    Some(NewAccount {
        instance_host: host.to_owned(),
        remote_id: remote_id.to_owned(),
        acct: account.acct.clone(),
        display_name: (!account.display_name.is_empty()).then(|| account.display_name.clone()),
        followers_count: i32::try_from(account.followers_count).unwrap_or(i32::MAX),
        bot: account.bot,
        locked: account.locked,
        discoverable: account.discoverable,
        indexable: account.indexable,
        noindex: account.noindex,
    })
}

/// Cosine similarity between two sets of ids.
///
/// Binary weights on purpose: the crawl knows *that* a follow exists, not how much it
/// matters, and inventing a weight from a count would make a prolific account look
/// twice as similar to everyone.
#[expect(
    clippy::cast_precision_loss,
    reason = "a profile of more than 16 million edges would lose precision; the crawl \
              stops at one page, so this is documentation rather than a risk"
)]
fn cosine(left: &HashSet<i64>, right: &HashSet<i64>) -> f32 {
    if left.is_empty() || right.is_empty() {
        return 0.0;
    }
    let shared = left.intersection(right).count() as f32;
    let size = (left.len() as f32 * right.len() as f32).sqrt();
    shared / size
}

#[cfg(test)]
mod tests {
    use super::cosine;
    use std::collections::HashSet;

    fn set(ids: &[i64]) -> HashSet<i64> {
        ids.iter().copied().collect()
    }

    #[test]
    fn identical_graphs_are_fully_similar() {
        assert!((cosine(&set(&[1, 2, 3]), &set(&[1, 2, 3])) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn disjoint_graphs_share_nothing() {
        assert!(cosine(&set(&[1, 2]), &set(&[3, 4])).abs() < f32::EPSILON);
    }

    #[test]
    fn one_shared_follow_counts_more_between_small_graphs() {
        // One in common out of two is a stronger claim than one in common out of six,
        // which is the whole reason a long follow list is not automatically a neighbour.
        let small = cosine(&set(&[1, 2]), &set(&[1, 3]));
        let large = cosine(&set(&[1, 2, 3, 4, 5, 6]), &set(&[1, 7, 8, 9, 10, 11]));
        assert!(small > large, "small {small} should beat large {large}");
    }

    #[test]
    fn an_empty_graph_is_like_nothing() {
        assert!(cosine(&set(&[]), &set(&[1])).abs() < f32::EPSILON);
        assert!(cosine(&set(&[1]), &set(&[])).abs() < f32::EPSILON);
    }
}
