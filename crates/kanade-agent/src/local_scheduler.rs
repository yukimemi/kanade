//! v0.23: agent-side cron scheduler for `runs_on: agent` schedules.
//!
//! When the operator marks a schedule `runs_on: agent`, the backend's
//! central scheduler steps out and leaves the definition in
//! `BUCKET_SCHEDULES` for each targeted agent to pick up. This
//! module is the agent-side counterpart: it watches the same KV,
//! filters for schedules whose target matches this agent and whose
//! `runs_on` is `Agent`, and runs an internal `tokio_cron_scheduler`
//! for them.
//!
//! On a local tick the agent looks up the Manifest from a small
//! locally-cached snapshot of `BUCKET_JOBS`, applies the mode-based
//! dedup against `<data_dir>/local_completions.json`, builds a
//! Command, and runs it through the same `handle_command` path that
//! the live-NATS Commands use — so kill / cooldown / inventory
//! projection all behave identically.
//!
//! What we don't yet do (v0.24 territory):
//!
//! * Full outbox for results when the broker is unreachable — we
//!   rely on async-nats client buffering, which handles seconds-to-
//!   minutes outages but won't survive a multi-day air-gap.
//! * Group membership reflection — we re-read `agent_groups` once
//!   per schedule-KV change. Group churn in between is missed until
//!   the next schedule edit.
//!
//! Both are gated on this feature actually being exercised in the
//! field; ship the minimum that's useful today.

use std::collections::{HashMap, HashSet};
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_nats::jetstream::kv::Operation;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use futures::{StreamExt, TryStreamExt};
use kanade_shared::kv::{
    BUCKET_FLEET_CONFIG, BUCKET_JOBS, BUCKET_SCHEDULES, BUCKET_SCRIPT_STATUS, KEY_FREEZE,
};
use kanade_shared::manifest::{
    ExecMode, Freeze, Manifest, OnTrigger, RunsOn, Schedule, ScheduleTz, When,
};
use kanade_shared::wire::Command;
use tokio::sync::Mutex;
use tokio_cron_scheduler::{Job, JobScheduler};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::commands::{CommandSource, handle_command};
use crate::nats_retry;
use crate::script_cache::ScriptCache;

/// A Manifest plus any pre-resolved metadata `local_tick` needs to
/// build a Command without touching the broker.
///
/// `script_object_sha256` is populated at `apply_resync` time (when
/// the broker is by definition reachable — we just listed
/// BUCKET_JOBS); `local_tick` reads it from cache so a
/// `runs_on: agent` schedule keeps firing `script_object:`
/// manifests after the broker goes away.
///
/// `None` covers two cases:
///   - inline-`script:` manifests (no digest needed)
///   - `script_object:` manifests whose digest fetch failed at
///     the last resync (broker race, bucket missing, …); these
///     skip the tick the same way pre-cache code did
#[derive(Clone, Debug)]
struct ResolvedJob {
    manifest: Manifest,
    /// Lowercase hex sha256 the agent's script_cache will verify
    /// fetched bytes against. Only set when `manifest.execute
    /// .script_object` is `Some` AND `digest_of` succeeded.
    script_object_sha256: Option<String>,
}

/// In-memory state shared across the watch loops and the tick
/// callbacks. Wrapped in a single `Mutex<State>` because the scheduler
/// only ticks one job at a time and the watch loops are also serial.
struct State {
    /// Latest snapshot of every job in BUCKET_JOBS plus any
    /// pre-resolved script_object digest (Gemini #214 HIGH fix —
    /// keeps `local_tick` offline-tolerant by removing its network
    /// round-trip).
    jobs: HashMap<String, ResolvedJob>,
    /// schedule_id → internal cron Uuid (for removing the Job).
    registered: HashMap<String, Uuid>,
    /// schedule_id → cached Schedule (so the tick callback knows
    /// what it's running without re-fetching).
    schedules: HashMap<String, Schedule>,
    /// Last-success timestamps keyed by `<schedule_id>::<job_id>`,
    /// persisted to `local_completions.json`.
    completions: HashMap<String, DateTime<Utc>>,
    /// Path to the completions file (under agent's data dir).
    completions_path: PathBuf,
    /// #418 event triggers: `schedule_id` → the OS `boot_time` (epoch
    /// secs) we last fired an `on: startup` schedule for. Lets the boot
    /// path fire startup schedules **once per OS boot** rather than on
    /// every agent restart (self-update / crash) within the same boot.
    /// Persisted to `startup_markers.json` so it survives the restart.
    startup_markers: HashMap<String, u64>,
    /// Path to the startup-markers file (under agent's data dir).
    startup_markers_path: PathBuf,
    /// schedule_id → deadline. While a fire's `handle_command` runs,
    /// the schedule is marked here so a concurrent tick doesn't
    /// double-fire before the first run records its completion
    /// (#445). `tokio-cron-scheduler` spawns each tick's callback
    /// (`cron_job.rs` `tokio::task::spawn`) rather than awaiting the
    /// previous one, so a `jitter` longer than the 1-minute poll lets
    /// later ticks start while the first is still sleeping in jitter —
    /// all seeing the same stale `completions`. The value is a
    /// self-healing deadline (`claim time + jitter + timeout + slack`):
    /// after a task dies past it, the next tick can reclaim the mark.
    /// A living task (including one queued for a slot) is protected by
    /// `live_fires` even beyond this deadline. Not persisted.
    in_flight: HashMap<String, DateTime<Utc>>,
    /// A living task may wait for a local slot beyond its historical TTL.
    /// Weak ownership prevents a cancelled/panicked task from wedging dedup.
    live_fires: HashMap<String, std::sync::Weak<()>>,
    /// Last-known fleet change-freeze (#418 Phase 5), kept fresh by
    /// [`spawn_freeze_watch_task`] (a `fleet_config` KV watcher) — NOT
    /// re-read per tick (gemini #472). Cached here so a freeze set
    /// before the agent went offline still holds while the broker is
    /// unreachable (the whole point of `runs_on: agent`). `None` ⇒ not
    /// frozen (key absent on the last successful read / watch event).
    freeze: Option<kanade_shared::manifest::Freeze>,
}

impl State {
    fn matching(&self, schedule: &Schedule, pc_id: &str, my_groups: &[String]) -> bool {
        matches!(schedule.runs_on, RunsOn::Agent)
            && schedule.enabled
            && target_includes(schedule, pc_id, my_groups)
    }

    fn key(schedule_id: &str, job_id: &str) -> String {
        format!("{schedule_id}::{job_id}")
    }

    fn record_completion(&mut self, schedule_id: &str, job_id: &str, when: DateTime<Utc>) {
        self.completions
            .insert(Self::key(schedule_id, job_id), when);
        if let Err(e) = self.flush_completions() {
            warn!(
                error = %e,
                "local_completions.json flush failed; in-memory state still consistent",
            );
        }
    }

    /// Atomically decide whether THIS tick should fire AND mark the
    /// schedule in-flight (#445). Returns `(claimed, reclaimed_stale)`:
    /// `claimed` is true iff the caller owns the fire and must later
    /// call [`finish_fire`](Self::finish_fire); `reclaimed_stale` is
    /// true when an overdue previous claim was taken over (the caller
    /// warns). Doing the dedup re-check and the in-flight mark under
    /// one `&mut self` borrow is what makes it atomic — two concurrent
    /// ticks can't both pass, since the second one observes the
    /// first's `in_flight` entry.
    ///
    /// `claim_ttl` is the longest a legitimate run can take
    /// (`jitter + timeout + slack`) without queueing. Past it, a claim
    /// whose task is no longer alive is reclaimed without a restart.
    fn try_claim_fire(
        &mut self,
        schedule_id: &str,
        job_id: &str,
        mode: ExecMode,
        cooldown: Option<ChronoDuration>,
        now: DateTime<Utc>,
        claim_ttl: ChronoDuration,
    ) -> (bool, bool) {
        if self
            .live_fires
            .get(schedule_id)
            .is_some_and(|task| task.strong_count() > 0)
        {
            return (false, false);
        }
        let should = match mode {
            // Event triggers fire on each occurrence — the OS event
            // source already decided "now" (boot / logon). Per-occurrence
            // dedup (startup once-per-boot) is the caller's job; here we
            // only gate concurrent double-claims via `in_flight`.
            ExecMode::EveryTick | ExecMode::Event => true,
            ExecMode::OncePerPc => match self.completions.get(&Self::key(schedule_id, job_id)) {
                None => true,
                Some(last) => cooldown.is_some_and(|cd| (now - *last) >= cd),
            },
            // Both are backend-only — validate() rejects them for
            // runs_on: agent (per_target needs fleet-wide completion data;
            // once_per_version needs the backend's per-version completion
            // history). Unreachable except via a hand-edited KV blob;
            // fail CLOSED (don't claim) rather than run with the wrong
            // semantics. local_tick's match warns + skips these loudly.
            ExecMode::OncePerTarget | ExecMode::OncePerPcVersion => false,
        };
        if !should {
            return (false, false);
        }
        let reclaimed_stale = match self.in_flight.get(schedule_id) {
            // A previous run is still within its own deadline — block
            // this concurrent tick.
            Some(&deadline) if now < deadline => return (false, false),
            // Overdue: the previous run overran jitter+timeout or died
            // — take it over.
            Some(_) => true,
            None => false,
        };
        self.in_flight
            .insert(schedule_id.to_string(), now + claim_ttl);
        (true, reclaimed_stale)
    }

    /// Release the in-flight mark (#445); on success also record the
    /// completion so subsequent ticks dedup against it.
    ///
    /// `deadline` is the token this run claimed (its `in_flight`
    /// value). The slot is released **only if it still holds that
    /// deadline** (gemini #463 review): if this run overran and a
    /// later tick already reclaimed the slot (a fresh deadline), a
    /// late `finish_fire` from the dead/overrun run must NOT clear the
    /// new owner's mark — otherwise a third tick could double-fire
    /// alongside the reclaimer. The completion is still recorded on
    /// success regardless (it's a real success; the latest wins).
    fn finish_fire(
        &mut self,
        schedule_id: &str,
        job_id: &str,
        deadline: DateTime<Utc>,
        success_at: Option<DateTime<Utc>>,
    ) {
        if self.in_flight.get(schedule_id) == Some(&deadline) {
            self.in_flight.remove(schedule_id);
            self.live_fires.remove(schedule_id);
        }
        if let Some(when) = success_at {
            self.record_completion(schedule_id, job_id, when);
        }
    }

    /// Is there a *live* (non-expired) in-flight claim for this
    /// schedule? A cheap early short-circuit (claude #463 review) so a
    /// concurrent tick blocked by an in-flight run skips before
    /// building the Command and hitting KV. TTL-aware on purpose: a
    /// stale entry with no living task falls through to `try_claim_fire`
    /// for reclamation. Queueing can legitimately outlast the TTL.
    fn is_live_in_flight(&self, schedule_id: &str, now: DateTime<Utc>) -> bool {
        if self
            .live_fires
            .get(schedule_id)
            .is_some_and(|task| task.strong_count() > 0)
        {
            return true;
        }
        self.in_flight
            .get(schedule_id)
            .is_some_and(|&deadline| now < deadline)
    }

    fn flush_completions(&self) -> Result<()> {
        let tmp = self.completions_path.with_extension("json.tmp");
        let bytes =
            serde_json::to_vec_pretty(&self.completions).context("serialise local_completions")?;
        if let Some(parent) = tmp.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&tmp, &bytes).context("write tmp completions file")?;
        std::fs::rename(&tmp, &self.completions_path).context("rename tmp → final")?;
        Ok(())
    }

    fn load_completions(path: &std::path::Path) -> HashMap<String, DateTime<Utc>> {
        match std::fs::read(path) {
            Ok(bytes) => match serde_json::from_slice(&bytes) {
                Ok(m) => m,
                Err(e) => {
                    warn!(error = %e, path = %path.display(), "parse local_completions; starting empty");
                    HashMap::new()
                }
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                warn!(error = %e, path = %path.display(), "read local_completions; starting empty");
                HashMap::new()
            }
        }
    }

    /// Record that an `on: startup` schedule fired for this OS boot, and
    /// persist (best-effort, like completions — in-memory state stays
    /// consistent on a write failure).
    fn record_startup_marker(&mut self, schedule_id: &str, boot_time: u64) {
        self.startup_markers
            .insert(schedule_id.to_string(), boot_time);
        if let Err(e) = self.flush_startup_markers() {
            warn!(error = %e, "startup_markers.json flush failed; in-memory state still consistent");
        }
    }

    fn flush_startup_markers(&self) -> Result<()> {
        let tmp = self.startup_markers_path.with_extension("json.tmp");
        let bytes = serde_json::to_vec_pretty(&self.startup_markers)
            .context("serialise startup_markers")?;
        if let Some(parent) = tmp.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        std::fs::write(&tmp, &bytes).context("write tmp startup_markers file")?;
        std::fs::rename(&tmp, &self.startup_markers_path).context("rename tmp → final")?;
        Ok(())
    }

    fn load_startup_markers(path: &std::path::Path) -> HashMap<String, u64> {
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
                warn!(error = %e, path = %path.display(), "parse startup_markers; starting empty");
                HashMap::new()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => HashMap::new(),
            Err(e) => {
                warn!(error = %e, path = %path.display(), "read startup_markers; starting empty");
                HashMap::new()
            }
        }
    }
}

/// How far apart two `boot_time` readings may be and still count as the
/// **same** OS boot. `boot_time` is derived (`now − uptime`) so NTP /
/// clock adjustments jitter it by seconds across a boot session; two
/// *distinct* boots are always minutes apart (shutdown + boot). 120s
/// absorbs the jitter without ever merging two real boots.
const STARTUP_BOOT_THRESHOLD_SECS: u64 = 120;

/// Pure decision for an `on: startup` fire (`#418`). Returns whether the
/// schedule should fire on this agent run:
/// - `recorded`: the `boot_time` we last fired this schedule for (`None`
///   = never fired on this host).
/// - `current_boot`: this OS boot time (epoch secs).
/// - `uptime_secs`: `now − current_boot` (how long after boot the agent
///   reached this point).
/// - `deadline_secs`: the schedule's `starting_deadline` in seconds, if
///   set — only fire when the agent came up within it after boot.
///
/// Fires when it's a **new boot** (no marker, or `current_boot` differs
/// from `recorded` by more than [`STARTUP_BOOT_THRESHOLD_SECS`]) AND, if
/// a `starting_deadline` is set, the agent is still within it. A restart
/// in the *same* boot (self-update / crash) is the same boot → skip.
fn should_fire_startup(
    recorded: Option<u64>,
    current_boot: u64,
    uptime_secs: u64,
    deadline_secs: Option<u64>,
) -> bool {
    let new_boot = match recorded {
        None => true,
        Some(r) => current_boot.abs_diff(r) > STARTUP_BOOT_THRESHOLD_SECS,
    };
    if !new_boot {
        return false;
    }
    match deadline_secs {
        Some(d) => uptime_secs <= d,
        None => true,
    }
}

/// Does this schedule target the given agent? Pure function for
/// testability — `pc_id` and `my_groups` are the agent's own. Shared
/// with the KLP `maintenance.list` handler so its upcoming-fire
/// preview applies exactly the same targeting the live tick does.
pub(crate) fn target_includes(schedule: &Schedule, pc_id: &str, my_groups: &[String]) -> bool {
    // #816: same all / pcs / group-overlap rule as `client.visible_to`, so
    // both share the one canonical `Target::matches` implementation.
    schedule.plan.target.matches(pc_id, my_groups)
}

pub fn spawn(
    client: async_nats::Client,
    pc_id: String,
    completions_path: PathBuf,
    groups_rx: tokio::sync::watch::Receiver<Vec<String>>,
    staleness: crate::staleness::Tracker,
    script_cache: ScriptCache,
    check_sink: crate::check_cache::CheckSink,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        run(
            client,
            pc_id,
            completions_path,
            groups_rx,
            staleness,
            script_cache,
            check_sink,
        )
        .await;
    })
}

async fn run(
    client: async_nats::Client,
    pc_id: String,
    completions_path: PathBuf,
    groups_rx: tokio::sync::watch::Receiver<Vec<String>>,
    staleness: crate::staleness::Tracker,
    script_cache: ScriptCache,
    check_sink: crate::check_cache::CheckSink,
) {
    let js = async_nats::jetstream::new(client.clone());

    // The internal scheduler doesn't talk to NATS, so it's created
    // unconditionally — even a broker-down boot lets `local_tick`
    // fire as soon as we've re-primed the cache after recovery.
    let internal = match JobScheduler::new().await {
        Ok(s) => s,
        Err(e) => {
            warn!(error = %e, "local_scheduler: JobScheduler::new failed; aborting subsystem");
            return;
        }
    };
    if let Err(e) = internal.start().await {
        warn!(error = %e, "local_scheduler: JobScheduler::start failed; aborting subsystem");
        return;
    }

    let completions = State::load_completions(&completions_path);
    info!(
        path = %completions_path.display(),
        loaded = completions.len(),
        "local_scheduler: loaded completion state",
    );
    // #418 event triggers: startup once-per-boot markers live next to
    // the completions file in the same data dir.
    let startup_markers_path = completions_path.with_file_name("startup_markers.json");
    let startup_markers = State::load_startup_markers(&startup_markers_path);
    let state = Arc::new(Mutex::new(State {
        jobs: HashMap::new(),
        registered: HashMap::new(),
        schedules: HashMap::new(),
        completions,
        completions_path,
        startup_markers,
        startup_markers_path,
        in_flight: HashMap::new(),
        live_fires: HashMap::new(),
        freeze: None,
    }));

    // Long-lived auxiliary task: react to group-membership flips even
    // while the schedules / jobs watches are mid-reopen. Uses
    // `wait_for_kv` so a flip during a broker outage queues up
    // properly instead of being lost.
    let _groups_task = spawn_groups_change_task(
        client.clone(),
        pc_id.clone(),
        staleness.clone(),
        groups_rx.clone(),
        internal.clone(),
        state.clone(),
        script_cache.clone(),
        check_sink.clone(),
    );

    // #418 event triggers: a global channel lets the Windows service
    // control handler signal session events (`on: logon` / `lock` /
    // `unlock`) to this async task. Best-effort `set` (only the first
    // run wins).
    #[cfg(target_os = "windows")]
    {
        let (event_tx, event_rx) = tokio::sync::mpsc::unbounded_channel();
        let _ = SESSION_EVENT_NOTIFY.set(event_tx);
        let _session_event_task = spawn_session_event_task(
            event_rx,
            client.clone(),
            pc_id.clone(),
            groups_rx.clone(),
            state.clone(),
            staleness.clone(),
            script_cache.clone(),
            check_sink.clone(),
        );
        // #418 `on: network_change`: a blocking NotifyAddrChange watcher
        // + debouncer that routes settled network changes through the
        // same session-event channel.
        spawn_network_change_watcher();
    }

    // #418 Phase 5: mirror the fleet change-freeze into `State` so
    // local_tick gates on it without a per-tick KV get (gemini #472).
    let _freeze_task = spawn_freeze_watch_task(client.clone(), staleness.clone(), state.clone());

    // Prime the freeze mirror SYNCHRONOUSLY before the reconcile loop
    // below registers any schedule — otherwise the first tick of a
    // schedule could fire in the gap before the async watch task seeds,
    // punching through a freeze that was set before this boot
    // (coderabbit #472 CRITICAL). Best-effort: offline at boot → stays
    // `None` until the watch seeds on connect (an offline agent can't
    // know the freeze state anyway).
    match js.get_key_value(BUCKET_FLEET_CONFIG).await {
        Ok(kv) => match kv.get(KEY_FREEZE).await {
            Ok(Some(bytes)) => state.lock().await.freeze = Some(parse_freeze_or_safe(&bytes)),
            Ok(None) => {} // not frozen — State.freeze is already None
            Err(e) => warn!(error = %e, "freeze boot-prime get failed; watch task will seed"),
        },
        Err(e) => warn!(error = %e, "freeze boot-prime KV unavailable; watch task will seed"),
    }

    // Outer reconnect loop. Owns schedules_kv + jobs_kv handles and
    // both `watch_all` streams; re-syncs caches + reconciles on
    // every (re-)entry so edits made during a disconnect get picked
    // up.
    loop {
        let schedules_kv = nats_retry::wait_for_kv(
            &js,
            &client,
            &staleness,
            BUCKET_SCHEDULES,
            "local_scheduler",
        )
        .await;
        let jobs_kv =
            nats_retry::wait_for_kv(&js, &client, &staleness, BUCKET_JOBS, "local_scheduler").await;

        // Walk both KVs into FRESH collections first. Don't touch
        // live state until both walks succeed end-to-end — a partial
        // failure must NOT clear the in-memory caches (Gemini #147
        // review: a transient keys() error would otherwise leave
        // the scheduler empty until the next watch event arrives).
        let new_jobs = match collect_jobs(&jobs_kv).await {
            Ok(j) => j,
            Err(()) => {
                warn!("local_scheduler: jobs KV walk failed; keeping previous state and reopening");
                nats_retry::reopen_pause().await;
                continue;
            }
        };
        let new_schedules = match collect_schedules(&schedules_kv).await {
            Ok(s) => s,
            Err(()) => {
                warn!(
                    "local_scheduler: schedules KV walk failed; keeping previous state and reopening"
                );
                nats_retry::reopen_pause().await;
                continue;
            }
        };

        let my_groups = groups_rx.borrow().clone();
        info!(
            pc_id = %pc_id,
            groups = ?my_groups,
            jobs = new_jobs.len(),
            schedules = new_schedules.len(),
            "local_scheduler: applying resync",
        );
        apply_resync(
            &internal,
            &state,
            &client,
            &pc_id,
            &my_groups,
            &staleness,
            &script_cache,
            &check_sink,
            new_jobs,
            new_schedules,
        )
        .await;
        let count = state.lock().await.registered.len();
        info!(count, "local_scheduler: registered schedules after resync");

        // #418 event triggers: fire `on: startup` schedules once per OS
        // boot (deduped by the host boot_time marker, so re-running this
        // on a reconnect within the same boot is a no-op). Runs after the
        // bulk reconcile so the event schedules are cached.
        fire_startup_schedules(
            &client,
            &pc_id,
            &state,
            &my_groups,
            &staleness,
            &script_cache,
            &check_sink,
        )
        .await;

        let mut schedules_watch = match schedules_kv.watch_all().await {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "schedules KV watch_all failed; reopening");
                nats_retry::reopen_pause().await;
                continue;
            }
        };
        let mut jobs_watch = match jobs_kv.watch_all().await {
            Ok(w) => w,
            Err(e) => {
                warn!(error = %e, "jobs KV watch_all failed; reopening");
                nats_retry::reopen_pause().await;
                continue;
            }
        };

        // Inner select loop. `break` (with label) on either watch
        // dropping so we re-prime both together.
        let dropped = 'inner: loop {
            tokio::select! {
                entry = schedules_watch.next() => {
                    let Some(entry) = entry else { break 'inner "schedules" };
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => { warn!(error = %e, "schedules watch error"); continue; }
                    };
                    let groups_snapshot = groups_rx.borrow().clone();
                    match entry.operation {
                        Operation::Put => {
                            if let Ok(s) = serde_json::from_slice::<Schedule>(&entry.value) {
                                reconcile_schedule(
                                    &internal, &state, &client, &pc_id, &groups_snapshot, &s, &staleness, &script_cache, &check_sink,
                                )
                                .await;
                            } else {
                                warn!(key = %entry.key, "deserialize Schedule on watch");
                            }
                        }
                        Operation::Delete | Operation::Purge => {
                            unregister_locally(&internal, &state, &entry.key).await;
                        }
                    }
                }
                entry = jobs_watch.next() => {
                    let Some(entry) = entry else { break 'inner "jobs" };
                    let entry = match entry {
                        Ok(e) => e,
                        Err(e) => { warn!(error = %e, "jobs watch error"); continue; }
                    };
                    match entry.operation {
                        Operation::Put => {
                            let Ok(m) = serde_json::from_slice::<Manifest>(&entry.value) else {
                                warn!(key = %entry.key, "local_scheduler: parse Manifest from jobs watch");
                                continue;
                            };
                            // Resolve digest BEFORE taking the lock —
                            // the call is a NATS round-trip and we
                            // don't want `local_tick` blocked behind
                            // it. Falls back to None on broker
                            // failure (tick skips that job until the
                            // next watch event succeeds).
                            let sha = match m.execute.script_object.as_deref() {
                                Some(key) => match script_cache.digest_of(key).await {
                                    Ok(d) => Some(d),
                                    Err(e) => {
                                        warn!(
                                            job_id = %entry.key,
                                            %key,
                                            error = %e,
                                            "jobs watch: digest fetch failed; caching manifest with digest=None",
                                        );
                                        None
                                    }
                                },
                                None => None,
                            };
                            let active_slugs = {
                                let mut s = state.lock().await;
                                s.jobs.insert(
                                    entry.key.clone(),
                                    ResolvedJob { manifest: m, script_object_sha256: sha },
                                );
                                active_check_slugs(&s.jobs)
                            };
                            check_sink.set_active_slugs(active_slugs);
                            debug!(job_id = %entry.key, "local_scheduler: cached job manifest");
                        }
                        Operation::Delete | Operation::Purge => {
                            // Keep the Health tab in step with the delete:
                            // recompute the live check-slug set so the
                            // gone job's cached check stops showing.
                            let active_slugs = {
                                let mut s = state.lock().await;
                                s.jobs.remove(&entry.key);
                                active_check_slugs(&s.jobs)
                            };
                            check_sink.set_active_slugs(active_slugs);
                        }
                    }
                }
            }
        };
        warn!(dropped, "local_scheduler watch ended; reopening");
        nats_retry::reopen_pause().await;
    }
}

/// The set of `check:` hint slugs across every job currently in
/// `BUCKET_JOBS`. The local scheduler publishes this to the
/// [`crate::check_cache::CheckSink`] after every jobs change so a check
/// whose job was **deleted** drops off the client's Health tab — once a
/// `check:` job stops running, nothing ever overwrites its cached
/// result, so without this it lingers forever.
///
/// Keyed on plain job existence (not schedule targeting): a delete is
/// the trigger, and including a slug whose check this PC never ran is a
/// harmless no-op — the read-time filter in `checks()` only ever
/// *removes* cached rows, never adds them.
fn active_check_slugs(jobs: &HashMap<String, ResolvedJob>) -> HashSet<String> {
    jobs.values()
        .filter_map(|j| j.manifest.check.as_ref())
        .map(|c| c.name.clone())
        .collect()
}

/// Walk `BUCKET_JOBS` into a fresh in-memory map. Returns `Err(())`
/// if `kv.keys()` itself fails — caller must treat that as
/// "connectivity-level failure, keep existing cache" rather than
/// "no jobs" (Gemini #147 review).
async fn collect_jobs(
    jobs_kv: &async_nats::jetstream::kv::Store,
) -> Result<HashMap<String, Manifest>, ()> {
    let keys = match jobs_kv.keys().await {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "local_scheduler: jobs_kv.keys() failed");
            return Err(());
        }
    };
    // #916: propagate a mid-stream enumeration fault instead of
    // truncating to the keys collected so far — `unwrap_or_default()`
    // turned a broker flap into an empty-but-Ok list, which made
    // apply_resync unregister every schedule (defeating the
    // "keep previous state on a partial walk" invariant above).
    let keys: Vec<String> = match keys.try_collect().await {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "local_scheduler: jobs_kv key stream faulted mid-walk");
            return Err(());
        }
    };
    let mut out = HashMap::with_capacity(keys.len());
    for k in keys {
        match jobs_kv.get(&k).await {
            Ok(Some(bytes)) => {
                // A decode failure is permanently-bad stored data, not a
                // transient error — skip that one job (we can't run what
                // we can't parse) rather than aborting the whole resync.
                if let Ok(m) = serde_json::from_slice::<Manifest>(&bytes) {
                    out.insert(k, m);
                } else {
                    warn!(key = %k, "local_scheduler: undecodable job blob; skipping");
                }
            }
            // Key vanished between keys() and get() — a benign delete
            // race; it's genuinely absent now, so leave it out.
            Ok(None) => {}
            Err(e) => {
                // #916: a transient get failure must abort the walk, not
                // drop the job — dropping it would unregister its
                // schedules on a broker hiccup.
                warn!(key = %k, error = %e, "local_scheduler: jobs_kv.get() failed mid-walk");
                return Err(());
            }
        }
    }
    Ok(out)
}

/// Walk `BUCKET_SCHEDULES` into a fresh list. Returns `Err(())` on
/// keys() failure — same rationale as [`collect_jobs`].
async fn collect_schedules(
    schedules_kv: &async_nats::jetstream::kv::Store,
) -> Result<Vec<Schedule>, ()> {
    let keys = match schedules_kv.keys().await {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "local_scheduler: schedules_kv.keys() failed");
            return Err(());
        }
    };
    // #916: propagate a mid-stream enumeration fault (see collect_jobs).
    let keys: Vec<String> = match keys.try_collect().await {
        Ok(k) => k,
        Err(e) => {
            warn!(error = %e, "local_scheduler: schedules_kv key stream faulted mid-walk");
            return Err(());
        }
    };
    let mut out = Vec::with_capacity(keys.len());
    for k in keys {
        match schedules_kv.get(&k).await {
            Ok(Some(bytes)) => {
                if let Ok(s) = serde_json::from_slice::<Schedule>(&bytes) {
                    out.push(s);
                } else {
                    warn!(key = %k, "local_scheduler: undecodable schedule blob; skipping");
                }
            }
            Ok(None) => {}
            Err(e) => {
                // #916: transient get failure aborts the walk rather than
                // dropping (and thus unregistering) the schedule.
                warn!(key = %k, error = %e, "local_scheduler: schedules_kv.get() failed mid-walk");
                return Err(());
            }
        }
    }
    Ok(out)
}

/// Atomically apply a fresh `new_jobs` / `new_schedules` snapshot.
/// Schedules that disappeared from KV (vs the in-memory cache) are
/// unregistered; remaining schedules are reconciled against the
/// new job manifests. Replaces the old `reset_state + prime` path
/// which would clear in-memory caches *before* trying to refill
/// them — a partial walk failure left the scheduler empty.
#[allow(clippy::too_many_arguments)]
async fn apply_resync(
    internal: &JobScheduler,
    state: &Arc<Mutex<State>>,
    client: &async_nats::Client,
    pc_id: &str,
    my_groups: &[String],
    staleness: &crate::staleness::Tracker,
    script_cache: &ScriptCache,
    check_sink: &crate::check_cache::CheckSink,
    new_jobs: HashMap<String, Manifest>,
    new_schedules: Vec<Schedule>,
) {
    // Resolve each manifest into a `ResolvedJob` — pre-fetch the
    // OBJECT_SCRIPTS digest for `script_object:` manifests so
    // `local_tick` reads it from cache (offline-tolerant; Gemini
    // #214 HIGH). Digest fetches happen here because we're already
    // talking to the broker — wait_for_kv returned the manifests
    // moments ago, so the digest_of call is on a warm path.
    //
    // A failed digest_of degrades to `script_object_sha256: None`,
    // which `local_tick` treats the same as "no cached digest" =
    // skip-with-warn. The manifest still gets cached so a later
    // resync with a healthier broker can populate the digest.
    //
    // Digests are resolved in parallel via `join_all` (Gemini #216
    // MED) so a fleet with many `script_object:` manifests doesn't
    // serialize N round-trips. Inline-only manifests skip the
    // network entirely — the async branch returns immediately.
    let resolve_futs = new_jobs.into_iter().map(|(id, manifest)| {
        let script_cache = script_cache.clone();
        async move {
            let script_object_sha256 = match manifest.execute.script_object.as_deref() {
                Some(key) => match script_cache.digest_of(key).await {
                    Ok(d) => Some(d),
                    Err(e) => {
                        warn!(
                            job_id = %id,
                            %key,
                            error = %e,
                            "apply_resync: script_object digest fetch failed; \
                             tick will skip until next successful resync",
                        );
                        None
                    }
                },
                None => None,
            };
            (
                id,
                ResolvedJob {
                    manifest,
                    script_object_sha256,
                },
            )
        }
    });
    let resolved: HashMap<String, ResolvedJob> = futures::future::join_all(resolve_futs)
        .await
        .into_iter()
        .collect();

    // Swap the jobs map atomically — under the lock so `local_tick`
    // sees either the old map in full or the new map in full, never
    // a half-cleared one.
    let active_slugs = {
        let mut st = state.lock().await;
        st.jobs = resolved;
        // Recompute the live check-slug set while we hold the lock so it
        // can't drift from `st.jobs`. Publishing it prunes the client's
        // Health tab of checks whose job an operator deleted (see
        // [`check_cache::CheckSink::set_active_slugs`]).
        active_check_slugs(&st.jobs)
    };
    check_sink.set_active_slugs(active_slugs);

    // Find schedules that vanished from KV → unregister them. Done
    // before the reconciliations so the diff is unambiguous.
    let new_ids: std::collections::HashSet<String> =
        new_schedules.iter().map(|s| s.id.clone()).collect();
    let stale_ids: Vec<String> = {
        let st = state.lock().await;
        st.schedules
            .keys()
            .filter(|id| !new_ids.contains(*id))
            .cloned()
            .collect()
    };
    for id in stale_ids {
        unregister_locally(internal, state, &id).await;
    }

    // Reconcile each schedule from the new snapshot. Updates the
    // cron registration in place where the schedule changed
    // (target / cron / enabled); no-ops where it's identical.
    for s in &new_schedules {
        reconcile_schedule(
            internal,
            state,
            client,
            pc_id,
            my_groups,
            s,
            staleness,
            script_cache,
            check_sink,
        )
        .await;
    }
}

/// v0.24: group-membership change handler. Re-reconciles every
/// schedule the agent already knows about so `target.groups` overlap
/// re-evaluates without waiting for the next schedule edit. Uses
/// `wait_for_kv` so a flip during a broker outage queues up and
/// reconciles once the link is back instead of being silently
/// dropped (`groups_rx.changed()` is edge-triggered; if we miss the
/// edge by being mid-disconnect we never get it again).
///
/// When the schedules-KV walk fails (`collect_schedules` returns
/// `Err(())`), we skip the iteration and wait for the next group
/// flip — better to defer reconciliation than to interpret a
/// transient read failure as "schedules vanished" and drop every
/// agent-side cron (sub-agent #147 review).
#[allow(clippy::too_many_arguments)]
fn spawn_groups_change_task(
    client: async_nats::Client,
    pc_id: String,
    staleness: crate::staleness::Tracker,
    mut groups_rx_for_watch: tokio::sync::watch::Receiver<Vec<String>>,
    internal: JobScheduler,
    state: Arc<Mutex<State>>,
    script_cache: ScriptCache,
    check_sink: crate::check_cache::CheckSink,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let js = async_nats::jetstream::new(client.clone());
        // Skip the initial value — already used in run()'s prime
        // pass. Future changes flow through here.
        loop {
            if groups_rx_for_watch.changed().await.is_err() {
                break;
            }
            let new_groups = groups_rx_for_watch.borrow().clone();
            info!(
                groups = ?new_groups,
                "local_scheduler: group membership changed; re-reconciling all schedules",
            );
            // Walk schedules KV again with retry semantics — a flip
            // during broker-down would otherwise be lost.
            let kv = nats_retry::wait_for_kv(
                &js,
                &client,
                &staleness,
                BUCKET_SCHEDULES,
                "local_scheduler_groups",
            )
            .await;
            let new_schedules = match collect_schedules(&kv).await {
                Ok(s) => s,
                Err(()) => {
                    warn!(
                        "local_scheduler: groups change resync — schedules walk failed; skipping iteration"
                    );
                    continue;
                }
            };
            // Compute the set of current schedules so we can drop
            // any that vanished. Done before reconciles so the diff
            // is unambiguous.
            let new_ids: std::collections::HashSet<String> =
                new_schedules.iter().map(|s| s.id.clone()).collect();
            let stale_ids: Vec<String> = {
                let st = state.lock().await;
                st.schedules
                    .keys()
                    .filter(|id| !new_ids.contains(*id))
                    .cloned()
                    .collect()
            };
            for id in stale_ids {
                unregister_locally(&internal, &state, &id).await;
            }
            for s in &new_schedules {
                reconcile_schedule(
                    &internal,
                    &state,
                    &client,
                    &pc_id,
                    &new_groups,
                    s,
                    &staleness,
                    &script_cache,
                    &check_sink,
                )
                .await;
            }
        }
    })
}

// v0.24: `read_my_groups` removed — membership now flows through the
// `groups::spawn` watch channel that `local_scheduler` subscribes to,
// so we no longer poll the KV ourselves.

/// Reconcile a single schedule: drop any existing cron registration
/// for the same id, then re-register it if it targets this agent.
///
/// Holds `state.lock()` for the entire body — including across the
/// async `internal.remove()` and `internal.add()` calls. This is
/// deliberate: two concurrent callers (the inner watch loop and
/// `spawn_groups_change_task`) can otherwise interleave their
/// `internal.add` calls and leave two cron entries for the same
/// schedule_id in the scheduler while `state.registered` records
/// only the second uuid — an orphaned cron that double-fires every
/// tick until the agent restarts (sub-agent #147 review F1).
///
/// The lock-across-await is supported by `tokio::sync::Mutex` and
/// is acceptable here because reconciles are infrequent (per Put
/// event from the schedules KV watch, or per group-change flip).
/// The cron callback (`local_tick`) also locks `state`, but it does
/// so briefly and only inside the tick handler — never while
/// reconcile is running, since reconcile holds the lock for ~ms
/// (internal.add is in-memory).
#[allow(clippy::too_many_arguments)]
async fn reconcile_schedule(
    internal: &JobScheduler,
    state: &Arc<Mutex<State>>,
    client: &async_nats::Client,
    pc_id: &str,
    my_groups: &[String],
    schedule: &Schedule,
    staleness: &crate::staleness::Tracker,
    script_cache: &ScriptCache,
    check_sink: &crate::check_cache::CheckSink,
) {
    let mut st = state.lock().await;
    let mine = st.matching(schedule, pc_id, my_groups);

    // Always unregister an existing copy first — cron / target /
    // enabled edits all need to land.
    if let Some(uuid) = st.registered.remove(&schedule.id) {
        st.schedules.remove(&schedule.id);
        if let Err(e) = internal.remove(&uuid).await {
            warn!(error = %e, schedule_id = %schedule.id, "local_scheduler: remove failed");
        } else {
            info!(schedule_id = %schedule.id, "local_scheduler: unregistered");
        }
    }

    if !mine {
        return;
    }

    // #418 event triggers (`when: { on }`): no cron — fired by the OS
    // event source (boot / session-change), not a tick. Cache the
    // Schedule so the event sources can find it, but skip the
    // tokio-cron registration entirely.
    if schedule.is_event() {
        st.schedules.insert(schedule.id.clone(), schedule.clone());
        info!(
            schedule_id = %schedule.id,
            when = %schedule.when,
            "local_scheduler: registered (event-triggered, no cron)",
        );
        return;
    }

    // #418: lower `when` onto the engine cron — POLL_CRON for
    // reconcile shapes, a 6/7-field cron for calendar shapes.
    // Phase 2: evaluated in the schedule's tz via new_async_tz
    // (Local = this agent's TZ, the natural "tz: local" meaning).
    let lowered = schedule.lowered();
    let cron = lowered.cron;
    let schedule_id = schedule.id.clone();
    let client_for_job = client.clone();
    let pc_id_for_job = pc_id.to_string();
    let state_for_job = state.clone();
    let schedule_for_job = schedule.clone();
    let staleness_for_job = staleness.clone();
    let script_cache_for_job = script_cache.clone();
    let check_sink_for_job = check_sink.clone();
    let cb = move |_uuid, _l| {
        let client = client_for_job.clone();
        let pc_id = pc_id_for_job.clone();
        let state = state_for_job.clone();
        let schedule = schedule_for_job.clone();
        let staleness = staleness_for_job.clone();
        let script_cache = script_cache_for_job.clone();
        let check_sink = check_sink_for_job.clone();
        Box::pin(async move {
            local_tick(
                &client,
                &pc_id,
                &state,
                &schedule,
                &staleness,
                &script_cache,
                &check_sink,
            )
            .await;
        }) as std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
    };
    let built = match lowered.tz {
        ScheduleTz::Utc => Job::new_async_tz(cron.as_str(), chrono::Utc, cb),
        ScheduleTz::Local => Job::new_async_tz(cron.as_str(), chrono::Local, cb),
    };
    let job = match built {
        Ok(j) => j,
        Err(e) => {
            warn!(
                schedule_id = %schedule.id,
                error = %e,
                "local_scheduler: Job::new_async_tz failed",
            );
            return;
        }
    };
    let job_uuid = match internal.add(job).await {
        Ok(u) => u,
        Err(e) => {
            warn!(
                schedule_id = %schedule.id,
                error = %e,
                "local_scheduler: internal.add failed",
            );
            return;
        }
    };
    st.schedules.insert(schedule.id.clone(), schedule.clone());
    st.registered.insert(schedule.id.clone(), job_uuid);
    info!(
        schedule_id = %schedule_id,
        when = %schedule.when,
        poll_cron = %cron,
        tz = ?lowered.tz,
        "local_scheduler: registered",
    );
    // A past-dated calendar one-shot never fires — warn so it's
    // diagnosable from the agent log (claude #432 review). Mirrors
    // the backend scheduler's register() check.
    if let When::Calendar(c) = &schedule.when {
        if let Some(fires_at) = c.oneshot_instant(schedule.tz) {
            if fires_at < Utc::now() {
                warn!(
                    schedule_id = %schedule_id,
                    %fires_at,
                    "local_scheduler: calendar one-shot date is in the past — it will never fire",
                );
            }
        }
    }
    // A corrupt constraints.window fails closed — warn so the stuck
    // schedule is diagnosable (gemini #452 review).
    if let Some(err) = schedule.bad_window() {
        warn!(
            schedule_id = %schedule_id,
            %err,
            "local_scheduler: constraints.window unparseable — blocked (fail-closed) until fixed",
        );
    }
    // A corrupt constraints.skip_dates entry fails closed too (#418).
    if let Some(err) = schedule.constraints.bad_skip_date() {
        warn!(
            schedule_id = %schedule_id,
            %err,
            "local_scheduler: constraints.skip_dates unparseable — blocked (fail-closed) until fixed",
        );
    }
    // A calendar whose `at` can never fall in its window never fires
    // (claude #452 review).
    if schedule.calendar_outside_window() {
        warn!(
            schedule_id = %schedule_id,
            when = %schedule.when,
            "local_scheduler: calendar fire time is outside constraints.window — it will never fire",
        );
    }
}

async fn unregister_locally(internal: &JobScheduler, state: &Arc<Mutex<State>>, schedule_id: &str) {
    let uuid_opt = {
        let mut st = state.lock().await;
        st.schedules.remove(schedule_id);
        // A KV delete is a clean teardown — drop any in-flight mark so
        // a delete+recreate with the same id isn't spuriously blocked
        // by the old run's deadline (claude #463 review). (Deliberately
        // NOT done in reconcile_schedule's unregister: an in-flight run
        // from before an *edit* should still guard the re-registered
        // schedule's first tick.)
        st.in_flight.remove(schedule_id);
        st.live_fires.remove(schedule_id);
        st.registered.remove(schedule_id)
    };
    if let Some(uuid) = uuid_opt {
        if let Err(e) = internal.remove(&uuid).await {
            warn!(error = %e, schedule_id, "local_scheduler: remove failed");
        } else {
            info!(schedule_id, "local_scheduler: unregistered");
        }
    }
}

/// Decode a fleet-freeze blob, failing *safe* on corruption: a
/// mangled value becomes a default (always-active) [`Freeze`] so the
/// agent skips rather than punch through a freeze the operator set
/// (#418 Phase 5).
fn parse_freeze_or_safe(bytes: &[u8]) -> Freeze {
    serde_json::from_slice::<Freeze>(bytes).unwrap_or_else(|e| {
        warn!(error = %e, "fleet freeze blob corrupt — failing safe (frozen)");
        Freeze::default()
    })
}

/// Long-lived task: mirror the fleet change-freeze (#418 Phase 5) into
/// [`State::freeze`] so `local_tick` reads it without a per-tick KV get
/// (gemini #472). Uses `wait_for_kv` so a freeze set during a broker
/// outage is picked up on reconnect; while disconnected the last-known
/// freeze stays in `State` (so an offline `runs_on: agent` still honors
/// a freeze that was active before it went dark). On reconnect it
/// re-seeds (catches a freeze set / cleared while away) then tails puts
/// and deletes.
fn spawn_freeze_watch_task(
    client: async_nats::Client,
    staleness: crate::staleness::Tracker,
    state: Arc<Mutex<State>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let js = async_nats::jetstream::new(client.clone());
        loop {
            let kv = nats_retry::wait_for_kv(
                &js,
                &client,
                &staleness,
                BUCKET_FLEET_CONFIG,
                "local_scheduler:freeze",
            )
            .await;
            // Re-seed on every (re-)connect. A get error leaves the
            // cached value untouched (keep last-known); Ok(None) is an
            // authoritative "not frozen".
            match kv.get(KEY_FREEZE).await {
                Ok(Some(bytes)) => state.lock().await.freeze = Some(parse_freeze_or_safe(&bytes)),
                Ok(None) => state.lock().await.freeze = None,
                Err(e) => warn!(error = %e, "freeze watch: re-seed get failed; keeping last-known"),
            }
            // `fleet_config` holds only KEY_FREEZE, so a single-key watch
            // is equivalent to the old `watch_all()` + client-side
            // `entry.key != KEY_FREEZE` filter — and #512: it scopes the
            // server-side consumer to the one key the scheduler cares
            // about instead of the whole bucket.
            let mut watch = match kv.watch(KEY_FREEZE).await {
                Ok(w) => w,
                Err(e) => {
                    warn!(error = %e, "freeze watch: watch failed; reopening");
                    nats_retry::reopen_pause().await;
                    continue;
                }
            };
            while let Some(entry) = watch.next().await {
                let entry = match entry {
                    Ok(e) => e,
                    Err(e) => {
                        warn!(error = %e, "freeze watch: entry error; reopening");
                        break;
                    }
                };
                let next = match entry.operation {
                    Operation::Put => Some(parse_freeze_or_safe(&entry.value)),
                    Operation::Delete | Operation::Purge => None,
                };
                let frozen = next.is_some();
                state.lock().await.freeze = next;
                debug!(
                    frozen,
                    "local_scheduler: fleet change-freeze mirror updated"
                );
            }
            nats_retry::reopen_pause().await;
        }
    })
}

/// #418 event triggers: fire every cached `on: startup` schedule that
/// targets this agent **once per OS boot**. The host `boot_time` +
/// per-schedule marker dedups across agent restarts (self-update /
/// crash) inside the same boot; a `starting_deadline` (if set) limits
/// firing to "the agent came up within that long after boot". Each fire
/// goes through `local_tick`, so the freeze / active / window /
/// skip_dates gates and the in-flight guard all still apply.
async fn fire_startup_schedules(
    client: &async_nats::Client,
    pc_id: &str,
    state: &Arc<Mutex<State>>,
    my_groups: &[String],
    staleness: &crate::staleness::Tracker,
    script_cache: &ScriptCache,
    check_sink: &crate::check_cache::CheckSink,
) {
    let now_secs = Utc::now().timestamp().max(0) as u64;
    // `boot_time()` returns 0 when unavailable/unsupported. Left as 0 it
    // breaks the dedup two ways (gemini #599): `uptime` becomes a huge
    // epoch so any `starting_deadline` never passes, and a recorded `0`
    // marker matches every future `0` so the schedule never fires again.
    // Fall back to the agent's start time: `on: startup` then degrades to
    // "fire on each agent start" (re-fires on restart) rather than
    // silently never firing — the safe direction for a startup trigger.
    let boot_time = match sysinfo::System::boot_time() {
        0 => {
            warn!(
                "local_scheduler: sysinfo boot_time unavailable (0); using agent start time — \
                 on:startup may re-fire on each agent restart until it reads correctly"
            );
            now_secs
        }
        bt => bt,
    };
    let uptime_secs = now_secs.saturating_sub(boot_time);

    // Snapshot the matching startup schedules + their markers under one
    // lock, then fire outside it (local_tick takes the lock itself).
    let to_fire: Vec<Schedule> = {
        let st = state.lock().await;
        st.schedules
            .values()
            .filter(|s| {
                s.event_triggers().contains(&OnTrigger::Startup) && st.matching(s, pc_id, my_groups)
            })
            .filter(|s| {
                let deadline_secs = s
                    .starting_deadline
                    .as_deref()
                    .and_then(|d| humantime::parse_duration(d).ok())
                    .map(|d| d.as_secs());
                should_fire_startup(
                    st.startup_markers.get(&s.id).copied(),
                    boot_time,
                    uptime_secs,
                    deadline_secs,
                )
            })
            .cloned()
            .collect()
    };

    for schedule in to_fire {
        info!(
            schedule_id = %schedule.id,
            boot_time,
            uptime_secs,
            "local_scheduler: firing on:startup (once per OS boot)",
        );
        // Mark synchronously BEFORE the spawn — deliberate (claude #599).
        // The marker is set under the same lock that read it, so a
        // concurrent reconnect re-running this fn sees it and can't
        // double-spawn (recording it inside the spawned task, after
        // local_tick's gates, would open a TOCTOU window). The trade-off:
        // the startup is "consumed" for this boot even if a freeze /
        // active-window blocks the actual run at this instant — that boot
        // is skipped rather than deferred. Acceptable for `on: startup`
        // (a fleet frozen at boot should stay quiet; non-event cron
        // schedules still run once unfrozen); kitting that must survive a
        // freeze uses `per_pc: once`, not an event trigger.
        state
            .lock()
            .await
            .record_startup_marker(&schedule.id, boot_time);
        // Spawn each fire so a slow / jitter-delayed run doesn't block the
        // others (matches how tokio-cron spawns each tick; gemini #599).
        // Different schedules run concurrently; the in-flight guard still
        // dedups concurrent fires of the SAME schedule.
        spawn_fire(
            client.clone(),
            pc_id.to_string(),
            state.clone(),
            schedule,
            staleness.clone(),
            script_cache.clone(),
            check_sink.clone(),
        );
    }
}

/// Spawn a single `local_tick` fire as a detached task — the
/// fire-and-forget shape tokio-cron uses for its ticks, so event fires
/// (startup / logon) don't serialise behind each other (gemini #599).
fn spawn_fire(
    client: async_nats::Client,
    pc_id: String,
    state: Arc<Mutex<State>>,
    schedule: Schedule,
    staleness: crate::staleness::Tracker,
    script_cache: ScriptCache,
    check_sink: crate::check_cache::CheckSink,
) {
    tokio::spawn(async move {
        local_tick(
            &client,
            &pc_id,
            &state,
            &schedule,
            &staleness,
            &script_cache,
            &check_sink,
        )
        .await;
    });
}

/// #418 event triggers: fire every cached event schedule that targets
/// this agent and lists `trigger` (used by the logon session-change
/// source). No per-occurrence marker — each event fires once, gated by
/// `local_tick`'s freeze / active / window checks + in-flight guard.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
#[allow(clippy::too_many_arguments)]
async fn fire_event_schedules(
    client: &async_nats::Client,
    pc_id: &str,
    state: &Arc<Mutex<State>>,
    my_groups: &[String],
    staleness: &crate::staleness::Tracker,
    script_cache: &ScriptCache,
    check_sink: &crate::check_cache::CheckSink,
    trigger: OnTrigger,
) {
    let to_fire: Vec<Schedule> = {
        let st = state.lock().await;
        st.schedules
            .values()
            .filter(|s| s.event_triggers().contains(&trigger) && st.matching(s, pc_id, my_groups))
            .cloned()
            .collect()
    };
    for schedule in to_fire {
        info!(
            schedule_id = %schedule.id,
            trigger = trigger.as_str(),
            "local_scheduler: firing event trigger",
        );
        // Spawn so multiple event schedules don't serialise (gemini #599).
        spawn_fire(
            client.clone(),
            pc_id.to_string(),
            state.clone(),
            schedule,
            staleness.clone(),
            script_cache.clone(),
            check_sink.clone(),
        );
    }
}

/// Bumped by the Windows service control handler on each interactive
/// logon (#418 `on: logon`). The scheduler subscribes and fires
/// matching event schedules. A global because the SCM control handler
/// (a sync closure in `service.rs`) can't reach the async scheduler
/// task directly.
#[cfg(target_os = "windows")]
pub(crate) static SESSION_EVENT_NOTIFY: std::sync::OnceLock<
    tokio::sync::mpsc::UnboundedSender<OnTrigger>,
> = std::sync::OnceLock::new();

/// Signal an OS session event (`logon` / `lock` / `unlock`) to the
/// scheduler. No-op until the scheduler has initialised the channel
/// (early boot, or non-running). An unbounded mpsc (not a watch) so two
/// quick events — e.g. lock then unlock — both reach the task instead of
/// coalescing to the latest.
#[cfg(target_os = "windows")]
pub(crate) fn notify_session_event(trigger: OnTrigger) {
    if let Some(tx) = SESSION_EVENT_NOTIFY.get() {
        // A send error means the receiver task is gone — i.e. the local
        // scheduler died. Warn so that's diagnosable rather than a
        // silently-dropped event (gemini #607).
        if let Err(e) = tx.send(trigger) {
            warn!(error = %e, ?trigger, "failed to signal session event — scheduler task gone?");
        }
    }
}

/// Long-lived task: fire `on: <event>` schedules each time the control
/// handler signals a session event via [`notify_session_event`].
#[cfg(target_os = "windows")]
#[allow(clippy::too_many_arguments)]
fn spawn_session_event_task(
    mut event_rx: tokio::sync::mpsc::UnboundedReceiver<OnTrigger>,
    client: async_nats::Client,
    pc_id: String,
    groups_rx: tokio::sync::watch::Receiver<Vec<String>>,
    state: Arc<Mutex<State>>,
    staleness: crate::staleness::Tracker,
    script_cache: ScriptCache,
    check_sink: crate::check_cache::CheckSink,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(trigger) = event_rx.recv().await {
            let my_groups = groups_rx.borrow().clone();
            fire_event_schedules(
                &client,
                &pc_id,
                &state,
                &my_groups,
                &staleness,
                &script_cache,
                &check_sink,
                trigger,
            )
            .await;
        }
    })
}

/// How long the network must be quiet before a burst of address changes
/// (one connect / DHCP renew / VPN / Wi-Fi roam emits several) counts as
/// a single `on: network_change` fire.
#[cfg(target_os = "windows")]
const NETWORK_CHANGE_DEBOUNCE_SECS: u64 = 8;

/// #418 `on: network_change`: watch the OS for IP-address-table changes
/// and route settled changes through [`notify_session_event`] (so they
/// share the session-event fire path). A dedicated OS thread runs the
/// blocking `NotifyAddrChange` (it returns once per change); an async
/// debouncer coalesces a burst into one fire after the network is quiet
/// for [`NETWORK_CHANGE_DEBOUNCE_SECS`].
#[cfg(target_os = "windows")]
fn spawn_network_change_watcher() {
    let (raw_tx, mut raw_rx) = tokio::sync::mpsc::unbounded_channel::<()>();

    // Async debouncer: one fire per settled burst.
    tokio::spawn(async move {
        let debounce = std::time::Duration::from_secs(NETWORK_CHANGE_DEBOUNCE_SECS);
        while raw_rx.recv().await.is_some() {
            // Drain further changes until the network is quiet for the
            // whole debounce window, then fire once.
            loop {
                tokio::select! {
                    next = raw_rx.recv() => {
                        if next.is_none() { return; } // watcher thread gone
                        // another change arrived — keep waiting
                    }
                    _ = tokio::time::sleep(debounce) => break,
                }
            }
            debug!("local_scheduler: network change settled — firing on:network_change");
            notify_session_event(OnTrigger::NetworkChange);
        }
    });

    // Blocking watcher on a dedicated OS thread: NotifyAddrChange(NULL,
    // NULL) blocks until the next IPv4 address-table change.
    let spawned = std::thread::Builder::new()
        .name("kanade-netwatch".into())
        .spawn(move || {
            use windows::Win32::NetworkManagement::IpHelper::NotifyAddrChange;
            // Floor on how often the blocking call may return. Normally
            // NotifyAddrChange genuinely blocks until the next change, but
            // under anomalies (IP Helper service restart, driver glitch) it
            // can return immediately and spin the thread at 100% CPU. Pace
            // it to one wakeup / 500ms so a pathological stack can't melt a
            // core (gemini #612).
            const MIN_INTERVAL: std::time::Duration = std::time::Duration::from_millis(500);
            let mut last_run = std::time::Instant::now();
            loop {
                // SAFETY: both args NULL → synchronous blocking call that
                // returns NO_ERROR (0) on the next address change.
                let ret = unsafe { NotifyAddrChange(std::ptr::null_mut(), std::ptr::null()) };
                if ret != 0 {
                    // Transient failure — back off so we don't busy-loop.
                    warn!(code = ret, "NotifyAddrChange failed; retrying");
                    std::thread::sleep(std::time::Duration::from_secs(5));
                    last_run = std::time::Instant::now();
                    continue;
                }
                // Anti-busy-loop pacing for the immediate-return case.
                let elapsed = last_run.elapsed();
                if elapsed < MIN_INTERVAL {
                    std::thread::sleep(MIN_INTERVAL - elapsed);
                }
                last_run = std::time::Instant::now();
                if raw_tx.send(()).is_err() {
                    break; // debouncer dropped — agent shutting down
                }
            }
        });
    if let Err(e) = spawned {
        // Without this thread, on:network_change never fires — surface it
        // instead of swallowing the spawn error (claude #612).
        warn!(
            error = %e,
            "failed to spawn kanade-netwatch thread; on:network_change will not fire",
        );
    }
}

/// Anchor local admission to this fire, so jitter and slot waits cannot extend
/// a configured starting deadline. Invalid or overflowing durations fail closed.
fn local_starting_deadline(
    raw: Option<&str>,
    fired_at: DateTime<Utc>,
) -> Result<Option<DateTime<Utc>>> {
    raw.map(|raw| {
        let duration = humantime::parse_duration(raw).context("parse starting_deadline")?;
        let duration = ChronoDuration::from_std(duration).context("starting_deadline overflow")?;
        fired_at
            .checked_add_signed(duration)
            .context("starting_deadline timestamp overflow")
    })
    .transpose()
}

async fn local_tick(
    client: &async_nats::Client,
    pc_id: &str,
    state: &Arc<Mutex<State>>,
    schedule: &Schedule,
    staleness: &crate::staleness::Tracker,
    script_cache: &ScriptCache,
    check_sink: &crate::check_cache::CheckSink,
) {
    // 0-) Fleet-wide change-freeze (#418 Phase 5) — same global gate
    //     as the backend scheduler so runs_on: agent fires stop too.
    //     Read the cached mirror (kept fresh by the freeze-watch task),
    //     so the hot path never blocks on a KV get and an offline agent
    //     still honors a freeze that was set before it went dark
    //     (gemini #472). Clone the reason under the lock, then release.
    let frozen_reason = {
        let st = state.lock().await;
        st.freeze
            .as_ref()
            .filter(|f| f.is_active(Utc::now()))
            .map(|f| f.reason.clone())
    };
    if let Some(reason) = frozen_reason {
        debug!(
            schedule_id = %schedule.id,
            reason = reason.as_deref().unwrap_or(""),
            "local_scheduler: fleet change-freeze active — skip",
        );
        return;
    }

    // 0) Dormant outside the optional `active.{from,until}` window
    //    (#418 decision G) — mirrors the backend scheduler's gate so
    //    runs_on: agent campaigns end on the same instant.
    if !schedule.active.contains(Utc::now(), schedule.tz) {
        debug!(
            schedule_id = %schedule.id,
            "local_scheduler: outside active window (dormant)",
        );
        return;
    }

    // 0b) Maintenance window (#418 Phase 3) — same gate as the
    //     backend scheduler, evaluated in this agent's tz.
    if !schedule.constraints.allows(Utc::now(), schedule.tz) {
        debug!(
            schedule_id = %schedule.id,
            "local_scheduler: outside maintenance window — skip",
        );
        return;
    }

    // 0c) Host-environment gate (#418 constraints.require) — ac_power /
    //     idle, sensed in-process (Win32). runs_on: agent only (validate
    //     rejects backend). Skip-this-tick if unmet: a reconcile cadence
    //     re-checks next tick (effectively deferring until the state is
    //     met — the intended pairing); a calendar one-shot is missed,
    //     same as the window gate above. Empty require → zero syscalls.
    if let Some(req) = &schedule.constraints.require
        && !crate::env_gate::require_satisfied(req)
    {
        debug!(
            schedule_id = %schedule.id,
            "local_scheduler: constraints.require not met (env gate) — skip",
        );
        return;
    }

    // 1) Manifest + (optional) pre-resolved script_object digest
    //    must be cached. If not, skip and try again next tick (the
    //    jobs_watch loop may pick it up).
    let resolved = {
        let st = state.lock().await;
        match st.jobs.get(&schedule.job_id).cloned() {
            Some(r) => r,
            None => {
                warn!(
                    schedule_id = %schedule.id,
                    job_id = %schedule.job_id,
                    "local_scheduler: job not in cache yet — skip this tick",
                );
                return;
            }
        }
    };
    let ResolvedJob {
        manifest,
        script_object_sha256: cached_digest,
    } = resolved;

    // 2) Mode-based dedup against local_completions.
    let now = Utc::now();
    // Cheap short-circuit (claude #463): if a run is still live in
    // flight, skip before building the Command + the KV round-trips
    // below. `try_claim_fire` is still the authoritative gate; this
    // only saves the busy work for the extra ticks tokio-cron spawns
    // during a long jitter sleep. Same `now` is threaded through to
    // the claim so the pre-check and the gate stay consistent.
    if state.lock().await.is_live_in_flight(&schedule.id, now) {
        debug!(
            schedule_id = %schedule.id,
            "local_scheduler: live run in flight — skip early (#445)",
        );
        return;
    }
    let lowered = schedule.lowered();
    // Defensive parse (gemini #419 review): validate() rejects a bad
    // `every` at create time, but a hand-edited KV blob bypasses
    // that. Silently mapping a parse failure to `None` would turn
    // the schedule into "permanent skip after first success" under
    // OncePerPc — warn + skip the tick instead, mirroring the
    // backend scheduler's parse_cooldown error path.
    let cooldown = match lowered.cooldown.as_deref() {
        None => None,
        Some(raw) => match humantime::parse_duration(raw)
            .ok()
            .and_then(|d| ChronoDuration::from_std(d).ok())
        {
            Some(cd) => Some(cd),
            None => {
                warn!(
                    schedule_id = %schedule.id,
                    every = %raw,
                    "local_scheduler: invalid when.every duration; skipping tick",
                );
                return;
            }
        },
    };
    let should_fire = match lowered.mode {
        // Event schedules reach `local_tick` only when an OS event
        // source (boot / session-change) calls it — the event already
        // decided "fire now". The boot path applies the once-per-boot
        // dedup BEFORE this; here it's an unconditional fire, gated by
        // the freeze / active / window checks above + the in-flight
        // claim below. (Event schedules are never tokio-cron-registered.)
        ExecMode::EveryTick | ExecMode::Event => true,
        ExecMode::OncePerTarget => {
            // per_target needs fleet-wide completion data and is
            // rejected by Schedule::validate() for runs_on: agent —
            // this branch is only reachable through a hand-edited
            // KV blob, so skip loudly instead of silently degrading
            // to per_pc like pre-#418 code did.
            warn!(
                schedule_id = %schedule.id,
                "local_scheduler: when.per_target is backend-only \
                 (validate() rejects it for runs_on: agent); skipping tick",
            );
            return;
        }
        // once_per_version is backend-only too (validate() rejects it for
        // runs_on: agent — version-aware dedup needs the backend's
        // execution_results.version history, which the agent's local
        // completion map has no equivalent of). Reachable only via a
        // hand-edited KV blob; fail CLOSED — skip loudly rather than
        // degrade to version-blind per_pc, which would run the job with
        // the wrong semantics (coderabbit #1003).
        ExecMode::OncePerPcVersion => {
            warn!(
                schedule_id = %schedule.id,
                "local_scheduler: when.per_pc: once_per_version is backend-only \
                 (validate() rejects it for runs_on: agent); skipping tick",
            );
            return;
        }
        ExecMode::OncePerPc => {
            let st = state.lock().await;
            let key = State::key(&schedule.id, &schedule.job_id);
            match st.completions.get(&key) {
                None => true,
                Some(last) => match cooldown {
                    None => false, // permanent skip after first success
                    Some(cd) => (now - *last) >= cd,
                },
            }
        }
    };
    if !should_fire {
        debug!(
            schedule_id = %schedule.id,
            "local_scheduler: dedup says skip",
        );
        return;
    }

    // 3) Build a Command in-process (no NATS hop) and call
    //    handle_command directly. Include the starting deadline because
    //    jitter and local admission can delay the actual execution.
    //
    // #210 / Gemini #214 HIGH: build the Command in the same shape
    // backend's exec.rs would — inline body for `script:` manifests,
    // or (script: "", script_object: Some(key), script_object_sha256:
    // Some(cached_digest)) for `script_object:` ones. The digest was
    // pre-resolved at apply_resync / jobs_watch time, so this path
    // doesn't touch the broker — `runs_on: agent` keeps firing
    // script_object jobs during broker outages from the last
    // successful resync's cache.
    let (script_body, script_object_ref) = match (
        manifest.execute.script.as_deref().filter(|s| !s.is_empty()),
        manifest.execute.script_object.as_deref(),
        cached_digest,
    ) {
        (Some(inline), _, _) => (inline.to_owned(), None),
        (None, Some(key), Some(digest)) => (String::new(), Some((key.to_owned(), digest))),
        (None, Some(key), None) => {
            warn!(
                schedule_id = %schedule.id,
                job_id = %manifest.id,
                %key,
                "local_scheduler: script_object digest not in cache (last resync's fetch failed); \
                 skipping tick — next successful resync will populate it",
            );
            return;
        }
        (None, None, _) => {
            warn!(
                schedule_id = %schedule.id,
                job_id = %manifest.id,
                "local_scheduler: manifest has no script source — Manifest::validate() should have caught this; skipping tick",
            );
            return;
        }
    };
    let timeout_secs = humantime::parse_duration(&manifest.execute.timeout)
        .ok()
        .map(|d| d.as_secs())
        .unwrap_or(60);
    let jitter_secs = schedule
        .plan
        .jitter
        .as_deref()
        .and_then(|s| humantime::parse_duration(s).ok())
        .map(|d| d.as_secs());
    let deadline_at = match local_starting_deadline(schedule.starting_deadline.as_deref(), now) {
        Ok(deadline) => deadline,
        Err(error) => {
            warn!(schedule_id = %schedule.id, %error, "local_scheduler: invalid starting deadline — skip");
            return;
        }
    };
    let exec_id = Uuid::new_v4().to_string();
    let cmd = Command {
        id: manifest.id.clone(),
        version: manifest.version.clone(),
        request_id: Uuid::new_v4().to_string(),
        exec_id: Some(exec_id),
        bypass_local_limit: manifest.execute.bypass_local_limit,
        shell: manifest.execute.shell.into(),
        script: script_body,
        script_object: script_object_ref.as_ref().map(|(k, _)| k.clone()),
        script_object_sha256: script_object_ref.as_ref().map(|(_, d)| d.clone()),
        timeout_secs,
        jitter_secs,
        run_as: manifest.execute.run_as,
        cwd: manifest.execute.cwd.clone(),
        deadline_at,
        // v0.26: forward the Manifest's Layer 2 staleness policy so
        // `handle_command` evaluates it against the agent's current
        // broker-connectivity reading at fire time.
        staleness: manifest.staleness.clone(),
        // Issue #246: forward the manifest's observability emit hint
        // so the agent routes stdout NDJSON to obs-outbox on fire.
        // Same forward rationale as `staleness` — no manifest re-fetch.
        emit: manifest.emit.clone(),
        // #290: forward the check hint so an agent-scheduled
        // (`runs_on: agent`) check job still feeds the Health tab.
        check: manifest.check.clone(),
        // #219: forward the collect hint so an agent-scheduled collect
        // job bundles + uploads its files even on the offline path.
        collect: manifest.collect.clone(),
        // #418 Phase 4: lower this schedule's on_failure.retry onto
        // the Command so handle_command re-runs a failed script
        // in-process even on the offline (`runs_on: agent`) path.
        retry: schedule.on_failure.lowered_retry(),
        // Forward the finalize hook so an agent-scheduled job runs it
        // after the collect step even on the offline path.
        finalize: manifest.finalize.as_ref().map(|f| f.lower()),
    };

    let js = async_nats::jetstream::new(client.clone());
    // No `script_current` fetch here: an agent-local fire skips the
    // version-pin gate (CommandSource::LocalScheduler), so pulling that KV
    // would be a wasted NATS round-trip on every tick, fleet-wide. The
    // revoke kill-switch still applies, so `script_status` is still read.
    let script_status = js.get_key_value(BUCKET_SCRIPT_STATUS).await.ok();

    // #445: claim the in-flight slot atomically right before firing.
    // `tokio-cron-scheduler` spawns each tick's callback, so a `jitter`
    // longer than the 1-minute poll lets later ticks start while this
    // one is still sleeping in jitter inside handle_command — all
    // seeing stale `completions`. The claim (dedup re-check + mark in
    // one lock) ensures only one wins; the rest skip. Placed here so
    // there is no early `return` between the claim and the await that
    // would leak the slot. `claim_ttl` = the longest a legitimate run
    // can take (jitter + script timeout + handle_command overhead).
    const IN_FLIGHT_SLACK_SECS: i64 = 60;
    // #418 Phase 4: on_failure.retry lets a single fire run the script
    // up to `max` extra times with `backoff` between, so the worst-case
    // legitimate duration grows by `max * (timeout + backoff)`. Fold
    // that into the claim TTL or a retrying run would overrun its own
    // deadline and the next tick would wrongly reclaim it as stale and
    // double-fire (gemini/coderabbit #466).
    let retry_budget_secs = cmd
        .retry
        .map(|r| r.max as i64 * (timeout_secs as i64 + r.backoff_secs as i64))
        .unwrap_or(0);
    let claim_ttl = ChronoDuration::seconds(
        jitter_secs.unwrap_or(0) as i64
            + timeout_secs as i64
            + retry_budget_secs
            + IN_FLIGHT_SLACK_SECS,
    );
    // Reuse the single tick `now` (captured above) so the early
    // pre-check, this claim, and the deadline token are all consistent
    // and we avoid a second `Utc::now()` syscall (claude #463 review).
    // `deadline` matches exactly what `try_claim_fire` inserts
    // (`now + claim_ttl`); `finish_fire` only releases the slot if it
    // still holds this token, so a late finish from an overrun run
    // can't clear a reclaimer's mark (gemini #463 review).
    let deadline = now + claim_ttl;
    let live_fire = Arc::new(());
    let (claimed, reclaimed_stale) = {
        let mut st = state.lock().await;
        let claim = st.try_claim_fire(
            &schedule.id,
            &manifest.id,
            lowered.mode,
            cooldown,
            now,
            claim_ttl,
        );
        if claim.0 {
            st.live_fires
                .insert(schedule.id.clone(), Arc::downgrade(&live_fire));
        }
        claim
    };
    if !claimed {
        debug!(
            schedule_id = %schedule.id,
            "local_scheduler: already in flight or deduped — skip (#445)",
        );
        return;
    }
    if reclaimed_stale {
        warn!(
            schedule_id = %schedule.id,
            "local_scheduler: previous run overran its jitter+timeout deadline — reclaiming (#445)",
        );
    }

    info!(
        schedule_id = %schedule.id,
        job_id = %manifest.id,
        request_id = %cmd.request_id,
        "local_scheduler: firing (runs_on: agent)",
    );

    // 4) Drive the same handle_command as the live-NATS path.
    let request_id = cmd.request_id.clone();
    let job_id_for_completion = manifest.id.clone();
    match handle_command(
        client.clone(),
        pc_id.to_string(),
        cmd,
        // `None`: the version-pin gate is skipped for LocalScheduler, so
        // script_current is never consulted on this path (and no longer
        // fetched above).
        None,
        script_status,
        staleness.clone(),
        script_cache.clone(),
        check_sink.clone(),
        // Agent-local fire: cmd.version is authoritative (from the same
        // BUCKET_JOBS snapshot), so skip the version-pin gate that would
        // otherwise self-reject every tick after a bump. Revoke still
        // applies. See [`CommandSource`].
        CommandSource::LocalScheduler,
    )
    .await
    {
        Ok(outcome) if outcome.is_success() => {
            // 5) The script actually ran and succeeded — release the
            //    in-flight slot AND record the completion (#445). For a
            //    `per_pc: once` schedule this is what marks the pc done.
            state.lock().await.finish_fire(
                &schedule.id,
                &job_id_for_completion,
                deadline,
                Some(Utc::now()),
            );
            debug!(
                schedule_id = %schedule.id,
                %request_id,
                "local_scheduler: completion recorded",
            );
        }
        Ok(outcome) => {
            // #910: the script ran but exited non-zero, OR the command
            // was gated before running (staleness / version-pin / revoke
            // / deadline skip). Neither is a success, so release the slot
            // WITHOUT recording a completion — a `per_pc: once` schedule
            // must keep re-firing "until that pc succeeds" rather than be
            // consumed forever by a skip during a version-pin lag. This
            // matches the backend dedup, which only counts `exit_code = 0`.
            state
                .lock()
                .await
                .finish_fire(&schedule.id, &job_id_for_completion, deadline, None);
            debug!(
                schedule_id = %schedule.id,
                %request_id,
                ?outcome,
                "local_scheduler: run did not succeed — not recording completion (will retry)",
            );
        }
        Err(e) => {
            // Release the in-flight slot without recording a completion
            // so the next tick retries (#445).
            state
                .lock()
                .await
                .finish_fire(&schedule.id, &job_id_for_completion, deadline, None);
            warn!(
                schedule_id = %schedule.id,
                %request_id,
                error = %e,
                "local_scheduler: handle_command failed (will retry next tick)",
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kanade_shared::manifest::{
        Active, Constraints, FanoutPlan, OnFailure, OnceLiteral, PerPolicy, ScheduleTz, Target,
        When,
    };

    // ---- #418 on:startup boot-dedup decision ----

    const T: u64 = STARTUP_BOOT_THRESHOLD_SECS; // 120

    #[test]
    fn local_deadline_is_anchored_to_the_fire_and_rejects_invalid_values() {
        assert_eq!(local_starting_deadline(None, t(100)).unwrap(), None);
        assert_eq!(
            local_starting_deadline(Some("30s"), t(100)).unwrap(),
            Some(t(130)),
        );
        assert!(local_starting_deadline(Some("invalid"), t(100)).is_err());
        assert!(local_starting_deadline(Some("1s"), DateTime::<Utc>::MAX_UTC).is_err());
    }

    #[test]
    fn a_queued_task_stays_in_flight_past_the_old_ttl() {
        let mut st = test_state();
        let task = Arc::new(());
        st.in_flight.insert("queued".into(), t(1));
        st.live_fires.insert("queued".into(), Arc::downgrade(&task));
        assert!(st.is_live_in_flight("queued", t(120)));
        assert_eq!(
            st.try_claim_fire(
                "queued",
                "job",
                ExecMode::EveryTick,
                None,
                t(120),
                ChronoDuration::seconds(60)
            ),
            (false, false)
        );
        drop(task);
        assert!(!st.is_live_in_flight("queued", t(120)));
        assert_eq!(
            st.try_claim_fire(
                "queued",
                "job",
                ExecMode::EveryTick,
                None,
                t(120),
                ChronoDuration::seconds(60)
            ),
            (true, true)
        );
    }
    #[test]
    fn startup_fires_when_never_recorded() {
        // No marker → first time on this host → fire.
        assert!(should_fire_startup(None, 1_000_000, 5, None));
    }

    #[test]
    fn startup_skips_same_boot_within_threshold() {
        // Agent restarted in the same boot: boot_time is the same (±jitter
        // under the threshold) → already fired this boot → skip.
        assert!(!should_fire_startup(Some(1_000_000), 1_000_000, 30, None));
        assert!(!should_fire_startup(
            Some(1_000_000),
            1_000_000 + T - 1,
            30,
            None
        ));
        assert!(!should_fire_startup(
            Some(1_000_000),
            1_000_000 - (T - 1),
            30,
            None
        ));
    }

    #[test]
    fn startup_fires_on_new_boot_past_threshold() {
        // A genuinely new boot is minutes apart → past the threshold → fire.
        assert!(should_fire_startup(
            Some(1_000_000),
            1_000_000 + T + 1,
            5,
            None
        ));
    }

    #[test]
    fn startup_starting_deadline_gates_late_agent_start() {
        // New boot, but the agent came up well after boot. With a
        // starting_deadline the late start is skipped; without one it fires.
        let new_boot = 2_000_000;
        let recorded = Some(1_000_000); // far in the past = new boot
        // uptime 600s, deadline 300s → too late → skip.
        assert!(!should_fire_startup(recorded, new_boot, 600, Some(300)));
        // uptime 100s, deadline 300s → within → fire.
        assert!(should_fire_startup(recorded, new_boot, 100, Some(300)));
        // no deadline → fire regardless of how late.
        assert!(should_fire_startup(recorded, new_boot, 36_000, None));
    }

    fn schedule(target: Target, runs_on: RunsOn) -> Schedule {
        Schedule {
            id: "s".into(),
            when: When::PerPc(PerPolicy::Once(OnceLiteral::Once)),
            job_id: "j".into(),
            plan: FanoutPlan {
                target,
                ..Default::default()
            },
            active: Active::default(),
            constraints: Constraints::default(),
            on_failure: OnFailure::default(),
            tz: ScheduleTz::default(),
            starting_deadline: None,
            runs_on,
            enabled: true,
            tags: Vec::new(),
            origin: None,
        }
    }

    // ---- in-flight guard (#445) ----

    fn test_state() -> State {
        // A unique temp completions path so finish_fire's flush is a
        // harmless real write (and parallel tests don't collide).
        let mut p = std::env::temp_dir();
        p.push(format!("kanade-test-completions-{}.json", Uuid::new_v4()));
        let mut sp = std::env::temp_dir();
        sp.push(format!("kanade-test-startup-{}.json", Uuid::new_v4()));
        State {
            jobs: HashMap::new(),
            registered: HashMap::new(),
            schedules: HashMap::new(),
            completions: HashMap::new(),
            completions_path: p,
            startup_markers: HashMap::new(),
            startup_markers_path: sp,
            in_flight: HashMap::new(),
            live_fires: HashMap::new(),
            freeze: None,
        }
    }

    fn t(secs: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + secs, 0).unwrap()
    }

    #[test]
    fn try_claim_fire_blocks_concurrent_once_per_pc() {
        let mut st = test_state();
        let ttl = ChronoDuration::seconds(60);
        let cd = Some(ChronoDuration::seconds(3600)); // every 1h
        // First tick (no completion yet) claims.
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::OncePerPc, cd, t(0), ttl),
            (true, false)
        );
        // A concurrent tick at the same instant is blocked (in flight).
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::OncePerPc, cd, t(0), ttl),
            (false, false)
        );
        // Finish + record success.
        st.finish_fire("s", "j", t(60), Some(t(0))); // claimed at t(0), deadline t(60)
        // Within cooldown → deduped (not in flight, but recent).
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::OncePerPc, cd, t(1800), ttl),
            (false, false)
        );
        // After cooldown → claims again.
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::OncePerPc, cd, t(3600), ttl),
            (true, false)
        );
    }

    #[test]
    fn try_claim_fire_blocks_concurrent_every_tick() {
        let mut st = test_state();
        let ttl = ChronoDuration::seconds(60);
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(0), ttl),
            (true, false)
        );
        // Concurrent EveryTick tick blocked while in flight.
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(10), ttl),
            (false, false)
        );
        st.finish_fire("s", "j", t(60), Some(t(10))); // claimed at t(0), deadline t(60)
        // Next EveryTick fires again (EveryTick ignores completions).
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(20), ttl),
            (true, false)
        );
    }

    #[test]
    fn try_claim_fire_reclaims_stale_past_deadline() {
        let mut st = test_state();
        let ttl = ChronoDuration::seconds(60);
        // Claim at T=0; deadline = T+60. finish_fire is NOT called
        // (simulates a dead/aborted run).
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(0), ttl),
            (true, false)
        );
        // Still within the deadline → blocked.
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(30), ttl),
            (false, false)
        );
        // Past the deadline → reclaimed (self-heal, no agent restart).
        assert_eq!(
            st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(61), ttl),
            (true, true)
        );
    }

    #[test]
    fn is_live_in_flight_is_ttl_aware() {
        let mut st = test_state();
        let ttl = ChronoDuration::seconds(60);
        assert!(!st.is_live_in_flight("s", t(0)), "no entry");
        st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(0), ttl); // deadline t(60)
        assert!(st.is_live_in_flight("s", t(30)), "within deadline → live");
        assert!(
            !st.is_live_in_flight("s", t(60)),
            "at deadline → not live (lets reclaim fall through)"
        );
        assert!(!st.is_live_in_flight("s", t(61)), "past deadline → stale");
    }

    #[test]
    fn finish_fire_ignores_stale_deadline_after_reclaim() {
        // A late finish from an overrun run must not clear the slot a
        // newer tick already reclaimed (gemini #463 review).
        let mut st = test_state();
        let ttl = ChronoDuration::seconds(60);
        // Task A claims at T=0 (deadline T+60).
        st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(0), ttl);
        // Task B reclaims at T=61 (deadline T+121) after A overran.
        st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(61), ttl);
        // Task A finally finishes and tries to release ITS slot (T+60).
        st.finish_fire("s", "j", t(60), Some(t(70)));
        // B's mark (T+121) must survive — else a third tick double-fires.
        assert_eq!(
            st.in_flight.get("s"),
            Some(&t(121)),
            "reclaimer's in_flight token preserved"
        );
        // B finishing with its own deadline clears it.
        st.finish_fire("s", "j", t(121), Some(t(130)));
        assert!(!st.in_flight.contains_key("s"), "owner releases its slot");
    }

    #[test]
    fn finish_fire_records_on_success_only_and_clears_in_flight() {
        let mut st = test_state();
        let ttl = ChronoDuration::seconds(60);
        let key = State::key("s", "j");

        // Success path: records completion + clears in_flight.
        st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(0), ttl);
        st.finish_fire("s", "j", t(60), Some(t(5))); // claimed at t(0), deadline t(60)
        assert!(!st.in_flight.contains_key("s"), "in_flight cleared");
        assert_eq!(st.completions.get(&key), Some(&t(5)), "completion recorded");

        // Failure path: clears in_flight, no completion change.
        st.try_claim_fire("s", "j", ExecMode::EveryTick, None, t(100), ttl);
        st.finish_fire("s", "j", t(160), None); // claimed at t(100), deadline t(160)
        assert!(
            !st.in_flight.contains_key("s"),
            "in_flight cleared on failure"
        );
        assert_eq!(
            st.completions.get(&key),
            Some(&t(5)),
            "failure leaves the last success untouched"
        );
    }

    #[test]
    fn target_all_matches_anyone() {
        let s = schedule(
            Target {
                all: true,
                ..Default::default()
            },
            RunsOn::Agent,
        );
        assert!(target_includes(&s, "pc-01", &[]));
    }

    #[test]
    fn target_pcs_explicit_match() {
        let s = schedule(
            Target {
                pcs: vec!["pc-01".into()],
                ..Default::default()
            },
            RunsOn::Agent,
        );
        assert!(target_includes(&s, "pc-01", &[]));
        assert!(!target_includes(&s, "other", &[]));
    }

    #[test]
    fn target_groups_intersect() {
        let s = schedule(
            Target {
                groups: vec!["canary".into(), "wave1".into()],
                ..Default::default()
            },
            RunsOn::Agent,
        );
        assert!(target_includes(&s, "any", &["wave1".into()]));
        assert!(target_includes(
            &s,
            "any",
            &["dept-eng".into(), "canary".into()]
        ));
        assert!(!target_includes(&s, "any", &["dept-eng".into()]));
    }

    #[test]
    fn target_none_matches_none() {
        let s = schedule(Target::default(), RunsOn::Agent);
        assert!(!target_includes(&s, "pc-01", &["canary".into()]));
    }
}
