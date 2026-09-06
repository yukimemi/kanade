//! `jobs.*` method handlers (SPEC §2.12.5 / §2.12.11).
//!
//! - `jobs.list` — return every manifest carrying a `client:` block,
//!   optionally narrowed to one category key, mapped into the
//!   [`UserInvokableJob`] wire shape the Client App renders. Categories
//!   are free-form keys (#792): the client groups jobs into one tab per
//!   distinct key, using the operator-supplied label/icon/order.
//! - `jobs.execute` — run a user-invokable job. Looks the manifest up
//!   by id, refuses anything without a `client:` block
//!   (`Unauthorized` per SPEC §2.12.4), mints a `run_id`, spawns the
//!   run, and returns the `run_id` immediately. The run streams
//!   `jobs.progress` pushes (Running → Completed/Failed/Killed) on the
//!   connection's push channel.
//! - `jobs.kill` — request termination of a `run_id` started ON THIS
//!   connection (cross-connection kill → `Unauthorized`). Publishes
//!   `subject::kill(run_id)`; the run's terminal `jobs.progress`
//!   (status = Killed) follows asynchronously once the child exits.
//!
//! `jobs.subscribe` / `jobs.unsubscribe` (an explicit progress
//! subscription) and incremental stdout/stderr streaming land in a
//! follow-up — today `jobs.execute` pushes progress directly on the
//! connection it was called on (the client always wants progress for a
//! run it explicitly started), and the terminal push carries the full
//! captured output rather than live chunks. `script_object` jobs
//! (Object Store bodies) are also a follow-up; `jobs.execute` only
//! runs inline-`script:` jobs for now.
//!
//! # Catalog source
//!
//! The agent reads the manifest catalog straight from the
//! `BUCKET_JOBS` KV at call time rather than from a cached snapshot,
//! so adding / removing a manifest's `client:` block (or editing its
//! `name`) takes effect on the client's next `jobs.list` / `jobs.execute`
//! without an agent restart — SPEC §2.1's "Agent 側で manifest を必ず 再
//! lookup" rule. These are cold, user-initiated paths (a tab tap, a
//! button press), so the extra KV round-trip is immaterial.
//!
//! The pure [`build_job_list`] / [`build_command`] /
//! [`outcome_to_progress`] helpers are split out from the KV + process
//! glue so they can be unit-tested without a live NATS or a real child
//! process.

use chrono::Utc;
use futures::TryStreamExt;
use kanade_shared::ipc::envelope::RpcNotification;
use kanade_shared::ipc::error::{ErrorKind, RpcError};
use kanade_shared::ipc::jobs::{
    JobConfirm, JobProgress, JobsExecuteParams, JobsExecuteResult, JobsKillParams, JobsKillResult,
    JobsListParams, JobsListResult, RunStatus, UserInvokableJob,
};
use kanade_shared::ipc::method;
use kanade_shared::ipc::state::CheckStatus;
use kanade_shared::kv::{
    BUCKET_AGENT_GROUPS, BUCKET_AGENT_GROUPS_DERIVED, BUCKET_JOBS, BUCKET_SCRIPT_STATUS,
    SCRIPT_STATUS_REVOKED,
};
use kanade_shared::manifest::Manifest;
use kanade_shared::wire::Command;
use kanade_shared::{ExecResult, default_paths, subject};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{debug, warn};
use uuid::Uuid;

use super::super::connection::ConnectionState;
use super::super::unlock;
use super::system::HandlerResult;
use crate::outbox;
use crate::process::{ExecOutcome, run_command_with_kill};

/// `jobs.list` — list the user-invokable job catalog for the Client
/// App, optionally filtered to a single tab's category.
///
/// Reads `BUCKET_JOBS` on demand (see module docs). A connectivity
/// failure opening or scanning the bucket surfaces as
/// [`ErrorKind::InternalError`]; the client retries on the next tab
/// switch.
pub async fn handle_jobs_list(
    conn: &ConnectionState,
    params: JobsListParams,
) -> HandlerResult<JobsListResult> {
    // `nats` is always wired in production (the listener calls
    // `with_nats`); a `None` here only happens in a unit test that
    // forgot to, so treat it as an internal wiring bug, not a client
    // error.
    let client = conn.nats.as_ref().ok_or_else(|| {
        RpcError::new(
            ErrorKind::InternalError,
            "jobs.list: NATS client not wired into the connection",
        )
    })?;

    let js = async_nats::jetstream::new(client.clone());
    let kv = js.get_key_value(BUCKET_JOBS).await.map_err(|e| {
        warn!(error = %e, "jobs.list: failed to open BUCKET_JOBS");
        RpcError::new(
            ErrorKind::InternalError,
            format!("jobs.list: open jobs catalog: {e}"),
        )
    })?;

    // keys() failing is a connectivity-level error (broker hiccup),
    // distinct from "no jobs registered" (an empty key set) — mirror
    // local_scheduler::collect_jobs and surface it rather than
    // returning an empty catalog the client would read as "nothing
    // to run".
    let keys = kv.keys().await.map_err(|e| {
        warn!(error = %e, "jobs.list: BUCKET_JOBS keys() failed");
        RpcError::new(
            ErrorKind::InternalError,
            format!("jobs.list: scan jobs catalog: {e}"),
        )
    })?;
    // A fault mid-iteration (broker hiccup after the cursor opened)
    // is a connectivity error, NOT "no jobs" — propagate it so the
    // client retries instead of rendering an empty catalog. Swallowing
    // it with `unwrap_or_default()` would contradict the keys()
    // handling just above.
    let keys: Vec<String> = keys.try_collect().await.map_err(|e| {
        warn!(error = %e, "jobs.list: BUCKET_JOBS key stream faulted mid-iteration");
        RpcError::new(
            ErrorKind::InternalError,
            format!("jobs.list: stream jobs catalog: {e}"),
        )
    })?;

    // Fetch every manifest concurrently: `jobs.list` has to read the
    // whole BUCKET_JOBS (it can't tell which entries are user-invokable
    // without parsing them), so a fleet with dozens of jobs would pay N
    // sequential round-trips if fetched in a loop. A single corrupt /
    // unreadable entry is skipped (logged) rather than sinking the
    // whole listing — same tolerance the scheduler's catalog walk uses.
    let manifests: Vec<Manifest> = futures::future::join_all(keys.into_iter().map(|k| {
        let kv = kv.clone();
        async move {
            match kv.get(&k).await {
                Ok(Some(bytes)) => match serde_json::from_slice::<Manifest>(&bytes) {
                    Ok(m) => Some(m),
                    Err(e) => {
                        warn!(key = %k, error = %e, "jobs.list: skipping unparseable manifest");
                        None
                    }
                },
                Ok(None) => None,
                Err(e) => {
                    warn!(key = %k, error = %e, "jobs.list: skipping unreadable manifest");
                    None
                }
            }
        }
    }))
    .await
    .into_iter()
    .flatten()
    .collect();

    // #816: scope `client.visible_to` to this agent. pc_id is the agent's
    // own (trusted); groups come from the agent_groups KV read here on the
    // cold list path.
    let groups = pc_groups(client, &conn.pc_id).await;
    // `client.show_when` gates a job on a health check's latest result.
    // Snapshot the live checks (name → status) the state evaluator keeps
    // fresh — `check_cache::record` re-publishes immediately after a check
    // runs (no 30 s tick), so a button-press run that re-emits its own
    // check flips the gate by the next list refresh. Snapshot into an owned
    // map so we don't hold the watch borrow (no await follows, but this
    // keeps the borrow scope trivial and the build pure).
    let checks: HashMap<String, CheckStatus> = conn
        .state_rx
        .borrow()
        .checks
        .iter()
        .map(|c| (c.name.clone(), c.status))
        .collect();
    // `client.unlock` hides a job entirely unless the calling OS user holds
    // a live grant for its scope (`support.unlock`). Resolved per call from
    // the process-wide grant store, so a grant that lapsed mid-session drops
    // the rows on the next refresh with no client cooperation needed.
    let unlocked = |scope: &str| unlock::holds(&conn.peer.user_sid, scope);
    Ok(build_job_list(
        &manifests,
        params.category,
        &conn.pc_id,
        &groups,
        &checks,
        &unlocked,
    ))
}

/// Resolve this agent's group membership from the `agent_groups.{pc_id}`
/// KV row. Best-effort on the cold `jobs.*` paths (one extra KV read,
/// immaterial here — see module docs): any miss / decode failure yields
/// no groups, so a `visible_to` that targets only groups simply won't
/// match (fails closed — better to hide than wrongly show).
async fn pc_groups(client: &async_nats::Client, pc_id: &str) -> Vec<String> {
    let js = async_nats::jetstream::new(client.clone());
    // #1032①: effective membership = operator `agent_groups` ∪ materialized
    // `agent_groups_derived`, so a job made visible via a dynamic group is
    // listed/run. This cold path re-reads KV directly (not the groups.rs watch
    // channel), so it must union the derived bucket itself.
    let manual = read_membership(&js, BUCKET_AGENT_GROUPS, pc_id).await;
    let derived = read_membership(&js, BUCKET_AGENT_GROUPS_DERIVED, pc_id).await;
    crate::groups::union_groups(&manual, &derived)
}

/// Read one membership bucket for `pc_id`. Best-effort on the cold `jobs.*`
/// paths (see module docs): any miss / decode / KV error yields no groups (a
/// `visible_to` targeting only groups then fails closed — hide over wrongly
/// show), logged so "why isn't my group-targeted job visible?" is traceable
/// (Gemini #816). Reuses the one `AgentGroups` decoder.
async fn read_membership(
    js: &async_nats::jetstream::Context,
    bucket: &'static str,
    pc_id: &str,
) -> Vec<String> {
    let kv = match js.get_key_value(bucket).await {
        Ok(kv) => kv,
        Err(e) => {
            warn!(error = %e, bucket, "jobs: open membership bucket for visibility failed");
            return Vec::new();
        }
    };
    match kv.get(pc_id).await {
        Ok(Some(bytes)) => crate::groups::parse_groups(&bytes),
        Ok(None) => Vec::new(),
        Err(e) => {
            warn!(pc_id = %pc_id, bucket, error = %e, "jobs: read membership for visibility failed");
            Vec::new()
        }
    }
}

/// Whether a manifest is visible to the asking agent (#816): a job with
/// no `client.visible_to` is visible to everyone; otherwise the agent's
/// `pc_id` / `groups` must match the target. A manifest without a
/// `client:` block is "visible" here (it's dropped later by
/// [`manifest_to_job`] as operator-only).
fn job_visible(m: &Manifest, pc_id: &str, groups: &[String]) -> bool {
    match m.client.as_ref().and_then(|c| c.visible_to.as_ref()) {
        None => true,
        Some(t) => t.matches(pc_id, groups),
    }
}

/// Whether a manifest's `client.show_when` display gate is satisfied by
/// the current check results. A job with no `show_when` always shows;
/// otherwise the named check's latest status must be one of `is`. A check
/// that has never run (absent from `checks`) does NOT match — the job
/// stays hidden until the detector first reports (fails closed, matching
/// the `show_when` doc + `job_visible`'s "better to hide than wrongly
/// show"). A `client:`-less manifest is "satisfied" here (dropped later by
/// [`manifest_to_job`] as operator-only).
fn job_show_when_satisfied(m: &Manifest, checks: &HashMap<String, CheckStatus>) -> bool {
    match m.client.as_ref().and_then(|c| c.show_when.as_ref()) {
        None => true,
        Some(sw) => checks
            .get(&sw.check)
            .is_some_and(|status| sw.is.contains(status)),
    }
}

/// Whether a manifest's `client.unlock` gate is open for the caller: a job
/// with no `unlock` scope is always listed; otherwise the caller must hold a
/// live grant for that exact scope (`unlocked`). A `client:`-less manifest is
/// "open" here (dropped later by [`manifest_to_job`] as operator-only).
///
/// Like `show_when` and unlike `visible_to`, this gates **listing only** — see
/// the note in [`handle_jobs_execute`]. Hidden here means "not offered to this
/// user right now", not "forbidden".
fn job_unlocked(m: &Manifest, unlocked: &dyn Fn(&str) -> bool) -> bool {
    match m.client.as_ref().and_then(|c| c.unlock.as_ref()) {
        None => true,
        Some(scope) => unlocked(scope),
    }
}

/// Pure mapping + filtering: manifests → the `jobs.list` wire result.
///
/// Keeps only manifests carrying a `client:` block, drops any whose
/// `visible_to` excludes this agent (#816), whose `show_when` gate the
/// current check results don't satisfy, or whose `client.unlock` scope the
/// caller hasn't unlocked, maps each to a [`UserInvokableJob`], applies the
/// optional category filter, and sorts by display name so the catalog
/// renders in a stable order regardless of KV key iteration order.
///
/// `unlocked` answers "does the caller hold a grant for this scope right
/// now" — injected rather than read from the grant store directly so this
/// stays a pure function the tests can drive.
pub fn build_job_list(
    manifests: &[Manifest],
    filter: Option<String>,
    pc_id: &str,
    groups: &[String],
    checks: &HashMap<String, CheckStatus>,
    unlocked: &dyn Fn(&str) -> bool,
) -> JobsListResult {
    let mut items: Vec<UserInvokableJob> = manifests
        .iter()
        .filter(|m| job_visible(m, pc_id, groups))
        .filter(|m| job_show_when_satisfied(m, checks))
        .filter(|m| job_unlocked(m, unlocked))
        .filter_map(manifest_to_job)
        .filter(|j| filter.as_deref().is_none_or(|c| j.category == c))
        .collect();
    // Stable, human-meaningful order: display name, then id as the
    // tiebreaker so two jobs sharing a name don't render
    // nondeterministically.
    items.sort_by(|a, b| {
        a.display_name
            .cmp(&b.display_name)
            .then_with(|| a.id.cmp(&b.id))
    });
    JobsListResult { items }
}

/// Map one manifest to its catalog row, or `None` when it carries no
/// `client:` block (i.e. it's an operator-only job).
///
/// The `client:` block's required fields (`name`, `category`) are
/// guaranteed present by serde at parse time, so this is a
/// straight field-for-field projection — no defaulting needed.
fn manifest_to_job(m: &Manifest) -> Option<UserInvokableJob> {
    let client = m.client.as_ref()?;
    Some(UserInvokableJob {
        id: m.id.clone(),
        display_name: client.name.clone(),
        display_description: client.description.clone(),
        icon: client.icon.clone(),
        category: client.category.clone(),
        category_label: client.category_label.clone(),
        category_icon: client.category_icon.clone(),
        category_order: client.category_order,
        version: m.version.clone(),
        // #865: surface the manifest's run deadline so the Client App's
        // stuck-run watchdog can honor it instead of a fixed 15 min. A
        // long, near-silent job (Office repair, Teams reinstall) is no
        // longer falsely flagged failed while still running. Best-effort
        // parse: an unparseable timeout yields `None` (the client falls
        // back to its fixed watchdog) rather than dropping the row —
        // `Manifest::validate` already rejects a bad timeout at write
        // time, so this only fails on a pre-validation legacy entry.
        timeout_secs: humantime::parse_duration(&m.execute.timeout)
            .ok()
            .map(|d| d.as_secs().max(1)), // truncates sub-second; floors < 1s to 1
        // Surface the operator's confirmation-dialog config so the Client
        // App can suppress the modal (`enabled: false`) or show a custom
        // message. `None` here keeps the client's historical default
        // (always confirm, built-in message).
        confirm: client.confirm.as_ref().map(|c| JobConfirm {
            enabled: c.enabled,
            message: c.message.clone(),
        }),
        // Display marker: lets the Client App badge the row so the user can
        // see this one came from the desk's support code and isn't part of
        // their everyday catalog.
        unlock: client.unlock.clone(),
        // Per-user run history is minted by `jobs.execute` (a
        // follow-up PR); until then every row is "never run by you".
        last_run: None,
    })
}

// ---------- jobs.execute ----------

/// `jobs.execute` — run a user-invokable job and stream its progress.
///
/// Looks the manifest up by id (re-lookup at fire time, SPEC §2.1),
/// refuses anything without a `client:` block (`Unauthorized`), mints
/// a `run_id`, spawns the run, and returns the `run_id` immediately.
/// The spawned task pushes `jobs.progress` (Running → terminal) on the
/// connection's push channel; the run is detached so it keeps going if
/// the client disconnects mid-run (a half-finished install shouldn't be
/// abandoned).
pub async fn handle_jobs_execute(
    conn: &mut ConnectionState,
    params: JobsExecuteParams,
) -> HandlerResult<JobsExecuteResult> {
    let client = conn
        .nats
        .as_ref()
        .ok_or_else(|| {
            RpcError::new(
                ErrorKind::InternalError,
                "jobs.execute: NATS client not wired into the connection",
            )
        })?
        .clone();

    let manifest = fetch_manifest(&client, &params.id).await?;

    // SPEC §2.12.4: only `client:` (user-invokable) jobs may be run
    // from the Client App. An operator-only job → Unauthorized, never
    // MethodNotFound (the method exists; this caller just can't run
    // THAT job).
    let Some(client_hint) = manifest.client.as_ref() else {
        return Err(RpcError::new(
            ErrorKind::Unauthorized,
            format!(
                "job '{}' is not user-invokable (no client: block)",
                params.id
            ),
        ));
    };

    // #816: enforce `visible_to` on the run path too — not just the
    // listing — so a job hidden from this PC can't be run by guessing its
    // id. The operator SPA path (`POST /api/exec`) is separate and stays
    // unrestricted. pc_id is the agent's own; groups come from KV.
    if let Some(target) = client_hint.visible_to.as_ref() {
        let groups = pc_groups(&client, &conn.pc_id).await;
        if !target.matches(&conn.pc_id, &groups) {
            return Err(RpcError::new(
                ErrorKind::Unauthorized,
                format!("job '{}' is not available on this PC", params.id),
            ));
        }
    }

    // NOTE: `client.unlock` is deliberately NOT enforced here. It is a
    // display gate (like `show_when`), not an authorization boundary (unlike
    // `visible_to`): the operator-side approval controls live on the SPA exec
    // path, and gating the run here would only add a race — the row is
    // visible, the grant lapses, and pressing 実行 fails on a button the user
    // was just looking at. Listing-only means anything visible is runnable.

    // #927: honour the operator's revoke gate on the KLP path too. The
    // NATS command path refuses REVOKED scripts (`commands.rs`), but a
    // user could still fire the same job from the Client App — an
    // operator who revoked a job that turned out to be dangerous
    // believes it is fleet-stopped. Same best-effort read as the NATS
    // path (a KV hiccup must not brick every client job), but a
    // *positive* REVOKED answer is a hard refusal.
    if job_is_revoked(&client, &params.id).await {
        warn!(job_id = %params.id, "jobs.execute: refusing revoked job");
        return Err(RpcError::new(
            ErrorKind::Unauthorized,
            format!("job '{}' has been revoked by the operator", params.id),
        ));
    }

    let run_id = Uuid::new_v4().to_string();
    let request_id = Uuid::new_v4().to_string();
    let cmd = build_command(&manifest, &run_id, &request_id)?;

    // Record the run BEFORE spawning so a near-instant `jobs.kill`
    // can't race ahead of the registry insert.
    conn.register_run(run_id.clone());

    let push_tx = conn.push_tx.clone();
    let pc_id = conn.pc_id.clone();
    let spawned_run_id = run_id.clone();
    tokio::spawn(run_job(client, cmd, spawned_run_id, push_tx, pc_id));

    Ok(JobsExecuteResult { run_id })
}

/// `true` when `BUCKET_SCRIPT_STATUS[job_id]` is REVOKED (#927).
/// Best-effort, mirroring the NATS command path's gate in
/// `commands.rs`: a missing bucket / key / read error reads as "not
/// revoked" (warn-logged) — the gate exists to stop a *known-bad*
/// script, not to make every client job depend on one more KV read.
async fn job_is_revoked(client: &async_nats::Client, job_id: &str) -> bool {
    let js = async_nats::jetstream::new(client.clone());
    let kv = match js.get_key_value(BUCKET_SCRIPT_STATUS).await {
        Ok(kv) => kv,
        Err(e) => {
            warn!(error = %e, "jobs.execute: failed to open script_status; treating as not revoked");
            return false;
        }
    };
    match kv.get(job_id).await {
        Ok(Some(entry)) => String::from_utf8_lossy(&entry) == SCRIPT_STATUS_REVOKED,
        Ok(None) => false,
        Err(e) => {
            warn!(job_id = %job_id, error = %e, "jobs.execute: script_status read failed; treating as not revoked");
            false
        }
    }
}

/// Fetch one manifest from `BUCKET_JOBS` by id. `InvalidParams` when
/// the id isn't a valid KV key, `NotFound` when the key is absent,
/// `InternalError` on a KV / decode failure.
async fn fetch_manifest(client: &async_nats::Client, id: &str) -> Result<Manifest, RpcError> {
    // Validate the client-supplied id up front: anything that isn't a
    // legal job id (= NATS KV key) would make `kv.get` fail with a
    // confusing InternalError. Catch it here as InvalidParams.
    if !valid_job_id(id) {
        return Err(RpcError::new(
            ErrorKind::InvalidParams,
            format!("job id '{id}' is not a valid job id (expected [A-Za-z0-9_.-])"),
        ));
    }
    let js = async_nats::jetstream::new(client.clone());
    let kv = js.get_key_value(BUCKET_JOBS).await.map_err(|e| {
        warn!(error = %e, "jobs.execute: failed to open BUCKET_JOBS");
        RpcError::new(
            ErrorKind::InternalError,
            format!("jobs.execute: open jobs catalog: {e}"),
        )
    })?;
    let bytes = kv
        .get(id)
        .await
        .map_err(|e| {
            warn!(key = %id, error = %e, "jobs.execute: KV get failed");
            RpcError::new(
                ErrorKind::InternalError,
                format!("jobs.execute: read job '{id}': {e}"),
            )
        })?
        .ok_or_else(|| RpcError::new(ErrorKind::NotFound, format!("job '{id}' not found")))?;
    serde_json::from_slice::<Manifest>(&bytes).map_err(|e| {
        warn!(key = %id, error = %e, "jobs.execute: manifest decode failed");
        RpcError::new(
            ErrorKind::InternalError,
            format!("jobs.execute: decode job '{id}': {e}"),
        )
    })
}

/// `true` if `id` is a legal manifest id / NATS KV key: a non-empty
/// slug of `[A-Za-z0-9_.-]`. Pure so the gate is unit-testable.
fn valid_job_id(id: &str) -> bool {
    !id.is_empty()
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

/// Build the wire [`Command`] the run path executes from a manifest.
/// Genuinely pure (no I/O, no id minting) so it's deterministically
/// unit-testable — the caller passes both ids. `run_id` doubles as the
/// `exec_id` so `run_command_with_kill` subscribes to
/// `subject::kill(run_id)` and `jobs.kill` can target it; `request_id`
/// is the per-run correlation id stamped on the wire Command.
///
/// Inline-`script:` only for now — `script_object` jobs (Object Store
/// bodies fetched via the agent's script cache) are a follow-up, and
/// `script_file` is operator-CLI-side and never reaches the agent.
pub fn build_command(
    manifest: &Manifest,
    run_id: &str,
    request_id: &str,
) -> Result<Command, RpcError> {
    if manifest.execute.script_object.is_some() {
        return Err(RpcError::new(
            ErrorKind::InvalidParams,
            format!(
                "job '{}' uses script_object, which is not yet runnable via KLP jobs.execute",
                manifest.id
            ),
        ));
    }
    let script = manifest
        .execute
        .script
        .as_deref()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            RpcError::new(
                ErrorKind::InvalidParams,
                format!("job '{}' has no inline script to run", manifest.id),
            )
        })?
        .to_string();
    // `.max(1)`: a sub-second timeout (e.g. `500ms`) truncates to 0
    // under `as_secs()`, and a 0 `timeout_secs` is ambiguous to the run
    // path (no-timeout vs immediate-timeout). Floor any positive
    // duration at 1s — a user-invokable action measured in milliseconds
    // is not a real config.
    let timeout_secs = humantime::parse_duration(&manifest.execute.timeout)
        .map_err(|e| {
            RpcError::new(
                ErrorKind::InvalidParams,
                format!("job '{}' has an invalid timeout: {e}", manifest.id),
            )
        })?
        .as_secs()
        .max(1);
    Ok(Command {
        id: manifest.id.clone(),
        version: manifest.version.clone(),
        request_id: request_id.to_string(),
        // run_id == exec_id: the kill subject the run subscribes to.
        exec_id: Some(run_id.to_string()),
        // KLP Client runs bypass admission by choosing the direct run_job
        // path below, regardless of the manifest's automation setting.
        bypass_local_limit: false,
        shell: manifest.execute.shell.into(),
        script,
        script_object: None,
        script_object_sha256: None,
        timeout_secs,
        // User-fired one-shot — no fan-out, so no jitter / deadline.
        jitter_secs: None,
        run_as: manifest.execute.run_as,
        cwd: manifest.execute.cwd.clone(),
        deadline_at: None,
        staleness: manifest.staleness.clone(),
        // A user-invokable action's stdout drives the progress display.
        // `emit:` (NDJSON) is NOT forwarded — the run path blanks stdout to
        // route events to the timeline, which would wipe the progress view.
        // `check:` IS forwarded (like `collect:` below): the run path reads
        // stdout to record the check WITHOUT blanking it (commands.rs), so
        // the progress display is unaffected. This is the linchpin of the
        // `show_when` display gate — an update job that re-emits its own
        // `check:` on completion flips the gate immediately (check_cache's
        // record() re-publishes the snapshot at once), so the button
        // disappears on the client's next jobs.list instead of waiting for
        // the detector job's next scheduled run.
        emit: None,
        check: manifest.check.clone(),
        // #219: collect IS forwarded (unlike emit/check) — a
        // `collect:` + `client:` job exists precisely so an end user can
        // trigger a collection from the Client App; `run_job` bundles +
        // uploads the listed files on success.
        collect: manifest.collect.clone(),
        // #418 Phase 4: a KLP-fired one-shot has no schedule behind it,
        // so no on_failure.retry policy — the user re-runs from the app.
        retry: None,
        // Forward the finalize hook so a `collect:` + `client:` job
        // triggered from the Client App runs its cleanup hook too.
        finalize: manifest.finalize.as_ref().map(|f| f.lower()),
    })
}

/// Spawned per-run task: push `Running`, run the child, push the
/// terminal `jobs.progress`, and publish the `ExecResult` to the
/// backend. Best-effort — every push tolerates a closed channel
/// (client gone) and the run still completes.
async fn run_job(
    client: async_nats::Client,
    cmd: Command,
    run_id: String,
    push_tx: mpsc::Sender<Vec<u8>>,
    pc_id: String,
) {
    // Client actions are interactive: start immediately without acquiring or
    // consuming a local slot, even when scheduled/admin jobs fill the budget.
    push_progress(
        &push_tx,
        JobProgress {
            run_id: run_id.clone(),
            status: RunStatus::Running,
            stdout_chunk: None,
            stderr_chunk: None,
            exit_code: None,
        },
    )
    .await;

    // #806: stream stdout/stderr to the Client App as it's produced, so
    // the user sees the job is actually working instead of a silent
    // "実行中…" until the one-shot terminal push. We reuse the LiveTail
    // ring — the very buffer the NATS `job.tail` path fills — and poll it,
    // pushing only the delta since the last tick as a `Running` progress.
    // The terminal push below still carries the full output and the client
    // REPLACES on a terminal status, so a dropped / duplicated live delta
    // self-heals. `LiveTail` is capped at 128 KiB, so a delta is always
    // well under the KLP frame limit.
    let live_handle = crate::live_tail::register(&run_id);
    let stop = Arc::new(AtomicBool::new(false));
    let poller = {
        let tail = live_handle.tail();
        let push_tx = push_tx.clone();
        let run_id = run_id.clone();
        let stop = stop.clone();
        tokio::spawn(async move {
            let (mut last_out, mut last_err) = (String::new(), String::new());
            loop {
                tokio::time::sleep(Duration::from_millis(400)).await;
                // Client gone → stop streaming (the run itself continues);
                // no point polling for the rest of a long job.
                if push_tx.is_closed() {
                    break;
                }
                // Read the stop flag BEFORE snapshotting so the final
                // iteration still flushes whatever landed after the run
                // returned, then breaks.
                let done = stop.load(Ordering::Relaxed);
                let snap = tail.snapshot();
                let out_delta = tail_delta(&last_out, &snap.stdout);
                let err_delta = tail_delta(&last_err, &snap.stderr);
                last_out = snap.stdout;
                last_err = snap.stderr;
                if !out_delta.is_empty() || !err_delta.is_empty() {
                    // Best-effort: never await here — a backpressured
                    // channel would stall the poller, which `run_job`
                    // awaits, delaying the terminal push.
                    try_push_progress(
                        &push_tx,
                        JobProgress {
                            run_id: run_id.clone(),
                            status: RunStatus::Running,
                            stdout_chunk: (!out_delta.is_empty()).then_some(out_delta),
                            stderr_chunk: (!err_delta.is_empty()).then_some(err_delta),
                            exit_code: None,
                        },
                    );
                }
                // `!snap.running` also breaks us out if the parent task died
                // and dropped the LiveHandle before ever setting `stop`.
                if done || !snap.running {
                    break;
                }
            }
        })
    };

    let started_at = Utc::now();
    let outcome = run_command_with_kill(&client, &cmd, Some(live_handle.tail())).await;
    let finished_at = Utc::now();

    // Stop the streamer and let its final tick flush before the terminal
    // push (which the client treats as the authoritative full output).
    stop.store(true, Ordering::Relaxed);
    let _ = poller.await;

    // Derive both the client progress AND the (exit_code, stdout,
    // stderr) the ExecResult records — for the ran case AND the
    // never-spawned case, so EVERY jobs.execute attempt lands on the
    // operator Activity page (#478), including a spawn failure.
    let (terminal, exit_code, stdout, stderr) = match &outcome {
        Ok(o) => {
            let (code, out, err) = outcome_to_result_parts(&cmd, o);
            (outcome_to_progress(run_id.clone(), o), code, out, err)
        }
        Err(e) => {
            warn!(run_id = %run_id, pc_id = %pc_id, error = %e, "jobs.execute: run failed to start");
            let msg = with_note("", &format!("agent failed to start the job: {e}"));
            (
                JobProgress {
                    run_id: run_id.clone(),
                    status: RunStatus::Failed,
                    stdout_chunk: None,
                    stderr_chunk: Some(msg.clone()),
                    exit_code: Some(-1),
                },
                -1,
                String::new(),
                msg,
            )
        }
    };
    debug!(run_id = %run_id, pc_id = %pc_id, status = ?terminal.status, "jobs.execute: run finished");
    push_progress(&push_tx, terminal).await;

    // #219: if this is a `collect:` job (typically `collect:` + `client:`
    // so it shows in the Client App) and it succeeded, bundle the
    // script's listed files and upload to OBJECT_COLLECTIONS — the same
    // helper the NATS path uses, so a Client-App-triggered collection
    // produces a bundle too. Read `&stdout` before build_exec_result
    // moves it. Best-effort: failure leaves `collect_object = None`.
    // Mint the parent run's result_id up front (#965): per-bundle
    // finalize runs INSIDE `maybe_collect` and back-links its own rows to
    // this id, so it must exist before collect — not minted later in
    // `build_exec_result`. The same id is handed to `build_exec_result`
    // below so the run's row and its finalize children agree.
    let parent_result_id = Uuid::new_v4().to_string();
    let bundles = if exit_code == 0 && cmd.collect.is_some() {
        let js = async_nats::jetstream::new(client.clone());
        crate::collect::maybe_collect(
            &js,
            &client,
            &cmd,
            &pc_id,
            &parent_result_id,
            &stdout,
            finished_at,
        )
        .await
    } else {
        Vec::new()
    };

    // Build the finalize payload while `bundles` is still in scope; the
    // hook runs AFTER the result is enqueued (below) so a slow cleanup
    // never holds the Activity row pending. Only a `collect:` job gets a
    // payload (non-collect finalize hooks see no `KANADE_COLLECT_RESULT`).
    let finalize_json = cmd
        .collect
        .as_ref()
        .map(|_| crate::finalize::collect_result_json(&bundles));

    // First bundle's key as the representative; the SPA enumerates the
    // bucket for the full per-run set.
    let collect_object = bundles.first().map(|b| b.key.clone());

    // #478: record the run on the backend so operators see
    // user-initiated jobs on the Activity page (audit trail), via the
    // same outbox → JetStream path a normal NATS-driven run uses.
    let mut result = build_exec_result(
        &cmd,
        parent_result_id.clone(),
        &pc_id,
        exit_code,
        stdout,
        stderr,
        started_at,
        finished_at,
    );
    result.collect_object = collect_object;
    enqueue_exec_result(result);

    // Job-generic `finalize:` hook — same as the NATS path, AFTER the
    // result is enqueued. Best-effort. #965: when `on_each_bundle` is set
    // the hook already ran per bundle inside `maybe_collect`; skip the
    // aggregate call so cleanup isn't run twice.
    if exit_code == 0
        && let Some(fin) = cmd.finalize.as_ref()
        && !fin.on_each_bundle
    {
        crate::finalize::run_finalize(
            &client,
            &cmd,
            fin,
            &pc_id,
            &parent_result_id,
            None,
            finalize_json.as_deref(),
        )
        .await;
    }
}

/// Map a finished outcome to the `(exit_code, stdout, stderr)` the
/// ExecResult records. Pure / unit-testable. Synthetic outcomes (kill /
/// timeout) carry exit `-1`; annotate stderr so an operator reading
/// `-1` on the Activity page knows which it was.
fn outcome_to_result_parts(cmd: &Command, outcome: &ExecOutcome) -> (i32, String, String) {
    match outcome {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => (*exit_code, stdout.clone(), stderr.clone()),
        ExecOutcome::Killed { stdout, stderr } => (
            -1,
            stdout.clone(),
            with_note(stderr, "killed by the user via KLP jobs.kill"),
        ),
        ExecOutcome::Timeout { stdout, stderr } => (
            -1,
            stdout.clone(),
            with_note(stderr, &format!("timed out after {}s", cmd.timeout_secs)),
        ),
    }
}

/// Assemble the [`ExecResult`] for a KLP run. Pure / unit-testable.
///
/// `exec_id` is `None`: a KLP run has no parent deployment, so this is
/// an ad-hoc result (like `kanade run`) and must NOT carry the
/// `run_id` as an `exec_id` — that would point the backend's
/// `executions`-aggregate projector at a row that doesn't exist
/// (#478). `cmd.exec_id` stays `Some(run_id)` for `jobs.kill`; only the
/// RESULT decouples. `result_id` is supplied by the caller (#966: minted
/// before collect so per-bundle finalize rows can back-link to it) and
/// asserted in tests.
#[allow(clippy::too_many_arguments)]
fn build_exec_result(
    cmd: &Command,
    result_id: String,
    pc_id: &str,
    exit_code: i32,
    stdout: String,
    stderr: String,
    started_at: chrono::DateTime<Utc>,
    finished_at: chrono::DateTime<Utc>,
) -> ExecResult {
    ExecResult {
        result_id,
        request_id: cmd.request_id.clone(),
        exec_id: None,
        // A KLP-initiated run is itself a parent, never a finalize row (#955).
        parent_result_id: None,
        pc_id: pc_id.to_string(),
        exit_code,
        stdout,
        stderr,
        started_at,
        finished_at,
        // The outbox drain offloads oversized output to the object
        // store on its own; None at enqueue keeps the full bytes on disk.
        stdout_object: None,
        stderr_object: None,
        manifest_id: Some(cmd.id.clone()),
        // #219: set by the collect step (PR2) for a `collect:` job; None
        // otherwise. The KLP path is exactly how a `collect:`+`client:`
        // job fired from the Client App gets bundled.
        collect_object: None,
    }
}

/// Enqueue a finished run's [`ExecResult`] onto the outbox. Offloaded
/// to the blocking pool because `outbox::enqueue` does synchronous file
/// I/O (`create_dir_all` / `write` / `rename`) that would otherwise
/// block an async runtime thread. Fire-and-forget + best-effort: an
/// enqueue failure is logged, never fails the run (the client already
/// got its terminal progress).
fn enqueue_exec_result(result: ExecResult) {
    let manifest_id = result.manifest_id.clone().unwrap_or_default();
    let pc_id = result.pc_id.clone();
    tokio::task::spawn_blocking(move || {
        let outbox_dir = default_paths::data_dir().join("outbox");
        match outbox::enqueue(&outbox_dir, &result) {
            Ok(path) => debug!(
                manifest_id = %manifest_id,
                pc_id = %pc_id,
                outbox = %path.display(),
                "jobs.execute: ExecResult enqueued (operator visibility, #478)",
            ),
            Err(e) => warn!(
                manifest_id = %manifest_id,
                pc_id = %pc_id,
                error = %e,
                "jobs.execute: ExecResult outbox enqueue failed (run still completed)",
            ),
        }
    });
}

/// Append a `[KLP] <note>` line to a captured stderr (or use it alone
/// when stderr is blank), so an operator seeing exit `-1` knows whether
/// the run was killed or timed out. Trailing whitespace is trimmed
/// first so a process's trailing newline doesn't produce a blank line
/// before the note.
fn with_note(stderr: &str, note: &str) -> String {
    let trimmed = stderr.trim_end();
    if trimmed.is_empty() {
        format!("[KLP] {note}")
    } else {
        format!("{trimmed}\n[KLP] {note}")
    }
}

/// New suffix of a live-tail snapshot beyond what was already streamed
/// (`prev`). When the 128 KiB ring has wrapped (output outran the buffer)
/// `current` no longer starts with `prev`; fall back to sending the whole
/// current tail — a rare large-output case where a little duplication
/// beats a gap, and the authoritative terminal push corrects it anyway.
fn tail_delta(prev: &str, current: &str) -> String {
    if let Some(rest) = current.strip_prefix(prev) {
        return rest.to_string();
    }
    // The 128 KiB ring wrapped (output outran the buffer since the last
    // tick), so `current` no longer starts with `prev`. Re-anchor on the
    // tail of `prev` (its last ~256 bytes) and emit only the genuinely-new
    // suffix, instead of resending the whole 128 KiB tail as a duplicate.
    let mut start = prev.len().saturating_sub(256);
    while start < prev.len() && !prev.is_char_boundary(start) {
        start += 1;
    }
    if start < prev.len() {
        let sig = &prev[start..];
        if let Some(pos) = current.rfind(sig) {
            return current[pos + sig.len()..].to_string();
        }
    }
    // No anchor found (the whole window churned) — fall back to the full
    // tail; a little duplication beats a gap, and the authoritative
    // terminal push self-heals it anyway.
    current.to_string()
}

/// Per-chunk cap on a terminal progress push's stdout/stderr. The KLP
/// framing layer rejects frames over 1 MiB (SPEC §2.12.2); a job that
/// dumps megabytes of output would otherwise produce a frame the
/// writer can't deliver, silently dropping the terminal status. Cap
/// each chunk at 256 KiB so stdout + stderr + the JSON envelope stay
/// comfortably under the frame limit. A truncated run still reports its
/// real status + exit_code; only the tail of the output is dropped (the
/// full output also lives in the agent log).
const MAX_PROGRESS_CHUNK_BYTES: usize = 256 * 1024;

/// Map a finished [`ExecOutcome`] to its terminal `jobs.progress`.
/// Pure so the status / exit-code mapping is unit-testable without a
/// real child. Empty stdout/stderr are omitted (`None`) per the wire
/// contract — strict JS clients reject `null` chunk strings.
pub fn outcome_to_progress(run_id: String, outcome: &ExecOutcome) -> JobProgress {
    use std::borrow::Cow;
    // Borrow the captured strings (they can be hundreds of KiB) — only
    // the Timeout arm needs an owned stderr to append its note, so it's
    // the only `Cow::Owned`.
    let (status, exit_code, stdout, stderr): (RunStatus, i32, Cow<str>, Cow<str>) = match outcome {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => {
            let status = if *exit_code == 0 {
                RunStatus::Completed
            } else {
                RunStatus::Failed
            };
            (
                status,
                *exit_code,
                Cow::Borrowed(stdout),
                Cow::Borrowed(stderr),
            )
        }
        // Synthetic outcomes carry exit_code -1; the `status` field is
        // what distinguishes "you stopped it" from "it errored".
        ExecOutcome::Killed { stdout, stderr } => (
            RunStatus::Killed,
            -1,
            Cow::Borrowed(stdout),
            Cow::Borrowed(stderr),
        ),
        // Timeout folds into `Failed` — the wire `RunStatus` has no
        // Timeout variant — so a bare client would render it
        // indistinguishably from a non-zero exit. Stamp a note onto
        // stderr so the Client App can show WHY it failed ("timed out"
        // vs "errored"), since the script's own stderr usually says
        // nothing about being killed at the deadline.
        ExecOutcome::Timeout { stdout, stderr } => {
            const NOTE: &str =
                "⏱ ジョブがタイムアウトしました（manifest の timeout で打ち切られました）";
            let stderr = if stderr.trim().is_empty() {
                NOTE.to_string()
            } else {
                format!("{stderr}\n{NOTE}")
            };
            (
                RunStatus::Failed,
                -1,
                Cow::Borrowed(stdout),
                Cow::Owned(stderr),
            )
        }
    };
    JobProgress {
        run_id,
        status,
        stdout_chunk: (!stdout.is_empty()).then(|| cap_chunk(&stdout)),
        stderr_chunk: (!stderr.is_empty()).then(|| cap_chunk(&stderr)),
        exit_code: Some(exit_code),
    }
}

/// Truncate a progress chunk to [`MAX_PROGRESS_CHUNK_BYTES`] on a UTF-8
/// char boundary, appending a marker so the user sees output was
/// dropped. Returns the input unchanged when it's already under cap.
fn cap_chunk(s: &str) -> String {
    if s.len() <= MAX_PROGRESS_CHUNK_BYTES {
        return s.to_string();
    }
    let mut end = MAX_PROGRESS_CHUNK_BYTES;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}\n…[truncated: output exceeded 256 KiB]", &s[..end])
}

/// Encode a `jobs.progress` notification to its wire frame. A
/// serialise failure is logged and yields `None` (the push is dropped);
/// shared by the awaited [`push_progress`] and the best-effort
/// [`try_push_progress`].
fn encode_progress(progress: &JobProgress) -> Option<Vec<u8>> {
    let notif = match RpcNotification::new(method::JOBS_PROGRESS, progress) {
        Ok(n) => n,
        Err(e) => {
            warn!(error = %e, "jobs.progress: failed to encode notification");
            return None;
        }
    };
    match serde_json::to_vec(&notif) {
        Ok(b) => Some(b),
        Err(e) => {
            warn!(error = %e, "jobs.progress: failed to serialise frame");
            None
        }
    }
}

/// Push a `jobs.progress` notification on the connection's writer
/// channel, awaiting backpressure. Used for the milestone pushes
/// (`Running` start, terminal status) that must not be dropped. A closed
/// channel (client disconnected) just means progress stops — the run
/// itself is unaffected.
async fn push_progress(push_tx: &mpsc::Sender<Vec<u8>>, progress: JobProgress) {
    let Some(body) = encode_progress(&progress) else {
        return;
    };
    if push_tx.send(body).await.is_err() {
        debug!("jobs.progress: push channel closed (client gone)");
    }
}

/// Best-effort `jobs.progress` push for the #806 live-delta stream: a
/// full-but-open channel DROPS the delta rather than awaiting, because
/// `run_job` awaits the poller — a stall here would delay the terminal
/// push and result recording (CodeRabbit). The authoritative terminal
/// push (awaited) carries the full output, so a dropped delta self-heals
/// on the client.
fn try_push_progress(push_tx: &mpsc::Sender<Vec<u8>>, progress: JobProgress) {
    let Some(body) = encode_progress(&progress) else {
        return;
    };
    use tokio::sync::mpsc::error::TrySendError;
    match push_tx.try_send(body) {
        Ok(()) => {}
        Err(TrySendError::Full(_)) => {
            debug!("jobs.progress: live delta dropped (channel full)");
        }
        Err(TrySendError::Closed(_)) => {
            debug!("jobs.progress: live delta dropped (client gone)");
        }
    }
}

// ---------- jobs.kill ----------

/// `jobs.kill` — request termination of a run started ON THIS
/// connection. SPEC §2.12.4 forbids cross-connection kill, so a
/// `run_id` this connection never started → `Unauthorized` (NOT
/// `NotFound`, which would leak whether the id exists on another
/// connection). Publishes `subject::kill(run_id)`; the run's terminal
/// `jobs.progress` (status = Killed) follows once the child exits.
pub async fn handle_jobs_kill(
    conn: &ConnectionState,
    params: JobsKillParams,
) -> HandlerResult<JobsKillResult> {
    if !conn.owns_run(&params.run_id) {
        return Err(RpcError::new(
            ErrorKind::Unauthorized,
            format!("run '{}' was not started on this connection", params.run_id),
        ));
    }
    let client = conn.nats.as_ref().ok_or_else(|| {
        RpcError::new(
            ErrorKind::InternalError,
            "jobs.kill: NATS client not wired into the connection",
        )
    })?;
    client
        .publish(subject::kill(&params.run_id), bytes::Bytes::new())
        .await
        .map_err(|e| {
            warn!(run_id = %params.run_id, error = %e, "jobs.kill: publish failed");
            RpcError::new(
                ErrorKind::InternalError,
                format!("jobs.kill: publish kill signal: {e}"),
            )
        })?;
    Ok(JobsKillResult {
        requested_at: Utc::now(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use kanade_shared::ipc::state::CheckStatus;
    use kanade_shared::manifest::{
        ClientHint, ConfirmHint, Execute, ExecuteShell, ShowWhen, Target,
    };
    use kanade_shared::wire::{RunAs, Staleness};

    /// No-checks map for the visibility/projection tests that don't
    /// exercise `show_when` (an empty snapshot gates nothing).
    fn no_checks() -> HashMap<String, CheckStatus> {
        HashMap::new()
    }

    /// Unlock predicate for the tests that don't exercise `client.unlock`:
    /// the caller holds no grants, which is the state every user is in until
    /// a support code is redeemed.
    fn all_locked(_scope: &str) -> bool {
        false
    }

    /// Build a manifest fixture. Pass `client: Some((name, category_key))`
    /// for a user-invokable job, `None` for an operator-only one.
    fn manifest(id: &str, client: Option<(&str, &str)>) -> Manifest {
        Manifest {
            id: id.into(),
            version: "1.0.0".into(),
            description: None,
            execute: Execute {
                bypass_local_limit: false,
                shell: ExecuteShell::Powershell,
                script: Some("echo hi".into()),
                script_file: None,
                script_object: None,
                timeout: "30s".into(),
                run_as: RunAs::default(),
                cwd: None,
            },
            require_approval: false,
            inventory: None,
            emit: None,
            check: None,
            collect: None,
            aggregate: None,
            staleness: Staleness::default(),
            client: client.map(|(name, category)| ClientHint {
                name: name.into(),
                description: None,
                category: category.into(),
                category_label: None,
                category_icon: None,
                category_order: None,
                icon: None,
                visible_to: None,
                show_when: None,
                confirm: None,
                unlock: None,
            }),
            tags: Vec::new(),
            origin: None,
            finalize: None,
            feed: Vec::new(),
            tier: None,
        }
    }

    #[test]
    fn lists_only_client_jobs() {
        let manifests = [
            manifest("inv-hw", None),
            manifest("chrome-update", Some(("Chrome を更新", "software_update"))),
            manifest("check-bitlocker", None),
        ];
        let result = build_job_list(&manifests, None, "PC1", &[], &no_checks(), &all_locked);
        assert_eq!(result.items.len(), 1);
        assert_eq!(result.items[0].id, "chrome-update");
        assert_eq!(result.items[0].display_name, "Chrome を更新");
        assert_eq!(result.items[0].category, "software_update");
        assert!(result.items[0].last_run.is_none());
    }

    #[test]
    fn category_filter_narrows_to_one_tab() {
        let manifests = [
            manifest("chrome-update", Some(("Chrome", "software_update"))),
            manifest("fix-teams", Some(("Teams 修復", "troubleshoot"))),
            manifest("install-slack", Some(("Slack", "catalog"))),
        ];
        let only_troubleshoot = build_job_list(
            &manifests,
            Some("troubleshoot".to_string()),
            "PC1",
            &[],
            &no_checks(),
            &all_locked,
        );
        assert_eq!(only_troubleshoot.items.len(), 1);
        assert_eq!(only_troubleshoot.items[0].id, "fix-teams");
    }

    #[test]
    fn empty_when_no_client_jobs() {
        let manifests = [manifest("inv-hw", None), manifest("inv-sw", None)];
        let result = build_job_list(&manifests, None, "PC1", &[], &no_checks(), &all_locked);
        assert!(result.items.is_empty());
    }

    #[test]
    fn visible_to_filters_by_pc_and_group() {
        // #816: one job visible to all, one scoped to group "wave1", one
        // scoped to pc "PC2".
        let public = manifest("public", Some(("Public", "catalog")));
        let mut grouped = manifest("grouped", Some(("Grouped", "settings")));
        grouped.client.as_mut().unwrap().visible_to = Some(Target {
            groups: vec!["wave1".into()],
            ..Default::default()
        });
        let mut pc_only = manifest("pc-only", Some(("PcOnly", "settings")));
        pc_only.client.as_mut().unwrap().visible_to = Some(Target {
            pcs: vec!["PC2".into()],
            ..Default::default()
        });
        let manifests = [public, grouped, pc_only];

        // PC1 in no groups → only the public job.
        let r = build_job_list(&manifests, None, "PC1", &[], &no_checks(), &all_locked);
        let ids: Vec<_> = r.items.iter().map(|j| j.id.as_str()).collect();
        assert_eq!(ids, vec!["public"]);

        // PC1 in wave1 → public + grouped.
        let r = build_job_list(
            &manifests,
            None,
            "PC1",
            &["wave1".to_string()],
            &no_checks(),
            &all_locked,
        );
        let mut ids: Vec<_> = r.items.iter().map(|j| j.id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["grouped", "public"]);

        // PC2 (no groups) → public + pc-only.
        let r = build_job_list(&manifests, None, "PC2", &[], &no_checks(), &all_locked);
        let mut ids: Vec<_> = r.items.iter().map(|j| j.id.clone()).collect();
        ids.sort();
        assert_eq!(ids, vec!["pc-only", "public"]);
    }

    #[test]
    fn show_when_gates_on_check_result() {
        // An update job gated on `office-up-to-date == fail`: shown while
        // the check fails (not yet updated), hidden once it's ok, and
        // hidden when the check has never run (absent ⇒ fails closed).
        let mut update = manifest("office-update", Some(("Office を更新", "software_update")));
        update.client.as_mut().unwrap().show_when = Some(ShowWhen {
            check: "office-up-to-date".into(),
            is: vec![CheckStatus::Fail],
        });
        let manifests = std::slice::from_ref(&update);

        let shown = |checks: &HashMap<String, CheckStatus>| {
            !build_job_list(manifests, None, "PC1", &[], checks, &all_locked)
                .items
                .is_empty()
        };

        // Check failing → not yet updated → button shown.
        let mut failing = HashMap::new();
        failing.insert("office-up-to-date".to_string(), CheckStatus::Fail);
        assert!(shown(&failing), "should show while check fails");

        // Check ok → already updated → button hidden.
        let mut ok = HashMap::new();
        ok.insert("office-up-to-date".to_string(), CheckStatus::Ok);
        assert!(!shown(&ok), "should hide once check is ok");

        // Check never ran (absent) → hidden (fails closed).
        assert!(!shown(&no_checks()), "absent check must hide the job");
    }

    #[test]
    fn show_when_absent_always_shows() {
        // A job with no show_when is unaffected by check state.
        let job = manifest("plain", Some(("Plain", "catalog")));
        let mut checks = HashMap::new();
        checks.insert("whatever".to_string(), CheckStatus::Fail);
        let r = build_job_list(
            std::slice::from_ref(&job),
            None,
            "PC1",
            &[],
            &checks,
            &all_locked,
        );
        assert_eq!(r.items.len(), 1);
    }

    #[test]
    fn unlock_hides_the_job_until_its_scope_is_granted() {
        // The core of the 裏コマンド gate: a scoped job is absent from the
        // catalog for a locked caller and present for an unlocked one.
        let mut secret = manifest(
            "profile-rebuild",
            Some(("プロファイル再作成", "troubleshoot")),
        );
        secret.client.as_mut().unwrap().unlock = Some("support".into());
        let manifests = std::slice::from_ref(&secret);

        assert!(
            build_job_list(manifests, None, "PC1", &[], &no_checks(), &all_locked)
                .items
                .is_empty(),
            "a locked caller must not even see the row",
        );

        let holds_support = |scope: &str| scope == "support";
        let r = build_job_list(manifests, None, "PC1", &[], &no_checks(), &holds_support);
        assert_eq!(r.items.len(), 1);
        // The row carries its scope so the client can badge it as
        // helpdesk-only rather than rendering it like an everyday action.
        assert_eq!(r.items[0].unlock.as_deref(), Some("support"));
    }

    #[test]
    fn unlock_grants_open_only_their_own_scope() {
        // Holding the first-line code must not reveal the administrator
        // jobs — the whole point of having more than one scope.
        let mut desk = manifest("desk-job", Some(("一次対応", "troubleshoot")));
        desk.client.as_mut().unwrap().unlock = Some("support".into());
        let mut admin = manifest("admin-job", Some(("管理者用", "troubleshoot")));
        admin.client.as_mut().unwrap().unlock = Some("admin".into());
        let manifests = [desk, admin];

        let holds_support = |scope: &str| scope == "support";
        let r = build_job_list(&manifests, None, "PC1", &[], &no_checks(), &holds_support);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].id, "desk-job");
    }

    #[test]
    fn unlock_absent_always_shows_and_carries_no_badge() {
        // Every ordinary job must be unaffected: this is the field that
        // could quietly empty the whole catalog if its default flipped.
        let plain = manifest("plain", Some(("Plain", "catalog")));
        let r = build_job_list(
            std::slice::from_ref(&plain),
            None,
            "PC1",
            &[],
            &no_checks(),
            &all_locked,
        );
        assert_eq!(r.items.len(), 1);
        assert!(r.items[0].unlock.is_none());
    }

    #[test]
    fn maps_all_client_fields() {
        // Full projection incl. the optional description + icon.
        let mut m = manifest("fix-teams", Some(("Teams 修復", "troubleshoot")));
        if let Some(c) = m.client.as_mut() {
            c.description = Some("重いとき用".into());
            c.icon = Some("brush-cleaning".into());
        }
        let result = build_job_list(
            std::slice::from_ref(&m),
            None,
            "PC1",
            &[],
            &no_checks(),
            &all_locked,
        );
        let row = &result.items[0];
        assert_eq!(row.display_description.as_deref(), Some("重いとき用"));
        assert_eq!(row.icon.as_deref(), Some("brush-cleaning"));
        assert_eq!(row.version, "1.0.0");
        // #865: the manifest's 30s timeout is lowered onto the row so the
        // client's stuck-run watchdog can honor it.
        assert_eq!(row.timeout_secs, Some(30));
    }

    #[test]
    fn maps_confirm_config() {
        // A manifest's `client.confirm` projects 1:1 onto the row so the
        // Client App can suppress the modal or reword it. Absent ⇒ None
        // (client keeps its always-confirm default).
        let plain = manifest("plain", Some(("Plain", "catalog")));
        let plain_row = &build_job_list(
            std::slice::from_ref(&plain),
            None,
            "PC1",
            &[],
            &no_checks(),
            &all_locked,
        )
        .items[0];
        assert!(plain_row.confirm.is_none());

        let mut m = manifest("wifi-tweak", Some(("Wi-Fi 省電力を切る", "settings")));
        m.client.as_mut().unwrap().confirm = Some(ConfirmHint {
            enabled: false,
            message: Some("すぐ実行します".into()),
        });
        let row = &build_job_list(
            std::slice::from_ref(&m),
            None,
            "PC1",
            &[],
            &no_checks(),
            &all_locked,
        )
        .items[0];
        let c = row.confirm.as_ref().expect("confirm projected");
        assert!(!c.enabled);
        assert_eq!(c.message.as_deref(), Some("すぐ実行します"));
    }

    #[test]
    fn timeout_secs_surfaced_and_floored() {
        // A long timeout passes through verbatim; a sub-second one floors
        // to 1s (same convention as build_command) so the client never
        // sees an ambiguous 0.
        let mut long = manifest("office-repair", Some(("Office 修復", "troubleshoot")));
        long.execute.timeout = "1h".into();
        let mut sub = manifest("blip", Some(("Blip", "catalog")));
        sub.execute.timeout = "500ms".into();
        let result = build_job_list(&[long, sub], None, "PC1", &[], &no_checks(), &all_locked);
        let by_id = |id: &str| {
            result
                .items
                .iter()
                .find(|j| j.id == id)
                .unwrap_or_else(|| panic!("{id} missing"))
        };
        assert_eq!(by_id("office-repair").timeout_secs, Some(3600));
        assert_eq!(by_id("blip").timeout_secs, Some(1));
    }

    #[test]
    fn items_sorted_by_display_name() {
        let manifests = [
            manifest("z", Some(("Zebra", "catalog"))),
            manifest("a", Some(("Apple", "catalog"))),
            manifest("m", Some(("Mango", "catalog"))),
        ];
        let result = build_job_list(&manifests, None, "PC1", &[], &no_checks(), &all_locked);
        let names: Vec<&str> = result
            .items
            .iter()
            .map(|j| j.display_name.as_str())
            .collect();
        assert_eq!(names, ["Apple", "Mango", "Zebra"]);
    }

    // ---------- build_command ----------

    #[test]
    fn build_command_maps_manifest_fields() {
        let mut m = manifest("fix-teams", Some(("Teams 修復", "troubleshoot")));
        m.execute.run_as = RunAs::User;
        m.execute.cwd = Some("C:/temp".into());
        m.execute.timeout = "90s".into();
        let cmd = build_command(&m, "run-123", "req-9").expect("build");
        assert_eq!(cmd.id, "fix-teams");
        assert_eq!(cmd.version, "1.0.0");
        assert_eq!(cmd.exec_id.as_deref(), Some("run-123")); // run_id == exec_id
        assert_eq!(cmd.request_id, "req-9"); // caller-supplied → deterministic
        assert_eq!(cmd.script, "echo hi");
        assert_eq!(cmd.timeout_secs, 90);
        assert_eq!(cmd.run_as, RunAs::User);
        assert_eq!(cmd.cwd.as_deref(), Some("C:/temp"));
        assert!(cmd.jitter_secs.is_none());
        assert!(cmd.deadline_at.is_none());
        // `emit:` is never forwarded (it would blank the progress stdout).
        // This fixture has no `check:`, so check stays None here — see
        // `build_command_forwards_check` for the forwarded case.
        assert!(cmd.emit.is_none() && cmd.check.is_none());
        assert!(cmd.script_object.is_none());
    }

    #[test]
    fn build_command_forwards_check() {
        // A `client:` + `check:` job (the show_when "self-freshen" pattern)
        // forwards its check hint so a button-press run records the check
        // on completion — like `collect:`, the run path reads stdout for it
        // without blanking the progress display.
        use kanade_shared::manifest::CheckHint;
        let mut m = manifest("office-update", Some(("Office を更新", "software_update")));
        m.check = Some(CheckHint {
            name: "office-up-to-date".into(),
            label: None,
            status_field: "status".into(),
            detail_field: "detail".into(),
            troubleshoot: None,
            fleet: true,
            health: true,
            alert: None,
        });
        let cmd = build_command(&m, "run-1", "req-1").expect("build");
        assert_eq!(
            cmd.check.expect("check forwarded").name,
            "office-up-to-date"
        );
        // emit is still never forwarded.
        assert!(cmd.emit.is_none());
    }

    #[test]
    fn build_command_rejects_script_object() {
        let mut m = manifest("obj-job", Some(("Obj", "catalog")));
        m.execute.script = None;
        m.execute.script_object = Some("cleanup/1.0.0".into());
        let err = build_command(&m, "r1", "req-1").expect_err("script_object unsupported");
        assert_eq!(err.data.unwrap().kind, ErrorKind::InvalidParams);
    }

    #[test]
    fn build_command_rejects_missing_inline_script() {
        let mut m = manifest("empty", Some(("Empty", "catalog")));
        m.execute.script = None;
        let err = build_command(&m, "r1", "req-1").expect_err("no script");
        let data = err.data.unwrap();
        assert_eq!(data.kind, ErrorKind::InvalidParams);
        assert!(data.detail.contains("no inline script"), "{}", data.detail);
    }

    #[test]
    fn build_command_rejects_bad_timeout() {
        let mut m = manifest("bad", Some(("Bad", "catalog")));
        m.execute.timeout = "not-a-duration".into();
        let err = build_command(&m, "r1", "req-1").expect_err("bad timeout");
        let data = err.data.unwrap();
        assert_eq!(data.kind, ErrorKind::InvalidParams);
        assert!(data.detail.contains("timeout"), "{}", data.detail);
    }

    #[test]
    fn build_command_floors_subsecond_timeout_to_one() {
        // `500ms`.as_secs() == 0, which is an ambiguous timeout to the
        // run path — floor any positive duration at 1s.
        let mut m = manifest("ms", Some(("Ms", "catalog")));
        m.execute.timeout = "500ms".into();
        let cmd = build_command(&m, "r1", "req-1").expect("build");
        assert_eq!(cmd.timeout_secs, 1);
    }

    // ---------- valid_job_id ----------

    #[test]
    fn valid_job_id_accepts_slugs_rejects_junk() {
        for ok in ["chrome-update", "fix_teams.cache", "Job123", "a"] {
            assert!(valid_job_id(ok), "{ok} should be valid");
        }
        for bad in ["", "has space", "wild*", "a>b", "with/slash", "qu?x"] {
            assert!(!valid_job_id(bad), "{bad:?} should be invalid");
        }
    }

    // ---------- cap_chunk ----------

    #[test]
    fn cap_chunk_passes_through_small_output() {
        assert_eq!(cap_chunk("hello"), "hello");
    }

    #[test]
    fn cap_chunk_truncates_oversize_on_char_boundary() {
        // A multibyte string well over the cap: truncation must land on
        // a char boundary (no panic) and carry the marker.
        let big = "あ".repeat(MAX_PROGRESS_CHUNK_BYTES); // 3 bytes each
        let out = cap_chunk(&big);
        assert!(out.len() < big.len(), "must shrink");
        assert!(out.contains("truncated"), "must mark truncation");
        // Round-trips as valid UTF-8 (would have panicked on a bad cut).
        assert!(out.is_char_boundary(out.len()));
    }

    // ---------- outcome_to_progress ----------

    #[test]
    fn outcome_completed_zero_is_completed() {
        let p = outcome_to_progress(
            "r1".into(),
            &ExecOutcome::Completed {
                exit_code: 0,
                stdout: "done".into(),
                stderr: String::new(),
            },
        );
        assert_eq!(p.status, RunStatus::Completed);
        assert_eq!(p.exit_code, Some(0));
        assert_eq!(p.stdout_chunk.as_deref(), Some("done"));
        // Empty stderr is omitted, not Some("").
        assert!(p.stderr_chunk.is_none());
    }

    #[test]
    fn outcome_completed_nonzero_is_failed() {
        let p = outcome_to_progress(
            "r1".into(),
            &ExecOutcome::Completed {
                exit_code: 3,
                stdout: String::new(),
                stderr: "boom".into(),
            },
        );
        assert_eq!(p.status, RunStatus::Failed);
        assert_eq!(p.exit_code, Some(3));
        assert!(p.stdout_chunk.is_none());
        assert_eq!(p.stderr_chunk.as_deref(), Some("boom"));
    }

    #[test]
    fn outcome_killed_maps_to_killed_minus_one() {
        let p = outcome_to_progress(
            "r1".into(),
            &ExecOutcome::Killed {
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        assert_eq!(p.status, RunStatus::Killed);
        assert_eq!(p.exit_code, Some(-1));
    }

    #[test]
    fn outcome_timeout_maps_to_failed_with_note() {
        // Timeout → Failed, but a note is stamped onto stderr so the
        // client can show "timed out" rather than a bare "failed".
        let p = outcome_to_progress(
            "r1".into(),
            &ExecOutcome::Timeout {
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        assert_eq!(p.status, RunStatus::Failed);
        assert_eq!(p.exit_code, Some(-1));
        assert!(
            p.stderr_chunk
                .as_deref()
                .is_some_and(|s| s.contains("タイムアウト")),
            "stderr_chunk should carry the timeout note: {:?}",
            p.stderr_chunk
        );
    }

    #[test]
    fn outcome_timeout_appends_note_after_existing_stderr() {
        let p = outcome_to_progress(
            "r1".into(),
            &ExecOutcome::Timeout {
                stdout: String::new(),
                stderr: "partial output before kill".into(),
            },
        );
        let chunk = p.stderr_chunk.expect("stderr present");
        assert!(chunk.contains("partial output before kill"), "{chunk}");
        assert!(chunk.contains("タイムアウト"), "{chunk}");
    }

    // ---------- jobs.kill authorization ----------

    fn fresh_conn() -> ConnectionState {
        use kanade_shared::ipc::state::StateSnapshot;
        use kanade_shared::wire::EffectiveConfig;
        use std::path::PathBuf;
        use tokio::sync::watch;

        let (_cfg_tx, cfg_rx) = watch::channel(EffectiveConfig::builtin_defaults());
        let snapshot = StateSnapshot {
            pc_id: "PC1".into(),
            online: true,
            checks: vec![],
            agent_version: "0.0.0".into(),
            target_version: "0.0.0".into(),
        };
        let (_state_tx, state_rx) = watch::channel(snapshot);
        let (push_tx, _push_rx) = mpsc::channel(8);
        ConnectionState::new(
            crate::klp::auth::PeerCredentials {
                user: "DOMAIN\\alice".into(),
                user_sid: "S-1-5-21-1001".into(),
                session_id: 2,
            },
            "PC1".into(),
            "0.0.0".into(),
            cfg_rx,
            state_rx,
            PathBuf::from("agent.log"),
            push_tx,
        )
    }

    #[tokio::test]
    async fn kill_unknown_run_is_unauthorized() {
        // A run_id this connection never started → Unauthorized (NOT
        // NotFound), and we never even reach the NATS publish.
        let conn = fresh_conn();
        let err = handle_jobs_kill(
            &conn,
            JobsKillParams {
                run_id: "never-started".into(),
            },
        )
        .await
        .expect_err("unknown run must be unauthorized");
        assert_eq!(err.data.unwrap().kind, ErrorKind::Unauthorized);
    }

    #[tokio::test]
    async fn kill_owned_run_passes_authorization() {
        // A registered run_id passes the same-connection gate; it then
        // fails at the NATS publish (no client wired in this test),
        // which proves authorization succeeded rather than being
        // rejected up front.
        let mut conn = fresh_conn();
        conn.register_run("run-mine".into());
        let err = handle_jobs_kill(
            &conn,
            JobsKillParams {
                run_id: "run-mine".into(),
            },
        )
        .await
        .expect_err("no nats wired → InternalError after auth passes");
        assert_eq!(err.data.unwrap().kind, ErrorKind::InternalError);
    }

    // ---------- build_exec_result (#478 operator visibility) ----------

    fn cmd_fixture(id: &str) -> Command {
        let m = manifest(id, Some(("Job", "catalog")));
        build_command(&m, "run-1", "req-1").expect("build_command")
    }

    #[test]
    fn exec_result_is_ad_hoc_with_manifest_id() {
        // The KLP run must record as an ad-hoc result (exec_id None) so
        // the backend doesn't try to increment a non-existent
        // `executions` aggregate row keyed by exec_id (#478).
        let cmd = cmd_fixture("fix-teams");
        let now = Utc::now();
        let r = build_exec_result(
            &cmd,
            "rid-1".into(),
            "PC1",
            0,
            "ok".into(),
            String::new(),
            now,
            now,
        );
        assert!(r.exec_id.is_none(), "KLP run must be ad-hoc (exec_id None)");
        assert_eq!(r.manifest_id.as_deref(), Some("fix-teams"));
        assert_eq!(r.pc_id, "PC1");
        assert_eq!(r.exit_code, 0);
        assert_eq!(r.stdout, "ok");
        assert_eq!(r.result_id, "rid-1", "caller-supplied result_id is used");
    }

    #[test]
    fn result_parts_completed_passes_through() {
        let cmd = cmd_fixture("j");
        let (code, out, err) = outcome_to_result_parts(
            &cmd,
            &ExecOutcome::Completed {
                exit_code: 2,
                stdout: "o".into(),
                stderr: "e".into(),
            },
        );
        assert_eq!((code, out.as_str(), err.as_str()), (2, "o", "e"));
    }

    #[test]
    fn result_parts_killed_and_timeout_annotate_stderr() {
        let cmd = cmd_fixture("j");

        let (code, _out, err) = outcome_to_result_parts(
            &cmd,
            &ExecOutcome::Killed {
                stdout: String::new(),
                stderr: String::new(),
            },
        );
        assert_eq!(code, -1);
        assert!(err.contains("killed"), "{err}");

        let (code, _out, err) = outcome_to_result_parts(
            &cmd,
            &ExecOutcome::Timeout {
                stdout: String::new(),
                stderr: "partial".into(),
            },
        );
        assert_eq!(code, -1);
        // Existing partial output is kept AND the note is appended.
        assert!(
            err.contains("partial") && err.contains("timed out"),
            "{err}"
        );
    }

    #[test]
    fn with_note_appends_or_stands_alone() {
        assert_eq!(with_note("", "x"), "[KLP] x");
        assert_eq!(with_note("   ", "x"), "[KLP] x");
        assert_eq!(with_note("out", "x"), "out\n[KLP] x");
        // Trailing newline is trimmed so there's no blank line before
        // the note.
        assert_eq!(with_note("out\n", "x"), "out\n[KLP] x");
    }

    #[test]
    fn tail_delta_emits_only_the_new_suffix() {
        // Steady state: current extends prev → just the appended part.
        assert_eq!(tail_delta("abc", "abcdef"), "def");
        // Nothing new since the last tick.
        assert_eq!(tail_delta("abc", "abc"), "");
        // First tick (no prior output).
        assert_eq!(tail_delta("", "hello"), "hello");
    }

    #[test]
    fn tail_delta_reanchors_after_ring_wrap() {
        // The re-anchor only kicks in once `prev` exceeds the 256-byte
        // signature window, so build a realistic >256-byte overlap. The
        // ring dropped its head ("DROPPED_HEAD"); `current` shares the
        // 300-byte body and adds a new tail — we want only that tail.
        let body: String = (0..300).map(|i| (b'a' + (i % 26) as u8) as char).collect();
        let prev = format!("DROPPED_HEAD{body}");
        let current = format!("{body}_NEW_TAIL");
        assert_eq!(tail_delta(&prev, &current), "_NEW_TAIL");
        // No overlap at all (even with a long prev) → fall back to the
        // full tail; a little duplication beats a gap.
        assert_eq!(tail_delta(&"z".repeat(300), "qqqq"), "qqqq");
    }
}
