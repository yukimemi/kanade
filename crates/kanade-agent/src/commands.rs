use std::collections::{HashSet, VecDeque};
use std::sync::Arc;

use anyhow::Result;
use async_nats::jetstream::kv::Store;
use futures::StreamExt;
use kanade_shared::ExecResult;
use kanade_shared::default_paths;
use kanade_shared::kv::{BUCKET_SCRIPT_CURRENT, BUCKET_SCRIPT_STATUS, SCRIPT_STATUS_REVOKED};
use kanade_shared::wire::{
    Command, EXIT_REJECTED_UNSIGNED, EXIT_SKIP_DEADLINE, EXIT_SKIP_REVOKED, EXIT_SKIP_STALENESS,
    EXIT_SKIP_VERSION_PIN,
};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::outbox;
use crate::process::{ExecOutcome, apply_jitter, run_command_with_kill};
use crate::script_cache::ScriptCache;
use crate::staleness::{StalenessDecision, Tracker, decide as staleness_decide};

/// FIFO-bounded set of recently-seen `request_id`s. Shared between
/// the core-sub `command_loop` and the JetStream-replay
/// `command_replay::run`. Either path may receive a given Command
/// first (live publish via core sub for online agents; replay on
/// reconnect for offline agents); the second arrival is dropped via
/// [`Self::insert`] returning `false`.
pub struct DedupCache {
    seen: HashSet<String>,
    order: VecDeque<String>,
    cap: usize,
}

impl DedupCache {
    pub fn new(cap: usize) -> Self {
        Self {
            seen: HashSet::with_capacity(cap),
            order: VecDeque::with_capacity(cap),
            cap,
        }
    }
    /// Returns `true` when `id` is newly inserted, `false` when it
    /// was already present (= duplicate, caller should drop).
    pub fn insert(&mut self, id: String) -> bool {
        if self.seen.contains(&id) {
            return false;
        }
        self.seen.insert(id.clone());
        self.order.push_back(id);
        while self.order.len() > self.cap {
            if let Some(old) = self.order.pop_front() {
                self.seen.remove(&old);
            }
        }
        true
    }
}

pub fn shared_dedup_cache() -> Arc<Mutex<DedupCache>> {
    // 4 KB of RAM gets us ~ 128 request_ids; 1024 is generous.
    Arc::new(Mutex::new(DedupCache::new(1024)))
}

/// Enqueue a finished (or synthetic-skip) run's `ExecResult` to the
/// outbox off the async runtime. `outbox::enqueue` does synchronous file
/// I/O (`create_dir_all` / `write` / `rename`) that would otherwise block
/// a Tokio worker thread; offload it to the blocking pool — the same
/// pattern the KLP path (`enqueue_exec_result`) and the finalize hook
/// already use, so all three agent enqueue paths now behave alike.
///
/// Fire-and-forget + best-effort: an enqueue failure is logged, never
/// propagated. Each site previously used `?`, which bubbled the error up
/// to be logged as "command handler failed" — but a failed write loses
/// the result either way (no file lands for the drain task), so making it
/// best-effort changes nothing observable except that it no longer stalls
/// the executor. `note` is the per-site success breadcrumb.
fn enqueue_result_best_effort(result: ExecResult, note: &'static str) {
    tokio::task::spawn_blocking(move || {
        let outbox_dir = default_paths::data_dir().join("outbox");
        // `enqueue` only borrows `result`, so after it returns `result` is
        // still owned here — read its fields directly rather than cloning
        // request_id / copying exit_code out before the move (gemini).
        match outbox::enqueue(&outbox_dir, &result) {
            Ok(path) => debug!(
                request_id = %result.request_id,
                exit_code = result.exit_code,
                outbox = %path.display(),
                "{note}",
            ),
            // Don't fold `note` (a success-phrased breadcrumb) into the
            // failure line — it would read "failed ... : ... enqueued"
            // (claude). request_id + error already identify the site.
            Err(e) => warn!(
                request_id = %result.request_id,
                error = %e,
                "outbox enqueue failed (run still completed)",
            ),
        }
    });
}

// One argument over the limit since #1165 added the verifier. Same
// handling as the other long plumbing signatures in this crate (10+
// existing allows): these thread the agent's shared state to a task, and
// bundling them is a refactor of unrelated code, not part of a security
// change.
#[allow(clippy::too_many_arguments)]
pub async fn command_loop(
    client: async_nats::Client,
    pc_id: String,
    dedup: Arc<Mutex<DedupCache>>,
    staleness: Tracker,
    mut sub: async_nats::Subscriber,
    script_cache: ScriptCache,
    check_sink: crate::check_cache::CheckSink,
    verifier: std::sync::Arc<crate::command_verify::Verifier>,
) {
    let jetstream = async_nats::jetstream::new(client.clone());
    let script_current = jetstream.get_key_value(BUCKET_SCRIPT_CURRENT).await.ok();
    let script_status = jetstream.get_key_value(BUCKET_SCRIPT_STATUS).await.ok();
    if script_current.is_none() {
        warn!(
            bucket = BUCKET_SCRIPT_CURRENT,
            "KV bucket missing — version-pinning skipped (run `kanade jetstream setup`)"
        );
    }
    if script_status.is_none() {
        warn!(
            bucket = BUCKET_SCRIPT_STATUS,
            "KV bucket missing — revoke check skipped (run `kanade jetstream setup`)"
        );
    }

    while let Some(msg) = sub.next().await {
        let cmd: Command = match serde_json::from_slice(&msg.payload) {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, subject = %msg.subject, "deserialize command");
                continue;
            }
        };
        // #1165: check provenance over the exact received bytes, report the
        // outcome, and — on a host that is enforcing — refuse.
        let outcome = verifier.observe(
            &msg.payload,
            &crate::command_verify::headers_of(&msg),
            &cmd.request_id,
        );
        if let Some(reason) = verifier.refusal(outcome) {
            warn!(
                request_id = %cmd.request_id,
                subject = %msg.subject,
                reason,
                "REFUSED: command did not verify",
            );
            // Before the dedup insert below, deliberately. A refusal must not
            // consume the request_id: the operator's fix (provision the key,
            // correct the clock, sign it properly) produces a *retry*, and on
            // the ad-hoc path that retry can legitimately carry the same id.
            // Marking it seen would make the second attempt vanish silently —
            // the exact failure this whole branch exists to end.
            publish_signature_refused(&pc_id, &cmd, reason);
            continue;
        }
        // Shared with command_replay: if the JetStream replay path
        // already ran this Command on an earlier reconnect (rare but
        // possible), drop the live duplicate here.
        if !dedup.lock().await.insert(cmd.request_id.clone()) {
            debug!(
                request_id = %cmd.request_id,
                "core-sub dedup: already seen via replay or earlier delivery",
            );
            continue;
        }
        let client = client.clone();
        let pc_id = pc_id.clone();
        let cur = script_current.clone();
        let sta = script_status.clone();
        let staleness = staleness.clone();
        let script_cache = script_cache.clone();
        let check_sink = check_sink.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_command(
                client,
                pc_id,
                cmd,
                cur,
                sta,
                staleness,
                script_cache,
                check_sink,
                CommandSource::Nats,
            )
            .await
            {
                error!(error = %e, "command handler failed");
            }
        });
    }
}

/// #418 Phase 4: should a finished run be retried (vs. published
/// as-is)? A non-zero exit or a timeout is a transient failure worth
/// re-running; a remote kill is the operator deliberately stopping
/// the job, so it is **never** retried — retrying would fight the
/// signal. Pure so the retry decision is unit-tested without a broker.
fn outcome_is_retryable(outcome: &ExecOutcome) -> bool {
    match outcome {
        ExecOutcome::Completed { exit_code, .. } => *exit_code != 0,
        ExecOutcome::Timeout { .. } => true,
        ExecOutcome::Killed { .. } => false,
    }
}

/// #418 Phase 4: a human-readable note folded into the published
/// `stderr` when a fire took at least one retry — "succeeded after N"
/// on an eventual clean exit, "failed after N exhausted" when the
/// budget ran out, or "stopped by remote kill after N" when the
/// operator killed a later attempt (or the backoff wait). Keying off
/// `exit_code` alone would mislabel a kill as "exhausted" (claude /
/// coderabbit #466), so a `killed` final outcome takes precedence.
/// `None` when no retry happened (the common case).
fn retry_note(attempt: u32, exit_code: i32, killed: bool) -> Option<String> {
    (attempt > 0).then(|| {
        let plural = if attempt == 1 { "retry" } else { "retries" };
        if killed {
            format!("stopped by remote kill after {attempt} {plural} (#418 on_failure.retry)")
        } else if exit_code == 0 {
            format!("succeeded after {attempt} {plural} (#418 on_failure.retry)")
        } else {
            format!("failed after {attempt} {plural} exhausted (#418 on_failure.retry)")
        }
    })
}

/// #418 Phase 4: sleep for `backoff` between retry attempts, but
/// return `true` early if a remote kill for `exec_id` arrives first.
/// Between attempts the run's own kill listener (inside
/// `run_command_with_kill`) is gone, so without this the backoff wait
/// would be deaf to an operator stop and fire another attempt anyway
/// (gemini HIGH / claude #466). An ad-hoc run with no `exec_id` has no
/// kill subject → plain sleep, always `false`. A failed subscribe
/// degrades to a plain sleep (best-effort, matching how the main kill
/// listener treats a subscribe failure).
async fn wait_or_killed(
    client: &async_nats::Client,
    exec_id: Option<&str>,
    backoff: std::time::Duration,
) -> bool {
    let Some(eid) = exec_id else {
        tokio::time::sleep(backoff).await;
        return false;
    };
    let kill_subject = kanade_shared::subject::kill(eid);
    match client.subscribe(kill_subject.clone()).await {
        Ok(mut kill_sub) => {
            tokio::select! {
                _ = tokio::time::sleep(backoff) => false,
                _ = kill_sub.next() => true,
            }
        }
        Err(e) => {
            warn!(
                error = %e,
                exec_id = %eid,
                subject = %kill_subject,
                "kill subscribe failed during retry backoff; sleeping deaf to kill",
            );
            tokio::time::sleep(backoff).await;
            false
        }
    }
}

/// What a [`handle_command`] call actually did, so a caller that
/// records per-PC scheduler completions (`local_scheduler::local_tick`)
/// can distinguish a genuine successful run from a run that skipped or
/// failed. The live-NATS / replay callers ignore this — they only care
/// about the `Result`'s `Err` arm for logging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandOutcome {
    /// The script ran to completion (or was killed / timed out) with
    /// this exit code. `0` = success; anything else is a real failure.
    Ran { exit_code: i32 },
    /// The command was gated before the script ran — a staleness /
    /// version-pin / revoke / deadline skip (synthetic exit 124-127).
    /// It carries no evidence the job succeeded, so a `per_pc: once`
    /// schedule must NOT count it as done (#910).
    Skipped,
}

impl CommandOutcome {
    /// The single rule a per-PC scheduler uses to decide whether a fire
    /// counts as done: only a script that actually ran and exited `0`.
    /// A non-zero exit or a pre-run skip must re-fire "until that pc
    /// succeeds" (#910), matching the backend dedup's `exit_code = 0`.
    pub fn is_success(self) -> bool {
        matches!(self, CommandOutcome::Ran { exit_code: 0 })
    }
}

/// Where a [`handle_command`] invocation originated. This gates the
/// Layer-2 **version-pin** check (§2.6.4): that gate exists to reject a
/// broker-queued Command whose pinned `version` has since gone stale, so
/// it only makes sense for commands that actually travelled over NATS.
///
/// An agent-local `local_scheduler` fire is different: it builds
/// `cmd.version` from `manifest.version` in the SAME freshly-reconciled
/// `BUCKET_JOBS` snapshot it read the manifest from (that snapshot is the
/// authoritative version source for `runs_on: agent` — refreshed by the
/// jobs KV watch while online and by a full `collect_jobs` resync on
/// reconnect). There is no independent, newer authority to check it
/// against. `script_current` is maintained ONLY by the backend fire /
/// exec path (`kanade-backend/src/api/exec.rs`), never by an agent-local
/// fire, so for a `runs_on: agent` job it lags one version bump behind
/// and the pin gate self-rejects every tick with exit 124
/// (`version-pin mismatch`) until someone runs a backend `kanade exec`.
/// `LocalScheduler` therefore skips the pin gate; `Nats` keeps it. The
/// revoke kill-switch (§2.6.4 (b)) is deliberately NOT gated on source —
/// a revoked script must stay revoked no matter who fires it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandSource {
    /// Delivered over NATS — the live core subscription or a JetStream
    /// replay of a missed command. Both may carry a stale pinned version,
    /// so both keep the version-pin gate.
    Nats,
    /// Synthesised by the agent's own `local_scheduler` for a
    /// `runs_on: agent` schedule tick. `cmd.version` is authoritative by
    /// construction, so the version-pin gate is skipped.
    LocalScheduler,
}

/// Apply every gate whose answer can change while a command waits. Calling
/// this both before jitter/admission and after admission preserves fail-fast
/// skips while preventing a queued command from running on a stale decision.
async fn command_is_gated(
    client: &async_nats::Client,
    pc_id: &str,
    cmd: &Command,
    script_current: Option<&Store>,
    script_status: Option<&Store>,
    staleness: &Tracker,
    source: CommandSource,
) -> Result<bool> {
    // Spec §2.6 Layer 2: staleness comes first because a stale broker view
    // makes the KV answers below misleading.
    match staleness_decide(&cmd.staleness, staleness.staleness(client)) {
        StalenessDecision::Proceed => {}
        StalenessDecision::Skip { observed, allowed } => {
            warn!(
                cmd_id = %cmd.id,
                request_id = %cmd.request_id,
                observed_s = observed.as_secs(),
                allowed_s = allowed.as_secs(),
                "skip: staleness policy (mode=strict) exceeded — broker view too old",
            );
            publish_staleness_skipped(pc_id, cmd, observed, allowed).await?;
            return Ok(true);
        }
    }

    // Only broker-delivered commands can carry a stale version pin. Local
    // scheduler commands were built from the authoritative local snapshot.
    if source == CommandSource::Nats
        && let Some(cur) = script_current
        && let Ok(Some(entry)) = cur.get(&cmd.id).await
    {
        let expected = String::from_utf8_lossy(&entry).to_string();
        if version_pin_rejects(source, Some(&expected), &cmd.version) {
            warn!(
                cmd_id = %cmd.id,
                expected = %expected,
                got = %cmd.version,
                request_id = %cmd.request_id,
                "skip stale command (version mismatch)",
            );
            publish_version_mismatch_skipped(pc_id, cmd, &expected).await?;
            return Ok(true);
        }
    }

    if let Some(sta) = script_status
        && let Ok(Some(entry)) = sta.get(&cmd.id).await
        && String::from_utf8_lossy(&entry) == SCRIPT_STATUS_REVOKED
    {
        warn!(
            cmd_id = %cmd.id,
            request_id = %cmd.request_id,
            "skip revoked command",
        );
        publish_revoked_skipped(pc_id, cmd).await?;
        return Ok(true);
    }

    let now = chrono::Utc::now();
    if let Some(deadline) = cmd.deadline_at
        && should_skip_for_deadline(deadline, now)
    {
        warn!(
            cmd_id = %cmd.id,
            request_id = %cmd.request_id,
            %deadline,
            %now,
            "skip: starting deadline expired",
        );
        publish_skipped(client, pc_id, cmd, deadline, now).await?;
        return Ok(true);
    }

    Ok(false)
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_command(
    client: async_nats::Client,
    pc_id: String,
    mut cmd: Command,
    script_current: Option<Store>,
    script_status: Option<Store>,
    staleness: Tracker,
    script_cache: ScriptCache,
    check_sink: crate::check_cache::CheckSink,
    source: CommandSource,
) -> Result<CommandOutcome> {
    if command_is_gated(
        &client,
        &pc_id,
        &cmd,
        script_current.as_ref(),
        script_status.as_ref(),
        &staleness,
        source,
    )
    .await?
    {
        return Ok(CommandOutcome::Skipped);
    }

    // Jitter BEFORE we log "executing command" and stamp `started_at`,
    // so the log line, the recorded duration (`finished_at -
    // started_at`), and the events.started lifecycle event all reflect
    // the real execution start — not the per-PC fleet-stagger wait. It
    // previously sat inside `run_command_with_kill`, i.e. after the
    // timestamp, so a 5-min jitter inflated the dashboard 所要時間 well
    // past the job's `timeout:` even though the script itself finished
    // in seconds (the timeout arm only ever bounded the post-jitter
    // execution), and "executing command" logged minutes before
    // anything ran. apply_jitter emits its own "applying jitter" line,
    // so the wait is still visible in the logs. The "実行中" view
    // likewise no longer lights up during the jitter wait.
    apply_jitter(&cmd).await;

    let _local_slot = match crate::concurrency::admit(&client, &cmd).await {
        Ok(permit) => permit,
        Err(outcome) => {
            let now = chrono::Utc::now();
            let (exit_code, stderr) = match outcome {
                ExecOutcome::Completed {
                    exit_code, stderr, ..
                } => (exit_code, stderr),
                ExecOutcome::Killed { stderr, .. } => (-1, stderr),
                ExecOutcome::Timeout { stderr, .. } => (-1, stderr),
            };
            enqueue_result_best_effort(
                ExecResult {
                    result_id: Uuid::new_v4().to_string(),
                    request_id: cmd.request_id.clone(),
                    exec_id: cmd.exec_id.clone(),
                    parent_result_id: None,
                    pc_id: pc_id.clone(),
                    exit_code,
                    stdout: String::new(),
                    stderr,
                    started_at: now,
                    finished_at: now,
                    stdout_object: None,
                    stderr_object: None,
                    manifest_id: Some(cmd.id.clone()),
                    collect_object: None,
                },
                "local admission cancellation enqueued",
            );
            return Ok(CommandOutcome::Skipped);
        }
    };

    // Recheck after jitter/admission: a queued job may have been revoked,
    // superseded or expired while waiting.
    if command_is_gated(
        &client,
        &pc_id,
        &cmd,
        script_current.as_ref(),
        script_status.as_ref(),
        &staleness,
        source,
    )
    .await?
    {
        return Ok(CommandOutcome::Skipped);
    }

    // #210: resolve OBJECT_SCRIPTS-backed scripts just in time.
    // Backend's exec.rs builds Commands with `script: ""` +
    // `script_object: Some(key)` + `script_object_sha256: Some(d)`
    // when the manifest uses `script_object:`. Fill `cmd.script`
    // here so the rest of the dispatch (run_command_with_kill,
    // stdout/stderr capture, exec_id event emission) stays
    // identical to the inline-script path.
    if cmd.script.is_empty()
        && let Some(key) = cmd.script_object.as_deref()
    {
        let sha = cmd.script_object_sha256.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "Command {request_id} has script_object={key} but no script_object_sha256 \
                 — wire builder bug",
                request_id = cmd.request_id,
            )
        })?;
        match script_cache.resolve(key, sha).await {
            Ok(body) => {
                debug!(
                    cmd_id = %cmd.id,
                    request_id = %cmd.request_id,
                    %key,
                    sha256 = %sha,
                    size = body.len(),
                    "script_object resolved",
                );
                cmd.script = body;
            }
            Err(e) => {
                warn!(
                    cmd_id = %cmd.id,
                    request_id = %cmd.request_id,
                    %key,
                    sha256 = %sha,
                    error = %e,
                    "script_object resolve failed — aborting run",
                );
                return Err(e);
            }
        }
    }

    info!(
        cmd_id = %cmd.id,
        request_id = %cmd.request_id,
        version = %cmd.version,
        exec_id = ?cmd.exec_id,
        "executing command",
    );
    let started_at = chrono::Utc::now();
    // v0.30 / PR α' unified: mint result_id once at the top of
    // handle_command and thread it through both the EventStarted
    // (script-spawn lifecycle event) and the ExecResult so the
    // backend's UPSERT against `execution_results.result_id`
    // coalesces both into a single row regardless of arrival order.
    let result_id = Uuid::new_v4().to_string();

    // Register an in-memory live-tail buffer so the
    // `job.tail.<pc_id>` handler can serve this job's stdout/stderr to
    // the SPA while it runs (same UX as the agent-log auto-refresh,
    // scoped to one job). The RAII handle marks the job finished
    // (`running` → false) when dropped right after the run; the buffer
    // lingers through a short grace window so the SPA's final poll
    // still catches the tail before the persisted row has projected.
    // See `crate::live_tail`.
    let live_handle = crate::live_tail::register(&result_id);

    // Emit `events.started.<exec_id>.<pc_id>` BEFORE child spawn
    // when the Command carries an exec_id (= deployment from
    // `kanade exec` or scheduler tick, not ad-hoc `kanade run`).
    // Goes through the file outbox so offline / mid-broker-outage
    // runs still surface on reconnect. Outbox enqueue failures are
    // warn-logged but never abort the run — losing the start
    // lifecycle event means the row in execution_results is
    // backfilled from the ExecResult side with default version etc.
    if let Some(exec_id) = cmd.exec_id.as_deref() {
        let event = kanade_shared::wire::EventStarted {
            result_id: result_id.clone(),
            request_id: cmd.request_id.clone(),
            exec_id: exec_id.to_string(),
            pc_id: pc_id.clone(),
            started_at,
            manifest_id: cmd.id.clone(),
            version: cmd.version.clone(),
        };
        let events_outbox_dir = default_paths::data_dir().join("events-outbox");
        match crate::events_outbox::enqueue(&events_outbox_dir, &event) {
            Ok(p) => debug!(
                result_id = %result_id,
                events_outbox = %p.display(),
                "started event enqueued (drain task delivers via JetStream)",
            ),
            Err(e) => warn!(
                error = %e,
                result_id = %result_id,
                "events_outbox enqueue failed; in-flight view will not show this row until ExecResult lands",
            ),
        }
    }

    // #418 Phase 4: fire-side retry. Re-run the script on a non-zero
    // exit or a timeout, up to `cmd.retry.max` extra attempts with a
    // fixed backoff between them. A remote kill is honored immediately
    // — the operator meant "stop", not "try harder" — so it never
    // retries. Only the final attempt's outcome is published (one
    // ExecResult row, the started event above fired once for the whole
    // sequence); a `status_note` records how many retries it took or
    // that they were exhausted. `attempt` ends as the retry count.
    let max_retries = cmd.retry.map(|r| r.max).unwrap_or(0);
    let backoff = cmd
        .retry
        .map(|r| std::time::Duration::from_secs(r.backoff_secs));
    let mut attempt: u32 = 0;
    let outcome = loop {
        let outcome = run_command_with_kill(&client, &cmd, Some(live_handle.tail())).await?;
        if !outcome_is_retryable(&outcome) || attempt >= max_retries {
            break outcome;
        }
        attempt += 1;
        warn!(
            cmd_id = %cmd.id,
            request_id = %cmd.request_id,
            attempt,
            max_retries,
            backoff_secs = backoff.map(|b| b.as_secs()).unwrap_or(0),
            "fire failed; retrying after backoff (#418 on_failure.retry)",
        );
        // Stay responsive to a remote kill during the backoff wait.
        // `run_command_with_kill` only listens to `kill.{exec_id}`
        // while the child runs, so between attempts the agent is deaf
        // to a stop signal — a plain sleep here would fire another
        // attempt after the operator already killed the job (gemini
        // HIGH / claude #466). Race the wait against a kill: if one
        // arrives, abandon the retry sequence as Killed.
        if let Some(b) = backoff
            && wait_or_killed(&client, cmd.exec_id.as_deref(), b).await
        {
            info!(
                cmd_id = %cmd.id,
                request_id = %cmd.request_id,
                attempt,
                "remote kill during retry backoff — aborting retries (#418 on_failure.retry)",
            );
            break ExecOutcome::Killed {
                stdout: String::new(),
                stderr: String::new(),
            };
        }
    };
    let finished_at = chrono::Utc::now();
    // Capture before the match below moves `outcome`: a final Killed
    // (mid-attempt or during a backoff abort) must not be mislabelled
    // "retries exhausted" by the retry note (claude / coderabbit #466).
    let final_killed = matches!(outcome, ExecOutcome::Killed { .. });
    // Flip the live buffer to "finished" promptly so the SPA's next
    // poll sees `running = false`. Grace retention (in `live_tail`)
    // keeps the final tail serveable until the persisted row lands.
    drop(live_handle);

    let (exit_code, stdout, stderr, status_note) = match outcome {
        ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        } => (exit_code, stdout, stderr, None),
        ExecOutcome::Killed { stdout, stderr } => {
            let eid = cmd.exec_id.as_deref().unwrap_or("?");
            (
                -1,
                stdout,
                stderr,
                Some(format!("killed by remote signal (kill.{eid})")),
            )
        }
        ExecOutcome::Timeout { stdout, stderr } => (
            -1,
            stdout,
            stderr,
            Some(format!("timeout after {}s", cmd.timeout_secs)),
        ),
    };
    // #418 Phase 4: append a retry summary so the Results page shows
    // the script eventually succeeded (or that the budget ran out)
    // rather than silently swallowing the earlier failures.
    let stderr = [status_note, retry_note(attempt, exit_code, final_killed)]
        .into_iter()
        .flatten()
        .fold(stderr, |acc, note| {
            if acc.is_empty() {
                note
            } else {
                format!("{acc}\n{note}")
            }
        });

    // #290: if this job is an operator-defined health check, map its
    // result into the KLP `StateSnapshot.checks` for the Client App's
    // Health tab. Done HERE — before the `emit` branch below can blank
    // `stdout` — so a check always reads the real script output even
    // if a (validation-prevented) `emit:` somehow rode along. On a
    // clean exit the status comes from the stdout object; a non-zero
    // exit records `Unknown` (with the exit code + stderr) rather than
    // leaving a stale `Ok`, so a persistently-crashing check can't read
    // as healthy.
    if let Some(check_hint) = &cmd.check {
        let check = if exit_code == 0 {
            crate::check_cache::build_check(check_hint, &stdout)
        } else {
            crate::check_cache::build_check_failed(check_hint, exit_code, &stderr)
        };
        check_sink.record(check);
    }

    // #219: if this job is a file collector, parse stdout for the file
    // list, zip those files, and upload the bundle to OBJECT_COLLECTIONS.
    // Only on a clean exit (a failed run has no trustworthy file list).
    // `collect:` is validated mutually exclusive with `emit:`, so the
    // emit branch below never blanks a collect job's stdout — but we read
    // it here first regardless. Best-effort: on any failure the result
    // still publishes with `collect_object = None`.
    let bundles = if exit_code == 0 && cmd.collect.is_some() {
        let js = async_nats::jetstream::new(client.clone());
        crate::collect::maybe_collect(&js, &client, &cmd, &pc_id, &result_id, &stdout, finished_at)
            .await
    } else {
        Vec::new()
    };

    // Build the finalize payload now, while `bundles` is still in scope.
    // The hook itself runs LATER — after the ExecResult is enqueued — so a
    // slow cleanup hook (up to its own timeout) never holds the Activity
    // row in "pending" after the main script already finished cleanly.
    // Only a `collect:` job gets a payload; a non-collect finalize hook
    // runs with no `KANADE_COLLECT_RESULT`.
    let finalize_json = cmd
        .collect
        .as_ref()
        .map(|_| crate::finalize::collect_result_json(&bundles));

    // The ExecResult records one representative bundle key (the first);
    // the SPA Collect page enumerates the Object Store bucket for the full
    // per-run set, and the file lists were for the finalize hook.
    let collect_object = bundles.first().map(|b| b.key.clone());

    // Issue #246: if the manifest is an event emitter, parse stdout
    // as NDJSON `ObsEvent` and route each line to obs_outbox.
    // Stdout is then DROPPED from the ExecResult — the timeline
    // data lives in `obs_events` and re-shipping it via
    // `execution_results.stdout` would multiply ~50/day/PC of
    // noise into a table designed for one row per script run.
    //
    // Only fires on a clean exit (`exit_code == 0`). A failed run
    // keeps stdout in the result so operators can see what went
    // wrong on the Activity page — partial event lines from a
    // crashed script are more confusing than absent ones.
    let stdout = if exit_code == 0
        && matches!(
            cmd.emit.as_ref().map(|e| e.kind),
            Some(kanade_shared::manifest::EmitKind::Events),
        ) {
        forward_obs_events(stdout, pc_id.clone()).await;
        // Don't ship the NDJSON itself in stdout; the events are
        // now in obs-outbox and the Activity row's stdout would
        // just duplicate them.
        String::new()
    } else {
        stdout
    };

    let result = ExecResult {
        // v0.30 / PR α' unified: same `result_id` value used in the
        // matching EventStarted above. Backend UPSERTs against
        // `execution_results.result_id`, so the events.started
        // insert and this ExecResult update coalesce into a single
        // row regardless of arrival order.
        result_id: result_id.clone(),
        request_id: cmd.request_id.clone(),
        // v0.29 / Issue #19: forward `Command.exec_id` so the backend
        // projector can increment `executions.success_count` /
        // `failure_count` and the upcoming /api/executions endpoint
        // can list per-PC results for one deployment.
        exec_id: cmd.exec_id.clone(),
        // Ordinary runs have no parent finalize link (#955).
        parent_result_id: None,
        pc_id: pc_id.clone(),
        exit_code,
        stdout,
        stderr,
        started_at,
        finished_at,
        // #227: outbox-drain side fills these in when stdout / stderr
        // exceeds the inline threshold and gets offloaded to
        // OBJECT_RESULT_OUTPUT. Stays None at enqueue time so the
        // outbox file on disk preserves the full bytes (drain task
        // re-runs the overflow check on every iteration — idempotent
        // re-upload to same key).
        stdout_object: None,
        stderr_object: None,
        // Forward `Command.id` (the manifest's id, e.g. "inventory-hw"),
        // NOT `Command.exec_id` (a per-deploy UUID). The backend's
        // results projector uses this to look up the manifest's
        // `inventory:` hint and upsert `inventory_facts` rows.
        manifest_id: Some(cmd.id.clone()),
        // #219: the bundle key from the collect step above (None unless
        // this job carried a `collect:` hint and the run succeeded).
        collect_object,
    };
    enqueue_result_best_effort(
        result,
        "result enqueued to outbox (drain task delivers via JetStream)",
    );

    // Job-generic `finalize:` hook — runs AFTER the result is enqueued
    // (so a long-running cleanup never keeps the row pending) with the
    // collect outcome injected as `KANADE_COLLECT_RESULT`. Best-effort:
    // failures are logged inside `run_finalize`, never the run's result.
    // #965: when `on_each_bundle` is set the hook already ran per bundle
    // inside `maybe_collect`; skip the aggregate call so cleanup isn't
    // run twice. Otherwise (the default, and every non-collect finalize)
    // run the single post-collect hook as before.
    //
    // Design trade-off (claude): the per-bundle hooks run INSIDE
    // `maybe_collect`, i.e. BEFORE this ExecResult is enqueued — which
    // deliberately reverses the "finalize runs after enqueue so a slow
    // cleanup never holds the row pending" principle above. It has to:
    // interrupt-resilience requires cleanup to interleave with the (slow)
    // upload, so an offline-mid-collect run still deletes what it shipped.
    // The parent row therefore stays pending across the per-bundle
    // cleanups — an accepted cost of the opt-in, scoped to jobs that ask
    // for it.
    if exit_code == 0
        && let Some(fin) = cmd.finalize.as_ref()
        && !fin.on_each_bundle
    {
        crate::finalize::run_finalize(
            &client,
            &cmd,
            fin,
            &pc_id,
            &result_id,
            None,
            finalize_json.as_deref(),
        )
        .await;
    }

    // `client` was used above only when a finalize hook ran; suppress the
    // unused warning on the no-hook happy path — we keep it in the
    // signature so future hooks (audit, kill ack, etc.) have it available.
    let _ = client;
    Ok(CommandOutcome::Ran { exit_code })
}

/// Issue #246 — parse each non-empty stdout line as `ObsEvent`
/// and enqueue to `obs-outbox`. Lines that fail to decode warn +
/// skip (don't fail the rest of the batch). The caller has already
/// ensured `cmd.emit.kind == Events` and `exit_code == 0`, so this
/// only runs when the manifest explicitly opts in AND the script
/// succeeded.
///
/// Each line is parsed in isolation; one bad line doesn't poison
/// the others. Empty lines (the natural NDJSON trailing newline +
/// any blank lines a script accidentally emits) are skipped
/// silently.
///
/// Gemini #249 high: the parse + per-line `enqueue` (tmp write +
/// rename) is synchronous file I/O on the Tokio runtime thread.
/// For a 50-event poll that's ~50 ms of blocked executor time per
/// agent — measurable on a busy host. Wrap the whole batch in
/// `spawn_blocking` so the executor stays free; the moved values
/// (`stdout`, `pc_id`) are owned strings the closure can carry.
async fn forward_obs_events(stdout: String, pc_id: String) {
    use kanade_shared::wire::ObsEvent;
    let obs_outbox_dir = default_paths::data_dir().join("obs-outbox");
    // Hoist the `create_dir_all` out of the per-event hot path
    // (Gemini #249 medium). One syscall per batch instead of per
    // event.
    if let Err(e) = crate::obs_outbox::ensure_outbox_dir(&obs_outbox_dir) {
        warn!(error = %e, "obs: ensure_outbox_dir failed; aborting forward");
        return;
    }
    let pc_id_log = pc_id.clone();
    let (ok, bad) = tokio::task::spawn_blocking(move || {
        let mut ok = 0usize;
        let mut bad = 0usize;
        for (i, raw) in stdout.lines().enumerate() {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                continue;
            }
            let mut event: ObsEvent = match serde_json::from_str(trimmed) {
                Ok(e) => e,
                Err(e) => {
                    warn!(
                        line_no = i + 1,
                        error = %e,
                        "obs: stdout line is not a valid ObsEvent JSON; skipping",
                    );
                    bad += 1;
                    continue;
                }
            };
            // Scripts that emit a hard-coded `pc_id` (the docs
            // example does this) would race with PC renames.
            // Override with the agent's authoritative value —
            // `obs.<pc_id>` subject and the backend UNIQUE-key
            // column both need to match.
            event.pc_id = pc_id.clone();
            if let Err(e) = crate::obs_outbox::enqueue(&obs_outbox_dir, &event) {
                warn!(
                    line_no = i + 1,
                    error = %e,
                    "obs: enqueue to outbox failed; line dropped",
                );
                bad += 1;
            } else {
                ok += 1;
            }
        }
        (ok, bad)
    })
    .await
    .unwrap_or_else(|e| {
        warn!(error = %e, "obs: forwarder task panicked / cancelled");
        (0, 0)
    });
    debug!(ok, bad, pc_id = %pc_id_log, "obs: forwarded NDJSON stdout to obs-outbox");
}

/// Pure deadline check — boundary policy: `now > deadline` skips,
/// `now == deadline` still runs (deadline is the inclusive last
/// instant to start). Kept as a free function so the
/// `should_skip_for_deadline_*` unit tests below can pin the
/// boundary without spinning up tokio / NATS.
fn should_skip_for_deadline(
    deadline: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> bool {
    now > deadline
}

/// Pure decision for the Layer-2 version-pin gate (§2.6.2): does the pin
/// reject this command? Kept as a free function so the `version_pin_*`
/// unit tests below can assert the source-gating + mismatch semantics
/// without a live KV `Store`. `pinned` is the `script_current.<id>` value
/// the agent read (None when the source isn't gated, the key is absent, or
/// the read failed). Only a NATS-delivered command whose pinned version
/// disagrees is rejected; an agent-local fire (`CommandSource::LocalScheduler`)
/// is always allowed because its `cmd.version` is authoritative by
/// construction — see [`CommandSource`].
fn version_pin_rejects(source: CommandSource, pinned: Option<&str>, cmd_version: &str) -> bool {
    source == CommandSource::Nats && matches!(pinned, Some(p) if p != cmd_version)
}

/// v0.26: Synthesise an ExecResult for "Layer 2 strict staleness
/// exceeded — agent couldn't verify it's running the latest version
/// because the broker view is too old." Exit code 127 is reserved
/// for this case. Agent-side skip exit codes are partitioned:
///
/// | Code | Meaning                                | Helper                            |
/// |------|----------------------------------------|-----------------------------------|
/// | 124  | Layer 2 version-pin mismatch (#271)    | `publish_version_mismatch_skipped`|
/// | 125  | deadline_at expired                    | `publish_skipped`                 |
/// | 126  | Layer 2 revoked (#271)                 | `publish_revoked_skipped`         |
/// | 127  | Layer 1 staleness (mode=strict)        | `publish_staleness_skipped`       |
///
/// The stderr carries the observed staleness window + the
/// configured allowance so the operator sees on the Results page
/// why the fire was suppressed and what they'd need to change to
/// allow it.
async fn publish_staleness_skipped(
    pc_id: &str,
    cmd: &Command,
    observed: std::time::Duration,
    allowed: std::time::Duration,
) -> Result<()> {
    let now = chrono::Utc::now();
    let stderr = format!(
        "skipped: staleness policy (mode=strict) exceeded — agent has been disconnected for {}, max allowed {}",
        humantime::format_duration(observed),
        humantime::format_duration(allowed),
    );
    let result = ExecResult {
        result_id: Uuid::new_v4().to_string(),
        request_id: cmd.request_id.clone(),
        exec_id: cmd.exec_id.clone(),
        // Synthetic skip results have no parent finalize link (#955).
        parent_result_id: None,
        pc_id: pc_id.to_string(),
        exit_code: EXIT_SKIP_STALENESS,
        stdout: String::new(),
        stderr,
        started_at: now,
        finished_at: now,
        stdout_object: None,
        stderr_object: None,
        manifest_id: Some(cmd.id.clone()),
        // #219: skip results never collect.
        collect_object: None,
    };
    enqueue_result_best_effort(result, "staleness-skip result enqueued to outbox");
    Ok(())
}

/// #1165 stage 3: synthesise an ExecResult for a command this host **refused**
/// because its provenance did not check out.
///
/// Publishing something is the whole point. `kanade run` waits on
/// `results.<request_id>`; a refusal that emitted nothing would be
/// indistinguishable from an agent that is simply gone, and the two need
/// opposite responses. That distinction is worth most in the case it is most
/// likely to arise: an operator's own break-glass command refused as stale on
/// a host whose clock is wrong, mid-incident, with the backend down — so the
/// `command_signature_stale` obs event is sitting in the outbox rather than
/// reaching anybody.
///
/// Shared by the live subscription and the JetStream replay, because both
/// decode the same bytes and a refusal reachable through only one of them is
/// the #1155 bypass with extra steps.
pub(crate) fn publish_signature_refused(pc_id: &str, cmd: &Command, reason: &str) {
    let now = chrono::Utc::now();
    // Deterministic `result_id`, unlike every other result this agent
    // publishes, because a refusal is the one that repeats.
    //
    // The refusal deliberately does not consume the `request_id` (see the call
    // site), so nothing stops the same unverifiable command being seen again —
    // and it will be: the replay consumer is `DeliverPolicy::LastPerSubject`,
    // so it re-delivers the newest command on every reconnect, and a broadcast
    // reaches `commands.all` and `commands.pc.<id>` both. With a fresh v4 each
    // time, one bad command would accrete a result row per delivery forever.
    //
    // Derived from (request_id, pc_id) so every re-publish lands on the same
    // row and the projector's `ON CONFLICT(result_id) DO UPDATE` collapses it.
    // Chosen over an in-memory "already refused" set because that set dies
    // with the process — and an agent restart is exactly when the replay
    // re-delivers.
    let result = ExecResult {
        result_id: refusal_result_id(&cmd.request_id, pc_id),
        request_id: cmd.request_id.clone(),
        exec_id: cmd.exec_id.clone(),
        parent_result_id: None,
        pc_id: pc_id.to_string(),
        exit_code: EXIT_REJECTED_UNSIGNED,
        stdout: String::new(),
        stderr: format!("refused: {reason}"),
        started_at: now,
        finished_at: now,
        stdout_object: None,
        stderr_object: None,
        manifest_id: Some(cmd.id.clone()),
        collect_object: None,
    };
    enqueue_result_best_effort(result, "signature-refusal result enqueued to outbox");
}

/// Synthesise an ExecResult that mirrors a real run but flags
/// "didn't actually run because we were too late". Exit code 125
/// follows the cron / GNU coreutils convention for "missed /
/// skipped"; stderr carries the deadline + receipt timestamp so
/// the operator can see *how* late we were on the Results page.
async fn publish_skipped(
    _client: &async_nats::Client,
    pc_id: &str,
    cmd: &Command,
    deadline: chrono::DateTime<chrono::Utc>,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<()> {
    let lateness = now - deadline;
    let stderr = format!(
        "skipped: starting deadline expired {} ago (deadline {}, received {})",
        humantime::format_duration(
            lateness
                .to_std()
                .unwrap_or(std::time::Duration::from_secs(0))
        ),
        deadline,
        now,
    );
    let result = ExecResult {
        result_id: Uuid::new_v4().to_string(),
        request_id: cmd.request_id.clone(),
        exec_id: cmd.exec_id.clone(),
        // Synthetic skip results have no parent finalize link (#955).
        parent_result_id: None,
        pc_id: pc_id.to_string(),
        exit_code: EXIT_SKIP_DEADLINE,
        stdout: String::new(),
        stderr,
        started_at: now,
        finished_at: now,
        stdout_object: None,
        stderr_object: None,
        manifest_id: Some(cmd.id.clone()),
        // #219: skip results never collect.
        collect_object: None,
    };
    enqueue_result_best_effort(result, "synthetic skipped-result enqueued to outbox");
    Ok(())
}

/// #271: Synthesise an ExecResult for "Layer 2 version-pin
/// mismatch — incoming Command's version doesn't match the
/// `script_current.<id>` KV value the backend just published."
/// Exit code 124 distinguishes this from the sibling skip paths
/// (see the table on [`publish_staleness_skipped`]).
///
/// Without this synthetic result, the matching `executions` row
/// stays at `status='pending'` forever and the `/api/jobs` `実行中`
/// counter monotonically inflates across every stale skip — the
/// bug #271 documents from the 0.43.1 → 0.43.2 bump.
async fn publish_version_mismatch_skipped(
    pc_id: &str,
    cmd: &Command,
    expected: &str,
) -> Result<()> {
    let now = chrono::Utc::now();
    let stderr = format!(
        "skipped: version-pin mismatch — script_current[{}] = {expected}, command brought {}",
        cmd.id, cmd.version,
    );
    let result = ExecResult {
        result_id: Uuid::new_v4().to_string(),
        request_id: cmd.request_id.clone(),
        exec_id: cmd.exec_id.clone(),
        // Synthetic skip results have no parent finalize link (#955).
        parent_result_id: None,
        pc_id: pc_id.to_string(),
        exit_code: EXIT_SKIP_VERSION_PIN,
        stdout: String::new(),
        stderr,
        started_at: now,
        finished_at: now,
        stdout_object: None,
        stderr_object: None,
        manifest_id: Some(cmd.id.clone()),
        // #219: skip results never collect.
        collect_object: None,
    };
    enqueue_result_best_effort(result, "version-mismatch skip result enqueued to outbox");
    Ok(())
}

/// #271: Synthesise an ExecResult for "Layer 2 revoked — the
/// operator marked this manifest revoked via
/// `script_status.<id> = revoked` before the agent received this
/// Command." Exit code 126 distinguishes this from the sibling
/// skip paths (see the table on [`publish_staleness_skipped`]).
///
/// Same `executions`-row rationale as
/// [`publish_version_mismatch_skipped`].
async fn publish_revoked_skipped(pc_id: &str, cmd: &Command) -> Result<()> {
    let now = chrono::Utc::now();
    let stderr = format!(
        "skipped: command was revoked (script_status[{}] = revoked)",
        cmd.id,
    );
    let result = ExecResult {
        result_id: Uuid::new_v4().to_string(),
        request_id: cmd.request_id.clone(),
        exec_id: cmd.exec_id.clone(),
        // Synthetic skip results have no parent finalize link (#955).
        parent_result_id: None,
        pc_id: pc_id.to_string(),
        exit_code: EXIT_SKIP_REVOKED,
        stdout: String::new(),
        stderr,
        started_at: now,
        finished_at: now,
        stdout_object: None,
        stderr_object: None,
        manifest_id: Some(cmd.id.clone()),
        // #219: skip results never collect.
        collect_object: None,
    };
    enqueue_result_best_effort(result, "revoked skip result enqueued to outbox");
    Ok(())
}

/// The `result_id` [`publish_signature_refused`] uses. Extracted so the
/// determinism it relies on is testable without a broker or an outbox.
fn refusal_result_id(request_id: &str, pc_id: &str) -> String {
    Uuid::new_v5(
        &Uuid::NAMESPACE_OID,
        format!("{request_id}|{pc_id}|signature-refused").as_bytes(),
    )
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;

    fn at(secs: i64) -> chrono::DateTime<chrono::Utc> {
        chrono::Utc
            .timestamp_opt(1_700_000_000 + secs, 0)
            .single()
            .unwrap()
    }

    #[test]
    fn a_repeated_refusal_lands_on_the_same_result_row() {
        // A refusal deliberately does not consume the request_id, so the same
        // unverifiable command WILL be seen again — the replay consumer is
        // LastPerSubject and re-delivers on every reconnect, and a broadcast
        // arrives on both `commands.all` and `commands.pc.<id>`. With a fresh
        // v4 per publish, one bad command would accrete a result row per
        // delivery, forever.
        let a = refusal_result_id("req-1", "PC1");
        let b = refusal_result_id("req-1", "PC1");
        assert_eq!(a, b, "the projector collapses on result_id; it must repeat");

        // Different command, or the same command on another machine, must NOT
        // collapse — each is a distinct refusal an operator needs to see.
        assert_ne!(a, refusal_result_id("req-2", "PC1"));
        assert_ne!(a, refusal_result_id("req-1", "PC2"));

        // Stable across processes -- an in-memory suppression set would
        // forget this on restart, which is precisely when the replay
        // re-delivers. A v5 UUID is a pure function of its name, so pinning
        // the derivation proves nothing process-local seeds it.
        assert_eq!(
            a,
            Uuid::new_v5(&Uuid::NAMESPACE_OID, b"req-1|PC1|signature-refused").to_string()
        );
        // A real v5, not a v4 that happened to repeat.
        assert_eq!(Uuid::parse_str(&a).unwrap().get_version_num(), 5);
    }

    #[test]
    fn command_outcome_is_success_only_for_clean_run() {
        // #910: the per-PC scheduler records a completion only when this
        // is true. A non-zero exit and every skip must re-fire.
        assert!(CommandOutcome::Ran { exit_code: 0 }.is_success());
        assert!(!CommandOutcome::Ran { exit_code: 1 }.is_success());
        assert!(!CommandOutcome::Ran { exit_code: 124 }.is_success());
        assert!(!CommandOutcome::Skipped.is_success());
    }

    #[test]
    fn version_pin_rejects_stale_nats_command() {
        // The bug this PR fixes: a NATS-delivered command whose pinned
        // version disagrees with `script_current` is rejected (exit 124).
        assert!(version_pin_rejects(
            CommandSource::Nats,
            Some("0.2.0"),
            "0.2.1"
        ));
    }

    #[test]
    fn version_pin_allows_matching_nats_command() {
        assert!(!version_pin_rejects(
            CommandSource::Nats,
            Some("0.2.1"),
            "0.2.1"
        ));
    }

    #[test]
    fn version_pin_allows_nats_command_with_no_kv_entry() {
        // No `script_current.<id>` value → nothing to disagree with, so the
        // gate stays open (matches the `if let Ok(Some(_))` guard).
        assert!(!version_pin_rejects(CommandSource::Nats, None, "0.2.1"));
    }

    #[test]
    fn version_pin_never_rejects_local_scheduler_fire() {
        // The heart of the fix: an agent-local fire is authoritative by
        // construction, so it is allowed even when `script_current` lags —
        // the exact condition that used to self-reject every tick.
        assert!(!version_pin_rejects(
            CommandSource::LocalScheduler,
            Some("0.2.0"),
            "0.2.1"
        ));
        // ...and also when it happens to match, and when there is no entry.
        assert!(!version_pin_rejects(
            CommandSource::LocalScheduler,
            Some("0.2.1"),
            "0.2.1"
        ));
        assert!(!version_pin_rejects(
            CommandSource::LocalScheduler,
            None,
            "0.2.1"
        ));
    }

    #[test]
    fn now_strictly_before_deadline_runs() {
        assert!(!should_skip_for_deadline(at(100), at(99)));
    }

    #[test]
    fn now_one_second_before_deadline_runs() {
        assert!(!should_skip_for_deadline(at(100), at(99)));
    }

    #[test]
    fn now_exactly_at_deadline_still_runs() {
        // Boundary: == is the *last* allowed instant. Lets a cron
        // tick fire at the exact starting_deadline without spuriously
        // skipping on clock-rounding.
        assert!(!should_skip_for_deadline(at(100), at(100)));
    }

    #[test]
    fn now_one_second_past_deadline_skips() {
        assert!(should_skip_for_deadline(at(100), at(101)));
    }

    #[test]
    fn now_long_past_deadline_skips() {
        assert!(should_skip_for_deadline(at(100), at(86400)));
    }

    // ---- #418 Phase 4: on_failure.retry ----

    fn completed(exit_code: i32) -> ExecOutcome {
        ExecOutcome::Completed {
            exit_code,
            stdout: String::new(),
            stderr: String::new(),
        }
    }

    #[test]
    fn clean_exit_is_not_retryable() {
        assert!(!outcome_is_retryable(&completed(0)));
    }

    #[test]
    fn nonzero_exit_is_retryable() {
        assert!(outcome_is_retryable(&completed(1)));
        assert!(outcome_is_retryable(&completed(-1)));
    }

    #[test]
    fn timeout_is_retryable() {
        assert!(outcome_is_retryable(&ExecOutcome::Timeout {
            stdout: String::new(),
            stderr: String::new(),
        }));
    }

    #[test]
    fn remote_kill_is_never_retried() {
        // The operator pressed stop — retrying would fight the signal.
        assert!(!outcome_is_retryable(&ExecOutcome::Killed {
            stdout: String::new(),
            stderr: String::new(),
        }));
    }

    #[test]
    fn no_retry_emits_no_note() {
        assert_eq!(retry_note(0, 0, false), None);
        assert_eq!(retry_note(0, 1, false), None);
    }

    #[test]
    fn retry_note_reports_eventual_success() {
        let note = retry_note(2, 0, false).expect("a retry happened");
        assert!(note.contains("succeeded after 2 retries"), "got: {note}");
    }

    #[test]
    fn retry_note_reports_exhaustion() {
        let note = retry_note(3, 1, false).expect("a retry happened");
        assert!(
            note.contains("failed after 3 retries exhausted"),
            "got: {note}"
        );
    }

    #[test]
    fn retry_note_killed_is_not_exhausted() {
        // A kill on a later attempt sets exit_code = -1, but the run was
        // stopped, not exhausted — the note must say so (claude /
        // coderabbit #466). `killed` wins over the exit_code branch.
        let note = retry_note(2, -1, true).expect("a retry happened");
        assert!(
            note.contains("stopped by remote kill after 2 retries"),
            "got: {note}"
        );
        assert!(!note.contains("exhausted"), "got: {note}");
    }

    #[test]
    fn retry_note_singular_for_one_retry() {
        let note = retry_note(1, 0, false).expect("a retry happened");
        assert!(note.contains("after 1 retry"), "got: {note}");
        assert!(!note.contains("retries"), "got: {note}");
    }
}
