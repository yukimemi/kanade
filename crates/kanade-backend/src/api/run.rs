//! Operator-side action endpoints that drive a single agent through
//! NATS request/reply or short subscribe windows. Mirrors the CLI's
//! `kanade run` + `kanade ping` so the web UI can offer the same
//! interactive controls without shelling out to the CLI.

use std::time::Duration;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use futures::StreamExt;
use kanade_shared::subject;
use kanade_shared::wire::{Command, ExecResult, Heartbeat, RunAs, Shell};
use serde::{Deserialize, Serialize};
use tracing::{info, warn};
use uuid::Uuid;

use super::AppState;

const DEFAULT_RUN_TIMEOUT_SECS: u64 = 60;
const RESULT_WAIT_PADDING_SECS: u64 = 10;
// v0.38 / #133: short timeout. The active-ping responder replies in
// single-digit ms on a healthy agent, so 5 s is generous; anything
// longer just keeps the operator's SPA spinner alive after the agent
// is definitely unreachable.
const DEFAULT_PING_WAIT_SECS: u64 = 5;

/// Body of `POST /api/run`. Maps loosely to the YAML manifest's
/// inline-script form (spec §2.4.1) but with the request_id
/// generated server-side so the response is a clean ExecResult.
#[derive(Deserialize)]
pub struct RunRequest {
    pub pc_id: String,
    /// `"powershell"` (or `ps`), `"pwsh"` (PowerShell 7,
    /// cross-platform), `"cmd"`, or `"sh"` (POSIX). Default powershell.
    /// Note `pwsh` is its own shell, not an alias of `powershell`.
    #[serde(default = "default_shell_str")]
    pub shell: String,
    pub script: String,
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,
    /// Optional. When set, `kanade kill <exec_id>` can terminate this
    /// run. v0.29 / Issue #19 renamed the field from `job_id` to
    /// `exec_id` for accuracy; `serde(alias)` keeps existing SPA POST
    /// bodies decodable.
    #[serde(default, alias = "job_id")]
    pub exec_id: Option<String>,
    #[serde(default)]
    pub jitter_secs: Option<u64>,
    /// Execution identity: `system` (default), `user`, or
    /// `system_gui` — same enum (and same agent dispatch path) as
    /// the manifest's `execute.run_as`. `#[serde(default)]` keeps
    /// pre-existing POST bodies decoding to the historical
    /// LocalSystem behaviour.
    #[serde(default)]
    pub run_as: RunAs,
}

fn default_shell_str() -> String {
    "powershell".to_string()
}
fn default_timeout_secs() -> u64 {
    DEFAULT_RUN_TIMEOUT_SECS
}

pub async fn run(
    State(state): State<AppState>,
    Json(req): Json<RunRequest>,
) -> Result<Json<ExecResult>, (StatusCode, String)> {
    let shell = match req.shell.as_str() {
        // `pwsh` is now its own variant (PowerShell 7, cross-platform),
        // no longer an alias for Windows PowerShell — so the SPA/API can
        // target a Linux agent with `sh` or `pwsh`.
        "powershell" | "ps" => Shell::Powershell,
        "cmd" => Shell::Cmd,
        "sh" => Shell::Sh,
        "pwsh" => Shell::Pwsh,
        other => {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown shell {other:?} (use powershell, pwsh, cmd, or sh)"),
            ));
        }
    };

    let request_id = Uuid::new_v4().to_string();
    let cmd = Command {
        id: "adhoc-run".to_string(),
        version: "0.0.0".to_string(),
        request_id: request_id.clone(),
        exec_id: req.exec_id.clone(),
        shell,
        script: req.script,
        // Backend ad-hoc `POST /api/run` is always inline; the
        // Object Store reference path lives on the manifest-driven
        // `POST /api/exec/{job_id}` flow (#210).
        script_object: None,
        script_object_sha256: None,
        timeout_secs: req.timeout_secs,
        bypass_local_limit: false,
        jitter_secs: req.jitter_secs,
        // Operator-selectable since the SPA Run page grew a run_as
        // picker; defaults to System (the inherited agent identity,
        // = LocalSystem in prod) so pre-existing callers keep the
        // historical behaviour.
        run_as: req.run_as,
        // Same rationale: cwd customisation belongs on a registered
        // Job, not on inline ad-hoc runs.
        cwd: None,
        // Ad-hoc `kanade run` has no scheduled tick → no deadline.
        deadline_at: None,
        // v0.26: ad-hoc inline run has no Manifest, so there's no
        // operator-declared staleness policy to honour. Default to
        // `Cached` — matching pre-v0.26 behaviour where Layer 2 was
        // best-effort (silently pass when KV unreachable).
        staleness: kanade_shared::wire::Staleness::Cached,
        // Issue #246: ad-hoc runs have no manifest, so no emit
        // hint either. Treat stdout as plain text.
        emit: None,
        // #290: ad-hoc runs aren't checks.
        check: None,
        // #219: ad-hoc runs have no manifest → no collect hint.
        collect: None,
        // #418 Phase 4: ad-hoc runs have no schedule → no retry policy.
        retry: None,
        // Ad-hoc runs have no manifest → no finalize hook.
        finalize: None,
    };

    let result_subj = subject::results(&request_id);
    let mut sub = state
        .nats
        .subscribe(result_subj.clone())
        .await
        .map_err(|e| {
            warn!(error = %e, request_id, "subscribe results subject");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("subscribe results: {e}"),
            )
        })?;
    // flush so the SUB is registered before we publish (see
    // reference_async_nats_subscribe_race).
    let _ = state.nats.flush().await;

    let payload = serde_json::to_vec(&cmd).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("encode Command: {e}"),
        )
    })?;
    state
        .commands
        .publish(subject::commands_pc(&req.pc_id), payload.into())
        .await
        .map_err(|e| {
            warn!(error = %e, pc_id = req.pc_id, "publish commands.pc.<id>");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("publish to {}: {e}", req.pc_id),
            )
        })?;
    let _ = state.nats.flush().await;

    info!(
        pc_id = %req.pc_id,
        request_id = %request_id,
        exec_id = ?req.exec_id,
        timeout_secs = req.timeout_secs,
        run_as = ?req.run_as,
        "sent command, waiting for result",
    );

    let wait = Duration::from_secs(req.timeout_secs + RESULT_WAIT_PADDING_SECS);
    let msg = tokio::time::timeout(wait, sub.next())
        .await
        .map_err(|_| {
            (
                StatusCode::REQUEST_TIMEOUT,
                format!("timeout waiting for result on {result_subj}"),
            )
        })?
        .ok_or_else(|| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "result subscription closed".to_string(),
            )
        })?;

    let result: ExecResult = serde_json::from_slice(&msg.payload).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("decode ExecResult: {e}"),
        )
    })?;
    Ok(Json(result))
}

#[derive(Deserialize, Default)]
pub struct PingQuery {
    /// Seconds to wait for the agent's ping reply. Default 5 (a
    /// live agent's responder turns around in single-digit ms; the
    /// short timeout means a wedged or unreachable agent surfaces
    /// fast in the SPA). Honored as the request timeout passed to
    /// `nats.request`.
    #[serde(default = "default_ping_wait")]
    pub wait_secs: u64,
}

fn default_ping_wait() -> u64 {
    DEFAULT_PING_WAIT_SECS
}

#[derive(Serialize)]
pub struct PingResponse {
    pub heartbeat: Heartbeat,
}

/// v0.38 / #133: active ping. Previous shape subscribed to the
/// periodic `heartbeat.<pc_id>` and waited up to ~45 s for the next
/// scheduled tick to land — average 15 s of operator-perceived
/// latency. Now publishes a request on `subject::ping(pc_id)` and
/// the agent's ping responder replies with a fresh Heartbeat in
/// single-digit ms.
///
/// Pre-#133 agents don't subscribe to that subject, so the request
/// times out → 408. Same operator-visible surface as the old
/// "no heartbeat within timeout" path; no coordinated upgrade
/// needed.
pub async fn ping(
    State(state): State<AppState>,
    Path(pc_id): Path<String>,
    Query(q): Query<PingQuery>,
) -> Result<Json<PingResponse>, (StatusCode, String)> {
    // Clamp to >=1s. `?wait_secs=0` would make `tokio::time::timeout`
    // fire on the very next poll, returning 408 before the request
    // ever reaches NATS — a fingerprint that looks like an offline
    // agent but isn't. 1 s is still well above the single-digit-ms
    // round trip a healthy agent serves.
    let wait_secs = q.wait_secs.max(1);
    let subj = subject::ping(&pc_id);
    info!(pc_id = %pc_id, subject = %subj, "ping: request");
    let reply = tokio::time::timeout(
        Duration::from_secs(wait_secs),
        state.nats.request(subj.clone(), bytes::Bytes::new()),
    )
    .await
    .map_err(|_| {
        (
            StatusCode::REQUEST_TIMEOUT,
            format!("no ping reply from {pc_id} within {wait_secs}s"),
        )
    })?
    .map_err(|e| {
        // NoResponders means no agent is subscribed to
        // `agents.<pc_id>.ping` — operator-visible == "agent
        // offline / not yet upgraded to #133". Surface as 408 so
        // the SPA renders the same "no heartbeat" UX it did before
        // this refactor. Other request errors (broker disconnect,
        // invalid subject) keep 500.
        let status = if matches!(e.kind(), async_nats::client::RequestErrorKind::NoResponders) {
            StatusCode::REQUEST_TIMEOUT
        } else {
            warn!(error = %e, pc_id, "ping request failed");
            StatusCode::INTERNAL_SERVER_ERROR
        };
        (status, format!("nats request {subj}: {e}"))
    })?;
    let hb: Heartbeat = serde_json::from_slice(&reply.payload).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("decode Heartbeat: {e}"),
        )
    })?;
    Ok(Json(PingResponse { heartbeat: hb }))
}
