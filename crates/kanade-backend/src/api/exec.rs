use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use base64::Engine as _;
use kanade_shared::kv::{BUCKET_SCRIPT_CURRENT, OBJECT_SCRIPTS};
use kanade_shared::manifest::{FanoutPlan, Manifest, Target};
use kanade_shared::subject;
use kanade_shared::wire::Command;
use serde::Serialize;
use tracing::{info, warn};
use uuid::Uuid;

use crate::api::AppState;
use crate::api::jobs;
use crate::audit;
use crate::audit::Caller;

#[derive(Serialize, Clone)]
pub struct ExecResponse {
    pub exec_id: String,
    pub job_id: String,
    pub version: String,
    pub target_count: u32,
    pub subjects: Vec<String>,
}

/// Core exec pipeline used by both the HTTP handler (actor = "operator")
/// and the scheduler (actor = "scheduler"). Validates the [`FanoutPlan`],
/// fans the Command out across every target subject (or schedules
/// wave-based fan-out when `rollout` is set), pins script_current,
/// records an `executions` row, and emits an audit event.
///
/// v0.18: the Manifest supplies only "what to run" (script + shell +
/// timeout + inventory hint). `target` / `rollout` / `jitter` come
/// from the caller's [`FanoutPlan`] — schedules carry one inline,
/// ad-hoc execs build one from CLI flags / SPA form input.
///
/// `caller` is `None` for the scheduler path (no HTTP request) and
/// `Some(_)` for operator-initiated execs, where the JWT subject and
/// `X-Kanade-Source` header get folded into the audit payload.
pub async fn exec_manifest(
    s: &AppState,
    manifest: Manifest,
    mut plan: FanoutPlan,
    actor: &str,
    caller: Option<&Caller>,
    // #418 Phase 4: the schedule's lowered on_failure.retry, stamped
    // onto every Command this exec produces. `None` for ad-hoc
    // operator exec (no schedule = no retry policy); the scheduler
    // passes `schedule.on_failure.lowered_retry()`.
    retry: Option<kanade_shared::wire::RetrySpec>,
) -> Result<ExecResponse, (StatusCode, String)> {
    let has_rollout = plan
        .rollout
        .as_ref()
        .map(|r| !r.waves.is_empty())
        .unwrap_or(false);
    if !has_rollout && !plan.target.is_specified() {
        return Err((
            StatusCode::BAD_REQUEST,
            "target must specify at least one of `all` / `groups` / `pcs` (or set `rollout.waves`)"
                .into(),
        ));
    }

    // Defensive — the write paths (`POST /api/jobs`, `kanade job
    // create`) already gate every manifest through
    // `Manifest::validate()` before it lands in BUCKET_JOBS, so by
    // the time exec_manifest sees one we expect a valid manifest.
    // Re-run the FULL validation here so a hypothetical write path
    // that bypassed it (direct NATS KV poke, downgrade-then-upgrade)
    // bails with a clear 400 instead of crashing the unwrap below or
    // lowering an invalid finalize hook (blank script / cmd shell /
    // unparseable timeout) into a runnable Command.
    manifest
        .validate()
        .map_err(|e| (StatusCode::BAD_REQUEST, e))?;

    // Execution-tier guard (#vuln-roadmap): a `tier: controller` job may
    // run ONLY on the trusted `controller_group` runners. Constrain the
    // requested target to those members (intersecting, so `all` means "all
    // controller runners") and refuse outright if the group is unset — all
    // BEFORE we resolve a target_count or publish anything. Fail closed.
    if crate::controller::requires_controller(&manifest) {
        if has_rollout {
            return Err((
                StatusCode::UNPROCESSABLE_ENTITY,
                "tier: controller jobs can't use rollout waves — the controller tier \
                 targets trusted runners, not a fleet rollout"
                    .into(),
            ));
        }
        let members = crate::controller::member_set(s).await.map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("controller group resolve failed: {e}"),
            )
        })?;
        // `all` ⇒ the controller runners ARE the effective target, so skip
        // the whole-fleet `resolve_expected_pcs` and use the (already
        // resolved) members directly — only a narrowed target needs the
        // fleet resolution (gemini #905). When the group is unset we don't
        // resolve at all (constrain returns GroupUnset regardless).
        let requested: Vec<String> = match (&members, plan.target.all) {
            (None, _) => Vec::new(),
            (Some(m), true) => m.iter().cloned().collect(),
            (Some(_), false) => crate::scheduler::resolve_expected_pcs(s, &plan.target)
                .await
                .map_err(|e| {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("resolve controller target: {e}"),
                    )
                })?,
        };
        match crate::controller::constrain(requested, &members) {
            crate::controller::Constrained::Pcs(pcs) => {
                plan.target = Target {
                    all: false,
                    groups: Vec::new(),
                    pcs,
                };
            }
            crate::controller::Constrained::GroupUnset => {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "tier: controller but no controller_group is configured \
                     (Settings -> server settings) — refusing to dispatch (fail-safe)"
                        .into(),
                ));
            }
            crate::controller::Constrained::NoMember => {
                return Err((
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "no online controller_group member matches this target — a \
                     tier: controller job needs a live controller runner"
                        .into(),
                ));
            }
        }
    }
    // Resolve the manifest's script source into the wire shape the
    // agent expects:
    //   - inline `script:`     → Command { script: <body>,
    //                                      script_object: None }
    //   - `script_object: k`   → look up the OBJECT_SCRIPTS digest
    //                            for `k` and emit Command { script: "",
    //                            script_object: Some(k),
    //                            script_object_sha256: Some(<digest>) };
    //                            the agent's script_cache pulls the body
    //                            at exec time (kanadehq/kanade#210).
    // `script_file:` is operator-side only — the CLI inlines its
    // contents into `script` before POSTing, so it never reaches us
    // as an unresolved alternative.
    let (inline_script, script_object_ref) = resolve_script_source(s, &manifest).await?;

    let timeout_secs = humantime::parse_duration(&manifest.execute.timeout)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid timeout: {e}")))?
        .as_secs();
    let jitter_secs = plan
        .jitter
        .as_deref()
        .map(humantime::parse_duration)
        .transpose()
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("invalid jitter: {e}")))?
        .map(|d| d.as_secs());

    let exec_id = Uuid::new_v4().to_string();

    let deadline_at = plan.deadline_at;
    let make_cmd = || Command {
        id: manifest.id.clone(),
        version: manifest.version.clone(),
        request_id: Uuid::new_v4().to_string(),
        exec_id: Some(exec_id.clone()),
        bypass_local_limit: manifest.execute.bypass_local_limit,
        shell: manifest.execute.shell.into(),
        script: inline_script.clone(),
        script_object: script_object_ref.as_ref().map(|(k, _)| k.clone()),
        script_object_sha256: script_object_ref.as_ref().map(|(_, d)| d.clone()),
        timeout_secs,
        jitter_secs,
        run_as: manifest.execute.run_as,
        cwd: manifest.execute.cwd.clone(),
        deadline_at,
        // v0.26: forward Layer 2 staleness policy to every emitted
        // Command so the agent can apply it whether it sees the live
        // publish or replays from STREAM_EXEC on reconnect.
        staleness: manifest.staleness.clone(),
        // Issue #246: forward the manifest's observability emit hint
        // so the agent can route stdout NDJSON to obs-outbox without
        // a manifest re-fetch.
        emit: manifest.emit.clone(),
        // #290: forward the manifest's check hint so the agent builds
        // a KLP Health-tab Check from the job's stdout (no re-fetch).
        check: manifest.check.clone(),
        // #219: forward the manifest's collect hint so the agent bundles
        // the script's listed files and uploads to OBJECT_COLLECTIONS
        // (no re-fetch).
        collect: manifest.collect.clone(),
        // #418 Phase 4: the schedule's retry policy (None for ad-hoc
        // exec). Copy is cheap — RetrySpec is Copy.
        retry,
        // Forward the manifest's finalize hook (lowered to wire form) so
        // the agent runs it after the collect step (no manifest re-fetch).
        finalize: manifest.finalize.as_ref().map(|f| f.lower()),
    };

    let mut subjects: Vec<String> = Vec::new();

    // #485: `target_count` = PCs expected to reply (alive-snapshot
    // via the scheduler's resolver), not subjects published — the
    // old per-subject count completed a fleet broadcast on its first
    // reply. Late replayers may still push counters past the
    // snapshot; the projector tolerates that. Floor at 1 so an
    // empty-alive resolve can't mark an exec completed-by-vacuity,
    // and fall back to the per-subject count if the resolve fails.
    let expected_target = expected_target_for(&plan);
    let target_count: u32 = match crate::scheduler::resolve_expected_pcs(s, &expected_target).await
    {
        Ok(pcs) => {
            if pcs.is_empty() {
                warn!(
                    job_id = %manifest.id,
                    "target resolved to zero alive PCs; flooring target_count at 1",
                );
            }
            (pcs.len() as u32).max(1)
        }
        Err(e) => {
            let fallback = fallback_subject_count(&plan);
            warn!(
                error = ?e,
                fallback,
                "target resolve failed; falling back to per-subject target_count",
            );
            fallback
        }
    };

    // #258: pin script_current BEFORE any publish (both rollout-wave
    // and plain target paths below). The agent's Layer 2 staleness
    // gate (commands.rs:151) compares the incoming cmd.version against
    // script_current.<id> — if the KV still holds the previous bump's
    // value when the command arrives, the agent silently drops the
    // first exec after every job bump. JetStream's KV propagation
    // isn't synchronous with the NATS publish that follows, so the
    // original ordering (publish → flush → put) raced even on a
    // single-node broker.
    match s.jetstream.get_key_value(BUCKET_SCRIPT_CURRENT).await {
        Ok(kv) => {
            if let Err(e) = kv
                .put(
                    &manifest.id,
                    bytes::Bytes::from(manifest.version.clone().into_bytes()),
                )
                .await
            {
                warn!(error = %e, cmd_id = %manifest.id, "script_current put failed");
            }
        }
        Err(e) => warn!(error = %e, "script_current KV missing; skipping version pin"),
    }

    if let Some(rollout) = plan.rollout.as_ref() {
        // Wave-based fan-out: pre-validate every delay so a bad humantime
        // string aborts the whole exec instead of silently failing on a
        // late wave inside a tokio::spawn.
        let mut delays = Vec::with_capacity(rollout.waves.len());
        for (idx, wave) in rollout.waves.iter().enumerate() {
            let d = humantime::parse_duration(&wave.delay).map_err(|e| {
                (
                    StatusCode::BAD_REQUEST,
                    format!("invalid rollout.waves[{idx}].delay: {e}"),
                )
            })?;
            delays.push(d);
        }

        for ((idx, wave), delay) in rollout.waves.iter().enumerate().zip(delays) {
            let subj = subject::commands_group(&wave.group);
            subjects.push(subj.clone());

            let cmd = make_cmd();
            let payload = serde_json::to_vec(&cmd)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {e}")))?;

            if delay.is_zero() {
                if let Err(e) = s.commands.publish(subj.clone(), payload.into()).await {
                    return Err((StatusCode::BAD_GATEWAY, format!("publish to {subj}: {e}")));
                }
                info!(wave = idx, subject = %subj, "wave published (immediate)");
            } else {
                // #1165: the publisher, not the bare client — a delayed wave
                // is signed when it actually goes out, so its signing time
                // means what a freshness bound would read it as rather than
                // "whenever this exec was assembled, possibly hours earlier".
                let commands = s.commands.clone();
                let subj_for_spawn = subj.clone();
                tokio::spawn(async move {
                    tokio::time::sleep(delay).await;
                    match commands
                        .publish(subj_for_spawn.clone(), payload.into())
                        .await
                    {
                        Ok(()) => info!(
                            wave = idx,
                            subject = %subj_for_spawn,
                            delay_secs = delay.as_secs(),
                            "wave published (delayed)",
                        ),
                        Err(e) => warn!(
                            error = %e,
                            wave = idx,
                            subject = %subj_for_spawn,
                            "delayed wave publish failed",
                        ),
                    }
                });
                info!(
                    wave = idx,
                    subject = %subj,
                    delay_secs = delay.as_secs(),
                    "wave scheduled",
                );
            }
        }
    } else {
        // Plain target-based fan-out (no rollout block).
        if plan.target.all {
            subjects.push(subject::COMMANDS_ALL.to_string());
        }
        for g in &plan.target.groups {
            subjects.push(subject::commands_group(g));
        }
        for pc in &plan.target.pcs {
            subjects.push(subject::commands_pc(pc));
        }

        // #913: ONE Command (hence one request_id) for the whole exec,
        // published verbatim to every subject. These subjects can
        // overlap on a single PC — `target: {groups:[a,b]}` with a PC
        // in both, or `{all:true, pcs:[x]}` — and the agent dedups by
        // request_id (commands.rs), so minting a fresh id per subject
        // (the old `make_cmd()`-in-the-loop) made that PC run the
        // script once per matching subject. Sharing one id lets the
        // agent's dedup cache absorb the redundant deliveries, matching
        // how a single `commands.all` broadcast already shares one
        // request_id across every PC. The Command is otherwise
        // identical across subjects, so build + serialise it once, into
        // a `Bytes` so each per-subject publish is a cheap refcount
        // clone rather than a fresh copy of the payload (gemini/claude
        // #946).
        let cmd = make_cmd();
        let payload = bytes::Bytes::from(
            serde_json::to_vec(&cmd)
                .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, format!("serialize: {e}")))?,
        );
        for subj in &subjects {
            if let Err(e) = s.commands.publish(subj.clone(), payload.clone()).await {
                warn!(error = %e, subject = %subj, "publish failed");
                return Err((StatusCode::BAD_GATEWAY, format!("publish to {subj}: {e}")));
            }
        }
    }
    let _ = s.nats.flush().await;

    // #390: initiated_at is bound explicitly (RFC 3339) — the
    // column's DEFAULT CURRENT_TIMESTAMP writes space-separated text,
    // which would mix formats with the chrono-bound cleanup cutoff.
    sqlx::query(
        "INSERT INTO executions (exec_id, job_id, version, initiated_by, target_count, status, initiated_at)
         VALUES (?, ?, ?, ?, ?, 'pending', ?)",
    )
    .bind(&exec_id)
    .bind(&manifest.id)
    .bind(&manifest.version)
    .bind(actor)
    .bind(target_count as i64)
    .bind(chrono::Utc::now())
    .execute(&s.pool)
    .await
    .map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("insert executions: {e}"),
        )
    })?;

    info!(
        exec_id = %exec_id,
        job_id = %manifest.id,
        version = %manifest.version,
        actor,
        target_count,
        wave_mode = has_rollout,
        subjects = ?subjects,
        "execution published",
    );

    audit::record(
        &s.nats,
        actor,
        "exec",
        Some(&manifest.id),
        caller,
        serde_json::json!({
            "exec_id": exec_id,
            "version": manifest.version,
            "target_count": target_count,
            "subjects": subjects,
            "wave_mode": has_rollout,
        }),
    )
    .await;

    Ok(ExecResponse {
        exec_id,
        job_id: manifest.id,
        version: manifest.version,
        target_count,
        subjects,
    })
}

/// `POST /api/exec/{job_id}` — fire a registered job from the
/// catalog against a caller-supplied [`FanoutPlan`]. The Manifest body
/// is never accepted inline; operators must `kanade job create` first.
/// 404 when the job isn't in `BUCKET_JOBS`.
pub async fn create(
    State(s): State<AppState>,
    Path(job_id): Path<String>,
    caller: Caller,
    Json(plan): Json<FanoutPlan>,
) -> Result<Json<ExecResponse>, (StatusCode, String)> {
    let manifest = match jobs::fetch(&s.jetstream, &job_id).await {
        Ok(Some(m)) => m,
        Ok(None) => {
            return Err((
                StatusCode::NOT_FOUND,
                format!(
                    "job '{job_id}' not found in catalog — register it first with \
                     `kanade job create <manifest.yaml>`"
                ),
            ));
        }
        Err(e) => {
            warn!(error = %e, %job_id, "exec: job catalog lookup failed");
            return Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("job catalog lookup: {e}"),
            ));
        }
    };
    // Ad-hoc operator exec has no schedule, hence no on_failure.retry.
    exec_manifest(&s, manifest, plan, "operator", Some(&caller), None)
        .await
        .map(Json)
}

/// Look up the wire shape for the manifest's script source.
///
/// Returns a tuple of `(inline_body, script_object_ref)`:
///
///   * Inline path — `(body, None)`. The Command embeds the body
///     directly (matching pre-#210 wire).
///   * Object Store path — `(String::new(), Some((key, sha256)))`.
///     The agent's script_cache fetches the body keyed by `key`,
///     verifies the bytes against `sha256`, then executes.
///
/// The Object Store path snapshots the current digest at exec
/// submission. If the operator re-uploads `key` with new bytes
/// between submission and the agent's fire, the agent's sha
/// check fails and the run aborts — that's the intended safety
/// net for the "operator re-uploaded mid-rollout" case.
async fn resolve_script_source(
    s: &AppState,
    manifest: &Manifest,
) -> Result<(String, Option<(String, String)>), (StatusCode, String)> {
    if let Some(inline) = manifest.execute.script.as_deref().filter(|s| !s.is_empty()) {
        return Ok((inline.to_owned(), None));
    }

    let key = manifest.execute.script_object.as_deref().ok_or((
        StatusCode::BAD_REQUEST,
        "execute: one of `script` or `script_object` must be set \
         (Manifest::validate() should have caught this earlier)"
            .to_string(),
    ))?;

    let store = s
        .jetstream
        .get_object_store(OBJECT_SCRIPTS)
        .await
        .map_err(|e| {
            warn!(error = %e, "exec: get_object_store scripts");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                format!(
                    "Object Store '{OBJECT_SCRIPTS}' missing — \
                     run `kanade jetstream setup`"
                ),
            )
        })?;
    let info = store.info(key).await.map_err(|e| {
        let msg = e.to_string();
        if msg.contains("not found") || msg.contains("no objects") {
            (
                StatusCode::NOT_FOUND,
                format!("script_object '{key}' not found in OBJECT_SCRIPTS"),
            )
        } else {
            warn!(error = %e, %key, "exec: object_store.info");
            (StatusCode::INTERNAL_SERVER_ERROR, msg)
        }
    })?;

    // NATS Object Store emits digests as `SHA-256=<base64url-no-pad>`
    // (JetStream protocol). The agent's script_cache verifies by
    // computing sha256(bytes) and hex-comparing, so re-encode to hex
    // once here — keeps the wire field operator-readable and frees
    // the agent from a base64 dep.
    let raw = info.digest.as_deref().ok_or((
        StatusCode::INTERNAL_SERVER_ERROR,
        format!(
            "script_object '{key}' has no digest metadata — \
             broker should always populate it"
        ),
    ))?;
    let b64 = raw.strip_prefix("SHA-256=").unwrap_or(raw);
    // NATS async-nats emits digests in URL-safe base64 WITH `=`
    // padding (e.g. `SHA-256=pzGZSHXYLupCjS_RB0lmdLNHpgyH53Y5vI8XYhb2H1o=`).
    // The original `URL_SAFE_NO_PAD` rejected the trailing `=` (a
    // copy-paste from a URL-safe-id case). Use an Indifferent
    // padding-mode config so a future broker emitting unpadded
    // digests doesn't break us — the crate's stock `URL_SAFE`
    // engine has `RequireCanonical` (Gemini #225) which would
    // re-introduce the same fragility in the other direction.
    // Bug surfaced during a live install-kanade-backend self-test
    // (#222 + #224 flow) as a 500 "Invalid padding" from
    // /api/exec/<job>.
    use base64::alphabet::URL_SAFE;
    use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
    static DECODER: GeneralPurpose = GeneralPurpose::new(
        &URL_SAFE,
        GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
    );
    let bytes = DECODER.decode(b64).map_err(|e| {
        warn!(error = %e, %key, raw, "exec: decode object_store digest");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("decode digest for '{key}': {e}"),
        )
    })?;
    let digest = hex_lower(&bytes);

    Ok((String::new(), Some((key.to_owned(), digest))))
}

/// Lower-case hex-encode without pulling `hex` as a fresh dep.
/// Output matches sha2's standard formatting on the agent side.
fn hex_lower(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// #485: the Target whose alive members `target_count` counts.
/// Mirrors the publish branch condition (`plan.rollout.is_some()`,
/// NOT waves-non-empty — review PR #543): a `rollout: {waves: []}`
/// plan publishes nothing, so it must also count nothing.
fn expected_target_for(plan: &FanoutPlan) -> kanade_shared::manifest::Target {
    if let Some(rollout) = plan.rollout.as_ref() {
        kanade_shared::manifest::Target {
            groups: rollout.waves.iter().map(|w| w.group.clone()).collect(),
            pcs: Vec::new(),
            all: false,
        }
    } else {
        plan.target.clone()
    }
}

/// #485: pre-fix per-subject count, kept as the resolve-failure
/// fallback. Same `is_some()` branch condition as
/// [`expected_target_for`] so success and failure paths agree.
fn fallback_subject_count(plan: &FanoutPlan) -> u32 {
    (if let Some(rollout) = plan.rollout.as_ref() {
        rollout.waves.len()
    } else {
        plan.target.all as usize + plan.target.groups.len() + plan.target.pcs.len()
    }) as u32
}

#[cfg(test)]
mod tests {
    use super::*;
    use kanade_shared::manifest::{FanoutPlan, Rollout, Target, Wave};

    fn plan(target: Target, rollout: Option<Rollout>) -> FanoutPlan {
        FanoutPlan {
            target,
            rollout,
            ..FanoutPlan::default()
        }
    }

    #[test]
    fn expected_target_plain_passes_through() {
        let t = Target {
            all: true,
            groups: vec!["g1".into()],
            pcs: vec!["pc-1".into()],
        };
        let p = plan(t.clone(), None);
        let resolved = expected_target_for(&p);
        assert!(resolved.all);
        assert_eq!(resolved.groups, t.groups);
        assert_eq!(resolved.pcs, t.pcs);
        assert_eq!(fallback_subject_count(&p), 3);
    }

    #[test]
    fn expected_target_rollout_unions_wave_groups() {
        let p = plan(
            Target::default(),
            Some(Rollout {
                strategy: Default::default(),
                waves: vec![
                    Wave {
                        group: "canary".into(),
                        delay: "0s".into(),
                    },
                    Wave {
                        group: "wave1".into(),
                        delay: "10m".into(),
                    },
                ],
            }),
        );
        let resolved = expected_target_for(&p);
        assert!(!resolved.all);
        assert_eq!(resolved.groups, vec!["canary", "wave1"]);
        assert!(resolved.pcs.is_empty());
        assert_eq!(fallback_subject_count(&p), 2);
    }

    #[test]
    fn empty_waves_rollout_counts_nothing_on_both_paths() {
        // Review PR #543 (gemini): `rollout: Some` with empty waves
        // publishes nothing, so expected target AND fallback must
        // both be zero — previously the fallback keyed off
        // waves-non-empty and would have counted the plain target.
        let p = plan(
            Target {
                all: true,
                groups: vec![],
                pcs: vec![],
            },
            Some(Rollout {
                strategy: Default::default(),
                waves: vec![],
            }),
        );
        let resolved = expected_target_for(&p);
        assert!(!resolved.all && resolved.groups.is_empty() && resolved.pcs.is_empty());
        assert_eq!(fallback_subject_count(&p), 0);
    }
}
