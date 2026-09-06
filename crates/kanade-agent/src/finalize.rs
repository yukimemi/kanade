//! Job-generic post-step hook (`finalize:`). Runs AFTER the main script
//! (and, for a `collect:` job, after the bundle upload) on a clean exit,
//! with the step's structured result injected as an environment variable
//! so the hook can delete / move / notify. Best-effort: a hook failure
//! never becomes the *parent run's* outcome — the upload, if any, already
//! succeeded.
//!
//! Observability (#955): the hook's own outcome is published as a
//! **separate `ExecResult` row** — its own `result_id` / `request_id`,
//! `exec_id = None` (so it can't double-count the parent deployment's
//! Issue #19 counters), and `manifest_id = "<job>__finalize"` (not a
//! catalog entry, so no inventory/feed/check projection fires). This
//! surfaces "did the delete-after-collect step actually run / succeed?"
//! on the backend and SPA Activity page, instead of only in the agent's
//! local rolling log (which is unreachable in fleets where `logs.fetch`
//! has no responders).
//!
//! The result is injected by **prepending a shell assignment** to the
//! hook body rather than threading an env var through the spawn paths.
//! That keeps the System / User / SystemGui launch code untouched and
//! makes the var available identically regardless of `run_as`.

use async_nats::Client;
use kanade_shared::default_paths;
use kanade_shared::wire::{Command, ExecResult, FinalizeCommand, Shell};
use serde_json::json;
use tracing::{debug, info, warn};

use crate::process::{ExecOutcome, run_command_with_kill};

/// Build the `KANADE_COLLECT_RESULT` JSON for a collect job's finalize
/// hook from the uploaded bundles. Each entry carries its `label` (None
/// for the single-bundle form), Object Store `key`, and the `files`
/// actually packed. An empty slice (no collect hint, or every upload
/// failed) yields `{ "ok": false, "bundles": [] }`, so a hook that only
/// acts on `uploaded` files touches nothing.
pub fn collect_result_json(bundles: &[crate::collect::BundleResult]) -> String {
    let arr: Vec<_> = bundles
        .iter()
        .map(|b| {
            json!({
                "label": b.label,
                "key": b.key,
                "uploaded": true,
                "files": b.files,
            })
        })
        .collect();
    json!({ "ok": !arr.is_empty(), "bundles": arr }).to_string()
}

/// Build the PowerShell prelude that injects `result_json` as
/// `KANADE_COLLECT_RESULT`. A single-quoted PowerShell string treats only
/// `'` as special (escaped by doubling); serde's JSON is single-line, so
/// there are no raw newlines to handle. This is the security-sensitive
/// step — kept as its own function so the escaping is unit-tested. (cmd
/// is rejected upstream, so only the PowerShell form exists.)
fn powershell_prelude(result_json: &str) -> String {
    format!(
        "$env:KANADE_COLLECT_RESULT = '{}'\n",
        result_json.replace('\'', "''")
    )
}

/// Append a `finalize: <note>` line to a captured stderr (or use it alone
/// when stderr is blank), so an operator seeing exit `-1` on the finalize
/// row knows whether the hook was killed / timed out / failed to spawn.
/// Trailing whitespace is trimmed first so a trailing newline doesn't
/// produce a blank line before the note.
fn with_finalize_note(stderr: &str, note: &str) -> String {
    let trimmed = stderr.trim_end();
    if trimmed.is_empty() {
        note.to_string()
    } else {
        format!("{trimmed}\n{note}")
    }
}

/// Run the `finalize:` hook best-effort. `result_json` is injected as
/// `KANADE_COLLECT_RESULT`. Reuses [`run_command_with_kill`] — the same
/// staging / kill / timeout machinery the main script uses. The hook's
/// outcome is published as its own [`ExecResult`] row (#955) so the
/// delete-after-collect step is observable from the backend / SPA, not
/// only in the agent's local log.
/// `disc` is a per-bundle discriminator (#966): when the per-bundle
/// finalize path calls this once per uploaded bundle it passes a value
/// unique within the run (the bundle index) so each finalize row gets a
/// distinct synthetic `request_id` — and thus a distinct outbox filename
/// (`<request_id>.json`). Without it every per-bundle call would reuse
/// `<parent>__finalize`, and two hooks finishing inside the ~1s drain
/// window would clobber each other's not-yet-drained outbox file, losing
/// a finalize row. `None` (the single aggregate call) keeps the plain
/// `<parent>__finalize` id — one call per run, so no collision.
pub async fn run_finalize(
    client: &Client,
    parent: &Command,
    fin: &FinalizeCommand,
    pc_id: &str,
    parent_result_id: &str,
    disc: Option<&str>,
    result_json: Option<&str>,
) {
    // Defense in depth: `Manifest::validate` already rejects a cmd
    // finalize at the write boundary. Bail here too so a Command that
    // somehow carried `Shell::Cmd` (validation bypass, downgraded wire)
    // never reaches the unsafe injection path — cmd.exe quoting doesn't
    // nest, so JSON `"` + shell metacharacters in a collected path could
    // break out into command injection at the agent's privilege.
    // `sh` is rejected alongside `cmd`: same non-nesting-quote injection
    // risk, plus the prelude below (`$env:KANADE_COLLECT_RESULT = '...'`)
    // is PowerShell syntax and would be malformed in a POSIX shell.
    // `pwsh` is fine — it's PowerShell, so the prelude is valid.
    if matches!(fin.shell, Shell::Cmd | Shell::Sh) {
        warn!(job = %parent.id, "finalize: cmd/sh shell is not supported (injection risk + PowerShell prelude); skipping hook");
        return;
    }
    // Inject `KANADE_COLLECT_RESULT` only when there's a collect payload
    // (a `collect:` job). A non-collect finalize hook sees no such
    // variable, rather than a synthetic `{"ok":false,"bundles":[]}` —
    // which would be an observable contract break for callers that key
    // off the variable's presence.
    let prelude = result_json.map(powershell_prelude).unwrap_or_default();
    let script = format!("{prelude}{}", fin.script);

    // A synthetic Command reusing the parent's identity/kill subject but
    // carrying NO hints (no recursion into collect/finalize) — the hook
    // is a plain script run.
    let fin_cmd = Command {
        id: format!("{}__finalize", parent.id),
        version: parent.version.clone(),
        request_id: parent.request_id.clone(),
        exec_id: parent.exec_id.clone(),
        shell: fin.shell,
        script,
        script_object: None,
        script_object_sha256: None,
        timeout_secs: fin.timeout_secs,
        bypass_local_limit: false,
        jitter_secs: None,
        run_as: fin.run_as,
        cwd: fin.cwd.clone(),
        deadline_at: None,
        staleness: parent.staleness.clone(),
        emit: None,
        check: None,
        collect: None,
        retry: None,
        finalize: None,
    };

    // Stamp around the run so the finalize row carries a real duration.
    let started_at = chrono::Utc::now();
    let outcome = run_command_with_kill(client, &fin_cmd, None).await;
    let finished_at = chrono::Utc::now();

    // Map the outcome to the (exit_code, stdout, stderr) recorded on the
    // finalize row, mirroring the main script's convention: a synthetic
    // kill / timeout / spawn-failure carries exit `-1` with a note in
    // stderr so `-1` on the Activity page is self-explanatory. The
    // local-log breadcrumbs are kept for a fleet that CAN reach the log.
    let (exit_code, stdout, stderr) = match outcome {
        Ok(ExecOutcome::Completed {
            exit_code: 0,
            stdout,
            stderr,
        }) => {
            info!(job = %parent.id, "finalize: hook completed");
            (0, stdout, stderr)
        }
        Ok(ExecOutcome::Completed {
            exit_code,
            stdout,
            stderr,
        }) => {
            warn!(job = %parent.id, exit_code, stderr = %stderr, "finalize: hook exited non-zero (ignored)");
            (exit_code, stdout, stderr)
        }
        Ok(ExecOutcome::Killed { stdout, stderr }) => {
            warn!(job = %parent.id, "finalize: hook killed (ignored)");
            (
                -1,
                stdout,
                with_finalize_note(&stderr, "finalize: hook killed"),
            )
        }
        Ok(ExecOutcome::Timeout { stdout, stderr }) => {
            warn!(job = %parent.id, "finalize: hook timed out (ignored)");
            (
                -1,
                stdout,
                with_finalize_note(
                    &stderr,
                    &format!("finalize: hook timed out after {}s", fin.timeout_secs),
                ),
            )
        }
        Err(e) => {
            warn!(job = %parent.id, error = %e, "finalize: hook spawn failed (ignored)");
            (
                -1,
                String::new(),
                format!("finalize: hook spawn failed: {e}"),
            )
        }
    };

    // #955: publish a dedicated ExecResult row so the hook's outcome is
    // queryable from the backend / SPA. Best-effort: an enqueue failure is
    // logged, never propagated (the hook already ran).
    let result = build_finalize_result(
        parent,
        &fin_cmd,
        pc_id,
        parent_result_id,
        disc,
        exit_code,
        stdout,
        stderr,
        started_at,
        finished_at,
    );
    // `outbox::enqueue` does synchronous file I/O (create_dir_all / write
    // / rename); offload it to the blocking pool so it never stalls an
    // async worker thread — same pattern as the KLP path's
    // `enqueue_exec_result` (gemini). Fire-and-forget + best-effort.
    let outbox_dir = default_paths::data_dir().join("outbox");
    let job = parent.id.clone();
    let pc = pc_id.to_string();
    tokio::task::spawn_blocking(move || match crate::outbox::enqueue(&outbox_dir, &result) {
        Ok(path) => debug!(
            %job,
            pc_id = %pc,
            exit_code,
            outbox = %path.display(),
            "finalize: outcome enqueued to outbox (#955 observability)",
        ),
        Err(e) => warn!(
            %job,
            pc_id = %pc,
            error = %e,
            "finalize: outcome enqueue failed (hook still ran)",
        ),
    });
}

/// Build the finalize hook's own [`ExecResult`] row (#955). Pure — no
/// I/O — so the row-shape invariants below are unit-tested without
/// spawning a process or a NATS client. A fresh `result_id` + a distinct
/// `request_id` (`__finalize` suffix) keep the outbox file (keyed by
/// `request_id`) and the `results.<request_id>` subject from colliding
/// with the parent's. `exec_id = None` avoids double-incrementing the
/// parent deployment's Issue #19 success/failure counters (the projector's
/// bump is gated on `result_id` freshness, not `exec_id`, so a fresh row
/// carrying the parent `exec_id` would count twice). `manifest_id` is the
/// synthetic `<job>__finalize` id (`fin_cmd.id`) — not a catalog entry, so
/// no inventory/feed/check projection fires, and it reads as its own
/// "<job>__finalize" line on the Activity page. `parent_result_id`
/// back-links to the triggering run so the SPA can navigate run <->
/// finalize in both directions.
#[allow(clippy::too_many_arguments)]
fn build_finalize_result(
    parent: &Command,
    fin_cmd: &Command,
    pc_id: &str,
    parent_result_id: &str,
    disc: Option<&str>,
    exit_code: i32,
    stdout: String,
    stderr: String,
    started_at: chrono::DateTime<chrono::Utc>,
    finished_at: chrono::DateTime<chrono::Utc>,
) -> ExecResult {
    // #966: the discriminator makes the synthetic request_id — and thus
    // the outbox filename — unique per bundle within a run, so per-bundle
    // finalize rows can't clobber each other on disk before the drain
    // task publishes them. The aggregate call (`None`) keeps the plain
    // `<parent>__finalize` id.
    let request_id = match disc {
        Some(d) => format!("{}__finalize-{d}", parent.request_id),
        None => format!("{}__finalize", parent.request_id),
    };
    ExecResult {
        result_id: uuid::Uuid::new_v4().to_string(),
        request_id,
        exec_id: None,
        parent_result_id: Some(parent_result_id.to_string()),
        pc_id: pc_id.to_string(),
        exit_code,
        stdout,
        stderr,
        started_at,
        finished_at,
        // The outbox drain offloads oversized output to the object store
        // on its own; None at enqueue keeps the full bytes on disk (#227).
        stdout_object: None,
        stderr_object: None,
        manifest_id: Some(fin_cmd.id.clone()),
        collect_object: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Minimal parent `Command` with the identity fields the finalize row
    /// derives from; everything else is default/None.
    fn parent_fixture(id: &str, request_id: &str) -> Command {
        Command {
            id: id.into(),
            version: "1".into(),
            request_id: request_id.into(),
            exec_id: Some("exec-uuid".into()),
            shell: Shell::Powershell,
            script: String::new(),
            script_object: None,
            script_object_sha256: None,
            timeout_secs: 60,
            bypass_local_limit: false,
            jitter_secs: None,
            run_as: Default::default(),
            cwd: None,
            deadline_at: None,
            staleness: Default::default(),
            emit: None,
            check: None,
            collect: None,
            retry: None,
            finalize: None,
        }
    }

    #[test]
    fn finalize_result_row_holds_its_invariants() {
        // #955: the finalize row must (a) carry exec_id = None so it can't
        // double-count the parent's Issue #19 counters, (b) use a distinct
        // `__finalize`-suffixed request_id so its outbox file / subject
        // don't collide with the parent, (c) set manifest_id to the
        // synthetic `<job>__finalize` id, and (d) back-link the parent run.
        let parent = parent_fixture("screenshot-collect", "req-123");
        let fin_cmd = parent_fixture("screenshot-collect__finalize", "req-123");
        let now = chrono::Utc::now();
        let r = build_finalize_result(
            &parent,
            &fin_cmd,
            "pc-9",
            "parent-run-uuid",
            None,
            1,
            "out".into(),
            "err".into(),
            now,
            now,
        );
        assert!(
            r.exec_id.is_none(),
            "finalize row must be ad-hoc (no #19 bump)"
        );
        assert_eq!(r.request_id, "req-123__finalize");
        assert_eq!(
            r.manifest_id.as_deref(),
            Some("screenshot-collect__finalize")
        );
        assert_eq!(r.parent_result_id.as_deref(), Some("parent-run-uuid"));
        assert_eq!(r.pc_id, "pc-9");
        assert_eq!(r.exit_code, 1);
        assert!(!r.result_id.is_empty(), "result_id minted");
    }

    #[test]
    fn per_bundle_finalize_request_ids_are_distinct() {
        // #966 (claude): the outbox file is keyed on request_id, so two
        // per-bundle finalize rows in the SAME run must NOT share one — a
        // second enqueue would overwrite the first's not-yet-drained file
        // and silently lose that row. The discriminator (bundle index)
        // keeps them distinct; `None` (the aggregate call) is the plain id.
        let parent = parent_fixture("screenshot-collect", "req-123");
        let fin_cmd = parent_fixture("screenshot-collect__finalize", "req-123");
        let now = chrono::Utc::now();
        let mk = |disc: Option<&str>| {
            build_finalize_result(
                &parent,
                &fin_cmd,
                "pc-9",
                "parent-run-uuid",
                disc,
                0,
                String::new(),
                String::new(),
                now,
                now,
            )
            .request_id
        };
        assert_eq!(mk(None), "req-123__finalize");
        assert_eq!(mk(Some("0")), "req-123__finalize-0");
        assert_ne!(
            mk(Some("0")),
            mk(Some("1")),
            "per-bundle finalize rows must have distinct request_ids (outbox filename)",
        );
    }

    #[test]
    fn result_json_marks_uploaded_when_collected() {
        let json = collect_result_json(&[
            crate::collect::BundleResult {
                label: Some("20260101".into()),
                key: "pc/job/20260101__ts.zip".into(),
                files: vec!["C:/a.png".into(), "C:/b.png".into()],
            },
            crate::collect::BundleResult {
                label: Some("20260102".into()),
                key: "pc/job/20260102__ts.zip".into(),
                files: vec!["C:/c.png".into()],
            },
        ]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["ok"], true);
        assert_eq!(v["bundles"].as_array().unwrap().len(), 2);
        assert_eq!(v["bundles"][0]["label"], "20260101");
        assert_eq!(v["bundles"][0]["key"], "pc/job/20260101__ts.zip");
        assert_eq!(v["bundles"][0]["uploaded"], true);
        assert_eq!(v["bundles"][0]["files"].as_array().unwrap().len(), 2);
    }

    #[test]
    fn powershell_prelude_doubles_single_quotes() {
        // A collected path containing `'` must be escaped by doubling so
        // it can't break out of the single-quoted assignment.
        let p = powershell_prelude(r#"{"files":["C:/it's here.png"]}"#);
        assert!(
            p.contains("it''s here"),
            "single quote must be doubled: {p}"
        );
        assert!(p.starts_with("$env:KANADE_COLLECT_RESULT = '"));
        assert!(p.ends_with("'\n"));
        // No unescaped lone single quote remains inside the value.
        let inner = p
            .trim_start_matches("$env:KANADE_COLLECT_RESULT = '")
            .trim_end_matches("'\n");
        assert!(!inner.contains('\'') || inner.contains("''"));
    }

    #[test]
    fn finalize_note_appends_or_stands_alone() {
        // Blank stderr → the note is the whole stderr (no leading newline).
        assert_eq!(
            with_finalize_note("", "finalize: hook killed"),
            "finalize: hook killed"
        );
        // Existing stderr → the note is appended on its own line, with the
        // captured stream's trailing whitespace trimmed first.
        assert_eq!(
            with_finalize_note(
                "Remove-Item: denied\n",
                "finalize: hook timed out after 30s"
            ),
            "Remove-Item: denied\nfinalize: hook timed out after 30s"
        );
    }

    #[test]
    fn result_json_is_empty_when_nothing_collected() {
        let json = collect_result_json(&[]);
        let v: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(v["ok"], false);
        assert_eq!(v["bundles"].as_array().unwrap().len(), 0);
    }
}
