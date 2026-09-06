use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

use super::Staleness;
use crate::manifest::{CheckHint, CollectHint, EmitConfig};

#[derive(Serialize, Deserialize, schemars::JsonSchema, Debug, Clone)]
pub struct Command {
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub bypass_local_limit: bool,
    pub id: String,
    pub version: String,
    pub request_id: String,
    /// v0.29 / Issue #19: the deployment / scheduler-fire UUID this
    /// Command belongs to. Forwarded into `ExecResult.exec_id` by the
    /// agent so the projector can attribute results back to the
    /// originating `executions` row. `None` for ad-hoc `kanade run`
    /// (no deployment row exists). Pre-v0.29 wire used the field name
    /// `job_id` for this same value — `serde(alias)` keeps old
    /// publishes in STREAM_EXEC decodable across the upgrade window.
    #[serde(alias = "job_id")]
    pub exec_id: Option<String>,
    pub shell: Shell,
    /// Inline script body, OR empty when [`script_object`] is set.
    /// Mutually exclusive with `script_object` at the wire level —
    /// backend builders fill one or the other (never both) and the
    /// agent's resolver picks the populated one. Pre-v0.43 wire
    /// always carries this populated.
    ///
    /// [`script_object`]: Self::script_object
    pub script: String,
    /// SPEC §2.4.1 / kanadehq/kanade#210: Object Store reference
    /// (`<name>/<version>` key into `OBJECT_SCRIPTS`). When set,
    /// the agent fetches the body via `script_cache` and verifies
    /// its sha256 against [`script_object_sha256`] before launching.
    /// `None` ⇒ inline `script` carries the body (legacy + the
    /// majority of jobs).
    ///
    /// [`script_object_sha256`]: Self::script_object_sha256
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_object: Option<String>,
    /// Hex-encoded sha256 of the bytes the operator approved at
    /// Command-build time. Required when [`script_object`] is set;
    /// the agent treats a mismatch on fetch as "operator
    /// re-uploaded the script between exec submission and agent
    /// fire" and aborts the run rather than silently executing the
    /// new bytes. Pre-v0.43 wire omits this; the resolver path
    /// requires both fields to be `Some`.
    ///
    /// [`script_object`]: Self::script_object
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub script_object_sha256: Option<String>,
    pub timeout_secs: u64,
    pub jitter_secs: Option<u64>,
    /// Which (token, session) combination the agent should launch the
    /// child process under (v0.21). Defaults to [`RunAs::System`] for
    /// back-compat with pre-v0.21 backends that don't send this field.
    #[serde(default)]
    pub run_as: RunAs,
    /// Working directory for the spawned child (v0.21.1). `None` ⇒
    /// inherit the agent's cwd. Pre-v0.21.1 wire payloads omit this
    /// field and parse fine via `#[serde(default)]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Absolute time after which the agent should refuse to run
    /// this Command (v0.22). Set by the scheduler from
    /// `Schedule.starting_deadline` (humantime) measured against
    /// the cron tick time. `None` ⇒ no deadline, run whenever
    /// received (default for ad-hoc `kanade exec` + back-compat
    /// for pre-v0.22 wire). The agent stamps a synthetic
    /// `ExecResult { exit_code: 125, stderr: "skipped: deadline
    /// expired ..." }` when it skips, so the operator sees the
    /// outcome on the Results / Dashboard pages instead of silence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deadline_at: Option<DateTime<Utc>>,
    /// v0.26: Manifest-declared Layer 2 staleness policy
    /// (see SPEC.md §2.6.2). Forwarded from `Manifest.staleness` so
    /// the agent can evaluate it at fire time without re-fetching the
    /// Manifest from `BUCKET_JOBS`. Pre-v0.26 wire omits this and
    /// `#[serde(default)]` falls back to `Staleness::Cached`, matching
    /// pre-v0.26 behaviour (silently use cached KV values).
    #[serde(default)]
    pub staleness: Staleness,
    /// Issue #246: forwarded from `Manifest.emit` so the agent
    /// doesn't have to re-fetch the manifest at fire time. When
    /// `Some` and `EmitKind::Events`, the agent parses script
    /// stdout as NDJSON `ObsEvent` and publishes each line on
    /// `obs.<pc_id>`. Pre-#246 wire omits this; the `#[serde(default)]`
    /// fallback to `None` preserves prior behaviour (stdout flows
    /// to `ExecResult` unchanged).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub emit: Option<EmitConfig>,
    /// #290: forwarded from `Manifest.check` so the agent can build a
    /// KLP Health-tab [`Check`](crate::ipc::state::Check) from the
    /// job's stdout without re-fetching the Manifest. When `Some`, the
    /// agent reads the `status_field` / `detail_field` values out of
    /// the stdout JSON object after a successful run and caches the
    /// result into `StateSnapshot.checks`. Pre-#290 wire omits this;
    /// `#[serde(default)]` → `None` preserves prior behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub check: Option<CheckHint>,
    /// #219: forwarded from `Manifest.collect` so the agent can bundle
    /// the script's listed files without re-fetching the Manifest. When
    /// `Some`, the agent — after a successful run — reads the
    /// `files_field` path array out of the stdout JSON object, zips those
    /// files (capped at `max_size`), uploads the archive to
    /// `OBJECT_COLLECTIONS`, and records the key in
    /// [`ExecResult::collect_object`](super::ExecResult::collect_object).
    /// Pre-#219 wire omits this; `#[serde(default)]` → `None` preserves
    /// prior behaviour.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub collect: Option<CollectHint>,
    /// #418 Phase 4: lowered from `Schedule.on_failure.retry` by the
    /// command builders (backend `exec_manifest` + the agent's local
    /// scheduler). When `Some`, the agent re-runs the script
    /// in-process on a non-zero exit / timeout, up to `max` extra
    /// attempts with `backoff_secs` between them, before publishing
    /// the final outcome. `None` (default) ⇒ no retry, the historical
    /// behaviour and what ad-hoc `kanade run` / `kanade exec` use.
    /// Pre-Phase-4 wire omits this; `#[serde(default)]` → `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry: Option<RetrySpec>,
    /// Job-generic post-step hook lowered from `Manifest.finalize`. When
    /// `Some` and the main script exits cleanly, the agent runs this hook
    /// after the collect step (injecting `KANADE_COLLECT_RESULT` for a
    /// `collect:` job) so the operator can delete / move / notify.
    /// Best-effort — a finalize failure is logged, never published as the
    /// run's outcome. Pre-finalize wire omits this; `#[serde(default)]` →
    /// `None`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub finalize: Option<FinalizeCommand>,
}

/// Lowered, engine-vocabulary form of [`crate::manifest::FinalizeSpec`]
/// — the post-step hook stamped onto a [`Command`]. The operator-facing
/// humantime `timeout` is reduced to whole seconds at build time
/// (mirrors `timeout_secs`), and the manifest `ExecuteShell` to the wire
/// [`Shell`], so the agent's fire path does no parsing.
#[derive(Serialize, Deserialize, schemars::JsonSchema, Debug, Clone)]
pub struct FinalizeCommand {
    pub shell: Shell,
    /// Inline script body (inline-only in P1).
    pub script: String,
    pub timeout_secs: u64,
    #[serde(default)]
    pub run_as: RunAs,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// #965: for a `collect:` job, run this hook once per uploaded
    /// bundle (single-bundle `KANADE_COLLECT_RESULT`) as each bundle
    /// uploads, instead of once after the whole set — so an interrupted
    /// collect still cleans up the days it managed to ship. `false`
    /// (default, pre-#965 wire) keeps the one-call-after-all contract.
    #[serde(default)]
    pub on_each_bundle: bool,
}

/// Lowered, engine-vocabulary form of [`crate::manifest::Retry`] — a
/// fixed-backoff retry policy stamped onto a [`Command`]. The
/// operator-facing humantime `backoff` is reduced to whole seconds at
/// build time (mirrors how `jitter_secs` / `timeout_secs` are
/// pre-lowered) so the agent's fire path does no humantime parsing.
#[derive(Serialize, Deserialize, schemars::JsonSchema, Debug, Clone, Copy, PartialEq, Eq)]
pub struct RetrySpec {
    /// Max additional attempts after the first failure (1..=10,
    /// enforced by `Schedule::validate`).
    pub max: u32,
    /// Seconds slept between attempts.
    pub backoff_secs: u64,
}

#[derive(Serialize, Deserialize, schemars::JsonSchema, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Shell {
    /// Windows PowerShell 5.1 — the literal `powershell` on PATH. The
    /// agent stages the script to a temp `.ps1` and runs it via a
    /// UTF-8-console launcher (see `process.rs`).
    Powershell,
    /// `cmd.exe` — `cmd /C <script>` inline. Windows only.
    Cmd,
    /// POSIX shell — `sh -c <script>` inline. Linux/macOS. The agent
    /// spawns the literal `sh` on PATH; there is no per-OS gate, so a
    /// misdirected `sh` job to a host without `sh` fails at spawn.
    Sh,
    /// PowerShell 7 (cross-platform) — the literal `pwsh` on PATH.
    /// Distinct from [`Shell::Powershell`] (Windows PowerShell 5.1):
    /// reuses the same temp-`.ps1` launcher, but skips
    /// `-ExecutionPolicy Bypass` off Windows (no execution policy
    /// there).
    Pwsh,
}

/// **Token + session combination** the agent uses to spawn a job's
/// child process. Two orthogonal axes — *whose privileges* and *which
/// session* — collapse into three meaningful combinations:
///
/// | variant            | session                | privileges  | GUI |
/// |--------------------|------------------------|-------------|-----|
/// | `System` (default) | Session 0 (services)   | LocalSystem | ❌  |
/// | `User`             | active console session | logged-in user (UAC-filtered when admin) | ✅ |
/// | `SystemGui`        | active console session | LocalSystem | ✅  |
///
/// `SystemGui` is the "PsExec `-i -s`" pattern: the agent duplicates
/// its own SYSTEM token and rewrites `TokenSessionId` to the user's
/// console session, then launches with that hybrid token — useful
/// when an installer needs admin power *and* needs the user to see
/// its UI.
#[derive(
    Serialize, Deserialize, schemars::JsonSchema, Debug, Clone, Copy, PartialEq, Eq, Default,
)]
#[serde(rename_all = "snake_case")]
pub enum RunAs {
    /// LocalSystem privileges in Session 0. No GUI. Historical
    /// default — every pre-v0.21 job ran this way.
    #[default]
    System,
    /// The currently-logged-in console user's identity, in their
    /// session. Can write HKCU / %APPDATA% / show GUI to the user.
    /// Privileges are whatever the user has (admin users get the
    /// UAC-filtered limited token, not the elevated one).
    User,
    /// LocalSystem privileges in the user's session — admin power
    /// with GUI visibility. Niche but real (force-restart dialogs,
    /// admin installers with progress UI).
    SystemGui,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_command() -> Command {
        Command {
            id: "echo-test".into(),
            version: "1.0.0".into(),
            request_id: "req-1".into(),
            exec_id: Some("dep-1".into()),
            shell: Shell::Powershell,
            script: "echo hi".into(),
            script_object: None,
            script_object_sha256: None,
            timeout_secs: 30,
            bypass_local_limit: false,
            jitter_secs: Some(5),
            run_as: RunAs::System,
            cwd: None,
            deadline_at: None,
            staleness: Staleness::Cached,
            emit: None,
            check: None,
            collect: None,
            retry: None,
            finalize: None,
        }
    }

    #[test]
    fn shell_serialises_lowercase() {
        let json = serde_json::to_string(&Shell::Powershell).unwrap();
        assert_eq!(json, "\"powershell\"");
        let json = serde_json::to_string(&Shell::Cmd).unwrap();
        assert_eq!(json, "\"cmd\"");
        let json = serde_json::to_string(&Shell::Sh).unwrap();
        assert_eq!(json, "\"sh\"");
        let json = serde_json::to_string(&Shell::Pwsh).unwrap();
        assert_eq!(json, "\"pwsh\"");
        // Round-trip the new variants from the wire form.
        assert_eq!(serde_json::from_str::<Shell>("\"sh\"").unwrap(), Shell::Sh);
        assert_eq!(
            serde_json::from_str::<Shell>("\"pwsh\"").unwrap(),
            Shell::Pwsh
        );
    }

    #[test]
    fn run_as_serialises_snake_case() {
        for (mode, expected) in [
            (RunAs::System, "\"system\""),
            (RunAs::User, "\"user\""),
            (RunAs::SystemGui, "\"system_gui\""),
        ] {
            let json = serde_json::to_string(&mode).unwrap();
            assert_eq!(json, expected, "serialise {mode:?}");
            let back: RunAs = serde_json::from_str(expected).unwrap();
            assert_eq!(back, mode, "round-trip {expected}");
        }
    }

    #[test]
    fn run_as_defaults_to_system() {
        assert_eq!(RunAs::default(), RunAs::System);
    }

    #[test]
    fn command_round_trips_through_json() {
        let orig = sample_command();
        let json = serde_json::to_string(&orig).expect("encode");
        let decoded: Command = serde_json::from_str(&json).expect("decode");
        assert_eq!(decoded.id, orig.id);
        assert_eq!(decoded.version, orig.version);
        assert_eq!(decoded.request_id, orig.request_id);
        assert_eq!(decoded.exec_id, orig.exec_id);
        assert_eq!(decoded.shell, orig.shell);
        assert_eq!(decoded.script, orig.script);
        assert_eq!(decoded.timeout_secs, orig.timeout_secs);
        assert_eq!(decoded.jitter_secs, orig.jitter_secs);
        assert_eq!(decoded.run_as, orig.run_as);
    }

    #[test]
    fn command_round_trips_each_run_as_variant() {
        for mode in [RunAs::System, RunAs::User, RunAs::SystemGui] {
            let cmd = Command {
                run_as: mode,
                ..sample_command()
            };
            let json = serde_json::to_string(&cmd).unwrap();
            let back: Command = serde_json::from_str(&json).unwrap();
            assert_eq!(back.run_as, mode);
        }
    }

    #[test]
    fn command_accepts_missing_optional_fields() {
        let json = r#"{
          "id": "x",
          "version": "1.0.0",
          "request_id": "r",
          "shell": "cmd",
          "script": "echo",
          "timeout_secs": 5
        }"#;
        let cmd: Command = serde_json::from_str(json).expect("decode");
        assert!(cmd.exec_id.is_none());
        assert!(cmd.jitter_secs.is_none());
        assert_eq!(cmd.shell, Shell::Cmd);
        // Pre-v0.21 wire payloads omit run_as → falls back to System.
        assert_eq!(cmd.run_as, RunAs::System);
        // Pre-v0.21.1 omit cwd → None (= inherit agent cwd).
        assert!(cmd.cwd.is_none());
        // Pre-v0.22 omit deadline_at → None (= no deadline).
        assert!(cmd.deadline_at.is_none());
        // Pre-v0.43 wire omits both script_object fields — agent
        // falls back to the inline `script` body.
        assert!(cmd.script_object.is_none());
        assert!(cmd.script_object_sha256.is_none());
    }

    #[test]
    fn command_round_trips_script_object_fields() {
        // kanadehq/kanade#210: backend builds Commands carrying an
        // OBJECT_SCRIPTS reference + the operator-approved digest;
        // agent resolves on fetch. Both fields must survive a JSON
        // round-trip with the same shape.
        let cmd = Command {
            script: String::new(),
            script_object: Some("cleanup-disk-temp/1.0.1".into()),
            script_object_sha256: Some(
                "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef".into(),
            ),
            ..sample_command()
        };
        let json = serde_json::to_string(&cmd).expect("encode");
        let back: Command = serde_json::from_str(&json).expect("decode");
        assert_eq!(back.script, "");
        assert_eq!(
            back.script_object.as_deref(),
            Some("cleanup-disk-temp/1.0.1")
        );
        assert_eq!(
            back.script_object_sha256.as_deref(),
            Some("deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef")
        );
    }

    #[test]
    fn command_decodes_legacy_job_id_field_as_exec_id() {
        // v0.29 / Issue #19: Commands sitting in STREAM_EXEC published
        // by a pre-v0.29 backend still carry the field named `job_id`.
        // The `#[serde(alias = "job_id")]` on `exec_id` keeps them
        // decodable through the upgrade window so the agent doesn't
        // start dropping replays on first boot of a new binary.
        let json = r#"{
          "id": "x",
          "version": "1.0.0",
          "request_id": "r",
          "job_id": "legacy-exec-uuid",
          "shell": "powershell",
          "script": "echo",
          "timeout_secs": 5
        }"#;
        let cmd: Command = serde_json::from_str(json).expect("decode legacy");
        assert_eq!(cmd.exec_id.as_deref(), Some("legacy-exec-uuid"));
    }

    #[test]
    fn command_deadline_at_round_trips() {
        use chrono::TimeZone;
        let deadline = Utc.with_ymd_and_hms(2026, 5, 18, 9, 30, 0).unwrap();
        let cmd = Command {
            deadline_at: Some(deadline),
            ..sample_command()
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(back.deadline_at, Some(deadline));
    }

    #[test]
    fn command_retry_round_trips() {
        // #418 Phase 4: a stamped retry policy must survive the wire
        // so the agent can apply it on a live publish or a STREAM_EXEC
        // replay.
        let cmd = Command {
            retry: Some(RetrySpec {
                max: 3,
                backoff_secs: 600,
            }),
            ..sample_command()
        };
        let json = serde_json::to_string(&cmd).unwrap();
        let back: Command = serde_json::from_str(&json).unwrap();
        assert_eq!(
            back.retry,
            Some(RetrySpec {
                max: 3,
                backoff_secs: 600
            })
        );
    }

    #[test]
    fn command_omits_retry_when_absent() {
        // skip_serializing_if keeps the field off the wire for the
        // common (no-retry) case, and pre-Phase-4 payloads that never
        // had it still decode (serde default → None).
        let json = serde_json::to_string(&sample_command()).unwrap();
        assert!(
            !json.contains("retry"),
            "retry must not appear when None: {json}"
        );
    }

    #[test]
    fn command_collect_round_trips_and_omits_when_absent() {
        // #219: `collect` is off the wire when None (skip_serializing_if),
        // so pre-#219 readers don't trip over it...
        let json = serde_json::to_string(&sample_command()).unwrap();
        assert!(
            !json.contains("collect"),
            "collect must be absent when None: {json}"
        );
        // ...and a forwarded CollectHint survives the round-trip.
        let cmd = Command {
            collect: Some(CollectHint {
                name: "diag".into(),
                description: Some("logs".into()),
                max_size: Some("50MB".into()),
                files_field: "files".into(),
            }),
            ..sample_command()
        };
        let back: Command = serde_json::from_str(&serde_json::to_string(&cmd).unwrap()).unwrap();
        let c = back.collect.expect("collect survived round-trip");
        assert_eq!(c.name, "diag");
        assert_eq!(c.max_size.as_deref(), Some("50MB"));
        assert_eq!(c.files_field, "files");
    }

    #[test]
    fn command_finalize_round_trips_and_omits_when_absent() {
        // Off the wire when None (skip_serializing_if), so pre-finalize
        // readers don't trip over it...
        let json = serde_json::to_string(&sample_command()).unwrap();
        assert!(
            !json.contains("finalize"),
            "finalize must be absent when None: {json}"
        );
        // ...and a forwarded FinalizeCommand survives the round-trip.
        let cmd = Command {
            finalize: Some(FinalizeCommand {
                shell: Shell::Powershell,
                script: "Remove-Item $env:FILE".into(),
                timeout_secs: 30,
                run_as: RunAs::System,
                cwd: None,
                on_each_bundle: false,
            }),
            ..sample_command()
        };
        let back: Command = serde_json::from_str(&serde_json::to_string(&cmd).unwrap()).unwrap();
        let f = back.finalize.expect("finalize survived round-trip");
        assert_eq!(f.shell, Shell::Powershell);
        assert_eq!(f.script, "Remove-Item $env:FILE");
        assert_eq!(f.timeout_secs, 30);
        assert_eq!(f.run_as, RunAs::System);
    }
}
