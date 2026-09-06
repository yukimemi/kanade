mod agent_watchdog;
mod api;
mod audit;
mod auth;
mod cleanup;
mod command_publisher;
mod controller;
mod http_error;
mod login_throttle;
mod mail;
mod mfa;
mod projector;
mod scheduler;
mod web;

#[cfg(target_os = "windows")]
mod service;

use std::future::Future;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use anyhow::{Context, Result};
use clap::Parser;
use kanade_shared::config::{LogSection, load_backend_config};
use kanade_shared::default_paths;
use sqlx::sqlite::{SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous};
use tokio::net::TcpListener;
use tower_http::compression::CompressionLayer;
use tower_http::trace::TraceLayer;
use tracing::{error, info, warn};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

/// Spawn a background projector task that retries with capped
/// exponential backoff on failure instead of permanently exiting.
///
/// Issue #1442: every projector previously did `if let Err(e) =
/// X::run(...).await { error!(...); }` inside a bare `tokio::spawn` —
/// a single startup failure (e.g. a JetStream consumer that can't be
/// created because the broker's own consumer metadata is corrupted)
/// permanently killed that projector for the rest of the process's
/// lifetime, with no retry and no restart. For the results projector
/// specifically this meant zero ExecResults were ever ingested again
/// until the next binary restart — silently, since the only symptom
/// was a slow buildup of reaped executions elsewhere.
///
/// `%e` (anyhow's `Display`) also only prints the top-level `.context()`
/// message, not the underlying cause — logging `{e:#}` instead surfaces
/// the full chain (e.g. the actual JetStream/NATS error), which is what
/// made this failure mode take manual JetStream API probing to diagnose
/// instead of being visible from the log alone.
///
/// `make` is called again on every retry so each attempt gets fresh
/// clones of whatever handles the projector needs (JetStream context,
/// pool, caches, ...) — a projector's `run` future is not reusable.
///
/// PR #1443 review: `run` returning `Ok(())` is NOT treated as a clean
/// shutdown — every supervised projector's `run` is a `while let
/// Some(msg) = messages.next().await { ... }` loop with no other
/// return path, so `Ok(())` only happens when the underlying
/// subscription/consumer stream itself ends (e.g. broker restart,
/// consumer deleted out from under it). Breaking out of the retry
/// loop there would silently reproduce this issue's exact failure
/// mode, just triggered by a stream end instead of a create error.
/// So both arms retry; only the log level and backoff-reset
/// eligibility differ.
fn spawn_retrying_projector<F, Fut>(name: &'static str, mut make: F)
where
    F: FnMut() -> Fut + Send + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    const INITIAL_BACKOFF: std::time::Duration = std::time::Duration::from_secs(1);
    const MAX_BACKOFF: std::time::Duration = std::time::Duration::from_secs(60);
    // A run that stays up at least this long before failing again is
    // treated as a fresh problem rather than continued instability —
    // otherwise a projector that flakes for a few minutes at broker
    // boot (ratcheting backoff up towards MAX_BACKOFF) and then runs
    // cleanly for weeks would inherit that elevated backoff on its
    // next, unrelated failure instead of retrying quickly.
    const STABLE_AFTER: std::time::Duration = std::time::Duration::from_secs(60);
    tokio::spawn(async move {
        let mut backoff = INITIAL_BACKOFF;
        loop {
            let started = std::time::Instant::now();
            match make().await {
                Ok(()) => warn!(
                    projector = name,
                    retry_in_secs = backoff.as_secs(),
                    "projector stream ended — reconnecting",
                ),
                Err(e) => error!(
                    error = %format!("{e:#}"),
                    projector = name,
                    retry_in_secs = backoff.as_secs(),
                    "projector exited — retrying",
                ),
            }
            if started.elapsed() >= STABLE_AFTER {
                backoff = INITIAL_BACKOFF;
            }
            tokio::time::sleep(backoff).await;
            backoff = next_backoff(backoff, MAX_BACKOFF);
        }
    });
}

/// Doubling backoff with a hard cap. Mirrors
/// `kanade_agent::nats_retry::next_backoff`'s shape (same doubling +
/// cap contract, no jitter here since this backs off a single
/// long-lived background task rather than a fleet of agents that
/// could otherwise hit the broker in lockstep).
fn next_backoff(current: std::time::Duration, cap: std::time::Duration) -> std::time::Duration {
    current.saturating_mul(2).min(cap)
}

#[cfg(test)]
mod spawn_retrying_projector_tests {
    use super::next_backoff;
    use std::time::Duration;

    #[test]
    fn next_backoff_doubles_then_caps() {
        let cap = Duration::from_secs(60);
        let mut backoff = Duration::from_secs(1);
        let mut seen = Vec::new();
        for _ in 0..8 {
            backoff = next_backoff(backoff, cap);
            seen.push(backoff.as_secs());
        }
        assert_eq!(seen, vec![2, 4, 8, 16, 32, 60, 60, 60]);
    }
}

#[derive(Parser, Debug)]
#[command(
    name = "kanade-backend",
    about = "kanade backend (axum + SQLite projector)",
    version
)]
struct Cli {
    /// Path to backend.toml. When unset, the backend looks at
    /// $KANADE_BACKEND_CONFIG, then `<config_dir>/backend.toml` (see
    /// kanade_shared::default_paths::config_dir).
    #[arg(long, global = true)]
    config: Option<PathBuf>,

    #[command(subcommand)]
    command: Option<Command>,
}

/// Operator subcommands. Absent = run the backend service (the default,
/// and what the Windows SCM invokes via the installed binPath).
#[derive(clap::Subcommand, Debug)]
enum Command {
    /// Print the fully-resolved `[db] sqlite_path` (after teravars
    /// rendering — `env()`, `is_windows()`, `vars.*` self-reference) to
    /// stdout and exit. `deploy-backend.ps1 -WipeDb` calls this so the
    /// wipe targets the exact file the backend opens, instead of
    /// re-deriving the path with a divergent default that silently
    /// misses a templated / non-default (e.g. `E:\…`) location.
    ResolveDbPath,
    /// #582 Phase 4: exit non-zero if `version` is quarantined by the
    /// boot sentinel (it crash-looped on a prior boot and was rolled
    /// back). The backend deploy script calls this BEFORE swapping a
    /// new binary in, so a known-bad version is refused at deploy time
    /// instead of crash-looping the service again. Exit 0 = safe to
    /// deploy, exit 3 = quarantined.
    CheckQuarantine {
        /// The version about to be deployed.
        version: String,
    },
    /// #582 Phase 4: arm the boot sentinel right before a deploy swaps
    /// the binary in. Snapshots the CURRENTLY-INSTALLED (outgoing,
    /// known-good) exe to `<exe>.last-good` and writes a sentinel for
    /// `new_version`, so if the new binary crash-loops on boot the
    /// service auto-rolls-back to the snapshot. Without this the deploy
    /// path never arms the sentinel and `check_on_boot` is a no-op
    /// (nothing gets counted or quarantined). The deploy script runs the
    /// STAGED (new) binary — which always carries this subcommand — and
    /// points it at the installed exe path that is about to be
    /// overwritten.
    ArmForSwap {
        /// The version about to be deployed (the staged/new binary).
        new_version: String,
        /// The installed exe path the service runs from. Its current
        /// (outgoing) contents are snapshotted to `<exe>.last-good`
        /// before the deploy overwrites it; `<exe>.last-good` also fixes
        /// where `check_on_boot` looks for the rollback target.
        installed_exe: PathBuf,
    },
    /// Drop the projector SQLite DB so it re-derives from JetStream
    /// replay on next boot, WITHOUT losing the durable `users` table.
    /// `deploy-backend.ps1 -WipeDb` calls this instead of `rm
    /// backend.db`: auth accounts live ONLY in SQLite (no NATS stream
    /// carries them), so a plain file delete locks every operator out
    /// until a bootstrap re-seed. This snapshots `users`, deletes the
    /// DB (+ `-wal`/`-shm`), re-creates the schema via migrations, then
    /// restores the accounts. Resolves the DB path the same way the
    /// service does (the global `--config`), so it targets the exact
    /// file the backend opens.
    WipeProjector,
    /// #1165: mint this backend's command-signing keypair.
    ///
    /// Runs **here**, on the backend host, rather than in the `kanade` CLI:
    /// the private key is born where it will live and never crosses a wire or
    /// an operator's shell history. The CLI deliberately holds no signing key
    /// — that is the property the whole design rests on.
    ///
    /// Writes the private key to `HKLM\SOFTWARE\kanade\backend` (the key
    /// `deploy-backend.ps1` already hardens to SYSTEM + Administrators) and
    /// prints only the public half, plus the ready-to-distribute keyring
    /// entry for agents.
    #[command(name = "command-key-generate")]
    KeyGenerate {
        /// Replace an existing signing key. Without this, an existing key is
        /// left alone — silently replacing the fleet's signer would make every
        /// agent report an unknown key at once.
        #[arg(long)]
        rotate: bool,
        /// Key id agents will match against. Defaults to a date-stamped one,
        /// because a rotation needs the old and new to coexist on one ring.
        #[arg(long)]
        kid: Option<String>,
    },
}

/// Top-level entry point.
///
/// Mirrors kanade-agent's main: on Windows we probe the Service
/// Control Manager first and run as a real service if SCM is
/// driving us; otherwise we fall through to console mode. Non-
/// Windows targets always run in console mode.
fn main() -> Result<()> {
    // Operator subcommands short-circuit BEFORE the Windows service
    // probe — they're console-invoked (e.g. by deploy-backend.ps1) and
    // must print + exit, not try to dispatch as a service. SCM starts
    // the service with no subcommand, so the default path is unchanged.
    let cli = Cli::parse();
    if let Some(cmd) = &cli.command {
        return match cmd {
            Command::ResolveDbPath => print_resolved_db_path(cli.config.as_deref()),
            Command::CheckQuarantine { version } => check_quarantine(version),
            Command::ArmForSwap {
                new_version,
                installed_exe,
            } => arm_for_swap(new_version, installed_exe),
            Command::WipeProjector => wipe_projector(cli.config.as_deref()),
            Command::KeyGenerate { rotate, kid } => command_key_generate(*rotate, kid.as_deref()),
        };
    }

    // #582 Phase 4: boot sentinel on the SERVICE path only (subcommands
    // short-circuited above) — before the service dispatcher, config,
    // DB, or JetStream bootstrap, so a binary that crash-loops on boot
    // (exactly the #573 regression that caused the 2026-06-11 outage)
    // is rolled back to last-good instead of looping forever.
    //
    // CAVEAT: the backend, unlike the agent, has a SQLite DB. If the
    // failed release also ran forward migrations, rolling back to an
    // older binary can hit "migration applied but missing in source"
    // (the 0.43.48 rollback block during the incident) — last-good then
    // also fails to boot. The sentinel is still strictly better than a
    // crash loop (it tries, quarantines, and logs CRITICAL for the
    // operator); pairing it with a deploy-time DB snapshot is tracked
    // as a follow-up in #582.
    // Resolve the exe once. A failure here must NOT silently skip the
    // rollback decision (that would let a crash-looping binary boot
    // unchecked) — surface it. Tracing isn't up yet on this path, so the
    // note goes to stderr like the rollback message below.
    match std::env::current_exe() {
        Ok(exe) => {
            use kanade_shared::boot_sentinel::{BootDecision, BootSentinel, DEFAULT_MAX_ATTEMPTS};
            let sentinel =
                BootSentinel::new(&default_paths::data_dir(), exe, env!("CARGO_PKG_VERSION"));
            if let BootDecision::RolledBack { from } = sentinel.check_on_boot(DEFAULT_MAX_ATTEMPTS)
            {
                eprintln!(
                    "boot sentinel: {from} crash-looped on boot — rolled back to last-good; \
                     exiting (1) for restart"
                );
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!(
                "boot sentinel: current_exe() failed ({e}) — skipping crash-loop rollback \
                 check this boot; proceeding unguarded"
            );
        }
    }

    #[cfg(target_os = "windows")]
    {
        match service::try_run_as_service() {
            Ok(()) => return Ok(()),
            Err(e) if service::is_not_under_scm(&e) => {
                // Not started by SCM — fall through to console mode.
            }
            Err(e) => return Err(anyhow::anyhow!("service dispatcher failed: {e}")),
        }
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;
    runtime.block_on(run_backend())
}

/// `resolve-db-path` subcommand: load the config exactly as the running
/// backend does and print the rendered `[db] sqlite_path` to stdout.
/// Synchronous + deliberately NO tracing init — stdout must carry only
/// the path so callers (deploy-backend.ps1 -WipeDb) can consume it
/// verbatim; any failure returns `Err`, which Rust prints to stderr and
/// exits non-zero, and the caller refuses to wipe rather than guessing.
fn print_resolved_db_path(config: Option<&Path>) -> Result<()> {
    let cfg_path = default_paths::find_config(config, "KANADE_BACKEND_CONFIG", "backend.toml")?;
    let cfg =
        load_backend_config(&cfg_path).with_context(|| format!("load config from {cfg_path:?}"))?;
    println!("{}", cfg.db.sqlite_path);
    Ok(())
}

/// One row of the durable `users` table, captured verbatim so a wipe can
/// restore accounts (incl. their original timestamps) byte-for-byte.
/// Timestamps are read as TEXT to round-trip them unchanged.
struct UserRow {
    username: String,
    password_hash: String,
    role: String,
    disabled: i64,
    must_change_pw: i64,
    /// #770 contact email. `None` for accounts captured from a pre-email
    /// DB (the column didn't exist yet) — preserved across the wipe so a
    /// migration-driven wipe doesn't drop everyone's address.
    email: Option<String>,
    /// #1008 page allow-list (raw JSON TEXT). `None` = unrestricted, or an
    /// account captured from a pre-`allowed_features` DB — preserved across
    /// the wipe so a migration-driven wipe doesn't silently reset everyone's
    /// page restriction back to unrestricted.
    allowed_features: Option<String>,
    /// #1008 Phase 3 permission-group membership. `None` = no group (or an
    /// account captured from a pre-`permission_group` DB) — preserved so a
    /// wipe doesn't drop everyone's group assignment.
    permission_group: Option<String>,
    /// #1192 TOTP secret (base32). `None` = MFA off, or an account captured
    /// from a pre-`totp_secret` DB — preserved across the wipe so a
    /// migration-driven wipe doesn't silently disable MFA for everyone.
    totp_secret: Option<String>,
    created_at: String,
    updated_at: String,
}

/// One row of the durable `permission_groups` table (#1008 Phase 3), captured
/// so a wipe can restore the groups accounts reference. Like `users`, this
/// table is SQLite-only (not projector-derived from NATS), so a blind wipe
/// would lose it.
struct PermGroupRow {
    name: String,
    features: String,
    created_at: String,
    updated_at: String,
}

/// Decide the `kid` for a generate run, and refuse the two ways it can wreck
/// a fleet.
///
/// Pure, and separate from the registry, because `read_hklm_value` returns
/// `None` on non-Windows — a test that reached through the registry would
/// assert nothing at all on CI, which is where these guards most need to be
/// held. Same lesson as extracting the transition rule in #1171: the decision
/// and the I/O have to come apart before the decision can be tested.
fn resolve_kid(
    key_exists: bool,
    existing_kid: Option<&str>,
    rotate: bool,
    requested: Option<&str>,
    today: &str,
) -> Result<String, String> {
    if key_exists && !rotate {
        return Err(format!(
            "a command-signing key already exists at HKLM\\{}\\{}. Pass --rotate to replace \
             it — and note that agents keep accepting the old key until you retire it from \
             their keyring, which is what makes a rotation safe.",
            kanade_shared::signing::REG_BACKEND_SUBKEY,
            kanade_shared::signing::REG_SIGNING_KEY
        ));
    }

    let kid = requested
        .map(str::to_owned)
        // Date-stamped so a rotation produces a distinguishable second entry:
        // two keys must coexist on one ring for the window in which some
        // agents have the new one and some do not.
        .unwrap_or_else(|| format!("backend-{today}"));

    // Rotating twice in a day would otherwise mint a second, different key
    // under an id agents already trust — every agent would then hold one
    // public key under that id and receive signatures from another, reporting
    // a bad signature fleet-wide and looking exactly like a forgery.
    if rotate && existing_kid == Some(kid.as_str()) {
        return Err(format!(
            "the new key would reuse the id {kid}, which already names the current key. Two \
             different keys must never share an id — agents match signatures to a key by it. \
             Pass an explicit --kid."
        ));
    }

    Ok(kid)
}

/// Mint the backend's command-signing keypair (#1165).
///
/// The private key goes straight into the registry and is never printed —
/// stdout here is expected to be pasted into a terminal, a ticket, or a chat
/// window, and a secret that reaches any of those is no longer a secret.
/// What is printed is the public key and the exact keyring entry agents need,
/// so the operator distributes something correct by construction rather than
/// assembling JSON by hand that `parse_keyring` may reject — a malformed entry
/// takes the whole ring with it.
fn command_key_generate(rotate: bool, kid: Option<&str>) -> Result<()> {
    use kanade_shared::signing;

    let existing = kanade_shared::secrets::read_hklm_value(
        signing::REG_BACKEND_SUBKEY,
        signing::REG_SIGNING_KEY,
    );
    let existing_kid = kanade_shared::secrets::read_hklm_value(
        signing::REG_BACKEND_SUBKEY,
        signing::REG_SIGNING_KID,
    );
    let kid = resolve_kid(
        existing.is_some(),
        existing_kid.as_deref(),
        rotate,
        kid,
        &chrono::Utc::now().format("%Y%m%d").to_string(),
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    let key = signing::generate_keypair().map_err(|e| anyhow::anyhow!(e))?;
    kanade_shared::secrets::write_hklm_value(
        signing::REG_BACKEND_SUBKEY,
        signing::REG_SIGNING_KEY,
        &signing::encode_secret(&key),
    )
    .map_err(|e| anyhow::anyhow!(e))?;
    // The kid is persisted beside the key, not merely printed. The signing
    // path needs it to fill `Kanade-Sig-Kid`, and it is the operator's choice
    // — re-deriving a date at signing time would produce a different id than
    // the one distributed to agents whenever the key is generated on one day
    // and first used on another.
    kanade_shared::secrets::write_hklm_value(
        signing::REG_BACKEND_SUBKEY,
        signing::REG_SIGNING_KID,
        &kid,
    )
    .map_err(|e| anyhow::anyhow!(e))?;

    let entry = signing::keyring_entry(&kid, &key.verifying_key(), "backend");
    println!(
        "Wrote the private key to HKLM\\{}\\{} (SYSTEM + Administrators only, inherited from the existing key's ACL).",
        signing::REG_BACKEND_SUBKEY,
        signing::REG_SIGNING_KEY
    );
    println!();
    println!("kid:        {kid}");
    println!(
        "public key: {}",
        signing::encode_public(&key.verifying_key())
    );
    // Printed because it is the value an operator matches against, not one they
    // transcribe: it is what a correctly provisioned agent reports in
    // `command_keys`, so a host listing this kid with any other fingerprint
    // holds the wrong key and will refuse every command once enforcement is on
    // (#1229). Deriving it here rather than by hand keeps the fleet check
    // honest — a fingerprint computed from the same mistyped paste that wrote
    // the ring would agree with itself.
    println!(
        "identity:   {kid}:{}",
        signing::fingerprint(&key.verifying_key())
    );
    println!();
    println!("Add this entry to every agent's HKLM\\SOFTWARE\\kanade\\agent\\CommandKeys array:");
    println!("{}", serde_json::to_string_pretty(&entry)?);
    println!();
    // Names both outcomes because this subcommand serves both cases: a
    // first-time mint leaves agents holding nothing (`unprovisioned`), a
    // rotation leaves them holding the previous key (`unknown_key`). Telling a
    // first-time operator to watch for the rotation alarm sends them looking
    // for a signal that will not appear.
    println!(
        "Distribute it to the whole fleet BEFORE the backend starts signing. An agent holding \
         no keys yet reports command_signature_unprovisioned; one mid-rotation, holding the \
         previous key but not this one, reports command_signature_unknown_key — the signal \
         that means a rotation went wrong. Signing first would raise one of those on every \
         machine at once and teach everyone to ignore it."
    );
    Ok(())
}

/// `wipe-projector` subcommand: drop the projector DB so it re-derives
/// from JetStream replay, preserving the durable `users` table.
///
/// Why a dedicated subcommand instead of `rm backend.db` in the deploy
/// script: of all the projector DB's tables, only `users` and
/// `executions` are NOT sourced from a NATS stream — everything else
/// (audit_log, notification_acks, execution_results, agents, perf
/// samples, obs_events, inventory_*, check_status, the explode tables)
/// re-projects on replay. A blind file delete therefore takes the auth
/// accounts with it and locks every operator out until a bootstrap
/// re-seed (the lockout that motivated this).
///
/// `executions` is the OTHER durable table but is deliberately NOT
/// preserved: the results projector bumps its `success_count` /
/// `failure_count` *incrementally* (an `UPDATE ... SET success_count =
/// success_count + delta`), so keeping a row across a wipe+replay would
/// double-count, and faithfully rebuilding it would mean reconstructing
/// the exec-lifecycle reaping state too. Losing run history is
/// acceptable collateral; an auth lockout is not.
fn wipe_projector(config: Option<&Path>) -> Result<()> {
    let cfg_path = default_paths::find_config(config, "KANADE_BACKEND_CONFIG", "backend.toml")?;
    let cfg =
        load_backend_config(&cfg_path).with_context(|| format!("load config from {cfg_path:?}"))?;
    let db_path = cfg.db.sqlite_path.clone();

    // A current-thread runtime is enough — the work is one short, serial
    // sequence of sqlite calls, no concurrency. The default service path
    // builds a multi-thread runtime; this subcommand must not.
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build current-thread runtime")?;
    let (users, groups) = runtime.block_on(wipe_projector_at(&db_path))?;
    eprintln!(
        "wipe-projector: wiped projector DB at {db_path}; preserved {users} user account(s) and {groups} permission group(s)"
    );
    Ok(())
}

/// Core of `wipe-projector`, split out so it can be unit-tested against a
/// throwaway DB path: snapshot durable tables (`users` + `permission_groups`)
/// → delete the DB + sidecars → re-create the schema via migrations → restore
/// them. Returns `(accounts, groups)` restored.
async fn wipe_projector_at(db_path: &str) -> Result<(usize, usize)> {
    let (users, groups) = snapshot_durable(db_path)
        .await
        .context("snapshot durable tables")?;
    remove_db_files(db_path).context("remove projector DB files")?;

    // Re-create with the SAME pragmas the service uses (WAL etc.) so the
    // sidecars it leaves match what the backend expects on next open.
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{db_path}"))
        .with_context(|| format!("parse sqlite path {db_path}"))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .context("open fresh sqlite pool")?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("run migrations on fresh DB")?;
    // Restore groups first, then users — no FK is enforced (the pool doesn't
    // run with `PRAGMA foreign_keys = ON`), but this keeps a member's
    // `permission_group` pointing at an already-present group.
    let groups_restored = restore_permission_groups(&pool, &groups)
        .await
        .context("restore permission groups")?;
    let users_restored = restore_users(&pool, &users)
        .await
        .context("restore users")?;
    pool.close().await;
    Ok((users_restored, groups_restored))
}

/// Read every durable (SQLite-only, not projector-derived) row worth
/// preserving across a wipe: `users` **and** `permission_groups` (#1008
/// Phase 3), from a single read-only open of the DB. Tolerates a missing DB
/// file (fresh box) and missing tables (older / partially-migrated DB) by
/// returning an empty snapshot — both mean "nothing to preserve", not an error.
async fn snapshot_durable(db_path: &str) -> Result<(Vec<UserRow>, Vec<PermGroupRow>)> {
    if !Path::new(db_path).exists() {
        return Ok((Vec::new(), Vec::new()));
    }
    // Open read-only — we only read here, and the file is about to be
    // deleted; no need to create or migrate it.
    let opts = SqliteConnectOptions::from_str(&format!("sqlite://{db_path}"))
        .with_context(|| format!("parse sqlite path {db_path}"))?
        .read_only(true)
        .busy_timeout(std::time::Duration::from_secs(30));
    // The file EXISTS but we can't open it: do NOT swallow this and
    // proceed to wipe with an empty snapshot — a transient lock (a still-
    // running backend, a stray SQLite client, an antivirus scan) would
    // then cause silent account loss and re-lock the operator out, the
    // exact failure this code exists to prevent. Abort instead, so the
    // wipe is re-runnable once the DB is unlocked. (A genuinely corrupt
    // DB the operator wants to discard can be deleted by hand first.)
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(opts)
        .await
        .with_context(|| {
            format!(
                "open existing projector DB at {db_path} to preserve accounts — refusing to wipe \
                 rather than risk silent account loss. Stop the service and close any SQLite \
                 client holding it open, then re-run (or, if the DB is corrupt and you accept \
                 losing accounts, delete it by hand first)."
            )
        })?;

    let has_users: Option<String> =
        sqlx::query_scalar("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            .fetch_optional(&pool)
            .await
            .context("probe for users table")?;
    if has_users.is_none() {
        pool.close().await;
        return Ok((Vec::new(), Vec::new()));
    }

    // The `email` (#770) and `allowed_features` (#1008) columns may be
    // absent in a pre-migration DB being wiped to upgrade. Probe for each and
    // `CAST(NULL AS TEXT)` when missing, so a single row shape works for both
    // old and new schemas.
    let column_exists = |col: &'static str| {
        let pool = pool.clone();
        async move {
            sqlx::query_scalar::<_, String>(
                "SELECT name FROM pragma_table_info('users') WHERE name = ?",
            )
            .bind(col)
            .fetch_optional(&pool)
            .await
            .with_context(|| format!("probe for users.{col} column"))
            .map(|o| o.is_some())
        }
    };
    let has_email = column_exists("email").await?;
    let has_allowed = column_exists("allowed_features").await?;
    let has_group = column_exists("permission_group").await?;
    let has_totp = column_exists("totp_secret").await?;
    let email_expr = if has_email {
        "email"
    } else {
        "CAST(NULL AS TEXT) AS email"
    };
    let allowed_expr = if has_allowed {
        "allowed_features"
    } else {
        "CAST(NULL AS TEXT) AS allowed_features"
    };
    let group_expr = if has_group {
        "permission_group"
    } else {
        "CAST(NULL AS TEXT) AS permission_group"
    };
    let totp_expr = if has_totp {
        "totp_secret"
    } else {
        "CAST(NULL AS TEXT) AS totp_secret"
    };
    // Composed only from hardcoded column literals above (the `*_expr`
    // branches are static strings, no user input), so it's injection-safe;
    // `AssertSqlSafe` is required because the composed string isn't `'static`.
    let select = format!(
        "SELECT username, password_hash, role, disabled, must_change_pw, created_at, updated_at, {email_expr}, {allowed_expr}, {group_expr}, {totp_expr} FROM users"
    );

    let rows = sqlx::query_as::<
        _,
        (
            String,
            String,
            String,
            i64,
            i64,
            String,
            String,
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
        ),
    >(sqlx::AssertSqlSafe(select))
    .fetch_all(&pool)
    .await
    .context("select users")?;

    let users: Vec<UserRow> = rows
        .into_iter()
        .map(
            |(
                username,
                password_hash,
                role,
                disabled,
                must_change_pw,
                created_at,
                updated_at,
                email,
                allowed_features,
                permission_group,
                totp_secret,
            )| {
                UserRow {
                    username,
                    password_hash,
                    role,
                    disabled,
                    must_change_pw,
                    email,
                    allowed_features,
                    permission_group,
                    totp_secret,
                    created_at,
                    updated_at,
                }
            },
        )
        .collect();

    // Same read-only session captures the groups accounts reference.
    let groups = snapshot_permission_groups(&pool).await?;
    pool.close().await;
    Ok((users, groups))
}

/// Read every `permission_groups` row (#1008 Phase 3) from an existing
/// projector DB. Tolerates a missing table (older DB) by returning an empty
/// snapshot. `pool` is an already-open read-only handle to the DB.
async fn snapshot_permission_groups(pool: &sqlx::SqlitePool) -> Result<Vec<PermGroupRow>> {
    let has_table: Option<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='permission_groups'",
    )
    .fetch_optional(pool)
    .await
    .context("probe for permission_groups table")?;
    if has_table.is_none() {
        return Ok(Vec::new());
    }
    let rows = sqlx::query_as::<_, (String, String, String, String)>(
        "SELECT name, features, created_at, updated_at FROM permission_groups",
    )
    .fetch_all(pool)
    .await
    .context("select permission_groups")?;
    Ok(rows
        .into_iter()
        .map(|(name, features, created_at, updated_at)| PermGroupRow {
            name,
            features,
            created_at,
            updated_at,
        })
        .collect())
}

/// Re-insert snapshotted permission groups into a freshly-migrated DB,
/// preserving their original timestamps. Same single-transaction discipline
/// as [`restore_users`].
async fn restore_permission_groups(
    pool: &sqlx::SqlitePool,
    groups: &[PermGroupRow],
) -> Result<usize> {
    let mut tx = pool.begin().await.context("begin group restore")?;
    for g in groups {
        sqlx::query(
            "INSERT INTO permission_groups (name, features, created_at, updated_at) \
             VALUES (?, ?, ?, ?)",
        )
        .bind(&g.name)
        .bind(&g.features)
        .bind(&g.created_at)
        .bind(&g.updated_at)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("restore group {}", g.name))?;
    }
    tx.commit().await.context("commit group restore")?;
    Ok(groups.len())
}

/// Re-insert the snapshotted accounts into a freshly-migrated DB,
/// preserving their original timestamps. Returns how many were restored.
///
/// All inserts run in a single transaction: a mid-restore failure (a
/// constraint violation, or a schema-incompatible column from a squash
/// migration) rolls the whole thing back rather than committing a
/// partial set and silently dropping some accounts. The error then
/// propagates and aborts the deploy so the operator sees it.
async fn restore_users(pool: &sqlx::SqlitePool, users: &[UserRow]) -> Result<usize> {
    let mut tx = pool.begin().await.context("begin restore transaction")?;
    for u in users {
        sqlx::query(
            "INSERT INTO users \
             (username, password_hash, role, disabled, must_change_pw, created_at, updated_at, email, allowed_features, permission_group, totp_secret) \
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(&u.username)
        .bind(&u.password_hash)
        .bind(&u.role)
        .bind(u.disabled)
        .bind(u.must_change_pw)
        .bind(&u.created_at)
        .bind(&u.updated_at)
        .bind(&u.email)
        .bind(&u.allowed_features)
        .bind(&u.permission_group)
        .bind(&u.totp_secret)
        .execute(&mut *tx)
        .await
        .with_context(|| format!("restore user {}", u.username))?;
    }
    tx.commit().await.context("commit restore transaction")?;
    Ok(users.len())
}

/// Delete the SQLite DB and its WAL/SHM sidecars. A missing file is fine
/// (nothing to wipe). Only these three exact paths are touched — never a
/// `data/*.db` glob — so a co-located agent `state.db` is never clobbered.
///
/// Order matters: the sidecars go FIRST and the main DB file LAST. The
/// caller has already snapshotted `users` into memory, so if a delete
/// fails (a lock / permission error) and aborts the wipe, we must not
/// have already destroyed the on-disk DB — otherwise the in-memory
/// snapshot dies with the process and the accounts are gone (the very
/// lockout this code prevents). Deleting the main DB last means any
/// failure leaves it (and its accounts) intact and the wipe re-runnable.
fn remove_db_files(db_path: &str) -> Result<()> {
    for path in [
        format!("{db_path}-wal"),
        format!("{db_path}-shm"),
        db_path.to_string(),
    ] {
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => {
                return Err(anyhow::anyhow!(
                    "failed to delete '{path}': {e}. Something is holding the projector DB open \
                     (a running backend, a SQLite client, an antivirus scan) — stop the service \
                     and close any client, then re-run."
                ));
            }
        }
    }
    Ok(())
}

/// `check-quarantine <version>` subcommand (#582 Phase 4): the deploy
/// script calls this before swapping a new binary in. Exit 3 if the
/// version is quarantined (crash-looped on a prior boot and was rolled
/// back) so the deploy aborts instead of re-deploying a known-bad
/// binary; exit 0 (safe) otherwise. No config / tracing — the result
/// is the exit code, and a one-line note goes to stderr.
fn check_quarantine(version: &str) -> Result<()> {
    let exe = std::env::current_exe().context("current_exe")?;
    let sentinel = kanade_shared::boot_sentinel::BootSentinel::new(
        &default_paths::data_dir(),
        exe,
        env!("CARGO_PKG_VERSION"),
    );
    if sentinel.is_quarantined(version) {
        eprintln!(
            "check-quarantine: {version} is QUARANTINED (it crash-looped on a prior boot and was \
             rolled back). Refusing — republish a fixed binary under a new version, or clear the \
             quarantine."
        );
        std::process::exit(3);
    }
    eprintln!("check-quarantine: {version} is not quarantined (safe to deploy)");
    Ok(())
}

/// `arm-for-swap <new_version> <installed_exe>` subcommand (#582 Phase
/// 4): the deploy script calls this with the STAGED (new) binary right
/// before it overwrites the installed exe. We snapshot the still-present
/// outgoing binary at `installed_exe` to `<installed_exe>.last-good` and
/// write a sentinel for `new_version`. The next boot of the new binary
/// then runs `check_on_boot`, which counts attempts and — if it
/// crash-loops — restores the snapshot and quarantines `new_version`.
///
/// `installed_exe` (not `current_exe()`) anchors the last-good sibling
/// path: we're running the staged binary from the release/staging dir,
/// but the rollback target must sit next to where the service actually
/// runs from. A failure returns `Err` (non-zero exit); the deploy script
/// treats arming as best-effort and proceeds with a warning, so a single
/// un-armed swap only loses rollback protection for that one deploy.
fn arm_for_swap(new_version: &str, installed_exe: &Path) -> Result<()> {
    let sentinel = kanade_shared::boot_sentinel::BootSentinel::new(
        &default_paths::data_dir(),
        installed_exe.to_path_buf(),
        env!("CARGO_PKG_VERSION"),
    );
    sentinel
        .arm_for_swap(installed_exe, new_version)
        .with_context(|| format!("arm boot sentinel for {new_version}"))?;
    eprintln!(
        "arm-for-swap: snapshotted {} -> last-good and armed boot sentinel for {new_version}",
        installed_exe.display()
    );
    Ok(())
}

pub(crate) async fn run_backend() -> Result<()> {
    // Config first so the tracing init can honor [log] path / level
    // / keep_days. v0.24: prior to this the backend's tracing layer
    // was stdout-only, which meant the Windows service (no console)
    // wrote zero log lines anywhere on disk — invisible crashes.
    let cli = Cli::parse();
    let cfg_path = default_paths::find_config(
        cli.config.as_deref(),
        "KANADE_BACKEND_CONFIG",
        "backend.toml",
    )?;
    let cfg =
        load_backend_config(&cfg_path).with_context(|| format!("load config from {cfg_path:?}"))?;

    // _log_guard must outlive the program — tracing_appender's
    // non_blocking writer flushes its pending buffer on Drop.
    let _log_guard = init_tracing(&cfg.log)
        .with_context(|| format!("init tracing from [log] in {cfg_path:?}"))?;

    // Route panics through tracing so they land in the log file. The
    // default hook only writes to stderr, which a Windows service
    // discards — a panic in a request handler (e.g. jsonwebtoken's
    // CryptoProvider panic on the first JWT mint) would otherwise vanish
    // without a trace, leaving an "endpoint stopped responding" report
    // undiagnosable from the box. hyper still catches per-request panics,
    // so this changes only their visibility, not the crash behaviour.
    let default_panic_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        // `force_capture` (not `capture`) so the backtrace is collected
        // even without RUST_BACKTRACE set — a Windows service has no
        // environment to flip, and the default hook prints the backtrace
        // to the same discarded stderr. line-tables-only debug info (see
        // [profile] in Cargo.toml) keeps the frames meaningful.
        let backtrace = std::backtrace::Backtrace::force_capture();
        error!(panic = %info, %backtrace, "panic");
        default_panic_hook(info);
    }));

    info!(
        bind = %cfg.server.bind,
        nats = %cfg.nats.url,
        db = %cfg.db.sqlite_path,
        log_path = %cfg.log.path,
        log_keep_days = cfg.log.keep_days,
        "starting kanade-backend",
    );

    // SQLite open + migrate. Ensure the parent directory exists so
    // `create_if_missing(true)` actually has a folder to drop the file
    // into when `db.sqlite_path` points at a fresh install-layout
    // location like `C:\ProgramData\Kanade\data\backend.db`.
    let sqlite_path = PathBuf::from(&cfg.db.sqlite_path);
    if let Some(parent) = sqlite_path.parent()
        && !parent.as_os_str().is_empty()
    {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("create sqlite parent {parent:?}"))?;
    }
    // #411: concurrency pragmas. sqlx leaves journal_mode untouched
    // (so a fresh DB runs in `delete` mode — every write takes an
    // exclusive lock that blocks all readers) and defaults to
    // synchronous=FULL + a 5 s busy_timeout. Measured on minipc with a
    // single PC: multi-second single-row INSERTs (up to 7.2 s — past
    // the 5 s busy_timeout, surfacing as `database is locked` to the
    // projectors, which skip the ack and trigger JetStream redelivery
    // storms).
    //   * WAL — readers and the writer no longer block each other,
    //     which is the actual shape of this workload (8-conn pool:
    //     projectors writing while the API/scheduler read).
    //   * synchronous=NORMAL — safe with WAL (power loss can drop the
    //     last commit(s) but never corrupts), and this DB is a
    //     projection that re-derives from JetStream anyway (#389
    //     WipeDb replay), so FULL's per-commit fsync tax buys nothing.
    //   * busy_timeout 30 s — headroom over the worst observed stall
    //     so residual writer-writer contention waits instead of
    //     erroring into the redelivery path.
    let sqlite_opts = SqliteConnectOptions::from_str(&format!("sqlite://{}", cfg.db.sqlite_path))
        .with_context(|| format!("parse sqlite path {}", cfg.db.sqlite_path))?
        .create_if_missing(true)
        .journal_mode(SqliteJournalMode::Wal)
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_secs(30));
    let pool = SqlitePoolOptions::new()
        .max_connections(8)
        .connect_with(sqlite_opts)
        .await
        .context("open sqlite pool")?;
    sqlx::migrate!("./migrations")
        .run(&pool)
        .await
        .context("run migrations")?;
    info!("sqlite migrations applied");

    // Dedicated read-only pool over the SAME db file (opened after
    // migrations so the file exists — `read_only(true)` can't create it).
    // Only the admin `POST /api/query` endpoint uses it, so any write in
    // operator-supplied SQL fails at the SQLite layer (SQLITE_OPEN_READONLY)
    // rather than relying on statement validation alone. WAL lets it read
    // concurrently with the writer pool above. Fewer connections — this is
    // an occasional operator tool, not a hot path.
    let query_pool_opts =
        SqliteConnectOptions::from_str(&format!("sqlite://{}", cfg.db.sqlite_path))
            .with_context(|| format!("parse sqlite read-only path {}", cfg.db.sqlite_path))?
            .read_only(true)
            .busy_timeout(std::time::Duration::from_secs(30));
    let query_pool = SqlitePoolOptions::new()
        .max_connections(4)
        .connect_with(query_pool_opts)
        .await
        .context("open sqlite read-only pool")?;

    // RBAC bootstrap: seed the first admin account if the users table
    // is empty (chicken-and-egg). Reads the password registry-first
    // (HKLM\SOFTWARE\kanade\backend\BootstrapAdminPassword) /
    // env-second ($KANADE_BOOTSTRAP_ADMIN_PASSWORD); a loud warning is
    // logged either way. Without it, the only entry is the static
    // service token / KANADE_AUTH_DISABLE.
    if let Err(e) = api::accounts::seed_bootstrap_admin(&pool).await {
        warn!(error = %e, "bootstrap admin seed failed");
    }

    // NATS connect + JetStream context. The role decides which credential
    // the helper looks for (#1155): `HKLM\SOFTWARE\kanade\backend\NatsToken`
    // when provisioned, otherwise the fleet-wide token every role shared
    // before roles existed, otherwise $KANADE_NATS_TOKEN.
    let nats = kanade_shared::nats_client::connect(
        kanade_shared::nats_client::NatsRole::Backend,
        &cfg.nats.url,
    )
    .await?;
    info!("connected to NATS");
    let jetstream = async_nats::jetstream::new(nats.clone());

    // Self-bootstrap every JetStream resource the fleet expects.
    // Idempotent — re-running just re-acks existing resources —
    // so a fresh NATS server, a partial setup, or a server restart
    // all converge to the same state without operator action.
    kanade_shared::bootstrap::ensure_jetstream_resources(&jetstream)
        .await
        .context("ensure_jetstream_resources")?;
    info!("jetstream resources ready");

    // Reconcile the collect-bundle Object Store retention to the
    // operator-configured window (`ServerSettings::collect_retention_days`).
    // bootstrap just created the bucket with the built-in default; this
    // applies any SPA override to the live bucket (max_age is broker-side, so
    // a changed value only takes hold once something updates the stream).
    // Non-fatal — a failure leaves the previous max_age in place and the next
    // save / restart retries.
    match api::server_settings::load_from_js(&jetstream).await {
        Ok(settings) => {
            let days = settings.effective_collect_retention_days();
            match kanade_shared::bootstrap::reconcile_collect_retention(&jetstream, days).await {
                Ok(true) => info!(
                    collect_retention_days = days,
                    "collect retention reconciled at boot"
                ),
                Ok(false) => {}
                Err(e) => {
                    warn!(error = %format!("{e:#}"), "collect retention reconcile at boot failed")
                }
            }
            // Same for `result_output`. Unlike collect's, this window is a
            // RECOVERY window, not a data lifetime: the results projector
            // derefs each blob into SQLite before the INSERT, so the text is
            // already safe — what the window bounds is how long a `-WipeDb`
            // replay can still rebuild it. Reconciled here because a fresh
            // bucket gets the shorter default at create time but an EXISTING
            // one keeps whatever it was born with (`create_object_store` does
            // not reconcile, #506), and every production bucket was born at
            // thirty days.
            let days = settings.effective_result_output_retention_days();
            match kanade_shared::bootstrap::reconcile_object_store_max_age(
                &jetstream,
                kanade_shared::kv::OBJECT_RESULT_OUTPUT,
                days,
            )
            .await
            {
                Ok(true) => info!(
                    result_output_retention_days = days,
                    "result_output retention reconciled at boot"
                ),
                Ok(false) => {}
                Err(e) => {
                    warn!(
                        error = %format!("{e:#}"),
                        "result_output retention reconcile at boot failed"
                    )
                }
            }
            // #1247: reconcile every object store's max_bytes cap onto its
            // backing stream. This is also the fix for pre-existing buckets
            // that never received their cap (create-drift tolerated by
            // ensure_object_store) — e.g. OBJ_result_output at 6.76 GB
            // against a nominal 1 GiB. Non-fatal per bucket: a failure
            // leaves the previous cap and the next save / restart retries.
            for (bucket, cap_mib) in settings.effective_object_store_caps().effective_all() {
                match kanade_shared::bootstrap::reconcile_object_store_max_bytes(
                    &jetstream, bucket, cap_mib,
                )
                .await
                {
                    Ok(true) => info!(bucket, cap_mib, "object store cap reconciled at boot"),
                    Ok(false) => {}
                    Err(e) => {
                        warn!(error = %format!("{e:#}"), bucket, "object store cap reconcile at boot failed")
                    }
                }
            }
        }
        Err(e) => {
            warn!(error = %format!("{e:#}"), "collect retention: read server_settings failed; skipping boot reconcile")
        }
    }

    // #389: a wiped projection DB (deploy -WipeDb, manual recovery)
    // leaves the projectors' durable consumers parked at the end of
    // their streams, so the spawn block below would silently resume
    // from there and never re-derive history. Detect the wipe (empty
    // projection tables) and drop the stale durables first; the
    // projectors then recreate them with deliver-all. Must run before
    // any projector spawns. Failures are non-fatal — worst case is
    // the pre-#389 behaviour.
    if let Err(e) = projector::consumer_reset::reset_if_wiped(&jetstream, &pool).await {
        warn!(error = %e, "projector consumer reset check failed");
    }

    // v0.31 / #40: walk every registered inventory manifest and
    // CREATE TABLE IF NOT EXISTS for any `explode` specs. Idempotent
    // — re-running is a no-op. Done at startup (vs lazily in the
    // results projector) so cross-PC search queries can hit the
    // derived tables immediately, even before any new result lands.
    // CodeRabbit #85 fix: visibility on prewarm failures. Pre-fix
    // every failure branch (KV unreachable, keys() error, per-key
    // get() / deserialize) was silently dropped, so a busted
    // prewarm + a later search request would 500 with "no such
    // table" and zero startup log to explain why. Each branch
    // now logs at warn-level. The search path's
    // `ensure_table_cached` fallback (CR #3) covers the actual
    // table-creation gap, but logs help diagnose root cause.
    match jetstream
        .get_key_value(kanade_shared::kv::BUCKET_JOBS)
        .await
    {
        Ok(jobs_kv) => {
            let mut manifests = Vec::new();
            match jobs_kv.keys().await {
                Ok(keys_stream) => {
                    match futures::TryStreamExt::try_collect::<Vec<String>>(keys_stream).await {
                        Ok(keys) => {
                            for k in keys {
                                match jobs_kv.get(&k).await {
                                    Ok(Some(bytes)) => {
                                        match serde_json::from_slice::<
                                            kanade_shared::manifest::Manifest,
                                        >(&bytes)
                                        {
                                            Ok(m) => manifests.push(m),
                                            Err(e) => tracing::warn!(
                                                error = %e,
                                                job_key = %k,
                                                "explode prewarm: manifest deserialize failed",
                                            ),
                                        }
                                    }
                                    Ok(None) => {}
                                    Err(e) => tracing::warn!(
                                        error = %e,
                                        job_key = %k,
                                        "explode prewarm: KV get failed",
                                    ),
                                }
                            }
                        }
                        Err(e) => tracing::warn!(
                            error = %e,
                            "explode prewarm: collect keys failed",
                        ),
                    }
                }
                Err(e) => tracing::warn!(
                    error = %e,
                    "explode prewarm: keys() failed",
                ),
            }
            if let Err(e) = projector::explode::ensure_tables_for_jobs(&pool, manifests).await {
                error!(error = %e, "explode: startup table-ensure pass failed (will retry per-result)");
            }
        }
        Err(e) => tracing::warn!(
            error = %e,
            bucket = %kanade_shared::kv::BUCKET_JOBS,
            "explode prewarm: BUCKET_JOBS KV unreachable (ok if fresh install)",
        ),
    }

    // v0.35 / #88 + #488: explode-spec / manifest lookup cache.
    // Constructed BEFORE the projector spawns so the results
    // projector resolves inventory/check hints from memory instead
    // of two jobs_kv round-trips per ExecResult; prewarm + the
    // BUCKET_JOBS watcher are wired up further down.
    let explode_spec_cache = projector::spec_cache::ExplodeSpecCache::new();

    // Optional outbound SMTP relay (compliance-alert + generic email).
    // Built once here (no live rebuild), then shared (Arc) with the results
    // projector and AppState. `None` when no mail config is present or the
    // build fails — email becomes a no-op, the in-app/NATS path is
    // unaffected, and the backend still starts (a mail misconfig must not
    // gate boot).
    //
    // #884: the non-secret SMTP settings live in the `server_settings` KV
    // (SPA-editable), not `backend.toml`. The SMTP password is NOT in the KV:
    // it's always the `MailPassword` registry secret / `$KANADE_MAIL_PASSWORD`.
    // Editing the KV takes effect on the next backend restart (this build runs
    // the mailer once). A missing / unreadable config ⇒ email off this boot.
    let mail_cfg: Option<kanade_shared::config::MailSection> = api::server_settings::load_from_js(
        &jetstream,
    )
    .await
    .unwrap_or_else(|e| {
        warn!(error = %format!("{e:#}"), "read server_settings at startup — email off this boot");
        kanade_shared::wire::ServerSettings::default()
    })
    .mail;
    let mailer: Option<std::sync::Arc<mail::Mailer>> = mail_cfg.as_ref().and_then(|m| {
        let password = kanade_shared::secrets::read_hklm_value(r"SOFTWARE\kanade\backend", "MailPassword")
            .or_else(|| std::env::var("KANADE_MAIL_PASSWORD").ok().filter(|s| !s.is_empty()));
        match mail::Mailer::from_config(m, password) {
            Ok(mx) => {
                info!(host = %m.host, port = m.port, "SMTP mailer configured");
                Some(std::sync::Arc::new(mx))
            }
            Err(e) => {
                warn!(error = %format!("{e:#}"), "mail config present but Mailer build failed — email disabled");
                None
            }
        }
    });

    // Projectors run in the background; if either exits the backend keeps
    // serving HTTP (read-only API stays useful even if a stream is missing).
    //
    // v0.14: the inventory projector is gone — inventory facts now
    // arrive through the results projector (via Manifest.inventory
    // hint + ExecResult.manifest_id). HwInventory wire is retired.
    {
        let pool = pool.clone();
        let js = jetstream.clone();
        let cache = explode_spec_cache.clone();
        let mailer = mailer.clone();
        spawn_retrying_projector("results", move || {
            projector::results::run(js.clone(), pool.clone(), cache.clone(), mailer.clone())
        });
    }
    {
        let pool = pool.clone();
        let js = jetstream.clone();
        spawn_retrying_projector("audit", move || {
            projector::audit::run(js.clone(), pool.clone())
        });
    }
    {
        let pool = pool.clone();
        let nats_client = nats.clone();
        spawn_retrying_projector("heartbeat", move || {
            projector::heartbeat::run(nats_client.clone(), pool.clone())
        });
    }
    // v0.40 Part 1: host-wide perf time-series projector. Same core-
    // NATS direct-subscribe shape as heartbeat (gaps acceptable, no
    // JetStream durability cost); writes to host_perf_samples
    // (append-only) instead of UPSERTing into agents.
    {
        let pool = pool.clone();
        let nats_client = nats.clone();
        spawn_retrying_projector("host_perf", move || {
            projector::host_perf::run(nats_client.clone(), pool.clone())
        });
    }
    // v0.41 / Phase 2: per-process perf time-series projector. Only
    // sees traffic while an operator has opted a PC into investigation
    // mode (process_perf_enabled=true + expires_at in the future); on
    // a quiet fleet this projector wakes up and immediately blocks
    // back on the subscription with no DB writes.
    {
        let pool = pool.clone();
        let nats_client = nats.clone();
        spawn_retrying_projector("process_perf", move || {
            projector::process_perf::run(nats_client.clone(), pool.clone())
        });
    }
    // v0.30 / PR α' unified: project agent `events.started.*.*` into
    // execution_results as in-flight rows. Pairs with results
    // projector — both UPSERT against execution_results.result_id
    // so the SPA Activity table sees one row per run that
    // transitions from running to finished.
    {
        let pool = pool.clone();
        let js = jetstream.clone();
        // #682: the events projector stamps each in-flight row's
        // per-run reap deadline from the cached manifest's timeout, so
        // it shares the same ExplodeSpecCache as the results projector.
        let cache = explode_spec_cache.clone();
        spawn_retrying_projector("events", move || {
            projector::events::run(js.clone(), pool.clone(), cache.clone())
        });
    }
    // Issue #246: per-PC observability timeline. Distinct from the
    // events.started projector above (lifecycle pairing) — this
    // one consumes the `obs.<pc_id>` stream into the dedicated
    // `obs_events` table that powers the SPA Timeline page.
    {
        let pool = pool.clone();
        let js = jetstream.clone();
        spawn_retrying_projector("obs_events", move || {
            projector::obs_events::run(js.clone(), pool.clone())
        });
    }
    // Phase E (KLP notifications): project
    // `events.notifications.acked.>` (off the shared EVENTS stream)
    // into `notification_acks` so the SPA can show who confirmed each
    // notification and when.
    {
        let pool = pool.clone();
        let js = jetstream.clone();
        spawn_retrying_projector("notification-acks", move || {
            projector::notifications::run(js.clone(), pool.clone())
        });
    }
    // v0.30 follow-up: periodic housekeeping that flips long-stale
    // `pending` executions to `expired`. Without this, fires whose
    // ExecResult never lands (offline targets, `run_as: user` with
    // no console session, agent died mid-script) pile up in the
    // Jobs page live chip indefinitely. 5 min cadence; the function
    // body details the policy.
    let _cleanup_handle = cleanup::spawn(pool.clone(), jetstream.clone());

    // v0.35 / #88: prewarm + watcher for the explode-spec / manifest
    // cache constructed above (before the projector spawns). Prewarm
    // walks every registered manifest at startup so the first batch
    // of search requests doesn't pay the cold-miss latency.
    match projector::spec_cache::prewarm(&explode_spec_cache, &jetstream).await {
        Ok(n) => info!(cached = n, "explode spec cache prewarm done"),
        Err(e) => warn!(
            error = %e,
            "explode spec cache prewarm failed (watcher + miss-path fallback will recover)",
        ),
    }
    {
        let cache = explode_spec_cache.clone();
        let js = jetstream.clone();
        tokio::spawn(async move {
            if let Err(e) = projector::spec_cache::run(cache, js).await {
                error!(error = %e, "explode spec cache watcher exited");
            }
        });
    }

    // #1051: keep the `agent_meta` query-side table in sync with the KV
    // bucket. The supervised watcher reconciles the full snapshot after
    // each (re)attach (async-nats `watch_all` has no initial delivery,
    // #911) and reopens on stream end, so the projection self-heals
    // without a backend restart. The list endpoint reads this table for
    // metadata columns + the `?meta_key=&meta_value=` filter; KV stays the
    // source of truth (SPA PUT / `kanade meta` write it).
    {
        let pool = pool.clone();
        let js = jetstream.clone();
        tokio::spawn(async move {
            if let Err(e) = projector::agent_meta::run(pool, js).await {
                error!(error = %e, "agent_meta projector exited");
            }
        });
    }

    // #1270: which NATS credential each agent's live connection
    // authenticated with, asked of the BROKER rather than of the agent.
    // Polls the monitoring endpoint; a broker with monitoring off or bound
    // elsewhere leaves `agents.nats_user` NULL, which reads as "never
    // correlated" — the honest answer, and the projector says so once
    // rather than once a minute.
    {
        let pool = pool.clone();
        let monitor_url = cfg.nats.resolved_monitor_url();
        // The broker connection rides along so the projector can tell a
        // credential it merely *resolved* from one the broker actually
        // *accepted* — only the latter proves which auth mode is in force.
        let nats_client = nats.clone();
        tokio::spawn(async move {
            if let Err(e) = projector::nats_conns::run(pool, monitor_url, nats_client).await {
                error!(error = %e, "nats connections projector exited");
            }
        });
    }

    // #1216: object-store metadata index — one supervised watcher per
    // bucket keeps `object_store_meta` in sync (including direct-NATS
    // writers the API never sees), and the four list endpoints read
    // the index instead of full-scanning the stream per request.
    for bucket in projector::object_meta::BUCKETS {
        let pool = pool.clone();
        let js = jetstream.clone();
        tokio::spawn(async move {
            projector::object_meta::run(pool, js, bucket).await;
        });
    }

    let app_state = api::AppState {
        pool: pool.clone(),
        // #1165 stage 2: every command the backend puts on the wire goes
        // through this, signed when the host holds a key. Built before the
        // bare `nats` handle moves into the state so the two share one
        // connection.
        commands: std::sync::Arc::new(command_publisher::CommandPublisher::from_host(nats.clone())),
        query_pool,
        nats,
        jetstream,
        explode_spec_cache,
        sql_view_cache: api::view_sql::new_cache(),
        group_cache: api::group_sql::new_cache(),
        mailer,
        public_url: cfg.server.public_url.clone(),
        nats_url: cfg.nats.url.clone(),
        login_throttle: std::sync::Arc::new(login_throttle::LoginThrottle::default()),
    };

    // Scheduler runs alongside the projectors; if it can't init (no
    // schedules KV, bad cron, etc.) the backend keeps serving HTTP.
    {
        let s = app_state.clone();
        tokio::spawn(async move {
            if let Err(e) = scheduler::run(s).await {
                error!(error = %e, "scheduler exited");
            }
        });
    }

    // #1032①: the group materializer reflects declared-group membership
    // (GroupDefs) into `agent_groups_derived` so dynamic groups reach the
    // agent-side consumers (exec --groups / group notifications / visible_to).
    // `run` loops forever and self-recovers from transient errors; it shares
    // the AppState (query pool + group cache + jetstream).
    {
        let s = app_state.clone();
        tokio::spawn(async move {
            projector::group_materializer::run(s).await;
        });
    }

    let app = api::router(app_state)
        // RBAC middleware needs the SQLite pool to re-read the caller's
        // authoritative role / disabled flag on every request.
        .layer(axum::middleware::from_fn_with_state(
            pool.clone(),
            auth::verify,
        ))
        .layer(TraceLayer::new_for_http())
        // #1215①: outermost layer so every response — API JSON and the
        // embedded SPA alike — is gzip/br/deflate-compressed when the
        // client advertises it. The 1.5 MB JS bundle and the ~500 KB
        // /api/jobs payload both compress ~10×. Upgrade requests (the
        // /api/remote WebSocket) carry no body and pass through
        // untouched.
        .layer(CompressionLayer::new());

    let listener = TcpListener::bind(&cfg.server.bind)
        .await
        .with_context(|| format!("bind {}", cfg.server.bind))?;
    info!(bind = %cfg.server.bind, "axum serving");

    // #582 Phase 4: we've bound the port and are about to serve — past
    // config, DB migrations, and JetStream bootstrap (where #573
    // crashed). After a short healthy-uptime grace, confirm to the boot
    // sentinel so this version is promoted to last-good and any pending
    // swap sentinel clears. A crash before the grace leaves the sentinel
    // armed, so the next boot re-counts toward rollback.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        // A failed current_exe() here means we can't promote this version
        // to last-good — surface it instead of silently leaving the
        // sentinel armed (which would re-count this healthy boot toward
        // rollback on the next restart).
        match std::env::current_exe() {
            Ok(exe) => {
                let sentinel = kanade_shared::boot_sentinel::BootSentinel::new(
                    &default_paths::data_dir(),
                    exe,
                    env!("CARGO_PKG_VERSION"),
                );
                if let Err(e) = sentinel.confirm_healthy() {
                    tracing::warn!(error = %e, "boot sentinel: confirm_healthy failed");
                }
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "boot sentinel: current_exe() failed — healthy version not promoted to last-good"
                );
            }
        }
    });

    axum::serve(listener, app).await.context("axum serve")?;
    Ok(())
}

/// Build the tracing subscriber: stdout (useful in foreground /
/// `cargo run` mode) + a daily-rotated file appender pointed at
/// `[log] path`. `RUST_LOG`, if set, overrides `[log] level`.
/// Returns the appender's `WorkerGuard`, which the caller must
/// keep alive — its Drop flushes the non-blocking writer's
/// pending buffer. v0.24: previously the backend used a stdout-
/// only `tracing_subscriber::fmt()` init, which meant the Windows
/// service (no console) wrote zero log lines anywhere on disk.
fn init_tracing(log: &LogSection) -> Result<Option<tracing_appender::non_blocking::WorkerGuard>> {
    let env_filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| log.level.clone().into());

    // keep_days = 0 → opt out of file logging entirely (stdout only).
    if log.keep_days == 0 {
        let _ = tracing_subscriber::registry()
            .with(env_filter)
            .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
            .try_init();
        return Ok(None);
    }

    let path = Path::new(&log.path);
    let dir = path
        .parent()
        .with_context(|| format!("[log] path '{}' has no parent dir", log.path))?;
    let stem = path
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or("backend");
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");

    std::fs::create_dir_all(dir).with_context(|| format!("create log dir {dir:?}"))?;

    let appender = tracing_appender::rolling::Builder::new()
        .filename_prefix(stem)
        .filename_suffix(ext)
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .max_log_files(log.keep_days)
        .build(dir)
        .with_context(|| format!("build rolling appender at {dir:?}"))?;
    let (non_blocking, guard) = tracing_appender::non_blocking(appender);

    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        // #413: `fmt::layer()` defaults to ansi(true) regardless of
        // whether the writer is a terminal, so without this the file
        // log fills with color escapes (~22k ESC bytes/day measured).
        // The agent's file layer has carried `.with_ansi(false)` since
        // v0.7.1; this mirrors it. Stdout keeps its colors.
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(non_blocking)
                .with_ansi(false),
        )
        .try_init();

    Ok(Some(guard))
}

#[cfg(test)]
mod compression_tests {
    use axum::Router;
    use axum::body::Body;
    use axum::http::{Request, header};
    use axum::routing::get;
    use tower::ServiceExt;
    use tower_http::compression::CompressionLayer;

    /// Big enough that compression is worth doing and repetitive enough to
    /// compress hard — the SPA bundle and the `/api/jobs` JSON are both like
    /// this in the ways that matter.
    fn payload() -> String {
        "the quick brown fox jumps over the lazy dog. ".repeat(400)
    }

    /// Drive the layer the router mounts (`main`, "#1215①") and assert it
    /// actually encodes.
    ///
    /// The failure this exists for is a PARTIAL feature drop, and it is
    /// silent. Measured, not assumed:
    ///
    /// - dropping **both** `compression-gzip` and `compression-br` from
    ///   tower-http is a compile error (`tower_http::compression` stops
    ///   existing), so that case was never able to slip through;
    /// - dropping **one** is not. The module still exists,
    ///   `CompressionLayer::new()` still compiles and still runs, and the
    ///   dropped encoding simply stops being negotiated. Removing `br` while
    ///   keeping `gzip` fails only `brotli_is_negotiated_too` here and
    ///   nothing else in the workspace.
    ///
    /// A Cargo feature edit reads as dependency housekeeping and would pass
    /// review on that basis, which is exactly why the encodings are asserted
    /// one by one rather than as "compression works".
    ///
    /// Deliberately built here rather than against the real router: the
    /// thing at risk is the negotiation, and reaching the real router needs
    /// an `AppState` (pool, mailer, NATS) whose setup would dominate the
    /// test and give it other reasons to break.
    async fn encoding_for(accept: &str) -> (Option<String>, usize) {
        let body = payload();
        let plain = body.len();
        let app = Router::new()
            .route("/x", get(move || async move { body }))
            .layer(CompressionLayer::new());
        let res = app
            .oneshot(
                Request::builder()
                    .uri("/x")
                    .header(header::ACCEPT_ENCODING, accept)
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let enc = res
            .headers()
            .get(header::CONTENT_ENCODING)
            .map(|v| v.to_str().unwrap().to_owned());
        let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(plain > 4096, "payload must be worth compressing");
        (enc, bytes.len())
    }

    #[tokio::test]
    async fn gzip_is_negotiated_and_actually_shrinks_the_body() {
        let (enc, len) = encoding_for("gzip").await;
        assert_eq!(enc.as_deref(), Some("gzip"));
        // Not just the header: a layer that labels without encoding would
        // pass a header-only assertion.
        assert!(len < payload().len() / 4, "gzip body was {len} bytes");
    }

    #[tokio::test]
    async fn brotli_is_negotiated_too() {
        let (enc, len) = encoding_for("br").await;
        assert_eq!(enc.as_deref(), Some("br"));
        assert!(len < payload().len() / 4, "br body was {len} bytes");
    }

    #[tokio::test]
    async fn a_client_that_advertises_nothing_gets_the_bytes_unchanged() {
        let (enc, len) = encoding_for("identity").await;
        assert_eq!(enc, None);
        assert_eq!(len, payload().len());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::SqlitePool;

    /// A throwaway DB path under the temp dir, unique to this process so
    /// parallel test runs don't collide. Sidecars (-wal/-shm) sit next
    /// to it and are cleaned by the wipe itself.
    fn temp_db_path(tag: &str) -> String {
        let p = std::env::temp_dir().join(format!(
            "kanade-wipe-test-{}-{}.db",
            std::process::id(),
            tag
        ));
        // Start from a clean slate even if a prior run left a file.
        let _ = remove_db_files(p.to_str().unwrap());
        p.to_string_lossy().into_owned()
    }

    async fn open(db_path: &str) -> SqlitePool {
        let opts = SqliteConnectOptions::from_str(&format!("sqlite://{db_path}"))
            .unwrap()
            .create_if_missing(true)
            .journal_mode(SqliteJournalMode::Wal);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(opts)
            .await
            .unwrap();
        sqlx::migrate!("./migrations").run(&pool).await.unwrap();
        pool
    }

    #[tokio::test]
    async fn wipe_preserves_users_and_drops_projector_rows() {
        let db_path = temp_db_path("preserve");

        // Seed a durable account + a permission group it belongs to + a
        // projector-derived row.
        let pool = open(&db_path).await;
        sqlx::query(
            "INSERT INTO permission_groups (name, features, created_at, updated_at) \
             VALUES ('sec', '[\"compliance\",\"inventory\"]', '2026-01-02 03:04:05', '2026-01-02 03:04:05')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO users \
             (username, password_hash, role, disabled, must_change_pw, created_at, updated_at, email, allowed_features, permission_group) \
             VALUES ('admin', 'argon2hash', 'admin', 0, 1, '2026-01-02 03:04:05', '2026-01-02 03:04:05', 'a@b.com', '[\"compliance\",\"inventory\"]', 'sec')",
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query(
            "INSERT INTO check_status (pc_id, check_name, status, detail, recorded_at, label) \
             VALUES ('pc1', 'c', 'ok', 'd', '2026-01-02 03:04:05', 'L')",
        )
        .execute(&pool)
        .await
        .unwrap();
        pool.close().await;

        let (users, groups) = wipe_projector_at(&db_path).await.unwrap();
        assert_eq!(users, 1, "the one admin account is restored");
        assert_eq!(groups, 1, "the one permission group is restored");

        // Reopen WITHOUT migrating (open() migrates, but the wipe already
        // left a migrated DB) and assert the split: users kept verbatim,
        // projector table emptied.
        let pool = open(&db_path).await;
        // A FromRow struct (rather than a wide tuple) keeps the row shape
        // readable and out of clippy's type-complexity lint.
        #[derive(sqlx::FromRow)]
        struct Preserved {
            username: String,
            password_hash: String,
            role: String,
            disabled: i64,
            must_change_pw: i64,
            created_at: String,
            email: Option<String>,
            allowed_features: Option<String>,
            permission_group: Option<String>,
        }
        let u: Preserved = sqlx::query_as(
            "SELECT username, password_hash, role, disabled, must_change_pw, created_at, email, allowed_features, permission_group \
                 FROM users",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(u.username, "admin");
        assert_eq!(u.password_hash, "argon2hash");
        assert_eq!(u.role, "admin");
        assert_eq!(u.disabled, 0);
        assert_eq!(u.must_change_pw, 1);
        assert_eq!(u.created_at, "2026-01-02 03:04:05", "timestamps round-trip");
        // #770 email + #1008 page allow-list + #1008 Phase 3 group membership
        // survive the wipe verbatim — a migration-driven wipe must not silently
        // drop a contact address, reset a page restriction to unrestricted, or
        // detach an account from its permission group.
        assert_eq!(u.email.as_deref(), Some("a@b.com"), "email round-trips");
        assert_eq!(
            u.allowed_features.as_deref(),
            Some(r#"["compliance","inventory"]"#),
            "allowed_features round-trips (not reset to NULL/unrestricted)"
        );
        assert_eq!(
            u.permission_group.as_deref(),
            Some("sec"),
            "permission_group membership round-trips"
        );

        // The referenced group's own row survives (it's SQLite-only, not
        // projector-derived, so a blind wipe would lose it).
        let (gname, gfeatures): (String, String) =
            sqlx::query_as("SELECT name, features FROM permission_groups")
                .fetch_one(&pool)
                .await
                .unwrap();
        assert_eq!(gname, "sec");
        assert_eq!(
            gfeatures, r#"["compliance","inventory"]"#,
            "group features round-trip"
        );

        let checks: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM check_status")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(
            checks, 0,
            "projector-derived rows are dropped (replay refills)"
        );
        pool.close().await;

        let _ = remove_db_files(&db_path);
    }

    #[tokio::test]
    async fn wipe_on_missing_db_is_a_noop() {
        // A fresh box (no DB yet): snapshot finds nothing, the wipe still
        // creates a migrated DB, and zero accounts are restored.
        let db_path = temp_db_path("missing");
        assert!(!Path::new(&db_path).exists());
        let (users, groups) = wipe_projector_at(&db_path).await.unwrap();
        assert_eq!(users, 0);
        assert_eq!(groups, 0);
        assert!(Path::new(&db_path).exists(), "schema is (re)created");

        let pool = open(&db_path).await;
        let users: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM users")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(users, 0);
        pool.close().await;
        let _ = remove_db_files(&db_path);
    }
}

#[cfg(test)]
mod key_generate_tests {
    use super::resolve_kid;

    const TODAY: &str = "20260728";

    #[test]
    fn a_fresh_host_gets_a_date_stamped_id() {
        assert_eq!(
            resolve_kid(false, None, false, None, TODAY).unwrap(),
            "backend-20260728"
        );
    }

    #[test]
    fn an_explicit_id_wins() {
        assert_eq!(
            resolve_kid(false, None, false, Some("prod-signer"), TODAY).unwrap(),
            "prod-signer"
        );
    }

    #[test]
    fn an_existing_key_is_not_replaced_without_rotate() {
        // The guard the PR body calls a fleet-safety property. It could not be
        // tested while it lived behind `read_hklm_value`, which returns None
        // on the CI runners.
        let err = resolve_kid(true, Some("backend-20260101"), false, None, TODAY).unwrap_err();
        assert!(err.contains("--rotate"), "{err}");
    }

    #[test]
    fn rotate_mints_a_new_id_alongside_the_old() {
        assert_eq!(
            resolve_kid(true, Some("backend-20260101"), true, None, TODAY).unwrap(),
            "backend-20260728"
        );
    }

    #[test]
    fn rotating_twice_in_a_day_refuses_to_reuse_the_id() {
        // Two different keys sharing an id is the worst outcome available
        // here: agents hold one public key under that id and receive
        // signatures made by another, so every command reports a bad
        // signature — fleet-wide, and looking exactly like a forgery.
        let err = resolve_kid(true, Some("backend-20260728"), true, None, TODAY).unwrap_err();
        assert!(err.contains("--kid"), "{err}");

        // An explicit distinct id is the way through.
        assert_eq!(
            resolve_kid(
                true,
                Some("backend-20260728"),
                true,
                Some("backend-20260728b"),
                TODAY
            )
            .unwrap(),
            "backend-20260728b"
        );
    }
}
