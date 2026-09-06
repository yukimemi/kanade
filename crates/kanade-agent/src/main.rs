mod check_cache;
mod collect;
mod commands;
mod concurrency;
mod config_supervisor;
mod env_gate;
mod finalize;
mod groups;
mod heartbeat;
mod host_perf;
mod idle_sampler;
mod job_object;
mod job_tail;
mod live_tail;
mod log_tail;
mod logs;
mod output_cap;
mod ping;
mod process;
mod process_perf;
mod self_update;

// KLP (SPEC §2.12) is Windows-only in this PR — Linux UDS lands
// in a follow-up. Compiling the module on non-Windows would just
// emit dead-code warnings (the listener's call sites are all
// Windows-gated), so the simplest gate is the mod declaration
// itself. Cross-platform unit tests (framing, etc.) move with the
// module; CI on Linux/macOS skips them, but the production target
// is Windows-only so coverage stays meaningful.
#[cfg(target_os = "windows")]
mod klp;

mod command_replay;
mod command_verify;
mod events_outbox;
mod local_scheduler;
mod nats_retry;
mod obs_outbox;
mod outbox;
mod outbox_retry;
mod script_cache;
mod staleness;
mod startup_event;
mod winlog;

#[cfg(target_os = "windows")]
mod client_shortcut;
#[cfg(target_os = "windows")]
mod cwd_expand;
#[cfg(target_os = "windows")]
mod process_as_user;
#[cfg(target_os = "windows")]
mod service;
// #855: SYSTEM-side supervisor that keeps a `--session-agent` child alive in
// the user session and feeds its in-session idle into env_gate's cache.
#[cfg(target_os = "windows")]
mod session_supervisor;
// #1140 PR2: DXGI Desktop Duplication plus the probe that measures it.
// Windows-only at the module declaration for the same reason `klp` is — the
// capture path is entirely Win32/D3D11, and the probe's only caller is the
// Windows runner, so compiling either elsewhere is all dead code.
// #1140 PR3a: framing for tiles crossing the in-session IPC pipe. Windows-
// only for the same reason capture_probe is — its only producer and consumer
// are the Windows capture path, so off-Windows every function is dead code
// and the build fails on it (learned the hard way in #1142).
#[cfg(target_os = "windows")]
mod capture_encode;
#[cfg(target_os = "windows")]
mod capture_frame_io;
#[cfg(target_os = "windows")]
mod capture_probe;
#[cfg(target_os = "windows")]
mod remote_session;
#[cfg(target_os = "windows")]
mod screen_capture;

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Parser;
use kanade_shared::config::{LogSection, load_agent_config};
use kanade_shared::{default_paths, subject};
use tracing::info;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Parser, Debug)]
#[command(
    name = "kanade-agent",
    about = "Windows endpoint management agent (kanade)",
    version
)]
struct Cli {
    /// Path to agent.toml. When unset, the agent looks at
    /// $KANADE_AGENT_CONFIG, then `<config_dir>/agent.toml` (see
    /// kanade_shared::default_paths::config_dir).
    #[arg(long)]
    config: Option<PathBuf>,

    /// #855 internal: run as the in-session idle sensor instead of the agent.
    /// Launched by the agent's session supervisor inside the logged-in user's
    /// console session (it reads GetLastInputInfo, truthful only in-session,
    /// and prints `{"idle_ms":N}` lines to stdout). Not for manual use.
    #[arg(long, hide = true)]
    session_agent: bool,

    /// #1140 PR2 internal: measure the DXGI Desktop Duplication capture path
    /// instead of running the agent, then exit. Diagnostic only — it must be
    /// run interactively (a Session 0 service cannot capture a desktop).
    #[arg(long, hide = true)]
    capture_probe: bool,

    /// How long `--capture-probe` samples for, in seconds.
    #[arg(long, hide = true, default_value_t = 10)]
    capture_probe_secs: u64,

    /// JPEG quality `--capture-probe` encodes at (1-100).
    #[arg(long, hide = true, default_value_t = 75)]
    capture_probe_quality: u8,

    /// Write the first captured frame here as a JPEG, so the run can be
    /// eyeballed and not just trusted.
    #[arg(long, hide = true)]
    capture_probe_save: Option<PathBuf>,

    /// #1140 PR3a internal: run as the in-session capture child. Streams
    /// length-prefixed tile frames on stdout for the agent to read. Launched
    /// by the agent inside the logged-in user session; not for manual use
    /// except when dumping frames for verification.
    #[arg(long, hide = true)]
    session_capture: bool,

    /// JPEG quality for `--session-capture`, 1-100.
    #[arg(long, hide = true, default_value_t = 75)]
    session_capture_quality: u8,

    /// Frame-rate ceiling for `--session-capture`. The desktop decides the
    /// real rate; this only bounds it.
    #[arg(long, hide = true, default_value_t = 10)]
    session_capture_max_fps: u8,

    /// Display output `--session-capture` attaches to, 0 = primary.
    #[arg(long, hide = true, default_value_t = 0)]
    session_capture_output: u32,

    /// Stop `--session-capture` after this many seconds. 0 = run until the
    /// pipe breaks, which is what the agent uses.
    #[arg(long, hide = true, default_value_t = 0)]
    session_capture_secs: u64,

    /// #1140 PR3a internal: decode a file of captured frames and print a
    /// summary. The verification counterpart to `--session-capture`, so a
    /// dump can be proved to round-trip rather than assumed to.
    #[arg(long, hide = true)]
    capture_decode: Option<PathBuf>,
}

/// Top-level entry point.
///
/// On Windows, we first try to attach to the Service Control Manager.
/// If that succeeds we run as a real Windows service (service.rs
/// owns the tokio runtime for the lifetime of the service); if it
/// fails with `ERROR_FAILED_SERVICE_CONTROLLER_CONNECT` (Win32 1063),
/// we fall through to console mode — convenient for `cargo run` and
/// for manual debugging.
///
/// On non-Windows targets we always run in console mode.
fn main() -> Result<()> {
    // #855: the `--session-agent` child is a plain in-session idle sensor.
    // It must NOT run the boot sentinel (it would corrupt the service's
    // rollback attempt counter in the shared data dir) and must NOT attach to
    // the SCM — so branch out before either. It reads its own argv only.
    let cli = Cli::parse();
    if cli.session_agent {
        return run_session_agent();
    }

    // #1140 PR2: the capture probe is a diagnostic, not the agent. It branches
    // out alongside `--session-agent` and for the same reasons — it must not
    // run the boot sentinel (it would corrupt the service's rollback attempt
    // counter) and must not attach to the SCM.
    if cli.capture_probe {
        return run_capture_probe(&cli);
    }

    // #1140 PR3a: the capture child and the frame-dump decoder branch out
    // here for the same reasons — neither is the agent, and running the boot
    // sentinel or attaching to the SCM would corrupt the service's state.
    if cli.session_capture {
        return run_session_capture(&cli);
    }
    if cli.capture_decode.is_some() {
        return run_capture_decode(&cli);
    }

    // #582: boot sentinel is the VERY first thing — before the service
    // dispatcher, config, tracing, or NATS — so a binary that
    // crash-loops on boot (the failure mode that took the backend down
    // via #573) is rolled back to last-good instead of looping forever.
    // It's sync and needs only the data dir + current exe + version.
    // On rollback we exit(64); whether under the SCM (a start failure
    // the failure-action recovers) or console, that relaunches into the
    // restored binary.
    if let Ok(exe) = std::env::current_exe() {
        use kanade_shared::boot_sentinel::{BootDecision, BootSentinel, DEFAULT_MAX_ATTEMPTS};
        let sentinel = BootSentinel::new(&default_paths::data_dir(), exe, AGENT_VERSION);
        if let BootDecision::RolledBack { from } = sentinel.check_on_boot(DEFAULT_MAX_ATTEMPTS) {
            eprintln!(
                "boot sentinel: {from} crash-looped on boot — rolled back to last-good; \
                 exiting (64) for restart"
            );
            std::process::exit(64);
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
    runtime.block_on(run_agent())
}

/// #1140 PR3a: run as the in-session capture child and exit.
///
/// Streams length-prefixed tile frames (see `capture_frame_io`) on stdout
/// until the pipe breaks — which is how the child learns the agent is gone,
/// since a killed parent leaves no other signal an unprivileged process in
/// the user session can observe.
fn run_session_capture(cli: &Cli) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::io::Write;
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

        use kanade_shared::wire::{FrameMeta, TileEncoding};

        use crate::capture_encode::encode_tiles;
        use crate::capture_frame_io::{FrameHeader, encode_frame};
        use crate::screen_capture::{Capture, CaptureSession};

        let mut session = CaptureSession::new(cli.session_capture_output).context(
            "attach capture to display — this must run in the interactive desktop session",
        )?;

        // A zero ceiling would divide by zero and, read literally, means
        // "no frames at all"; treat it as 1 fps so a typo degrades to slow
        // rather than to a panic.
        let fps = cli.session_capture_max_fps.max(1);
        let min_interval = Duration::from_millis(1000 / u64::from(fps));

        let deadline = (cli.session_capture_secs > 0)
            .then(|| Instant::now() + Duration::from_secs(cli.session_capture_secs));

        let mut out = std::io::stdout().lock();
        let mut scratch = Vec::new();
        let mut frame_seq: u64 = 0;
        // Edge-triggered: one gap when capture stops, not one per poll.
        let mut in_gap = false;

        loop {
            if deadline.is_some_and(|d| Instant::now() >= d) {
                break;
            }
            let started = Instant::now();

            match session.next_frame(100)? {
                // Nothing changed. Normally that means saying nothing —
                // an idle desktop is the steady state, not an event. The
                // exception is the first successful poll after a gap: the
                // desktop is reachable again, and a consumer that only
                // learns this from the next tile would keep showing
                // "unavailable" for as long as nobody moved a window.
                // A recovered-but-static screen produces no tiles at all,
                // so the transition needs its own message.
                Capture::Idle => {
                    if in_gap {
                        in_gap = false;
                        let bytes = encode_frame(&FrameHeader::Resumed, &[])?;
                        if out.write_all(&bytes).is_err() || out.flush().is_err() {
                            return Ok(());
                        }
                    }
                }
                // Capture stopped: locked workstation, UAC secure desktop,
                // display mode change. Reported rather than skipped, so a
                // viewer can say "the screen is unavailable" instead of
                // holding the last picture, which reads as a live but frozen
                // desktop. Repeats are suppressed because the retry runs at
                // the poll interval and would otherwise emit ten gaps a
                // second for as long as the machine stays locked.
                Capture::Unavailable(reason) => {
                    if !in_gap {
                        in_gap = true;
                        let bytes = encode_frame(&FrameHeader::Gap, reason.as_bytes())?;
                        if out.write_all(&bytes).is_err() || out.flush().is_err() {
                            return Ok(());
                        }
                    }
                }
                Capture::Frame(frame) => {
                    // A tile is itself proof capture recovered, so no
                    // separate Resumed marker is needed on this path.
                    in_gap = false;
                    let tiles = encode_tiles(&frame, cli.session_capture_quality, &mut scratch)?;
                    let tile_count = u16::try_from(tiles.len()).unwrap_or(u16::MAX);
                    let captured_at_ms = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);

                    for (i, tile) in tiles.iter().enumerate() {
                        let header = FrameHeader::Tile {
                            meta: FrameMeta {
                                frame_seq,
                                tile_index: u16::try_from(i).unwrap_or(u16::MAX),
                                tile_count,
                                x: tile.x,
                                y: tile.y,
                                w: tile.w,
                                h: tile.h,
                                screen_w: frame.width,
                                screen_h: frame.height,
                                captured_at_ms,
                            },
                            encoding: TileEncoding::Jpeg,
                        };
                        let bytes = encode_frame(&header, &tile.jpeg)?;
                        // A broken pipe means the agent exited. That is a
                        // normal end of life for this process, not a failure
                        // to report — there is nobody left to report it to.
                        if out.write_all(&bytes).is_err() {
                            return Ok(());
                        }
                    }
                    if out.flush().is_err() {
                        return Ok(());
                    }
                    frame_seq += 1;
                }
            }

            // Pace against the whole iteration, not just the sleep, so a
            // slow encode eats into the interval instead of adding to it.
            let elapsed = started.elapsed();
            if elapsed < min_interval {
                std::thread::sleep(min_interval - elapsed);
            }
        }
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = cli;
        anyhow::bail!("--session-capture is Windows-only")
    }
}

/// #1140 PR3a: decode a dump of captured frames and print a summary.
///
/// The verification counterpart to `--session-capture`. The capture child
/// can only be spawned for real by the agent (the token dance needs
/// LocalSystem), so being able to run the child by hand, redirect stdout to
/// a file, and prove the bytes round-trip is what makes the framing
/// testable without a deployment.
fn run_capture_decode(cli: &Cli) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::collections::BTreeSet;
        use std::io::BufReader;

        use crate::capture_frame_io::read_frame;

        let path = cli
            .capture_decode
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("--capture-decode needs a path"))?;
        let file = std::fs::File::open(path)
            .with_context(|| format!("open frame dump {}", path.display()))?;
        let mut reader = BufReader::new(file);

        let mut tiles = 0u64;
        let mut bytes = 0u64;
        let mut frames = BTreeSet::new();
        let mut screens = BTreeSet::new();
        let mut largest = 0usize;
        let mut gaps: Vec<String> = Vec::new();
        let mut resumes = 0u64;

        loop {
            match read_frame(&mut reader) {
                Ok(msg) => {
                    if let Some(reason) = msg.as_gap() {
                        gaps.push(reason);
                        continue;
                    }
                    if msg.is_resumed() {
                        resumes += 1;
                        continue;
                    }
                    let (meta, _enc) = msg
                        .as_tile()
                        .ok_or_else(|| anyhow::anyhow!("message is neither tile nor gap"))?;
                    tiles += 1;
                    bytes += msg.payload.len() as u64;
                    largest = largest.max(msg.payload.len());
                    frames.insert(meta.frame_seq);
                    screens.insert((meta.screen_w, meta.screen_h));
                    // Every tile must be a real JPEG and sit inside its
                    // screen — this is the round-trip proof, not a formality.
                    anyhow::ensure!(
                        msg.payload.starts_with(&[0xFF, 0xD8]),
                        "tile {} of frame {} is not a JPEG",
                        meta.tile_index,
                        meta.frame_seq,
                    );
                    meta.validate()
                        .map_err(|e| anyhow::anyhow!("frame {} geometry: {e}", meta.frame_seq))?;
                    // The check that makes this dump proof of shippability
                    // rather than just of framing: a tile over the budget
                    // would be rejected by the broker, and a real 3840x1600
                    // capture does produce those without splitting.
                    anyhow::ensure!(
                        msg.payload.len() <= kanade_shared::wire::MAX_TILE_BYTES,
                        "tile {} of frame {} is {} bytes, over the {} wire budget",
                        meta.tile_index,
                        meta.frame_seq,
                        msg.payload.len(),
                        kanade_shared::wire::MAX_TILE_BYTES,
                    );
                }
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(anyhow::anyhow!("decode frame {}: {e}", tiles + 1)),
            }
        }

        println!("frames      {}", frames.len());
        println!("tiles       {tiles}");
        println!(
            "tiles/frame {:.1}",
            if frames.is_empty() {
                0.0
            } else {
                tiles as f64 / frames.len() as f64
            }
        );
        println!(
            "payload     {:.0} KB total | {:.0} KB mean | {:.0} KB largest",
            bytes as f64 / 1024.0,
            if tiles == 0 {
                0.0
            } else {
                bytes as f64 / tiles as f64 / 1024.0
            },
            largest as f64 / 1024.0,
        );
        for (w, h) in &screens {
            println!("screen      {w}x{h}");
        }
        if !gaps.is_empty() || resumes > 0 {
            println!("gaps        {} ({resumes} resumed)", gaps.len());
            for g in &gaps {
                println!("  - {g}");
            }
        }
        anyhow::ensure!(tiles > 0, "dump contained no frames");
        println!(
            "\nevery tile round-tripped, is a JPEG, fits its screen, and is under \
             the {} KB wire budget",
            kanade_shared::wire::MAX_TILE_BYTES / 1024,
        );
        Ok(())
    }
    #[cfg(not(target_os = "windows"))]
    {
        let _ = cli;
        anyhow::bail!("--capture-decode is Windows-only")
    }
}

/// #1140 PR2: run the screen-capture probe and exit.
///
/// Kept as its own function so the platform gate lives in exactly one place
/// instead of splitting `main`'s control flow across two `cfg` blocks.
fn run_capture_probe(cli: &Cli) -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        capture_probe::run(
            cli.capture_probe_secs,
            cli.capture_probe_quality,
            cli.capture_probe_save.clone(),
        )
    }
    #[cfg(not(target_os = "windows"))]
    {
        // Referenced so the probe flags don't read as dead fields off-Windows.
        let _ = cli;
        anyhow::bail!(
            "--capture-probe is Windows-only: it measures DXGI Desktop Duplication, \
             which has no non-Windows counterpart in this agent"
        )
    }
}

/// #855: the `--session-agent` child. Runs INSIDE the user's console session
/// (spawned by `session_supervisor` via the `RunAs::User` token dance), reads
/// `GetLastInputInfo` — truthful only in-session — and prints the idle as one
/// `{"idle_ms":N}` NDJSON line per sample to stdout, which the supervisor reads
/// back into `env_gate`'s console-idle cache. No service, no NATS, no config:
/// the lightest possible resident sensor. Exits when stdout breaks (the parent
/// agent is gone) or when killed.
fn run_session_agent() -> Result<()> {
    #[cfg(target_os = "windows")]
    {
        use std::io::Write;
        use windows::Win32::System::SystemInformation::GetTickCount;
        use windows::Win32::UI::Input::KeyboardAndMouse::{GetLastInputInfo, LASTINPUTINFO};

        let mut out = std::io::stdout();
        loop {
            // SAFETY: `lii` is a valid, correctly-sized LASTINPUTINFO out-param;
            // GetTickCount takes no args. GetLastInputInfo reads the input
            // desktop of THIS process's session — truthful because we run in
            // the user's session (a SYSTEM/session-0 caller could not).
            let line = unsafe {
                let mut lii = LASTINPUTINFO {
                    cbSize: std::mem::size_of::<LASTINPUTINFO>() as u32,
                    dwTime: 0,
                };
                if GetLastInputInfo(&mut lii).as_bool() {
                    // Both are DWORD ms since boot; wrapping_sub handles the
                    // ~49.7-day GetTickCount wrap (idle is always far below it).
                    let idle_ms = GetTickCount().wrapping_sub(lii.dwTime);
                    format!("{{\"idle_ms\":{idle_ms}}}\n")
                } else {
                    "{\"idle_ms\":null}\n".to_string()
                }
            };
            // A broken stdout (parent closed its read end / agent gone) → stop.
            if out.write_all(line.as_bytes()).is_err() || out.flush().is_err() {
                break;
            }
            std::thread::sleep(env_gate::SESSION_IDLE_SAMPLE_INTERVAL);
        }
    }
    #[cfg(not(target_os = "windows"))]
    {
        // No in-session idle off Windows; the fleet is all-Windows and this
        // child is only ever spawned by the Windows session supervisor.
    }
    Ok(())
}

/// Run the agent's tokio main loop. Called either from console
/// mode (directly from `main`) or from inside the Windows service
/// entry point (see [`service::run_service`]).
pub(crate) async fn run_agent() -> Result<()> {
    // (boot sentinel check runs in `main()` before the service
    // dispatcher — see there.)

    // Load config first so the tracing init can honor [log] path / level
    // / keep_days. Early errors from this load fall back to stderr.
    let cli = Cli::parse();
    let cfg_path =
        default_paths::find_config(cli.config.as_deref(), "KANADE_AGENT_CONFIG", "agent.toml")?;
    let cfg =
        load_agent_config(&cfg_path).with_context(|| format!("load config from {cfg_path:?}"))?;

    // `_log_guard` must outlive the program — `tracing_appender::non_blocking`
    // writes asynchronously, so the worker thread flushes on its Drop.
    let _log_guard = init_tracing(&cfg.log)
        .with_context(|| format!("init tracing from [log] in {cfg_path:?}"))?;

    cleanup_stale_upgrade_artifacts();

    info!(
        pc_id = %cfg.agent.id,
        nats_url = %cfg.agent.nats_url,
        version = AGENT_VERSION,
        log_path = %cfg.log.path,
        log_keep_days = cfg.log.keep_days,
        "starting kanade-agent",
    );

    // v0.26: build the staleness tracker BEFORE the NATS client so we
    // can hand its event_callback closure to the connect path. Every
    // subsequent `Event::Connected` (initial handshake + every
    // reconnect) stamps the tracker's `last_connected_at`. The
    // tracker itself owns no task — `staleness()` is a pure read.
    let staleness_tracker = staleness::Tracker::new();
    let client = kanade_shared::nats_client::connect_with_event_callback(
        // The agent's role key is the same registry path the fleet-wide
        // token already lives at, so this role sees no migration (#1155).
        kanade_shared::nats_client::NatsRole::Agent,
        &cfg.agent.nats_url,
        // #1270: announce the pc_id in the connection name. The broker
        // echoes it in `/connz` beside the user it authenticated us as,
        // which is the only way the backend can say *which host* is still
        // on the old credential — the agent's own account of itself
        // (a heartbeat field) would be exactly what is in doubt.
        Some(cfg.agent.id.as_str()),
        staleness_tracker.on_event(),
    )
    .await?;
    info!("connected to NATS");

    let cmd_all = client.subscribe(subject::COMMANDS_ALL).await?;
    let cmd_self = client
        .subscribe(subject::commands_pc(&cfg.agent.id))
        .await?;
    info!(
        commands_all = subject::COMMANDS_ALL,
        commands_self = %subject::commands_pc(&cfg.agent.id),
        "subscribed",
    );

    let pc_id = cfg.agent.id.clone();

    // Sprint 6: every fleet-wide knob (heartbeat cadence, inventory
    // cadence / jitter / enabled, target_version) is now sourced
    // from the agent_config KV bucket and watched live. The
    // supervisor publishes the resolved EffectiveConfig on a watch
    // channel; heartbeat / inventory / self_update subscribe.
    let cfg_rx = config_supervisor::spawn(client.clone(), pc_id.clone(), staleness_tracker.clone());
    concurrency::watch_config(cfg_rx.clone());

    // #1165: one verifier shared by every command entry point, so the
    // transition reporting reflects the machine rather than one subscription.
    //
    // Built here rather than beside the command subscriptions further down
    // because the heartbeat reports which keys it holds, and the heartbeat
    // starts first. Its construction depends on nothing but `pc_id` and a pure
    // path resolution, so moving it earlier costs nothing.
    let verifier = std::sync::Arc::new(command_verify::Verifier::new(
        pc_id.clone(),
        // `default_dir()` rather than the `obs_outbox_dir` binding below: the
        // command paths are spawned before it exists, and it is the same pure
        // resolution either way.
        obs_outbox::default_dir(),
    ));

    tokio::spawn(heartbeat::heartbeat_loop(
        client.clone(),
        pc_id.clone(),
        AGENT_VERSION.to_string(),
        cfg_rx.clone(),
        verifier.clone(),
    ));
    // v0.40 Part 1: host-wide perf snapshot publisher. Runs on its
    // own cadence (default 60 s) so the slightly heavier host-wide
    // sysinfo refresh stays out of the 30 s heartbeat loop. Pre-0.40
    // backends without a host_perf projector simply ignore the
    // traffic, so the agent can be upgraded ahead of the backend.
    tokio::spawn(host_perf::host_perf_loop(
        client.clone(),
        pc_id.clone(),
        cfg_rx.clone(),
    ));
    // v0.41 / Phase 2: per-process telemetry. The loop itself is
    // always spawned, but it stays quiet until the operator flips
    // `process_perf_enabled=true` on this PC's agent_config row
    // (and `process_perf_expires_at` is still in the future). When
    // the deadline passes the loop auto-stops publishing without
    // needing the operator to come back and unset the flag.
    tokio::spawn(process_perf::process_perf_loop(
        client.clone(),
        pc_id.clone(),
        cfg_rx.clone(),
    ));
    // Keep the end-user Client App's all-users Start-Menu shortcut
    // (Start-Menu label + WinRT toast sender name) in step with the
    // operator-configured `client_display_name`. Event-driven off the
    // same config watch; the PowerShell re-stamp only fires when the
    // resolved name actually changes (see client_shortcut docs).
    #[cfg(target_os = "windows")]
    client_shortcut::spawn(cfg_rx.clone());
    tokio::spawn(self_update::run(
        client.clone(),
        pc_id.clone(),
        AGENT_VERSION.to_string(),
        cfg_rx.clone(),
        staleness_tracker.clone(),
    ));
    // #582: we're past early boot (config, tracing, NATS connect,
    // subscriptions, every loop spawn). After a short healthy-uptime
    // grace, confirm to the boot sentinel so this version is promoted
    // to last-good and any pending swap sentinel clears. A crash before
    // the grace elapses leaves the sentinel armed, so the next boot
    // re-counts toward rollback.
    tokio::spawn(async {
        tokio::time::sleep(std::time::Duration::from_secs(30)).await;
        if let Ok(exe) = std::env::current_exe() {
            let sentinel = kanade_shared::boot_sentinel::BootSentinel::new(
                &default_paths::data_dir(),
                exe,
                AGENT_VERSION,
            );
            if let Err(e) = sentinel.confirm_healthy() {
                tracing::warn!(error = %e, "boot sentinel: confirm_healthy failed");
            }
        }
    });
    tokio::spawn(logs::serve(
        client.clone(),
        pc_id.clone(),
        std::path::PathBuf::from(&cfg.log.path),
        staleness_tracker.clone(),
    ));
    // Live job-tail responder: serves `job.tail.<pc_id>` from the
    // in-memory live registry so the SPA can poll a running job's
    // stdout/stderr (same UX as the agent-log auto-refresh, scoped
    // to one job). No persistence — purely the in-flight ring buffer.
    tokio::spawn(job_tail::serve(
        client.clone(),
        pc_id.clone(),
        staleness_tracker.clone(),
    ));
    // v0.38 / #133: active ping responder. Independent of the
    // periodic heartbeat loop so an operator's "ping" round-trips
    // in single-digit ms instead of waiting up to ~30 s for the
    // next scheduled tick.
    tokio::spawn(ping::serve(
        client.clone(),
        pc_id.clone(),
        AGENT_VERSION.to_string(),
        std::env::var("COMPUTERNAME")
            .ok()
            .or_else(|| std::env::var("HOSTNAME").ok()),
        Some(std::env::consts::OS.to_string()),
        staleness_tracker.clone(),
    ));

    // KLP listener (SPEC §2.12) — Windows Named Pipe today, Linux
    // UDS in a follow-up. The detached JoinHandle is intentional:
    // the foundation PR has no graceful-shutdown path and the
    // listener should run for the agent's full lifetime.
    //
    // The state evaluator runs on a 30 s cadence in its own task
    // and publishes StateSnapshots to a watch channel that the
    // KLP listener fans out to subscribers (state.subscribe).
    // Seed the watch with `eval_once` synchronously so the first
    // `state.snapshot` call returns real data without waiting for
    // a tick.
    // #290: operator-defined health-check results flow from the
    // command path into this sink and out via the KLP StateSnapshot.
    // Constructed unconditionally (the command-path writer is
    // cross-platform); only the Windows KLP evaluator reads it.
    // Persisted to data_dir so the Health tab survives an agent
    // restart and shows last-known status while offline.
    let check_sink =
        check_cache::CheckSink::load(default_paths::data_dir().join("check_results.json"));
    // KLP Phase E: process-wide notification broadcast. Created before
    // the listener so the same sender feeds both the KLP
    // `ListenerContext` (per-connection forwarders derive receivers from
    // it) and the `notify_bus` task spawned once `groups_rx` exists.
    // The initial receiver is dropped — receivers are minted on demand
    // by `notifications.subscribe`; until then `send` is a no-op.
    #[cfg(target_os = "windows")]
    let notif_tx =
        tokio::sync::broadcast::channel::<kanade_shared::ipc::notifications::Notification>(
            klp::notify_bus::BROADCAST_CAPACITY,
        )
        .0;
    // Sibling broadcast for post-send amends (recall). Same lifecycle as
    // `notif_tx`: one sender feeds the listener + the notify_bus task.
    #[cfg(target_os = "windows")]
    let amend_tx = tokio::sync::broadcast::channel::<
        kanade_shared::ipc::notifications::NotificationAmend,
    >(klp::notify_bus::BROADCAST_CAPACITY)
    .0;
    #[cfg(target_os = "windows")]
    {
        let initial_snapshot = klp::state::eval_once(
            &pc_id,
            AGENT_VERSION,
            &cfg_rx.borrow(),
            klp::state::client_online(&client),
            &check_sink.checks(),
        );
        let (state_tx, state_rx) = tokio::sync::watch::channel(initial_snapshot);
        tokio::spawn(klp::state::eval_loop(
            state_tx,
            cfg_rx.clone(),
            pc_id.clone(),
            AGENT_VERSION.to_string(),
            client.clone(),
            check_sink.clone(),
        ));
        let _klp_handle = klp::server::spawn(klp::server::ListenerContext {
            pc_id: std::sync::Arc::from(pc_id.as_str()),
            agent_version: std::sync::Arc::from(AGENT_VERSION),
            config_rx: cfg_rx.clone(),
            state_rx,
            log_path: std::path::PathBuf::from(&cfg.log.path),
            nats: client.clone(),
            notif_tx: notif_tx.clone(),
            amend_tx: amend_tx.clone(),
        });
    }

    // Group membership: Sprint 5 moves this from agent.toml (per-box
    // local config) to a server-managed KV bucket. The manager reads
    // `agent_groups.{pc_id}` from JetStream KV, spawns one
    // `commands.group.<name>` subscriber per current group, and reacts
    // to KV updates by adding / dropping subscriptions live.
    if !cfg.agent.groups.is_empty() {
        tracing::warn!(
            local_groups = ?cfg.agent.groups,
            "agent.toml::[agent] groups is deprecated; use `kanade agent groups set` instead — local value is ignored",
        );
    }
    // v0.22.1: dedup cache shared between core sub (live online
    // path) and the JetStream replay consumer (reconnect catch-up).
    // Either path can be the first to deliver a given Command's
    // request_id; the second arrival is dropped.
    let dedup = commands::shared_dedup_cache();

    // #210: OBJECT_SCRIPTS-backed manifest scripts. Constructed
    // once here (cheap Clone — jetstream::Context is Arc-internal)
    // and threaded into every dispatch path (groups subs + replay +
    // live sub + local scheduler) so they all share one cache
    // directory.
    let script_cache = script_cache::ScriptCache::new(
        async_nats::jetstream::new(client.clone()),
        default_paths::data_dir().join("script_cache"),
    );

    // v0.24: groups::spawn returns a watch::Receiver<Vec<String>>
    // carrying the current membership list. `local_scheduler`
    // subscribes to it so `runs_on: agent` schedules targeting a
    // group reflect membership changes without waiting for the
    // next schedule edit.
    let (groups_rx, _groups_handle) = groups::spawn(
        client.clone(),
        pc_id.clone(),
        dedup.clone(),
        staleness_tracker.clone(),
        script_cache.clone(),
        check_sink.clone(),
        verifier.clone(),
    );

    // KLP Phase E (live push): subscribe to the membership-filtered
    // `notifications.{all|group.X|pc.Y}` subjects and re-broadcast each
    // incoming notification to every connected Client App. Follows
    // `groups_rx` so the subject set tracks group membership, just like
    // command_replay. Windows-only (the whole KLP module is).
    #[cfg(target_os = "windows")]
    klp::notify_bus::spawn(
        client.clone(),
        pc_id.clone(),
        groups_rx.clone(),
        notif_tx,
        amend_tx,
    );

    // Reconnect catch-up: durable consumer on STREAM_EXEC that
    // replays the latest retained Command per subject. See
    // `crates/kanade-agent/src/command_replay.rs` for the flow.
    // #483: it follows `groups_rx` so the durable's server-side
    // filter_subjects track group membership (and group Commands
    // never reach non-members).
    command_replay::spawn(
        client.clone(),
        pc_id.clone(),
        dedup.clone(),
        staleness_tracker.clone(),
        script_cache.clone(),
        check_sink.clone(),
        groups_rx.clone(),
        verifier.clone(),
    );
    // v0.24: file-based outbox for ExecResult publishes. Every
    // result the agent produces is persisted under `outbox/<rid>.json`
    // first; a background drain task publishes via JetStream and
    // deletes on PubAck. Survives agent crashes + broker-down
    // periods longer than the async-nats client buffer.
    let outbox_dir = default_paths::data_dir().join("outbox");
    let _outbox_handle = outbox::spawn_drain(client.clone(), outbox_dir.clone());
    // v0.30 / PR α' unified: parallel outbox for `EventStarted`
    // lifecycle events (script-spawn time). Same atomic write +
    // drain pattern as the ExecResult outbox; separate directory so
    // existing v0.24 ExecResult files keep working unchanged across
    // the upgrade.
    let events_outbox_dir = default_paths::data_dir().join("events-outbox");
    let _events_outbox_handle =
        events_outbox::spawn_drain(client.clone(), events_outbox_dir.clone());
    // Issue #246: per-PC observability event outbox + drain. Distinct
    // from `events-outbox/` above (which carries `EventStarted`
    // lifecycle events) — `obs-outbox/` carries the timeline
    // `ObsEvent`s a script emits via `emit.type: events` manifests.
    let obs_outbox_dir = obs_outbox::default_dir();
    let _obs_outbox_handle = obs_outbox::spawn_drain(client.clone(), obs_outbox_dir.clone());
    // #1089 / #970: record the restart itself. The backend infers outages from
    // heartbeat gaps, but cannot see a restart shorter than its staleness
    // threshold, cannot know the true recovery instant (only whatever its
    // sweep happens to read), and can never describe a window it was down for.
    // Enqueued rather than published, so it survives a broker that is
    // unreachable right now and backfills with its real `at`.
    startup_event::emit(&pc_id, AGENT_VERSION, &obs_outbox_dir);
    // #841: agent-native idle/active sampler — the one swimlane signal not in
    // the Event Log. Emits `active`/`idle` ObsEvents to the same outbox on
    // debounced transitions; the drain above publishes them.
    tokio::spawn(idle_sampler::run(pc_id.clone(), obs_outbox_dir.clone()));
    // #855: keep a `--session-agent` child alive in the user's console session
    // and feed its in-session GetLastInputInfo idle into env_gate's cache, so
    // console_idle() — and thus both idle_sampler above and the #418 require
    // gate — reads truthful idle instead of the stale WTS LastInputTime.
    #[cfg(target_os = "windows")]
    if let Ok(self_exe) = std::env::current_exe() {
        tokio::spawn(session_supervisor::run(self_exe.clone()));
        // #1140 PR3b: serve `remote.ctrl.<pc_id>`. Subscribing unconditionally
        // at startup is the point — the responder has to already be listening
        // when an operator first clicks "connect", so it cannot be started on
        // demand. Subscribing costs nothing until a Start arrives: no capture
        // child exists, and therefore no capture, encoding or traffic.
        tokio::spawn(remote_session::serve(
            client.clone(),
            pc_id.clone(),
            self_exe,
        ));
    }
    // #841 PR2: native Windows Event Log reader — power/session/sleep lanes
    // straight from the log via EvtQuery, replacing the collect-winlog-events
    // PowerShell job. Enqueues to the same outbox; the drain publishes them.
    tokio::spawn(winlog::run(pc_id.clone(), obs_outbox_dir.clone()));
    // v0.23: schedules marked `runs_on: agent` tick locally so the
    // agent keeps firing even when the broker is unreachable. See
    // `crates/kanade-agent/src/local_scheduler.rs` for the flow.
    let completions_path = default_paths::data_dir().join("local_completions.json");
    local_scheduler::spawn(
        client.clone(),
        pc_id.clone(),
        completions_path,
        groups_rx,
        staleness_tracker.clone(),
        script_cache.clone(),
        check_sink.clone(),
    );

    let _ = tokio::join!(
        commands::command_loop(
            client.clone(),
            pc_id.clone(),
            dedup.clone(),
            staleness_tracker.clone(),
            cmd_all,
            script_cache.clone(),
            check_sink.clone(),
            verifier.clone(),
        ),
        commands::command_loop(
            client.clone(),
            pc_id.clone(),
            dedup.clone(),
            staleness_tracker.clone(),
            cmd_self,
            script_cache.clone(),
            check_sink.clone(),
            verifier.clone(),
        ),
    );

    Ok(())
}

/// Build the tracing subscriber: stdout (useful in foreground /
/// `cargo run` mode) + a daily-rotated file appender pointed at
/// `log.path`. `RUST_LOG`, if set, overrides `log.level`. Returns
/// the appender's `WorkerGuard`, which the caller must keep alive
/// — its Drop flushes the non-blocking writer's pending buffer.
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
    let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("agent");
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("log");

    std::fs::create_dir_all(dir).with_context(|| format!("create log dir {dir:?}"))?;

    let appender = tracing_appender::rolling::Builder::new()
        .filename_prefix(stem)
        .filename_suffix(ext)
        .rotation(tracing_appender::rolling::Rotation::DAILY)
        .max_log_files(log.keep_days)
        .build(dir)
        .context("build rolling file appender")?;
    let (file_writer, guard) = tracing_appender::non_blocking(appender);

    let _ = tracing_subscriber::registry()
        .with(env_filter)
        .with(tracing_subscriber::fmt::layer().with_writer(std::io::stdout))
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(file_writer)
                .with_ansi(false),
        )
        .try_init();

    Ok(Some(guard))
}

/// Remove `<exe>.old` / `<exe>.new` left over from the previous
/// self-update cycle. `.old` is the previous-version exe, no longer
/// loaded; `.new` would only exist if a swap was interrupted before
/// the final rename (the in-place exe is still valid in that case).
/// Either way, removal here keeps the install dir tidy and stops
/// stale binaries from accumulating across upgrade cycles.
fn cleanup_stale_upgrade_artifacts() {
    let Ok(current) = std::env::current_exe() else {
        return;
    };
    let Some(exe_dir) = current.parent() else {
        return;
    };
    let Some(exe_name) = current.file_name().and_then(|n| n.to_str()) else {
        return;
    };
    for suffix in ["old", "new"] {
        let path = exe_dir.join(format!("{exe_name}.{suffix}"));
        if !path.exists() {
            continue;
        }
        match std::fs::remove_file(&path) {
            Ok(_) => tracing::info!(?path, suffix, "removed stale upgrade artifact"),
            Err(e) => {
                tracing::warn!(?path, suffix, error = %e, "couldn't remove stale upgrade artifact")
            }
        }
    }
}
