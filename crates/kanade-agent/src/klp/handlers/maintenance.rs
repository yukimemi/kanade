//! `maintenance.*` method handlers (SPEC §2.1 / §2.12.5).
//!
//! - `maintenance.list` — preview the upcoming scheduled jobs that
//!   will fire against THIS PC over the next N days, so the Client App
//!   can answer "what's about to happen on my machine?". Reads
//!   `BUCKET_SCHEDULES` ∩ (this agent's `pc_id` + group membership),
//!   keeps the calendar-shaped schedules (a discrete future fire time,
//!   unlike the every-minute reconcile poll), computes each one's next
//!   cron occurrence, and decorates it with the firing manifest's
//!   display name for the UI.
//!
//! `maintenance.defer` (push back an imminent reboot) lands in a
//! follow-up PR — it's a side-effecting write into the local
//! scheduler's skip state, distinct from this read-only preview.
//!
//! # Why calendar-only
//!
//! Reconcile-shaped schedules (`when: { per_pc | per_target: … }`)
//! lower to [`POLL_CRON`](kanade_shared::manifest) — they tick every
//! minute and re-converge state, so "next fire" for one is always
//! "within 60s" and tells the user nothing about upcoming maintenance.
//! The preview SPEC §2.1 wants is the *calendar* schedules: the nightly
//! reboot, the patch window, the 09:00 reminder. Those carry a real
//! wall-clock fire time, which is exactly what this handler surfaces.
//!
//! # Catalog source
//!
//! Like `jobs.list`, every bucket is read fresh from KV at call time
//! (no cached snapshot), so a schedule edit or a manifest rename takes
//! effect on the client's next `maintenance.list` with no agent
//! restart. This is a cold, user-initiated path (opening a tab), so
//! the extra KV round-trips are immaterial.
//!
//! The pure [`build_maintenance_list`] / [`next_calendar_fire`]
//! helpers are split out from the KV glue so they unit-test without a
//! live NATS.

use std::collections::HashMap;

use chrono::{DateTime, Duration, Utc};
use futures::TryStreamExt;
use kanade_shared::ipc::error::{ErrorKind, RpcError};
use kanade_shared::ipc::jobs::CATEGORY_SOFTWARE_UPDATE;
use kanade_shared::ipc::maintenance::{
    MaintenanceItem, MaintenanceListParams, MaintenanceListResult,
};
use kanade_shared::kv::{BUCKET_AGENT_GROUPS, BUCKET_JOBS, BUCKET_SCHEDULES};
use kanade_shared::manifest::{Manifest, Schedule};
use tracing::warn;

use super::super::connection::ConnectionState;
use super::system::HandlerResult;
use crate::groups::parse_groups;
use crate::local_scheduler::target_includes;

/// `maintenance.list` — upcoming scheduled jobs targeting this PC.
///
/// A connectivity failure opening or scanning any bucket surfaces as
/// [`ErrorKind::InternalError`]; the client retries on the next tab
/// switch. An empty membership read (`agent_groups` has no entry for
/// this PC) is NOT an error — the agent simply belongs to no groups,
/// so only `all` / direct-`pcs` schedules apply.
pub async fn handle_maintenance_list(
    conn: &ConnectionState,
    params: MaintenanceListParams,
) -> HandlerResult<MaintenanceListResult> {
    // `nats` is always wired in production (the listener calls
    // `with_nats`); a `None` here is a unit-test wiring bug, not a
    // client error — mirror `jobs.list`.
    let client = conn.nats.as_ref().ok_or_else(|| {
        RpcError::new(
            ErrorKind::InternalError,
            "maintenance.list: NATS client not wired into the connection",
        )
    })?;
    let js = async_nats::jetstream::new(client.clone());

    let my_groups = read_my_groups(&js, &conn.pc_id).await?;
    let schedules = read_schedules(&js).await?;
    let manifests = read_manifests(&js).await?;

    // Clamp matches the wire contract (`window_days` ∈ [1, 30]); a
    // hand-rolled client sending 0 or 9999 gets a sane preview rather
    // than an empty / unbounded one.
    let window_days = params.window_days.clamp(1, 30);
    Ok(build_maintenance_list(
        &schedules,
        &manifests,
        &conn.pc_id,
        &my_groups,
        Utc::now(),
        window_days,
    ))
}

/// Read this PC's group membership from `BUCKET_AGENT_GROUPS`. A
/// missing entry → no groups (not an error); a broker-level open
/// failure → `InternalError` so the client retries instead of seeing a
/// preview silently missing every group-targeted schedule.
async fn read_my_groups(
    js: &async_nats::jetstream::Context,
    pc_id: &str,
) -> HandlerResult<Vec<String>> {
    let kv = js.get_key_value(BUCKET_AGENT_GROUPS).await.map_err(|e| {
        warn!(error = %e, "maintenance.list: failed to open BUCKET_AGENT_GROUPS");
        RpcError::new(
            ErrorKind::InternalError,
            format!("maintenance.list: open group membership: {e}"),
        )
    })?;
    match kv.get(pc_id).await {
        Ok(Some(bytes)) => Ok(parse_groups(&bytes)),
        Ok(None) => Ok(Vec::new()),
        Err(e) => {
            warn!(error = %e, "maintenance.list: agent_groups read failed");
            Err(RpcError::new(
                ErrorKind::InternalError,
                format!("maintenance.list: read group membership: {e}"),
            ))
        }
    }
}

/// Read every `Schedule` from `BUCKET_SCHEDULES`, skipping unparseable
/// entries (logged) rather than sinking the whole preview — the same
/// tolerance `jobs.list` and the scheduler's catalog walk use. An
/// open / scan failure is a connectivity error and propagates.
async fn read_schedules(js: &async_nats::jetstream::Context) -> HandlerResult<Vec<Schedule>> {
    let kv = js.get_key_value(BUCKET_SCHEDULES).await.map_err(|e| {
        warn!(error = %e, "maintenance.list: failed to open BUCKET_SCHEDULES");
        RpcError::new(
            ErrorKind::InternalError,
            format!("maintenance.list: open schedules: {e}"),
        )
    })?;
    let keys: Vec<String> = kv
        .keys()
        .await
        .map_err(|e| {
            warn!(error = %e, "maintenance.list: BUCKET_SCHEDULES keys() failed");
            RpcError::new(
                ErrorKind::InternalError,
                format!("maintenance.list: scan schedules: {e}"),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            warn!(error = %e, "maintenance.list: schedule key stream faulted mid-iteration");
            RpcError::new(
                ErrorKind::InternalError,
                format!("maintenance.list: stream schedules: {e}"),
            )
        })?;

    let schedules = futures::future::join_all(keys.into_iter().map(|k| {
        let kv = kv.clone();
        async move {
            match kv.get(&k).await {
                Ok(Some(bytes)) => match serde_json::from_slice::<Schedule>(&bytes) {
                    Ok(s) => Some(s),
                    Err(e) => {
                        warn!(key = %k, error = %e, "maintenance.list: skipping unparseable schedule");
                        None
                    }
                },
                Ok(None) => None,
                Err(e) => {
                    warn!(key = %k, error = %e, "maintenance.list: skipping unreadable schedule");
                    None
                }
            }
        }
    }))
    .await
    .into_iter()
    .flatten()
    .collect();
    Ok(schedules)
}

/// Read `BUCKET_JOBS` into an id→manifest map for display-name +
/// `deferrable` lookup. A single bad entry is skipped (logged); an
/// open / scan failure propagates as a connectivity error.
async fn read_manifests(
    js: &async_nats::jetstream::Context,
) -> HandlerResult<HashMap<String, Manifest>> {
    let kv = js.get_key_value(BUCKET_JOBS).await.map_err(|e| {
        warn!(error = %e, "maintenance.list: failed to open BUCKET_JOBS");
        RpcError::new(
            ErrorKind::InternalError,
            format!("maintenance.list: open jobs catalog: {e}"),
        )
    })?;
    let keys: Vec<String> = kv
        .keys()
        .await
        .map_err(|e| {
            warn!(error = %e, "maintenance.list: BUCKET_JOBS keys() failed");
            RpcError::new(
                ErrorKind::InternalError,
                format!("maintenance.list: scan jobs catalog: {e}"),
            )
        })?
        .try_collect()
        .await
        .map_err(|e| {
            warn!(error = %e, "maintenance.list: jobs key stream faulted mid-iteration");
            RpcError::new(
                ErrorKind::InternalError,
                format!("maintenance.list: stream jobs catalog: {e}"),
            )
        })?;

    let pairs = futures::future::join_all(keys.into_iter().map(|k| {
        let kv = kv.clone();
        async move {
            match kv.get(&k).await {
                Ok(Some(bytes)) => match serde_json::from_slice::<Manifest>(&bytes) {
                    Ok(m) => Some((m.id.clone(), m)),
                    Err(e) => {
                        warn!(key = %k, error = %e, "maintenance.list: skipping unparseable manifest");
                        None
                    }
                },
                Ok(None) => None,
                Err(e) => {
                    warn!(key = %k, error = %e, "maintenance.list: skipping unreadable manifest");
                    None
                }
            }
        }
    }))
    .await;
    Ok(pairs.into_iter().flatten().collect())
}

/// Pure core: schedules + manifests → the `maintenance.list` wire
/// result. Keeps the calendar-shaped schedules that (a) are enabled,
/// (b) target this PC, (c) have a next cron fire within
/// `[now, now + window_days]`, and (d) whose `active` window admits
/// that fire — then decorates each with the firing manifest's display
/// name and `deferrable` flag, sorted soonest-first.
pub fn build_maintenance_list(
    schedules: &[Schedule],
    manifests: &HashMap<String, Manifest>,
    pc_id: &str,
    my_groups: &[String],
    now: DateTime<Utc>,
    window_days: u32,
) -> MaintenanceListResult {
    let horizon = now + Duration::days(window_days as i64);
    let mut items: Vec<MaintenanceItem> = schedules
        .iter()
        .filter(|s| s.enabled)
        .filter(|s| target_includes(s, pc_id, my_groups))
        .filter_map(|s| {
            let next = s.next_calendar_fire(now)?;
            // Past the preview horizon, dormant (outside the
            // schedule's `active` window at that fire), or gated by
            // `constraints.window` — `local_tick` skips all three, so
            // a fire the preview shows must pass the same gates.
            if next > horizon || !s.active.contains(next, s.tz) || !s.constraints.allows(next, s.tz)
            {
                return None;
            }
            let manifest = manifests.get(&s.job_id);
            Some(MaintenanceItem {
                schedule_id: s.id.clone(),
                manifest_id: s.job_id.clone(),
                display_name: display_name_for(s, manifest),
                next_fire_at: next,
                deferrable: is_deferrable(manifest),
            })
        })
        .collect();
    // Soonest first; schedule_id breaks ties so two fires at the same
    // instant render in a stable order.
    items.sort_by(|a, b| {
        a.next_fire_at
            .cmp(&b.next_fire_at)
            .then_with(|| a.schedule_id.cmp(&b.schedule_id))
    });
    MaintenanceListResult { items }
}

/// The display name the Client App shows for a previewed fire: the
/// firing manifest's `client:` name when it has one, else the manifest
/// id (== `Schedule.job_id`) so an operator-only job still reads
/// sensibly. SPEC §2.1: "Manifest's display_name (or Manifest.id)".
fn display_name_for(schedule: &Schedule, manifest: Option<&Manifest>) -> String {
    manifest
        .and_then(|m| m.client.as_ref())
        .map(|c| c.name.clone())
        .unwrap_or_else(|| schedule.job_id.clone())
}

/// Whether the SPA should offer the "延期申請" button for this fire.
/// Per SPEC §2.1 that's currently the software-update (reboot) jobs —
/// keyed off the firing manifest's `client:` category. A schedule
/// whose manifest is missing or operator-only (no `client:` block) is
/// never deferrable.
fn is_deferrable(manifest: Option<&Manifest>) -> bool {
    manifest
        .and_then(|m| m.client.as_ref())
        .is_some_and(|c| c.category == CATEGORY_SOFTWARE_UPDATE)
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use kanade_shared::manifest::{
        Active, CalendarSpec, ClientHint, Constraints, Execute, ExecuteShell, FanoutPlan,
        OnFailure, RunsOn, ScheduleTz, When,
    };
    use kanade_shared::wire::{RunAs, Staleness};

    /// Fixed reference instant: 2026-06-09 08:00:00 UTC. A daily 09:00
    /// calendar schedule fires at 09:00 the same day — one hour out,
    /// comfortably inside any window.
    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 6, 9, 8, 0, 0).unwrap()
    }

    /// A daily-`at` calendar schedule (UTC) targeting all PCs.
    fn cal_schedule(id: &str, job_id: &str, at: &str) -> Schedule {
        let mut plan = FanoutPlan::default();
        plan.target.all = true;
        Schedule {
            id: id.into(),
            when: When::Calendar(CalendarSpec {
                at: at.into(),
                days: vec![],
            }),
            job_id: job_id.into(),
            plan,
            active: Active::default(),
            constraints: Constraints::default(),
            on_failure: OnFailure::default(),
            tz: ScheduleTz::Utc,
            starting_deadline: None,
            runs_on: RunsOn::Backend,
            enabled: true,
            tags: Vec::new(),
            origin: None,
        }
    }

    /// Manifest fixture; `client: Some((name, category_key))` for a
    /// user-invokable job, `None` for operator-only.
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

    fn manifest_map(ms: Vec<Manifest>) -> HashMap<String, Manifest> {
        ms.into_iter().map(|m| (m.id.clone(), m)).collect()
    }

    #[test]
    fn previews_targeted_calendar_fire_with_client_metadata() {
        let schedules = [cal_schedule("nightly-reboot", "reboot-job", "09:00")];
        let manifests = manifest_map(vec![manifest(
            "reboot-job",
            Some(("今夜の再起動", "software_update")),
        )]);
        let r = build_maintenance_list(&schedules, &manifests, "PC1", &[], now(), 7);
        assert_eq!(r.items.len(), 1);
        let it = &r.items[0];
        assert_eq!(it.schedule_id, "nightly-reboot");
        assert_eq!(it.manifest_id, "reboot-job");
        assert_eq!(it.display_name, "今夜の再起動");
        assert!(it.deferrable, "software_update jobs are deferrable");
        assert_eq!(
            it.next_fire_at,
            Utc.with_ymd_and_hms(2026, 6, 9, 9, 0, 0).unwrap()
        );
    }

    #[test]
    fn display_name_and_deferrable_fall_back_without_client() {
        // Operator-only manifest (no client block) → name is the
        // job_id, and the fire is never deferrable.
        let schedules = [cal_schedule("s1", "op-job", "09:00")];
        let manifests = manifest_map(vec![manifest("op-job", None)]);
        let r = build_maintenance_list(&schedules, &manifests, "PC1", &[], now(), 7);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].display_name, "op-job");
        assert!(!r.items[0].deferrable);
    }

    #[test]
    fn missing_manifest_still_previews_with_job_id() {
        // A schedule pointing at a job not (yet) in BUCKET_JOBS still
        // previews — the user should see the pending fire even if the
        // catalog entry is momentarily absent.
        let schedules = [cal_schedule("s1", "ghost-job", "09:00")];
        let r = build_maintenance_list(&schedules, &HashMap::new(), "PC1", &[], now(), 7);
        assert_eq!(r.items.len(), 1);
        assert_eq!(r.items[0].display_name, "ghost-job");
        assert!(!r.items[0].deferrable);
    }

    #[test]
    fn skips_untargeted_schedules() {
        let mut s = cal_schedule("s1", "j", "09:00");
        s.plan.target.all = false;
        s.plan.target.pcs = vec!["OTHER-PC".into()];
        let r = build_maintenance_list(&[s], &HashMap::new(), "PC1", &[], now(), 7);
        assert!(r.items.is_empty(), "schedule targets a different PC");
    }

    #[test]
    fn matches_via_group_membership() {
        let mut s = cal_schedule("s1", "j", "09:00");
        s.plan.target.all = false;
        s.plan.target.groups = vec!["finance".into()];
        let mine = vec!["finance".into()];
        let r = build_maintenance_list(&[s], &HashMap::new(), "PC1", &mine, now(), 7);
        assert_eq!(r.items.len(), 1, "group membership brings the schedule in");
    }

    #[test]
    fn skips_disabled_schedules() {
        let mut s = cal_schedule("s1", "j", "09:00");
        s.enabled = false;
        let r = build_maintenance_list(&[s], &HashMap::new(), "PC1", &[], now(), 7);
        assert!(r.items.is_empty(), "disabled schedules never fire");
    }

    #[test]
    fn skips_reconcile_shapes() {
        use kanade_shared::manifest::{OnceLiteral, PerPolicy};
        let mut s = cal_schedule("s1", "j", "09:00");
        s.when = When::PerPc(PerPolicy::Once(OnceLiteral::Once));
        let r = build_maintenance_list(&[s], &HashMap::new(), "PC1", &[], now(), 7);
        assert!(r.items.is_empty(), "reconcile shapes have no calendar fire");
    }

    #[test]
    fn skips_fires_beyond_the_window() {
        // Weekly Monday 09:00 fire, previewed with a 1-day window from a
        // Tuesday — the next Monday is 6 days out, past the horizon.
        let schedules = [cal_schedule("weekly", "j", "09:00")];
        let mut s = schedules[0].clone();
        s.when = When::Calendar(CalendarSpec {
            at: "09:00".into(),
            days: vec!["mon".into()],
        });
        // now() is 2026-06-09, a Tuesday → next Monday is 6 days away.
        let r = build_maintenance_list(&[s], &HashMap::new(), "PC1", &[], now(), 1);
        assert!(r.items.is_empty(), "fire is past the 1-day horizon");
    }

    #[test]
    fn skips_fires_blocked_by_maintenance_window() {
        // Daily 09:00 UTC fire, but `constraints.window` only admits
        // 22:00-05:00 — `local_tick` would skip every fire, so the
        // preview must not show one.
        let mut s = cal_schedule("nightly", "j", "09:00");
        s.constraints.window = Some("22:00-05:00".into());
        let r = build_maintenance_list(&[s], &HashMap::new(), "PC1", &[], now(), 7);
        assert!(r.items.is_empty(), "09:00 fire is outside 22:00-05:00");
    }

    #[test]
    fn sorts_soonest_first() {
        let schedules = [
            cal_schedule("later", "j", "15:00"),
            cal_schedule("sooner", "j", "09:00"),
        ];
        let r = build_maintenance_list(&schedules, &HashMap::new(), "PC1", &[], now(), 7);
        assert_eq!(r.items.len(), 2);
        assert_eq!(r.items[0].schedule_id, "sooner");
        assert_eq!(r.items[1].schedule_id, "later");
    }
}
