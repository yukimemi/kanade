//! Layered fleet configuration that lives in the `agent_config` KV
//! bucket (Sprint 6).
//!
//! Three scopes flow into the agent's effective config, in order of
//! increasing specificity:
//!
//! ```text
//! built-in default        (compiled in; floor when nothing else is set)
//!   ↓
//! agent_config:global     (whole-fleet default)
//!   ↓
//! agent_config:groups.<g> (per-group override; one or more apply)
//!   ↓
//! agent_config:pcs.<pc>   (per-PC override; final word)
//! ```
//!
//! The wire type for every scope is the same — [`ConfigScope`], a
//! struct of `Option<T>` fields. `Some` means "this scope sets this
//! field"; `None` means "fall through to the next layer". JSON
//! `null` is the same as the field being absent thanks to serde's
//! struct-level `default`.
//!
//! [`resolve`] is the pure functional core that flattens the scope
//! stack into an [`EffectiveConfig`] (concrete values, no Options).
//! When the same field is set on more than one group the PC belongs
//! to, alphabetical group order wins last (CSS-cascade style) and a
//! [`ResolutionWarning::MultiGroupConflict`] is emitted so the
//! caller can log it — pre-empts the "why does this PC have value X?
//! none of my groups say X" debugging session.
//!
//! v0.20.0: `inventory_interval` / `inventory_jitter` /
//! `inventory_enabled` removed. They were leftovers from the
//! v0.14-retired hardcoded WMI inventory loop; runtime inventory
//! now lives in operator-defined probe jobs (`configs/jobs/
//! inventory-*.yaml`), so the layered config no longer carries
//! anything about it.

use std::collections::BTreeMap;
use std::time::Duration;

use serde::{Deserialize, Serialize};

/// Per-scope partial config. Every field is `Option<T>`: `Some` =
/// set, `None` = inherit from the next-less-specific scope. Serde
/// `default` + `skip_serializing_if` keeps the wire JSON tight —
/// unset fields don't appear in the bucket value.
#[derive(Serialize, Deserialize, Debug, Clone, Default, PartialEq, Eq)]
#[serde(default)]
pub struct ConfigScope {
    /// Maximum simultaneous non-Client jobs on each PC.
    /// Unset uses the agent CPU count; zero is invalid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_local_concurrent: Option<std::num::NonZeroU32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_version: Option<String>,
    /// Random sleep window applied at each agent before it starts
    /// downloading a new target_version, so a fleet-wide rollout
    /// doesn't slam the Object Store / broker all at once
    /// (humantime, e.g. `"30m"`). `"0s"` = no jitter (explicit
    /// opt-in for canary / single-PC deploys); unset falls back to
    /// the safe built-in default (10m — #491).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_version_jitter: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_interval: Option<String>,
    /// Cadence for the whole-host perf snapshot loop (`host_perf.<pc_id>`).
    /// Separate from `heartbeat_interval` because the host-wide
    /// sysinfo refresh is slightly heavier than the per-process self-
    /// perf one (memory + disk + network counters in addition to CPU)
    /// and gappier data is acceptable for graphing. Default 60 s.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_perf_interval: Option<String>,
    /// v0.41 / Phase 2: operator-driven opt-in for the heavy per-
    /// process snapshot loop (`process_perf.<pc_id>`). Default off
    /// because walking the full process table is the most expensive
    /// sysinfo call on Citrix / RDS hosts; flip on only when an
    /// operator is actively investigating a host. Paired with
    /// `process_perf_expires_at` to auto-disable after a window —
    /// see [`EffectiveConfig::process_perf_active_at`].
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_perf_enabled: Option<bool>,
    /// Wall-clock RFC3339 timestamp after which `process_perf_enabled`
    /// is considered expired and the agent stops publishing process
    /// snapshots — even if the flag itself is still `true`. Lets the
    /// SPA toggle "ON for 30 m" without the operator having to come
    /// back and clear the flag manually. `None` (or the past) +
    /// enabled=true means "indefinitely on" (rare; mostly a test path).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_perf_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Top-N processes (ordered by CPU%) the agent publishes per tick.
    /// 20 by default — enough to cover the usual suspects on a
    /// constrained host without ballooning the projector row volume
    /// when several PCs are simultaneously in investigation mode.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_perf_top_n: Option<u32>,
    /// Operator-facing product name the end-user Client App shows in
    /// its window title, header, Start-Menu shortcut, and toast
    /// attribution — so each deployment can brand the client for its
    /// customer (e.g. `"端末管理支援ツール"`) instead of surfacing the
    /// internal `kanade` name. Flows to the client via the KLP
    /// handshake (window title / header) and is materialised into the
    /// all-users Start-Menu shortcut by the agent (Start-Menu label /
    /// toast sender name). `None` = inherit; the client falls back to
    /// the built-in default name when nothing sets it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_display_name: Option<String>,
}

impl ConfigScope {
    pub fn is_empty(&self) -> bool {
        self.max_local_concurrent.is_none()
            && self.target_version.is_none()
            && self.target_version_jitter.is_none()
            && self.heartbeat_interval.is_none()
            && self.host_perf_interval.is_none()
            && self.process_perf_enabled.is_none()
            && self.process_perf_expires_at.is_none()
            && self.process_perf_top_n.is_none()
            && self.client_display_name.is_none()
    }
}

/// Concrete config the agent runs against once the scope stack has
/// been flattened. `target_version` stays `Option` because "no
/// rollout target set anywhere" is a meaningful state (the agent
/// just keeps running the version it has); the other fields always
/// have a value, falling back to [`EffectiveConfig::builtin_defaults`]
/// when no scope sets them.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub struct EffectiveConfig {
    /// None means automatic sizing on the endpoint, never on the backend.
    #[serde(default)]
    pub max_local_concurrent: Option<std::num::NonZeroU32>,
    pub target_version: Option<String>,
    pub target_version_jitter: String,
    pub heartbeat_interval: String,
    pub host_perf_interval: String,
    /// v0.41 / Phase 2 — see [`ConfigScope::process_perf_enabled`].
    pub process_perf_enabled: bool,
    /// v0.41 / Phase 2 — see [`ConfigScope::process_perf_expires_at`].
    pub process_perf_expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// v0.41 / Phase 2 — see [`ConfigScope::process_perf_top_n`].
    pub process_perf_top_n: u32,
    /// Operator-facing client product name — see
    /// [`ConfigScope::client_display_name`]. Stays `Option` (unlike
    /// the perf fields) because "no name set anywhere" is a real
    /// state: the client then falls back to its built-in default name
    /// rather than the agent inventing one here.
    pub client_display_name: Option<String>,
}

impl EffectiveConfig {
    /// Floor values used when no KV scope sets a given field.
    pub fn builtin_defaults() -> Self {
        Self {
            max_local_concurrent: None,
            target_version: None,
            // #491: safe-by-default. The pre-Sprint-11 "0s" default
            // meant a fleet-wide target_version flip made every
            // agent pull the multi-MB binary from the Object Store
            // at the same instant (3,000 hosts ≈ tens of GB through
            // one broker NIC) unless the operator remembered
            // `--jitter` on every rollout. 10m amortises a
            // 3,000-host fleet to ~5 downloads/s while staying
            // tolerable for mid-size rollouts. Canary / dev flows
            // that want the immediate swap opt in explicitly with
            // `--jitter 0s` (fleet-deploy.ps1 does this for
            // single-PC deploys).
            target_version_jitter: "10m".to_string(),
            heartbeat_interval: "30s".to_string(),
            // 60 s default: 2× the heartbeat cadence so the chart has
            // a roughly aligned point every other heartbeat, while
            // keeping the host-wide sysinfo refresh (which on Citrix /
            // RDS hosts is the heaviest call we make) out of the
            // tight 30 s loop.
            host_perf_interval: "60s".to_string(),
            // Off by default. Per-process collection walks the full
            // OS process table — the most expensive sysinfo call —
            // so the fleet pays nothing until an operator opts a
            // specific host into "investigation mode".
            process_perf_enabled: false,
            process_perf_expires_at: None,
            process_perf_top_n: 20,
            // No name set anywhere → the client renders its built-in
            // default product name. The agent does not invent one here
            // so "unset" stays distinguishable from "explicitly named".
            client_display_name: None,
        }
    }

    /// Returns true when process-perf collection should actually run
    /// **right now**: the flag is set AND no expiry has passed.
    /// Centralised here so agent / backend / SPA all agree on the
    /// active-vs-expired distinction.
    pub fn process_perf_active_at(&self, now: chrono::DateTime<chrono::Utc>) -> bool {
        if !self.process_perf_enabled {
            return false;
        }
        match self.process_perf_expires_at {
            None => true,
            Some(deadline) => now < deadline,
        }
    }

    /// Parsed `heartbeat_interval`, falling back to the built-in
    /// 30 s default on a malformed string. Logging the parse error
    /// is the caller's job (so that test code can stay quiet).
    pub fn heartbeat_duration(&self) -> Duration {
        humantime::parse_duration(&self.heartbeat_interval).unwrap_or(Duration::from_secs(30))
    }

    /// Parsed `host_perf_interval`, falling back to the built-in
    /// 60 s default on a malformed string.
    pub fn host_perf_duration(&self) -> Duration {
        humantime::parse_duration(&self.host_perf_interval).unwrap_or(Duration::from_secs(60))
    }

    /// Parsed `target_version_jitter`. #491: a malformed string
    /// falls back to the safe built-in default (10 m), not zero —
    /// the old ZERO fallback silently turned a `--jitter 30minutes`
    /// typo into the exact fleet-wide download herd the flag exists
    /// to prevent. The write boundaries (CLI `config set` /
    /// `agent rollout`, backend rollout API) now reject malformed
    /// strings outright, so this fallback only covers values that
    /// predate that validation.
    pub fn target_version_jitter_duration(&self) -> Duration {
        humantime::parse_duration(&self.target_version_jitter)
            .unwrap_or(Duration::from_secs(10 * 60))
    }
}

impl Default for EffectiveConfig {
    fn default() -> Self {
        Self::builtin_defaults()
    }
}

/// Non-fatal observations from [`resolve`] that the caller should
/// log. Currently only "two of this PC's groups set the same field
/// to different values" — useful pre-emptive debugging signal when
/// canary / wave / dept overlays accidentally overlap.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolutionWarning {
    MultiGroupConflict {
        field: &'static str,
        /// Group names that set this field, in alphabetical order
        /// (i.e. the application order — the last name in this list
        /// is the one whose value actually won).
        groups: Vec<String>,
    },
}

/// Flatten the scope stack into an [`EffectiveConfig`].
///
/// * `global` — the `global` key in the `agent_config` bucket
///   (`None` if no row yet).
/// * `group_scopes` — every `groups.<name>` row currently in the
///   bucket (the caller can pass all of them; only the ones whose
///   name is in `my_groups` are applied).
/// * `pc_scope` — the `pcs.<pc_id>` row for this agent (`None` if
///   no row yet).
/// * `my_groups` — this agent's current memberships (from the
///   `agent_groups` bucket).
///
/// Order of application: built-in default → global → per-group
/// (alphabetical, last wins) → per-pc. Multi-group conflicts (≥ 2
/// of `my_groups` setting the same field) are returned as warnings
/// alongside the resolved config.
pub fn resolve(
    global: Option<&ConfigScope>,
    group_scopes: &BTreeMap<String, ConfigScope>,
    pc_scope: Option<&ConfigScope>,
    my_groups: &[String],
) -> (EffectiveConfig, Vec<ResolutionWarning>) {
    let mut out = EffectiveConfig::builtin_defaults();
    let mut warnings = Vec::new();

    if let Some(g) = global {
        apply_scope(&mut out, g);
    }

    // Sort + dedup the group list so iteration order is deterministic
    // and "last wins" is well-defined.
    let mut sorted_groups: Vec<&str> = my_groups.iter().map(String::as_str).collect();
    sorted_groups.sort();
    sorted_groups.dedup();

    // Pass 1: find multi-setter fields so the caller can warn before
    // pass 2 silently lets the alphabetical-last value win.
    let mut setters: BTreeMap<&'static str, Vec<String>> = BTreeMap::new();
    for g in &sorted_groups {
        let Some(scope) = group_scopes.get(*g) else {
            continue;
        };
        if scope.max_local_concurrent.is_some() {
            setters
                .entry("max_local_concurrent")
                .or_default()
                .push(g.to_string());
        }
        if scope.target_version.is_some() {
            setters
                .entry("target_version")
                .or_default()
                .push(g.to_string());
        }
        if scope.target_version_jitter.is_some() {
            setters
                .entry("target_version_jitter")
                .or_default()
                .push(g.to_string());
        }
        if scope.heartbeat_interval.is_some() {
            setters
                .entry("heartbeat_interval")
                .or_default()
                .push(g.to_string());
        }
        if scope.host_perf_interval.is_some() {
            setters
                .entry("host_perf_interval")
                .or_default()
                .push(g.to_string());
        }
        if scope.process_perf_enabled.is_some() {
            setters
                .entry("process_perf_enabled")
                .or_default()
                .push(g.to_string());
        }
        if scope.process_perf_expires_at.is_some() {
            setters
                .entry("process_perf_expires_at")
                .or_default()
                .push(g.to_string());
        }
        if scope.process_perf_top_n.is_some() {
            setters
                .entry("process_perf_top_n")
                .or_default()
                .push(g.to_string());
        }
        if scope.client_display_name.is_some() {
            setters
                .entry("client_display_name")
                .or_default()
                .push(g.to_string());
        }
    }
    for (field, groups) in setters {
        if groups.len() > 1 {
            warnings.push(ResolutionWarning::MultiGroupConflict { field, groups });
        }
    }

    // Pass 2: actually apply, alphabetically. Last-wins by construction.
    for g in &sorted_groups {
        if let Some(scope) = group_scopes.get(*g) {
            apply_scope(&mut out, scope);
        }
    }

    if let Some(p) = pc_scope {
        apply_scope(&mut out, p);
    }

    (out, warnings)
}

fn apply_scope(out: &mut EffectiveConfig, s: &ConfigScope) {
    if let Some(v) = s.max_local_concurrent {
        out.max_local_concurrent = Some(v);
    }
    if let Some(v) = &s.target_version {
        out.target_version = Some(v.clone());
    }
    if let Some(v) = &s.target_version_jitter {
        out.target_version_jitter = v.clone();
    }
    if let Some(v) = &s.heartbeat_interval {
        out.heartbeat_interval = v.clone();
    }
    if let Some(v) = &s.host_perf_interval {
        out.host_perf_interval = v.clone();
    }
    if let Some(v) = s.process_perf_enabled {
        out.process_perf_enabled = v;
    }
    if let Some(v) = s.process_perf_expires_at {
        out.process_perf_expires_at = Some(v);
    }
    if let Some(v) = s.process_perf_top_n {
        out.process_perf_top_n = v;
    }
    if let Some(v) = &s.client_display_name {
        out.client_display_name = Some(v.clone());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_limit_inherits_and_rejects_zero() {
        let global: ConfigScope = serde_json::from_str(r#"{"max_local_concurrent":4}"#).unwrap();
        let pc: ConfigScope = serde_json::from_str(r#"{"max_local_concurrent":2}"#).unwrap();
        assert!(!pc.is_empty());
        assert!(serde_json::from_str::<ConfigScope>(r#"{"max_local_concurrent":0}"#).is_err());
        let (inherited, _) = resolve(Some(&global), &BTreeMap::new(), None, &[]);
        assert_eq!(inherited.max_local_concurrent.unwrap().get(), 4);
        let (overridden, _) = resolve(Some(&global), &BTreeMap::new(), Some(&pc), &[]);
        assert_eq!(overridden.max_local_concurrent.unwrap().get(), 2);
        assert!(EffectiveConfig::default().max_local_concurrent.is_none());
    }
    fn scope() -> ConfigScope {
        ConfigScope::default()
    }

    #[test]
    fn empty_stack_gives_builtin_defaults() {
        let (eff, warns) = resolve(None, &BTreeMap::new(), None, &[]);
        assert_eq!(eff, EffectiveConfig::builtin_defaults());
        assert!(warns.is_empty());
    }

    #[test]
    fn client_display_name_unset_resolves_to_none() {
        // Nothing sets it → stays None so the client uses its built-in
        // default product name (the agent never invents one).
        let (eff, _) = resolve(None, &BTreeMap::new(), None, &[]);
        assert!(eff.client_display_name.is_none());
    }

    #[test]
    fn client_display_name_layers_global_then_pc() {
        let global = ConfigScope {
            client_display_name: Some("端末管理支援ツール".into()),
            ..scope()
        };
        let (eff, _) = resolve(Some(&global), &BTreeMap::new(), None, &[]);
        assert_eq!(
            eff.client_display_name.as_deref(),
            Some("端末管理支援ツール")
        );

        // A per-pc override is the final word — lets one machine carry
        // a customer-specific name distinct from the fleet default.
        let pc = ConfigScope {
            client_display_name: Some("PC専用名".into()),
            ..scope()
        };
        let (eff, _) = resolve(Some(&global), &BTreeMap::new(), Some(&pc), &[]);
        assert_eq!(eff.client_display_name.as_deref(), Some("PC専用名"));
    }

    #[test]
    fn client_display_name_multi_group_conflict_warns() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "site-a".into(),
            ConfigScope {
                client_display_name: Some("A社ツール".into()),
                ..scope()
            },
        );
        groups.insert(
            "site-b".into(),
            ConfigScope {
                client_display_name: Some("B社ツール".into()),
                ..scope()
            },
        );
        let (eff, warns) = resolve(None, &groups, None, &["site-a".into(), "site-b".into()]);
        // "site-b" sorts last alphabetically, so it wins.
        assert_eq!(eff.client_display_name.as_deref(), Some("B社ツール"));
        assert_eq!(warns.len(), 1);
        match &warns[0] {
            ResolutionWarning::MultiGroupConflict { field, .. } => {
                assert_eq!(*field, "client_display_name");
            }
        }
    }

    #[test]
    fn global_only() {
        let g = ConfigScope {
            heartbeat_interval: Some("60s".into()),
            ..scope()
        };
        let (eff, _) = resolve(Some(&g), &BTreeMap::new(), None, &[]);
        assert_eq!(eff.heartbeat_interval, "60s");
        // Unset fields stay at builtin defaults (#491: jitter's
        // builtin default is the safe 10m, not 0s).
        assert_eq!(eff.target_version_jitter, "10m");
        assert!(eff.target_version.is_none());
    }

    #[test]
    fn group_overrides_global() {
        let global = ConfigScope {
            heartbeat_interval: Some("30s".into()),
            ..scope()
        };
        let mut groups = BTreeMap::new();
        groups.insert(
            "canary".into(),
            ConfigScope {
                heartbeat_interval: Some("5s".into()),
                ..scope()
            },
        );
        let (eff, warns) = resolve(Some(&global), &groups, None, &["canary".into()]);
        assert_eq!(eff.heartbeat_interval, "5s");
        assert!(warns.is_empty());
    }

    #[test]
    fn pc_overrides_group() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "wave1".into(),
            ConfigScope {
                heartbeat_interval: Some("30s".into()),
                ..scope()
            },
        );
        let pc = ConfigScope {
            heartbeat_interval: Some("5s".into()),
            ..scope()
        };
        let (eff, _) = resolve(None, &groups, Some(&pc), &["wave1".into()]);
        assert_eq!(eff.heartbeat_interval, "5s");
    }

    #[test]
    fn pc_overrides_global_when_no_group_match() {
        let global = ConfigScope {
            heartbeat_interval: Some("30s".into()),
            ..scope()
        };
        let pc = ConfigScope {
            heartbeat_interval: Some("5s".into()),
            ..scope()
        };
        let (eff, _) = resolve(Some(&global), &BTreeMap::new(), Some(&pc), &[]);
        assert_eq!(eff.heartbeat_interval, "5s");
    }

    #[test]
    fn partial_override_only_changes_named_fields() {
        let global = ConfigScope {
            target_version_jitter: Some("30m".into()),
            heartbeat_interval: Some("30s".into()),
            ..scope()
        };
        let pc = ConfigScope {
            heartbeat_interval: Some("15s".into()),
            // intentionally not touching target_version_jitter
            ..scope()
        };
        let (eff, _) = resolve(Some(&global), &BTreeMap::new(), Some(&pc), &[]);
        assert_eq!(eff.target_version_jitter, "30m"); // from global
        assert_eq!(eff.heartbeat_interval, "15s"); // from pc
    }

    #[test]
    fn multi_group_conflict_emits_warning() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "wave1".into(),
            ConfigScope {
                heartbeat_interval: Some("5s".into()),
                ..scope()
            },
        );
        groups.insert(
            "dept-eng".into(),
            ConfigScope {
                heartbeat_interval: Some("60s".into()),
                ..scope()
            },
        );
        let (eff, warns) = resolve(None, &groups, None, &["wave1".into(), "dept-eng".into()]);
        // "dept-eng" sorts before "wave1", so wave1 wins (last alphabetical).
        assert_eq!(eff.heartbeat_interval, "5s");
        assert_eq!(warns.len(), 1);
        match &warns[0] {
            ResolutionWarning::MultiGroupConflict { field, groups } => {
                assert_eq!(*field, "heartbeat_interval");
                assert_eq!(groups, &vec!["dept-eng".to_string(), "wave1".to_string()]);
            }
        }
    }

    #[test]
    fn group_alphabetical_last_wins_no_conflict_when_only_one_sets() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "wave1".into(),
            ConfigScope {
                heartbeat_interval: Some("5s".into()),
                ..scope()
            },
        );
        groups.insert(
            "dept-eng".into(),
            ConfigScope {
                // Different field — doesn't conflict.
                target_version_jitter: Some("15m".into()),
                ..scope()
            },
        );
        let (eff, warns) = resolve(None, &groups, None, &["wave1".into(), "dept-eng".into()]);
        assert_eq!(eff.heartbeat_interval, "5s");
        assert_eq!(eff.target_version_jitter, "15m");
        assert!(warns.is_empty());
    }

    #[test]
    fn unknown_group_is_silently_ignored() {
        // my_groups names a group that has no scope row yet. Common
        // on the first agent that joins a freshly-named group; the
        // resolver should treat it as a no-op, not an error.
        let mut groups = BTreeMap::new();
        groups.insert(
            "canary".into(),
            ConfigScope {
                heartbeat_interval: Some("5s".into()),
                ..scope()
            },
        );
        let (eff, warns) = resolve(
            None,
            &groups,
            None,
            &["canary".into(), "ghost-group".into()],
        );
        assert_eq!(eff.heartbeat_interval, "5s");
        assert!(warns.is_empty());
    }

    #[test]
    fn group_scope_not_applied_when_pc_not_in_group() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "canary".into(),
            ConfigScope {
                target_version: Some("0.3.0".into()),
                ..scope()
            },
        );
        let (eff, _) = resolve(None, &groups, None, &["dept-eng".into()]);
        // PC is NOT in canary, so the rollout target shouldn't apply.
        assert!(eff.target_version.is_none());
    }

    #[test]
    fn duplicate_group_names_dedup_silently() {
        let mut groups = BTreeMap::new();
        groups.insert(
            "wave1".into(),
            ConfigScope {
                heartbeat_interval: Some("5s".into()),
                ..scope()
            },
        );
        // my_groups carries the same name twice — the dedup pass
        // keeps it from looking like a conflict-with-self.
        let (eff, warns) = resolve(None, &groups, None, &["wave1".into(), "wave1".into()]);
        assert_eq!(eff.heartbeat_interval, "5s");
        assert!(warns.is_empty());
    }

    #[test]
    fn config_scope_serde_round_trip() {
        let s = ConfigScope {
            target_version: Some("0.3.0".into()),
            heartbeat_interval: Some("15s".into()),
            ..scope()
        };
        let json = serde_json::to_string(&s).unwrap();
        // Only set fields appear in JSON.
        assert_eq!(
            json,
            r#"{"target_version":"0.3.0","heartbeat_interval":"15s"}"#
        );
        let back: ConfigScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn empty_config_scope_round_trips_as_empty_json() {
        let s = ConfigScope::default();
        assert!(s.is_empty());
        let json = serde_json::to_string(&s).unwrap();
        assert_eq!(json, "{}");
        let back: ConfigScope = serde_json::from_str(&json).unwrap();
        assert_eq!(back, s);
    }

    #[test]
    fn deserialize_tolerates_unknown_fields_for_forward_compat() {
        // Older agent / backend builds should keep parsing in case
        // we add fields later. v0.20 also relies on this so pre-v0.20
        // rows that still have inventory_interval / inventory_jitter
        // / inventory_enabled in the bucket value parse OK as the
        // new (smaller) ConfigScope — the dropped fields just
        // dissolve into "unknown, ignored".
        let json =
            r#"{"target_version":"0.3.0","inventory_interval":"24h","future_knob":"future_value"}"#;
        let s: ConfigScope = serde_json::from_str(json).unwrap();
        assert_eq!(s.target_version.as_deref(), Some("0.3.0"));
    }

    #[test]
    fn pc_does_not_override_other_pcs() {
        // Sanity: pc_scope passed in is by definition the row for THIS
        // pc; the caller is responsible for picking the right one.
        // This test guards against a future refactor that accidentally
        // wires in the wrong scope by ensuring the apply happens last
        // (after groups), so the PC value is the visible one.
        let mut groups = BTreeMap::new();
        groups.insert(
            "wave1".into(),
            ConfigScope {
                heartbeat_interval: Some("30s".into()),
                ..scope()
            },
        );
        let pc = ConfigScope {
            heartbeat_interval: Some("5s".into()),
            ..scope()
        };
        let (eff, _) = resolve(None, &groups, Some(&pc), &["wave1".into()]);
        assert_eq!(eff.heartbeat_interval, "5s");
    }

    #[test]
    fn malformed_jitter_falls_back_to_safe_default_not_zero() {
        // #491: pre-fix this fell back to ZERO, silently turning a
        // typo'd jitter into a fleet-wide simultaneous download.
        // (Note "30minutes" is VALID humantime — full unit names
        // parse — so the malformed sample must be genuinely broken.)
        let eff = EffectiveConfig {
            target_version_jitter: "not-a-duration".into(),
            ..EffectiveConfig::builtin_defaults()
        };
        assert_eq!(
            eff.target_version_jitter_duration(),
            Duration::from_secs(10 * 60),
        );
        // Explicit 0s remains an honoured opt-in.
        let zero = EffectiveConfig {
            target_version_jitter: "0s".into(),
            ..EffectiveConfig::builtin_defaults()
        };
        assert_eq!(zero.target_version_jitter_duration(), Duration::ZERO);
    }
}
