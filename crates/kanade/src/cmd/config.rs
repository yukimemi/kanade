//! `kanade config …` — operate the layered agent_config KV bucket
//! (Sprint 6).
//!
//! Goes straight at JetStream KV (same pattern as `agent publish` /
//! `agent groups`) so the operator workstation doesn't need a
//! reachable backend.

use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow, bail};
use clap::{Args, Subcommand};
use futures::StreamExt;
use kanade_shared::kv::{
    BUCKET_AGENT_CONFIG, BUCKET_AGENT_GROUPS, KEY_AGENT_CONFIG_GLOBAL, agent_config_group_key,
    agent_config_pc_key, parse_agent_config_group_key,
};
use kanade_shared::wire::{AgentGroups, ConfigScope, resolve};

#[derive(Args, Debug)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub sub: ConfigSub,
}

#[derive(Args, Debug, Clone)]
pub struct ScopeSel {
    /// Operate on the per-group override `groups.<name>` instead of
    /// the global scope. Mutually exclusive with `--pc`.
    #[arg(long, conflicts_with = "pc", value_name = "NAME")]
    pub group: Option<String>,

    /// Operate on the per-pc override `pcs.<pc_id>` instead of the
    /// global scope. Mutually exclusive with `--group`.
    #[arg(long, conflicts_with = "group", value_name = "PC_ID")]
    pub pc: Option<String>,
}

#[derive(Subcommand, Debug)]
pub enum ConfigSub {
    /// Print the scope's current ConfigScope as pretty-printed JSON.
    Get {
        #[command(flatten)]
        scope: ScopeSel,
    },
    /// Set one field. `<spec>` is `<field>=<value>` (e.g.
    /// `heartbeat_interval=15s`, `host_perf_interval=2m`,
    /// `process_perf_enabled=true`,
    /// `process_perf_expires_at=2026-05-24T15:30:00Z`,
    /// `process_perf_top_n=20`, `target_version_jitter=30m`,
    /// `target_version=0.3.0`,
    /// `client_display_name=端末管理支援ツール`).
    Set {
        spec: String,
        #[command(flatten)]
        scope: ScopeSel,
    },
    /// Clear one field. Equivalent to PUT-ing the same scope back
    /// without that field set.
    Unset {
        field: String,
        #[command(flatten)]
        scope: ScopeSel,
    },
    /// Delete the whole scope row from the bucket.
    Clear {
        #[command(flatten)]
        scope: ScopeSel,
    },
    /// Print the resolved EffectiveConfig for one pc_id — the same
    /// view the agent's config_supervisor computes locally.
    Effective { pc_id: String },
}

pub async fn execute(client: async_nats::Client, args: ConfigArgs) -> Result<()> {
    let js = async_nats::jetstream::new(client);
    let kv = js
        .get_key_value(BUCKET_AGENT_CONFIG)
        .await
        .with_context(|| {
            format!("KV '{BUCKET_AGENT_CONFIG}' missing — run `kanade jetstream setup`")
        })?;
    match args.sub {
        ConfigSub::Get { scope } => get(&kv, &scope).await,
        ConfigSub::Set { spec, scope } => set(&kv, &scope, &spec).await,
        ConfigSub::Unset { field, scope } => unset(&kv, &scope, &field).await,
        ConfigSub::Clear { scope } => clear(&kv, &scope).await,
        ConfigSub::Effective { pc_id } => effective(&js, pc_id).await,
    }
}

fn scope_key(sel: &ScopeSel) -> Result<String> {
    match (&sel.group, &sel.pc) {
        (None, None) => Ok(KEY_AGENT_CONFIG_GLOBAL.to_string()),
        (Some(g), None) => Ok(agent_config_group_key(g)),
        (None, Some(p)) => Ok(agent_config_pc_key(p)),
        // clap's conflicts_with should keep this unreachable.
        (Some(_), Some(_)) => bail!("--group and --pc are mutually exclusive"),
    }
}

fn scope_label(sel: &ScopeSel) -> String {
    match (&sel.group, &sel.pc) {
        (None, None) => "global".into(),
        (Some(g), None) => format!("groups.{g}"),
        (None, Some(p)) => format!("pcs.{p}"),
        (Some(_), Some(_)) => "<invalid>".into(),
    }
}

async fn get(kv: &async_nats::jetstream::kv::Store, sel: &ScopeSel) -> Result<()> {
    let key = scope_key(sel)?;
    let scope = read_scope(kv, &key).await?;
    println!("# {} = {}", scope_label(sel), key);
    println!("{}", serde_json::to_string_pretty(&scope)?);
    Ok(())
}

async fn set(kv: &async_nats::jetstream::kv::Store, sel: &ScopeSel, spec: &str) -> Result<()> {
    let (field, value) = spec
        .split_once('=')
        .ok_or_else(|| anyhow!("expected <field>=<value>, got '{spec}'"))?;
    // Validate the field/value once up front so a typo fails before
    // the CAS loop rather than on every retry.
    apply_field(&mut ConfigScope::default(), field, Some(value))?;
    let key = scope_key(sel)?;
    // #505: CAS read-modify-write — a blind get→put raced e.g. a
    // rollout writing target_version on the same scope and
    // clobbered it.
    kanade_shared::kv_cas::read_modify_write(kv, &key, |scope: &mut ConfigScope| {
        let before = scope.clone();
        // Pre-validated above, so Err is unreachable here; comparing
        // against the prior state lets an already-set value skip the
        // write entirely (no revision bump, no watcher wake).
        let _ = apply_field(scope, field, Some(value));
        *scope != before
    })
    .await?;
    println!("set {field} = {value} on {}", scope_label(sel));
    Ok(())
}

async fn unset(kv: &async_nats::jetstream::kv::Store, sel: &ScopeSel, field: &str) -> Result<()> {
    apply_field(&mut ConfigScope::default(), field, None)?;
    let key = scope_key(sel)?;
    kanade_shared::kv_cas::read_modify_write(kv, &key, |scope: &mut ConfigScope| {
        let before = scope.clone();
        let _ = apply_field(scope, field, None);
        *scope != before
    })
    .await?;
    println!("unset {field} on {}", scope_label(sel));
    Ok(())
}

async fn clear(kv: &async_nats::jetstream::kv::Store, sel: &ScopeSel) -> Result<()> {
    let key = scope_key(sel)?;
    kv.delete(&key).await.context("kv delete")?;
    println!("cleared {} ({})", scope_label(sel), key);
    Ok(())
}

async fn effective(js: &async_nats::jetstream::Context, pc_id: String) -> Result<()> {
    let cfg_kv = js
        .get_key_value(BUCKET_AGENT_CONFIG)
        .await
        .with_context(|| format!("KV '{BUCKET_AGENT_CONFIG}' missing"))?;
    let groups_kv = js
        .get_key_value(BUCKET_AGENT_GROUPS)
        .await
        .with_context(|| format!("KV '{BUCKET_AGENT_GROUPS}' missing"))?;

    // Snapshot every scope row the resolver will need.
    let global_scope = read_scope_optional(&cfg_kv, KEY_AGENT_CONFIG_GLOBAL).await?;
    let pc_scope = read_scope_optional(&cfg_kv, &agent_config_pc_key(&pc_id)).await?;

    let mut group_scopes: BTreeMap<String, ConfigScope> = BTreeMap::new();
    let mut keys = cfg_kv.keys().await.context("kv keys")?;
    while let Some(k) = keys.next().await {
        let k = k.context("kv key entry")?;
        if let Some(group) = parse_agent_config_group_key(&k)
            && let Some(scope) = read_scope_optional(&cfg_kv, &k).await?
        {
            group_scopes.insert(group.to_string(), scope);
        }
    }

    let my_groups = match groups_kv.get(&pc_id).await? {
        Some(bytes) => serde_json::from_slice::<AgentGroups>(&bytes)
            .map(|g| g.groups)
            .unwrap_or_default(),
        None => Vec::new(),
    };

    let (eff, warns) = resolve(
        global_scope.as_ref(),
        &group_scopes,
        pc_scope.as_ref(),
        &my_groups,
    );

    println!("# pc_id      = {pc_id}");
    println!("# my_groups  = {my_groups:?}");
    println!("{}", serde_json::to_string_pretty(&eff)?);
    for w in &warns {
        println!("# warning: {w:?}");
    }
    Ok(())
}

async fn read_scope(kv: &async_nats::jetstream::kv::Store, key: &str) -> Result<ConfigScope> {
    Ok(read_scope_optional(kv, key).await?.unwrap_or_default())
}

async fn read_scope_optional(
    kv: &async_nats::jetstream::kv::Store,
    key: &str,
) -> Result<Option<ConfigScope>> {
    match kv.get(key).await.context("kv get")? {
        Some(bytes) => Ok(Some(
            serde_json::from_slice(&bytes).context("decode ConfigScope")?,
        )),
        None => Ok(None),
    }
}

/// Apply `value` (or `None` for unset) to the named field on
/// `scope`. Lives here rather than as a generic helper because the
/// field names + types are stable enough that an open-coded match
/// is the most readable form.
fn apply_field(scope: &mut ConfigScope, field: &str, value: Option<&str>) -> Result<()> {
    // #491: duration fields are humantime-validated BEFORE the KV
    // put. The agent maps an unparseable value to a silent fallback
    // (jitter especially used to fall back to ZERO — turning a
    // `30minutes`-style typo into a fleet-wide simultaneous-download
    // herd on the next rollout), so the only safe place to catch the
    // typo is the write boundary, where the operator gets an error.
    let parsed_duration = |field: &str, v: Option<&str>| -> Result<Option<String>> {
        match v {
            None => Ok(None),
            Some(v) => {
                humantime::parse_duration(v).with_context(|| {
                    format!("{field}: expected a humantime duration (e.g. 30s, 10m, 1h), got {v:?}")
                })?;
                Ok(Some(v.to_string()))
            }
        }
    };
    match field {
        "max_local_concurrent" => {
            scope.max_local_concurrent = value
                .map(str::parse::<std::num::NonZeroU32>)
                .transpose()
                .context("max_local_concurrent: expected an integer >= 1")?;
        }
        "target_version" => scope.target_version = value.map(String::from),
        "target_version_jitter" => {
            scope.target_version_jitter = parsed_duration(field, value)?;
        }
        "heartbeat_interval" => scope.heartbeat_interval = parsed_duration(field, value)?,
        "host_perf_interval" => scope.host_perf_interval = parsed_duration(field, value)?,
        "process_perf_enabled" => {
            scope.process_perf_enabled = match value {
                None => None,
                Some(v) => Some(v.parse::<bool>().with_context(|| {
                    format!("process_perf_enabled: expected true|false, got {v:?}")
                })?),
            };
        }
        "process_perf_expires_at" => {
            scope.process_perf_expires_at = match value {
                None => None,
                Some(v) => Some(
                    chrono::DateTime::parse_from_rfc3339(v)
                        .with_context(|| {
                            format!(
                                "process_perf_expires_at: expected RFC3339 timestamp, got {v:?}"
                            )
                        })?
                        .with_timezone(&chrono::Utc),
                ),
            };
        }
        "process_perf_top_n" => {
            scope.process_perf_top_n = match value {
                None => None,
                Some(v) => Some(v.parse::<u32>().with_context(|| {
                    format!("process_perf_top_n: expected positive integer, got {v:?}")
                })?),
            };
        }
        // Free-form product name (e.g. "端末管理支援ツール") — no
        // format validation; any non-empty string is a valid brand.
        // The agent/client trim + treat blank as "unset" downstream.
        "client_display_name" => scope.client_display_name = value.map(String::from),
        other => bail!(
            "unknown field '{other}' — supported: max_local_concurrent, target_version, target_version_jitter, heartbeat_interval, host_perf_interval, process_perf_enabled, process_perf_expires_at, process_perf_top_n, client_display_name"
        ),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_limit_sets_clears_and_rejects_invalid_values() {
        let mut s = ConfigScope::default();
        apply_field(&mut s, "max_local_concurrent", Some("2")).unwrap();
        assert_eq!(s.max_local_concurrent.unwrap().get(), 2);
        for value in ["0", "-1", "1.5", "4294967296"] {
            assert!(apply_field(&mut s, "max_local_concurrent", Some(value)).is_err());
        }
        apply_field(&mut s, "max_local_concurrent", None).unwrap();
        assert!(s.max_local_concurrent.is_none());
    }
    #[test]
    fn apply_field_sets_string() {
        let mut s = ConfigScope::default();
        apply_field(&mut s, "heartbeat_interval", Some("15s")).unwrap();
        assert_eq!(s.heartbeat_interval.as_deref(), Some("15s"));
    }

    #[test]
    fn apply_field_unset_clears_string() {
        let mut s = ConfigScope {
            heartbeat_interval: Some("15s".into()),
            ..Default::default()
        };
        apply_field(&mut s, "heartbeat_interval", None).unwrap();
        assert!(s.heartbeat_interval.is_none());
    }

    #[test]
    fn apply_field_sets_and_clears_client_display_name() {
        let mut s = ConfigScope::default();
        apply_field(&mut s, "client_display_name", Some("端末管理支援ツール")).unwrap();
        assert_eq!(s.client_display_name.as_deref(), Some("端末管理支援ツール"));
        apply_field(&mut s, "client_display_name", None).unwrap();
        assert!(s.client_display_name.is_none());
    }

    #[test]
    fn apply_field_rejects_unknown() {
        let mut s = ConfigScope::default();
        let err = apply_field(&mut s, "nope", Some("x")).unwrap_err();
        assert!(err.to_string().contains("unknown field"));
    }

    #[test]
    fn apply_field_rejects_malformed_durations() {
        // #491: a typo'd duration must be rejected at the write
        // boundary, never stored (the agent's parse failure falls
        // back silently — jitter especially used to fall back to
        // ZERO, defeating the rollout stagger fleet-wide).
        let mut s = ConfigScope::default();
        for field in [
            "target_version_jitter",
            "heartbeat_interval",
            "host_perf_interval",
        ] {
            let err = apply_field(&mut s, field, Some("not-a-duration")).unwrap_err();
            assert!(err.to_string().contains("humantime"), "{field}: {err:#}",);
        }
        // Unset still works for validated fields.
        apply_field(&mut s, "target_version_jitter", None).unwrap();
        assert!(s.target_version_jitter.is_none());
    }

    #[test]
    fn scope_key_routing() {
        assert_eq!(
            scope_key(&ScopeSel {
                group: None,
                pc: None
            })
            .unwrap(),
            "global",
        );
        assert_eq!(
            scope_key(&ScopeSel {
                group: Some("canary".into()),
                pc: None
            })
            .unwrap(),
            "groups.canary",
        );
        assert_eq!(
            scope_key(&ScopeSel {
                group: None,
                pc: Some("PC-01".into())
            })
            .unwrap(),
            "pcs.PC-01",
        );
    }
}
