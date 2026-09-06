# Configuration Reference

`kanade` services rely on structured configurations loaded from TOML files, environment variables, or registry paths.

---

## 1. Agent Configuration

The agent searches for its configuration via the `KANADE_AGENT_CONFIG` environment variable or falls back to native paths.

### Dev Configuration (`configs/agent.dev.toml`)

```toml
# Dev configuration schema
[agent]
id = "dev-pc"
nats_url = "nats://localhost:4223"
data_dir = "target/dev-data/agent"

[log]
level = "debug"
file = "target/dev-data/agent/logs/agent.log"
```

### Configuration Parameters

| Field | Type | Description | Environment Override |
|---|---|---|---|
| `agent.id` | String | Unique hardware identifier (`pc_id`). | `KANADE_DEV_AGENT_ID` (templated) |
| `agent.nats_url` | String | Network address of the NATS broker. | `KANADE_NATS_URL` |
| `agent.data_dir` | Path | Root path to cache outbox scripts, state database, and local completions. | `KANADE_AGENT_DATA_DIR` |
| `log.level` | String | Logging verbosity (`error`, `warn`, `info`, `debug`, `trace`). | `RUST_LOG` |
| `log.file` | Path | Filepath destination for rolling logs. | - |

---

### Per-PC job concurrency

`max_local_concurrent` lives in the layered `agent_config` store, not the
agent TOML file. It applies to backend schedules, agent-local schedules,
and operator runs from the CLI or administration SPA. One agent shares a
single budget across these paths. **User-triggered kanade-client actions
are exempt**: they start without waiting for or consuming a slot. They do
not interrupt jobs already running.

When no scope sets the limit, the agent uses its locally available logical
CPU count (falling back to 1 if detection fails). The backend leaves this
automatic value as `null`; it never substitutes the backend host's CPU count.
An explicit limit must be an integer of at least 1. Scopes apply in order:
built-in automatic default → global → groups → PC.

```sh
kanade config set max_local_concurrent=4
kanade config set --group low-power max_local_concurrent=2
kanade config set --pc EXACT-HOSTNAME max_local_concurrent=1
kanade config unset --pc EXACT-HOSTNAME max_local_concurrent
```

`unset` restores inheritance; when all applicable scopes omit the field,
CPU-based sizing resumes. Updates apply without restarting the agent.
Reducing the limit lets existing jobs finish and holds new jobs until enough
slots are free. A job keeps its slot through retries, collection and finalize.
Jitter happens before admission. Queued jobs can be killed and are skipped if
their starting deadline expires. Waiting does not
consume the script timeout or emit a running lifecycle event. Execution gates
(version pin, revocation, staleness and deadline) are checked before jitter
and again after admission.

Compatibility note: `runs_on: agent` schedules previously omitted their
starting deadline from local commands. They now enforce `starting_deadline`
from the local fire time, including jitter and slot waiting. Existing schedules
whose jitter exceeds that deadline can therefore report a deadline skip even
with a free slot. Keep the deadline longer than the maximum jitter plus the
acceptable queue wait, or omit it when late execution is acceptable.
Kill delivery is best effort: if the broker subscription fails, the agent logs
a warning and continues waiting under the same capacity and deadline rules.

A critical job can opt out for every execution of that manifest:

```yaml
execute:
  shell: powershell
  script: 'Write-Output "critical action"'
  timeout: 30s
  bypass_local_limit: true
```

Exempt jobs consume no slots, so total host concurrency can exceed the limit.
The budget is agent-process-wide; it assumes one agent service per PC.
`constraints.max_concurrent` remains a separate backend, fleet-wide per-job
limit. This setting does not fix its jitter accounting issue (#1373).

## 2. Backend Configuration

The backend coordination layer retrieves its configurations from the file specified by `KANADE_BACKEND_CONFIG` or registers default structures.

### Dev Configuration (`configs/backend.dev.toml`)

```toml
[backend]
listen_addr = "127.0.0.1:8081"
nats_url = "nats://localhost:4223"
database_url = "sqlite://target/dev-data/backend/state.db"

[auth]
# Auth settings
```

### Configuration Parameters

| Field | Type | Description | Environment Override |
|---|---|---|---|
| `backend.listen_addr` | String | Network bind address for HTTP/WebSocket traffic. | `KANADE_BIND_ADDR` |
| `backend.nats_url` | String | Target NATS broker URL. | `KANADE_NATS_URL` |
| `backend.database_url`| String | SQLite database connection string. | `DATABASE_URL` |
| `auth.disable` | Boolean| Set to true to disable operator token validation (dev environment only). | `KANADE_AUTH_DISABLE` |

---

## 3. Windows Registry Integration

In production environments, security-sensitive tokens (like NATS client tokens and administrative API bearer tokens) are stored in the secure Windows Registry rather than plaintext files.

### Key Paths
- **Agent Settings**: `HKLM:\SOFTWARE\Kanade\agent`
- **Backend Settings**: `HKLM:\SOFTWARE\Kanade\backend`

These registry paths are protected with local ACL configurations, allowing read permissions strictly to `SYSTEM` and designated operators.
