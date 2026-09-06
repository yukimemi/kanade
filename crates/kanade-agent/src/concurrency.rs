//! One process-wide budget shared by NATS, replay and local schedules.
//! Interactive KLP Client actions bypass this budget entirely.
//! A permit covers the entire job, including retries, collection and finalize.
use std::sync::{Arc, Mutex, OnceLock};

use futures::StreamExt;
use kanade_shared::wire::{Command, EXIT_SKIP_DEADLINE, EffectiveConfig};
use tokio::sync::{Mutex as AsyncMutex, Notify, watch};

use crate::process::ExecOutcome;

struct State {
    active: u32,
    limit: u32,
}

struct Limiter {
    state: Mutex<State>,
    queue: AsyncMutex<()>,
    changed: Notify,
}

pub struct Permit(Option<Arc<Limiter>>);

impl Drop for Permit {
    fn drop(&mut self) {
        if let Some(limiter) = &self.0 {
            limiter.state.lock().unwrap().active -= 1;
            limiter.changed.notify_one();
        }
    }
}

impl Limiter {
    fn new(limit: u32) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(State { active: 0, limit }),
            queue: AsyncMutex::new(()),
            changed: Notify::new(),
        })
    }

    fn set_limit(&self, limit: u32) {
        self.state.lock().unwrap().limit = limit;
        self.changed.notify_one();
    }

    fn try_acquire(self: &Arc<Self>, bypass: bool) -> Option<Permit> {
        if bypass {
            return Some(Permit(None));
        }
        // Respect an existing queue. A newcomer may use the fast path only
        // when it can prove no waiter currently owns or awaits this lock.
        let _queue = self.queue.try_lock().ok()?;
        self.try_acquire_slot()
    }

    fn try_acquire_slot(self: &Arc<Self>) -> Option<Permit> {
        let mut state = self.state.lock().unwrap();
        if state.active >= state.limit {
            return None;
        }
        state.active += 1;
        Some(Permit(Some(self.clone())))
    }

    async fn acquire(self: &Arc<Self>, bypass: bool) -> Permit {
        if let Some(permit) = self.try_acquire(bypass) {
            return permit;
        }
        // Serialize waiters so one completion cannot admit a burst.
        let _queue = self.queue.lock().await;
        loop {
            if let Some(permit) = self.try_acquire_slot() {
                return permit;
            }
            // Only the queue head waits here; notify_one retains a permit
            // if a completion/config change raced with the check above.
            self.changed.notified().await;
        }
    }
}

fn shared() -> &'static Arc<Limiter> {
    static LIMITER: OnceLock<Arc<Limiter>> = OnceLock::new();
    LIMITER.get_or_init(|| Limiter::new(cpu_limit()))
}

fn cpu_limit() -> u32 {
    std::thread::available_parallelism()
        .map(|n| u32::try_from(n.get()).unwrap_or(u32::MAX))
        .unwrap_or(1)
}

fn resolved_limit(config: &EffectiveConfig) -> u32 {
    config
        .max_local_concurrent
        .map_or_else(cpu_limit, std::num::NonZeroU32::get)
}

pub fn watch_config(mut config: watch::Receiver<EffectiveConfig>) {
    shared().set_limit(resolved_limit(&config.borrow()));
    tokio::spawn(async move {
        while config.changed().await.is_ok() {
            let limit = resolved_limit(&config.borrow_and_update());
            shared().set_limit(limit);
            tracing::info!(max_local_concurrent = limit, "updated local job limit");
        }
    });
}

/// Wait without consuming the job's runtime timeout. No start event is emitted
/// until admission. Kills and starting deadlines also apply while queued.
pub async fn admit(client: &async_nats::Client, cmd: &Command) -> Result<Permit, ExecOutcome> {
    if cmd.deadline_at.is_some_and(|at| chrono::Utc::now() > at) {
        return Err(deadline_expired());
    }
    if let Some(permit) = shared().try_acquire(cmd.bypass_local_limit) {
        return Ok(permit);
    }
    let mut kill = if let Some(exec_id) = &cmd.exec_id {
        match client
            .subscribe(kanade_shared::subject::kill(exec_id))
            .await
        {
            Ok(sub) => Some(sub),
            Err(e) => {
                tracing::warn!(
                    request_id = %cmd.request_id,
                    error = %e,
                    "kill subscribe failed while waiting for local slot; continuing without kill delivery",
                );
                None
            }
        }
    } else {
        None
    };
    tracing::info!(request_id = %cmd.request_id, "waiting for local job slot");
    wait_for_slot(shared(), cmd.bypass_local_limit, cmd.deadline_at, async {
        if let Some(sub) = &mut kill {
            sub.next().await;
        } else {
            std::future::pending::<()>().await;
        }
    })
    .await
}

async fn wait_for_slot(
    limiter: &Arc<Limiter>,
    bypass: bool,
    deadline_at: Option<chrono::DateTime<chrono::Utc>>,
    killed: impl std::future::Future<Output = ()>,
) -> Result<Permit, ExecOutcome> {
    if deadline_at.is_some_and(|at| chrono::Utc::now() > at) {
        return Err(deadline_expired());
    }
    let deadline = async {
        if let Some(at) = deadline_at {
            let wait = (at - chrono::Utc::now()).to_std().unwrap_or_default();
            tokio::time::sleep(wait).await;
        } else {
            std::future::pending::<()>().await;
        }
    };
    tokio::select! {
        biased;
        _ = deadline => Err(deadline_expired()),
        _ = killed => Err(ExecOutcome::Killed {
            stdout: String::new(),
            stderr: "killed while waiting for local job slot".into(),
        }),
        permit = limiter.acquire(bypass) => Ok(permit),
    }
}

fn deadline_expired() -> ExecOutcome {
    ExecOutcome::Completed {
        exit_code: EXIT_SKIP_DEADLINE,
        stdout: String::new(),
        stderr: "skipped: starting deadline expired while waiting for local job slot".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn newcomers_cannot_steal_a_notified_waiters_slot() {
        let limiter = Limiter::new(1);
        let active = limiter.acquire(false).await;
        let queued = limiter.acquire(false);
        tokio::pin!(queued);
        assert!(futures::poll!(&mut queued).is_pending());
        drop(active);
        // The queue head has been notified but has not been polled again.
        assert!(limiter.try_acquire(false).is_none());
        let interactive = limiter.try_acquire(true).unwrap();
        assert_eq!(limiter.state.lock().unwrap().active, 0);
        let admitted = queued.await;
        assert_eq!(limiter.state.lock().unwrap().active, 1);
        drop((interactive, admitted));
        assert!(limiter.try_acquire(false).is_some());
    }

    #[tokio::test]
    async fn queued_deadlines_and_kills_never_consume_a_slot() {
        let limiter = Limiter::new(1);
        let active = limiter.acquire(false).await;
        let deadline = chrono::Utc::now() + chrono::Duration::milliseconds(20);
        let expired = wait_for_slot(&limiter, false, Some(deadline), std::future::pending()).await;
        assert!(matches!(
            expired,
            Err(ExecOutcome::Completed {
                exit_code: EXIT_SKIP_DEADLINE,
                ..
            })
        ));
        let killed = wait_for_slot(&limiter, false, None, async {}).await;
        assert!(matches!(killed, Err(ExecOutcome::Killed { .. })));
        assert_eq!(limiter.state.lock().unwrap().active, 1);
        drop(active);
        let expired_with_free_slot =
            wait_for_slot(&limiter, false, Some(deadline), std::future::pending()).await;
        assert!(matches!(
            expired_with_free_slot,
            Err(ExecOutcome::Completed {
                exit_code: EXIT_SKIP_DEADLINE,
                ..
            })
        ));
        assert_eq!(limiter.state.lock().unwrap().active, 0);
    }

    #[test]
    fn unset_limit_is_resolved_on_this_agent_and_overrides_win() {
        assert_eq!(resolved_limit(&EffectiveConfig::default()), cpu_limit());
        assert!(cpu_limit() >= 1);
        let config = EffectiveConfig {
            max_local_concurrent: std::num::NonZeroU32::new(3),
            ..Default::default()
        };
        assert_eq!(resolved_limit(&config), 3);
    }

    #[tokio::test]
    async fn jobs_share_slots_and_cancelled_waiters_release_the_queue() {
        let limiter = Limiter::new(1);
        let first = limiter.acquire(false).await;
        assert!(
            tokio::time::timeout(Duration::from_millis(20), limiter.acquire(false))
                .await
                .is_err()
        );
        let bypass = limiter.acquire(true).await;
        assert_eq!(limiter.state.lock().unwrap().active, 1);
        drop(bypass);
        drop(first);
        let next = tokio::time::timeout(Duration::from_secs(1), limiter.acquire(false))
            .await
            .unwrap();
        assert_eq!(limiter.state.lock().unwrap().active, 1);
        drop(next);
        assert_eq!(limiter.state.lock().unwrap().active, 0);
    }

    #[tokio::test]
    async fn resizing_never_cancels_active_jobs_and_wakes_waiters() {
        let limiter = Limiter::new(2);
        let first = limiter.acquire(false).await;
        let second = limiter.acquire(false).await;
        limiter.set_limit(1);
        drop(first);
        assert!(
            tokio::time::timeout(Duration::from_millis(20), limiter.acquire(false))
                .await
                .is_err()
        );
        let waiting = tokio::spawn({
            let limiter = limiter.clone();
            async move { limiter.acquire(false).await }
        });
        limiter.set_limit(2);
        let third = tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(limiter.state.lock().unwrap().active, 2);
        drop((second, third));
    }
}
