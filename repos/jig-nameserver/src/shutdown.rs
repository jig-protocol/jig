//! Graceful shutdown (#438).
//!
//! On SIGTERM or SIGINT the nameserver stops accepting connections, lets
//! requests already in flight finish within `[network] shutdown_drain_ms`, and
//! returns. Whatever is still open when the drain runs out is cut, as before.
//! A registration being written when the drain is cut is stored whole or not
//! at all: each SQLite write is one transaction.
//!
//! This is a copy of `jig_server::shutdown` (#424), less its WebSocket hold:
//! the nameserver has no WebSockets, and the two crates share no runtime
//! crate to keep it in. A fix to one belongs in the other.

use std::future::Future;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The server's shutdown signal and the connections that must drain before
/// it stops. Cloning shares both.
///
/// The listeners spawn every connection through [`Shutdown::spawn`], so
/// [`Shutdown::drain`] waits for all of them.
#[derive(Clone, Debug, Default)]
pub struct Shutdown {
    token: CancellationToken,
    tracker: TaskTracker,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start shutting down: listeners stop accepting, and connections finish
    /// their current request.
    pub fn begin(&self) {
        self.token.cancel();
    }

    pub fn is_shutting_down(&self) -> bool {
        self.token.is_cancelled()
    }

    /// Resolves once [`Shutdown::begin`] has been called.
    pub async fn cancelled(&self) {
        self.token.cancelled().await;
    }

    /// [`Shutdown::cancelled`] as an owned future, for APIs that take one
    /// (`axum::serve(..).with_graceful_shutdown`).
    pub fn cancelled_owned(&self) -> impl Future<Output = ()> + Send + 'static {
        self.token.clone().cancelled_owned()
    }

    /// Spawn `task`, and have [`Shutdown::drain`] wait for it.
    pub fn spawn<F>(&self, task: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tracker.spawn(task)
    }

    /// How many tracked connections and sessions are still running.
    pub fn in_flight(&self) -> usize {
        self.tracker.len()
    }

    /// Wait up to `bound` for every tracked task to finish. `true` when they
    /// all did; `false` when the bound ran out first, leaving the rest to be
    /// cut when the process exits.
    pub async fn drain(&self, bound: Duration) -> bool {
        self.tracker.close();
        tokio::time::timeout(bound, self.tracker.wait())
            .await
            .is_ok()
    }
}

/// How long the runtime waits, once the server has returned, for blocking
/// work still running (a SQLite call) before the process
/// exits anyway. The drain bounds connections; this bounds what they left on
/// the blocking pool.
pub const TEARDOWN_GRACE: Duration = Duration::from_secs(1);

/// Run `main` on a multi-threaded runtime, then shut the runtime down within
/// [`TEARDOWN_GRACE`]. `#[tokio::main]` instead waits, without a bound, for
/// every blocking task already started, so a slow SQLite call (one waiting
/// on a lock, say) could hold a stopping server past its drain.
pub fn run<F: Future>(main: F) -> std::io::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let out = runtime.block_on(main);
    runtime.shutdown_timeout(TEARDOWN_GRACE);
    Ok(out)
}

/// A future that resolves on the next SIGTERM or SIGINT. The handlers are
/// registered when this is called, not when the future is first polled, so a
/// signal that arrives once the server has logged that it is listening is
/// never the default action (an immediate exit).
///
/// The server waits on one to start shutting down, then calls this again
/// while draining, so a second signal cuts the drain short: the escape from a
/// drain an operator won't wait for.
pub fn signal() -> impl Future<Output = ()> + Send + 'static {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let term = signal(SignalKind::terminate());
        let int = signal(SignalKind::interrupt());
        async move {
            let (mut term, mut int) = match (term, int) {
                (Ok(term), Ok(int)) => (term, int),
                (Err(e), _) | (_, Err(e)) => {
                    // No graceful stop; the process keeps the default action.
                    tracing::warn!("cannot listen for SIGTERM/SIGINT ({e}); stopping is immediate");
                    return std::future::pending().await;
                }
            };
            tokio::select! {
                _ = term.recv() => tracing::info!("SIGTERM received"),
                _ = int.recv() => tracing::info!("SIGINT received"),
            }
        }
    }
    #[cfg(not(unix))]
    {
        async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Ctrl-C received");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn drain_waits_for_tracked_tasks_and_is_bounded() {
        let shutdown = Shutdown::new();
        let (done_tx, done_rx) = tokio::sync::oneshot::channel::<()>();
        shutdown.spawn(async move {
            let _ = done_rx.await;
        });
        assert_eq!(shutdown.in_flight(), 1);

        // Still running: the bound runs out.
        let started = std::time::Instant::now();
        assert!(!shutdown.drain(Duration::from_millis(100)).await);
        assert!(started.elapsed() < Duration::from_secs(2));

        // Finished: the drain returns at once.
        done_tx.send(()).unwrap();
        assert!(shutdown.drain(Duration::from_secs(5)).await);
        assert_eq!(shutdown.in_flight(), 0);
    }

    /// Blocking work still running when the server returns does not hold
    /// the process: the runtime gives it [`TEARDOWN_GRACE`], then goes.
    #[test]
    fn run_does_not_wait_for_blocking_work_past_the_grace() {
        let started = std::time::Instant::now();
        let out = run(async {
            let (running_tx, running_rx) = tokio::sync::oneshot::channel();
            tokio::task::spawn_blocking(move || {
                let _ = running_tx.send(());
                std::thread::sleep(Duration::from_secs(30));
            });
            running_rx.await.unwrap();
            7
        })
        .unwrap();
        assert_eq!(out, 7);
        assert!(
            started.elapsed() < TEARDOWN_GRACE + Duration::from_secs(3),
            "returned after {:?}",
            started.elapsed()
        );
    }

    #[tokio::test]
    async fn begin_wakes_every_clone() {
        let shutdown = Shutdown::new();
        let clone = shutdown.clone();
        let waiter = tokio::spawn(async move { clone.cancelled().await });
        assert!(!shutdown.is_shutting_down());
        shutdown.begin();
        tokio::time::timeout(Duration::from_secs(1), waiter)
            .await
            .expect("woken")
            .unwrap();
        assert!(shutdown.is_shutting_down());
    }
}
