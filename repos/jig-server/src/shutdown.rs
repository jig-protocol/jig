//! Graceful shutdown (#424).
//!
//! On SIGTERM or SIGINT the server stops accepting connections, sends each
//! WebSocket client a close frame with code 1001 (going away), lets requests
//! already in flight finish within `[server] shutdown_drain_ms`, and returns.
//! Whatever is still open when the drain runs out is cut, as before.
//!
//! Ingest needs nothing here. A block being ingested when the signal arrives
//! finishes or fails as one unit, because persistence runs in a transaction;
//! the drain only bounds how long the server waits for it.
//!
//! `jig_nameserver::shutdown` (#438) is a copy of this, less the WebSocket
//! hold. A fix to one belongs in the other.

use std::future::Future;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

/// The server's shutdown signal and the connections that must drain before
/// it stops. Cloning shares both.
///
/// The listeners spawn every connection through [`Shutdown::spawn`], and the
/// WebSocket handler holds a token from [`Shutdown::hold`] for each session,
/// so [`Shutdown::drain`] waits for all of them.
#[derive(Clone, Debug, Default)]
pub struct Shutdown {
    token: CancellationToken,
    /// Set when the drain runs out or is cut: every task spawned with
    /// [`Shutdown::spawn_cut`] ends at its next poll.
    cut: CancellationToken,
    tracker: TaskTracker,
}

impl Shutdown {
    pub fn new() -> Self {
        Self::default()
    }

    /// Start shutting down: listeners stop accepting, connections finish
    /// their current request, and WebSocket sessions close with 1001.
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

    /// Spawn `task`, and have [`Shutdown::drain`] wait for it.
    pub fn spawn<F>(&self, task: F) -> tokio::task::JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.tracker.spawn(task)
    }

    /// Have [`Shutdown::drain`] wait until the returned token is dropped.
    /// Taken synchronously, it covers work that starts later, such as a
    /// WebSocket session whose upgrade has not completed yet.
    pub fn hold(&self) -> tokio_util::task::task_tracker::TaskTrackerToken {
        self.tracker.token()
    }

    /// [`Shutdown::spawn`] a connection: `task` also ends, dropped where it
    /// stands, once [`Shutdown::cut`] is called, so nothing outlives a drain
    /// that ran out, whether or not the runtime keeps running.
    pub fn spawn_cut<F>(&self, task: F) -> tokio::task::JoinHandle<()>
    where
        F: Future<Output = ()> + Send + 'static,
    {
        let cut = self.cut.clone();
        self.tracker.spawn(async move {
            tokio::select! {
                () = task => {}
                () = cut.cancelled() => {}
            }
        })
    }

    /// Resolves once [`Shutdown::cut`] has been called.
    pub async fn cut_off(&self) {
        self.cut.cancelled().await;
    }

    /// End every task spawned with [`Shutdown::spawn_cut`], then wait up to
    /// `bound` for the tracked tasks to finish. `true` when they all did.
    pub async fn cut(&self, bound: Duration) -> bool {
        self.cut.cancel();
        self.drain(bound).await
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
/// work still running (a text render, a SQLite call) before the process
/// exits anyway. The drain bounds connections; this bounds what they left on
/// the blocking pool.
pub const TEARDOWN_GRACE: Duration = Duration::from_secs(1);

/// Run `main` on a multi-threaded runtime, then shut the runtime down within
/// [`TEARDOWN_GRACE`]. `#[tokio::main]` instead waits, without a bound, for
/// every blocking task already started, so a render queued for an execution
/// slot could hold a stopping server past its drain.
pub fn run<F: Future>(main: F) -> std::io::Result<F::Output> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    let out = runtime.block_on(main);
    runtime.shutdown_timeout(TEARDOWN_GRACE);
    Ok(out)
}

/// The process's first and second SIGTERM or SIGINT, as two futures. The
/// handlers are registered here, before the server binds, not when a future is
/// first polled: a signal that arrives once the server has logged that it is
/// listening is never the default action (an immediate exit).
///
/// The server waits on the first to start shutting down, and on the second to
/// cut the drain short: the escape from a drain an operator won't wait for.
/// Both come from one set of receivers, kept from start to end, so a second
/// signal that arrives just as the drain begins is not lost.
pub fn signals() -> (
    impl Future<Output = ()> + Send + 'static,
    impl Future<Output = ()> + Send + 'static,
) {
    let (first_tx, first) = tokio::sync::oneshot::channel::<()>();
    let (second_tx, second) = tokio::sync::oneshot::channel::<()>();
    let mut listener = Listener::register();
    tokio::spawn(async move {
        listener.recv().await;
        let _ = first_tx.send(());
        listener.recv().await;
        let _ = second_tx.send(());
    });
    // A sender dropped unsent (the runtime ending) is no signal.
    let wait = |rx: tokio::sync::oneshot::Receiver<()>| async move {
        if rx.await.is_err() {
            std::future::pending::<()>().await;
        }
    };
    (wait(first), wait(second))
}

/// The receivers [`signals`] listens on. Registration failing leaves the
/// process with the default action, and every `recv` pending.
struct Listener {
    #[cfg(unix)]
    receivers: Option<(tokio::signal::unix::Signal, tokio::signal::unix::Signal)>,
    #[cfg(windows)]
    receivers: Option<tokio::signal::windows::CtrlC>,
}

impl Listener {
    fn register() -> Self {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let receivers = match (
                signal(SignalKind::terminate()),
                signal(SignalKind::interrupt()),
            ) {
                (Ok(term), Ok(int)) => Some((term, int)),
                (Err(e), _) | (_, Err(e)) => {
                    tracing::warn!("cannot listen for SIGTERM/SIGINT ({e}); stopping is immediate");
                    None
                }
            };
            Self { receivers }
        }
        #[cfg(windows)]
        {
            let receivers = match tokio::signal::windows::ctrl_c() {
                Ok(ctrl_c) => Some(ctrl_c),
                Err(e) => {
                    tracing::warn!("cannot listen for Ctrl-C ({e}); stopping is immediate");
                    None
                }
            };
            Self { receivers }
        }
        #[cfg(not(any(unix, windows)))]
        {
            Self {}
        }
    }

    /// The next signal.
    async fn recv(&mut self) {
        #[cfg(unix)]
        {
            let Some((term, int)) = self.receivers.as_mut() else {
                return std::future::pending().await;
            };
            tokio::select! {
                _ = term.recv() => tracing::info!("SIGTERM received"),
                _ = int.recv() => tracing::info!("SIGINT received"),
            }
        }
        #[cfg(windows)]
        {
            let Some(ctrl_c) = self.receivers.as_mut() else {
                return std::future::pending().await;
            };
            let _ = ctrl_c.recv().await;
            tracing::info!("Ctrl-C received");
        }
        #[cfg(not(any(unix, windows)))]
        {
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
    async fn hold_keeps_the_drain_waiting_until_dropped() {
        let shutdown = Shutdown::new();
        let held = shutdown.hold();
        assert!(!shutdown.drain(Duration::from_millis(50)).await);
        drop(held);
        assert!(shutdown.drain(Duration::from_secs(5)).await);
    }

    /// One SIGINT resolves the first future and not the second; another
    /// resolves the second.
    #[cfg(unix)]
    #[tokio::test]
    async fn signals_hands_out_the_first_and_the_second_signal() {
        let (first, second) = signals();
        let interrupt = || {
            let sent = std::process::Command::new("kill")
                .args(["-INT", &std::process::id().to_string()])
                .status()
                .expect("run kill");
            assert!(sent.success());
        };
        tokio::pin!(second);
        interrupt();
        tokio::time::timeout(Duration::from_secs(5), first)
            .await
            .expect("the first signal");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), &mut second)
                .await
                .is_err(),
            "one signal is not two"
        );
        interrupt();
        tokio::time::timeout(Duration::from_secs(5), second)
            .await
            .expect("the second signal");
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
