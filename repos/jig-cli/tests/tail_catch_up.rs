//! `jig tail` that falls behind a busy channel catches up by itself.
//!
//! Runs the real `jig` binary against a real server, and stops reading its
//! stdout while a burst is posted. The pipe fills, the tail blocks on its
//! next line, the client's subscription queue fills behind it, and the
//! stream ends lagged. Once stdout is read again, every message of the burst
//! must be there exactly once, and the tail must still be live.
//!
//! `HOME` points at a tempdir, so the pin store is this test's own.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use integration_tests::harness::{TestJigServer, test_identity};

/// More than a full pipe of lines (64 KiB at about 1 KiB a line) plus a
/// full subscription queue (`SUBSCRIPTION_QUEUE`, 64), with room to spare.
const BURST: usize = 300;

fn jig(home: &Path) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_jig"));
    cmd.env("HOME", home)
        // Never the developer's real keychain; seal test keys with a fixed secret.
        .env("JIG_KEYCHAIN", "none")
        .env("JIG_KEY_UNLOCK", "env:JIG_TEST_KEY_SECRET")
        .env(
            "JIG_TEST_KEY_SECRET",
            "jig cli tests: a fixed, public secret",
        )
        .env("JIG_NONINTERACTIVE", "1")
        .env("RUST_BACKTRACE", "0");
    cmd
}

/// Lines from `out`, read on a thread so the test can wait with a timeout.
fn lines<R: BufRead + Send + 'static>(out: R) -> mpsc::Receiver<String> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        for line in out.lines() {
            let Ok(line) = line else { break };
            if tx.send(line).is_err() {
                break;
            }
        }
    });
    rx
}

/// Read `out` up to the line starting with `prefix`, then hand it back
/// unread past that, so the pipe behind it can fill.
fn read_until<R: BufRead + Send + 'static>(mut out: R, prefix: &'static str) -> R {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut line = String::new();
        loop {
            line.clear();
            if out.read_line(&mut line).unwrap_or(0) == 0 {
                return;
            }
            if line.starts_with(prefix) {
                let _ = tx.send(out);
                return;
            }
        }
    });
    rx.recv_timeout(Duration::from_secs(60))
        .unwrap_or_else(|_| panic!("no line starting {prefix:?}"))
}

/// The burst message a line shows, if it shows one.
fn message(line: &str) -> Option<String> {
    line.split_whitespace()
        .find(|w| w.starts_with("burst-") || *w == "after")
        .map(str::to_string)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tail_that_falls_behind_catches_up_with_nothing_missed_or_repeated() {
    let server = TestJigServer::start().await.expect("start");
    let owner = test_identity();
    server
        .create_channel(&owner, "#busy", "open")
        .await
        .expect("create");

    let home = tempfile::tempdir().unwrap();
    let out = jig(home.path()).args(["init", "me"]).output().unwrap();
    assert!(out.status.success(), "jig init: {out:?}");
    let path = home.path().join(".jig").join("cli.toml");
    let mut cfg: toml::Table = toml::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
    cfg["server"]["base_url"] = toml::Value::String(server.http_url());
    std::fs::write(&path, toml::to_string(&cfg).unwrap()).unwrap();

    let mut tail = jig(home.path())
        .args(["tail", "#busy"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stderr = lines(BufReader::new(tail.stderr.take().unwrap()));
    let stdout = read_until(BufReader::new(tail.stdout.take().unwrap()), "Tailing #busy");

    // Nothing reads stdout now. The burst fills the pipe, the tail blocks
    // writing, and its subscription queue fills behind it.
    let pad = "x".repeat(1000);
    for i in 0..BURST {
        server
            .send_text_render(&owner, "#busy", &format!("burst-{i:04} {pad}"))
            .await
            .expect("send");
    }
    // Let the server's deliveries reach the client and overflow its queue.
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Read again, until the last of the burst, then post once more: the tail
    // must still be live after catching up.
    let stdout = lines(stdout);
    let mut seen: BTreeMap<String, usize> = BTreeMap::new();
    let last = format!("burst-{:04}", BURST - 1);
    let mut posted_after = false;
    loop {
        let line = stdout
            .recv_timeout(Duration::from_secs(60))
            .unwrap_or_else(|_| panic!("stalled; shown so far: {}", seen.len()));
        let Some(m) = message(&line) else { continue };
        *seen.entry(m.clone()).or_default() += 1;
        if m == last && !posted_after {
            posted_after = true;
            server
                .send_text_render(&owner, "#busy", "after")
                .await
                .expect("send");
        }
        if m == "after" {
            break;
        }
    }
    // Give a late duplicate the chance to show.
    while let Ok(line) = stdout.recv_timeout(Duration::from_secs(2)) {
        if let Some(m) = message(&line) {
            *seen.entry(m).or_default() += 1;
        }
    }
    tail.kill().unwrap();
    let _ = tail.wait();
    let errors: Vec<String> = stderr.try_iter().collect();

    let missing: Vec<String> = (0..BURST)
        .map(|i| format!("burst-{i:04}"))
        .filter(|m| !seen.contains_key(m))
        .collect();
    let repeated: Vec<(&String, &usize)> = seen.iter().filter(|(_, n)| **n > 1).collect();
    assert!(
        missing.is_empty(),
        "missing {missing:?}; stderr: {errors:?}"
    );
    assert!(repeated.is_empty(), "shown twice {repeated:?}");
    assert_eq!(seen.get("after"), Some(&1), "live after catching up");
    assert!(
        errors.iter().any(|e| e.contains("caught up")),
        "the burst must actually have overflowed the queue, or this test \
         proves nothing; stderr: {errors:?}"
    );
}
