//! SIGTERM, the signal a service manager's stop sends, stops the nameserver
//! gracefully (#438): it logs the shutdown, drains, and exits 0 well within
//! the drain bound, rather than dying on the signal.

#![cfg(unix)]

use std::io::BufRead;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

/// A scratch directory that deletes itself on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "jig-ns-sigterm-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A config for a nameserver in `dir` on an ephemeral loopback port.
fn write_config(dir: &Path) -> PathBuf {
    let key = dir.join("ns.key");
    let unlock = jig_client::server_key::credential_for_tests(dir);
    jig_nameserver::v0_0_2::keygen(&key, std::slice::from_ref(&unlock)).unwrap();
    let path = dir.join("ns.toml");
    std::fs::write(
        &path,
        format!(
            "[network]\nbind = \"127.0.0.1\"\nport = 0\n\n\
             [storage]\ndatabase_path = {db:?}\n\n\
             [v0_0_2.server]\nserver_did_keyfile = {key:?}\n\n\
             [v0_0_2.keys]\nunlock = {unlock:?}\n\n\
             [[v0_0_2.nameserver.alias_suffixes]]\nsuffix = \"names.example.org\"\n",
            db = dir.join("ns.db"),
        ),
    )
    .unwrap();
    path
}

#[test]
fn sigterm_stops_the_nameserver_gracefully_and_it_exits_cleanly() {
    let dir = Scratch::new("graceful");
    let config = write_config(&dir.0);
    let mut child = Command::new(env!("CARGO_BIN_EXE_jig-nameserver"))
        .args(["--config", config.to_str().unwrap(), "serve"])
        .env("RUST_LOG", "info")
        .env_remove("JIG_NS_CONFIG")
        .env_remove("JIG_NS_BIND")
        .env_remove("JIG_NS_PORT")
        .env_remove("JIG_NS_SHUTDOWN_DRAIN_MS")
        .current_dir(&dir.0)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn jig-nameserver");

    // Every log line, from both streams, as it is written.
    let (lines_tx, lines) = std::sync::mpsc::channel::<String>();
    let readers: Vec<_> = [
        Box::new(child.stdout.take().unwrap()) as Box<dyn std::io::Read + Send>,
        Box::new(child.stderr.take().unwrap()),
    ]
    .into_iter()
    .map(|stream| {
        let lines_tx = lines_tx.clone();
        std::thread::spawn(move || {
            for line in std::io::BufReader::new(stream)
                .lines()
                .map_while(|l| l.ok())
            {
                let _ = lines_tx.send(line);
            }
        })
    })
    .collect();
    drop(lines_tx);

    let mut log = String::new();
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let wait = deadline.saturating_duration_since(Instant::now());
        match lines.recv_timeout(wait) {
            Ok(line) => {
                let listening = line.contains("listening on");
                log.push_str(&line);
                log.push('\n');
                if listening {
                    break;
                }
            }
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                panic!("jig-nameserver never reported listening\n{log}");
            }
        }
    }

    let sent = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("run kill");
    assert!(sent.success(), "kill -TERM failed");
    // Idle, so the drain is immediate; the default bound is five seconds.
    let Some(status) = wait_bounded(&mut child, Duration::from_secs(5)) else {
        let _ = child.kill();
        let _ = child.wait();
        panic!("jig-nameserver outlived its drain after SIGTERM\n{log}");
    };
    for reader in readers {
        let _ = reader.join();
    }
    log.extend(lines.try_iter().map(|line| line + "\n"));
    assert!(
        status.success(),
        "a graceful stop exits 0, not on the signal: {status:?}\n{log}"
    );
    assert!(log.contains("SIGTERM received"), "{log}");
    assert!(log.contains("shutdown complete"), "{log}");
}

/// Wait up to `limit` for the child to exit. `None` means it outlived the
/// deadline; the caller kills it.
fn wait_bounded(child: &mut Child, limit: Duration) -> Option<std::process::ExitStatus> {
    let deadline = Instant::now() + limit;
    while Instant::now() < deadline {
        if let Some(status) = child.try_wait().expect("try_wait") {
            return Some(status);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}
