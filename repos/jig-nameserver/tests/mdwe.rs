//! The nameserver serves under W^X denial, as its systemd unit runs it
//! (`MemoryDenyWriteExecute=yes`).
//!
//! The binary starts with `prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN)`, the
//! kernel mechanism systemd uses for that setting: no mapping may become both
//! writable and executable, or gain execute later. A Wasm JIT cannot run under
//! it (jig-server, which compiles blocks at boot, exits on it). The test checks
//! the nameserver boots and answers health and a signed challenge.
//!
//! In a workspace build cargo unifies features, so this binary may link
//! jig-pipeline's executor; it must still never create an executable mapping.
//! CI separately checks that a build of jig-nameserver alone links no wasmtime.
#![cfg(target_os = "linux")]

use std::io::{Read, Write};
use std::os::unix::process::CommandExt;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

const PR_SET_MDWE: libc::c_int = 65;
const PR_MDWE_REFUSE_EXEC_GAIN: libc::c_ulong = 1;

/// Is `PR_SET_MDWE` available (Linux 6.3 and later)? Tried in a child, so this
/// process is left as it was.
fn mdwe_supported() -> bool {
    let mut probe = Command::new("/bin/true");
    deny_write_execute(&mut probe);
    probe.status().is_ok_and(|s| s.success())
}

/// Have `cmd` start under `PR_SET_MDWE`, which persists across `execve`.
fn deny_write_execute(cmd: &mut Command) {
    // SAFETY: prctl is async-signal-safe, and the closure allocates nothing.
    unsafe {
        cmd.pre_exec(|| {
            if libc::prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn get(port: u16, path: &str) -> std::io::Result<String> {
    let mut stream = std::net::TcpStream::connect(("127.0.0.1", port))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    Ok(response)
}

#[test]
fn serves_with_write_execute_memory_denied() {
    if !mdwe_supported() {
        eprintln!("skipped: this kernel has no PR_SET_MDWE (Linux 6.3+)");
        return;
    }
    let dir = std::env::temp_dir().join(format!("jig-ns-mdwe-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let config = dir.join("ns.toml");
    // The signing key is sealed at rest; a test credential opens it.
    let unlock = jig_client::server_key::credential_for_tests(&dir);
    std::fs::write(
        &config,
        format!(
            // Plaintext, so the probe below can speak raw HTTP.
            "[tls]\nenabled = false\n\n\
             [v0_0_2.keys]\nunlock = \"{unlock}\"\n\n\
             [[v0_0_2.nameserver.alias_suffixes]]\nsuffix = \"mdwe.jig\"\n"
        ),
    )
    .unwrap();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let mut cmd = Command::new(env!("CARGO_BIN_EXE_jig-nameserver"));
    cmd.arg("serve")
        .env("JIG_NS_CONFIG", &config)
        .env("JIG_NS_DB_PATH", dir.join("nameserver.db"))
        .env("JIG_NS_BIND", "127.0.0.1")
        .env("JIG_NS_PORT", port.to_string())
        .env("HOME", &dir)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    deny_write_execute(&mut cmd);
    let mut child = cmd.spawn().expect("spawn jig-nameserver");

    let deadline = Instant::now() + Duration::from_secs(30);
    let health = loop {
        if let Some(status) = child.try_wait().unwrap() {
            let mut stderr = String::new();
            child
                .stderr
                .take()
                .unwrap()
                .read_to_string(&mut stderr)
                .ok();
            panic!("jig-nameserver exited under MDWE ({status}): {stderr}");
        }
        match get(port, "/v1/health") {
            Ok(response) => break response,
            Err(_) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(100)),
            Err(e) => panic!("no answer on port {port}: {e}"),
        }
    };
    assert!(health.contains(r#"{"status":"ok"}"#), "{health}");

    // A challenge signs an offer with the nameserver's key.
    let did = jig_core::Did::from_ed25519_pubkey(&[7; 32]).to_did_jig_string();
    let challenge = get(
        port,
        &format!("/v1/challenge?action=register&did={did}&name=alice@mdwe.jig"),
    )
    .unwrap();
    assert!(challenge.contains("\"pow_offer\""), "{challenge}");
    assert!(child.try_wait().unwrap().is_none(), "exited after serving");

    child.kill().ok();
    child.wait().ok();
    let _ = std::fs::remove_dir_all(&dir);
}
