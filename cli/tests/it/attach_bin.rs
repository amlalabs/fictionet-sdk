//! The `fictionet attach` binary against a real `listen` in this process.
//! The tests that need a tun device are in `tests/host/attach_bin.rs`.

use crate::common::logged;
use crate::common::temp;

use logged::logged;

use std::process::{Command, Stdio};

const BIN: &str = env!("CARGO_BIN_EXE_fictionet");

#[test]
fn left_out_flags_exit_2_and_say_dhcp_is_missing() {
    let out = Command::new(BIN)
        .args([
            "attach",
            "--world",
            "unix:/nowhere",
            "--name",
            "a",
            "--type",
            "tun",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("DHCP is not implemented yet"), "{err}");
}

#[test]
fn no_subcommand_is_a_usage_error() {
    let out = Command::new(BIN).output().unwrap();
    assert_eq!(out.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&out.stderr).contains("usage: fictionet attach"));
}

#[test]
fn attach_help_goes_to_stdout_and_exits_0() {
    for flag in ["--help", "-h"] {
        let out = Command::new(BIN).args(["attach", flag]).output().unwrap();
        assert_eq!(out.status.code(), Some(0), "{flag}");
        let text = String::from_utf8_lossy(&out.stdout);
        assert!(text.contains("usage: fictionet attach"), "{text}");
        assert!(text.contains("--resolv-conf"), "{text}");
        assert!(
            out.stderr.is_empty(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
}

#[test]
fn a_flag_after_a_value_flag_is_a_usage_error() {
    let out = Command::new(BIN)
        .args([
            "attach",
            "--world",
            "unix:/nowhere",
            "--name",
            "a",
            "--type",
            "tun",
            "--resolv-conf",
            "--no-resolv-conf",
        ])
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(2));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("--resolv-conf needs a value"), "{err}");
}

#[test]
fn ready_exits_0_only_when_the_file_exists() {
    let dir = temp::dir();
    let file = dir.join("ready");
    let run = |args: &[&str]| Command::new(BIN).arg("ready").args(args).output().unwrap();
    let out = run(&[file.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("does not exist"));
    std::fs::write(&file, "abc\n").unwrap();
    assert_eq!(run(&[file.to_str().unwrap()]).status.code(), Some(0));
    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["a", "b"]).status.code(), Some(2));
    // Help goes to stdout and exits 0, as every other subcommand's does.
    let help = run(&["--help"]);
    assert_eq!(help.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&help.stdout).contains("usage: fictionet ready"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failed_ready_file_write_does_not_leave_a_successful_probe() {
    use std::os::unix::process::CommandExt;

    let dir = temp::dir();
    let sock = dir.join("w.sock");
    let ready = dir.join("ready");
    let token = dir.join("token");
    std::fs::write(&token, "test-token\n").unwrap();
    let (attacher, _attachments) = fictionet::attachments();
    let _listening =
        fictionet::listen(fictionet::WorldSocket::UnixSocket(sock.clone()), attacher).unwrap();

    // The child may create a file, but writing past this size returns EFBIG.
    for limit in [0, 3] {
        let mut command = Command::new(BIN);
        command
            .args([
                "attach",
                "--world",
                &format!("unix:{}", sock.display()),
                "--name",
                &format!("agent-{limit}"),
                "--type",
                "http_proxy",
                "--listen",
                "127.0.0.1:0",
                "--ip-addr",
                "10.0.0.2",
                "--dns",
                "10.0.0.1",
                "--token-file",
            ])
            .arg(&token)
            .arg("--ready-file")
            .arg(&ready);
        // SAFETY: the hook only calls async-signal-safe functions in the child.
        unsafe {
            command.pre_exec(move || {
                if libc::signal(libc::SIGXFSZ, libc::SIG_IGN) == libc::SIG_ERR {
                    return Err(std::io::Error::last_os_error());
                }
                let size = libc::rlimit {
                    rlim_cur: limit,
                    rlim_max: limit,
                };
                if libc::setrlimit(libc::RLIMIT_FSIZE, &size) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let out = command.output().unwrap();
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{err}");
        assert!(err.contains("writing the ready file"), "{err}");
        assert!(
            err.contains(&std::io::Error::from_raw_os_error(libc::EFBIG).to_string()),
            "{err}"
        );
        let probe = Command::new(BIN).arg("ready").arg(&ready).output().unwrap();
        assert_eq!(probe.status.code(), Some(1));
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn wait_blocked_waits_while_an_address_answers_and_exits_0_once_it_stops() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let open = listener.local_addr().unwrap().to_string();
    // A port with nothing listening: refused, which counts as blocked.
    let closed = {
        let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        l.local_addr().unwrap().to_string()
    };
    let run = |args: &[&str]| {
        Command::new(BIN)
            .arg("wait-blocked")
            .args(args)
            .output()
            .unwrap()
    };

    let out = run(&[&closed]);
    assert_eq!(
        out.status.code(),
        Some(0),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("unreachable 3 times in a row"));

    // Even instant refusals cannot complete three rounds before one second.
    let out = run(&["--timeout", "1", &closed]);
    assert_eq!(out.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&out.stderr).contains("after 1 s"));

    // One address still answers: no exit 0, however many others fail.
    let out = run(&["--timeout", "1", &closed, &open]);
    assert_eq!(out.status.code(), Some(1));
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(
        err.contains(&format!("after 1 s, {open} still reachable")),
        "{err}"
    );

    // It exits 0 soon after the address stops answering.
    let mut child = Command::new(BIN)
        .args(["wait-blocked", "--timeout", "20", &open])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let log = logged(child.stderr.take().unwrap(), "still reachable; waiting");
    assert!(
        child.try_wait().unwrap().is_none(),
        "exited while the address still answered"
    );
    drop(listener);
    let out = child.wait_with_output().unwrap();
    let err = log.join().unwrap();
    assert_eq!(out.status.code(), Some(0), "{err}");
    assert!(err.contains("still reachable; waiting"));

    assert_eq!(run(&[]).status.code(), Some(2));
    assert_eq!(run(&["example.com:443"]).status.code(), Some(2));
}
