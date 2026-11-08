//! A simulated bash prompt that disconnects before the first command runs.
//! All replies are made from world data; client bytes never reach a process,
//! a host file, a socket destination or an operating-system terminal.

use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::protocols::ssh::{
    auth, connection,
    transport::{HostKey, Transport},
};
use fictionet::stdlib::services::{serve, ssh};
use fictionet::sync::Mutex;
use fictionet_extras::ssh::{
    Profile, authentication_delay, honeypot, password_failure_delay, terminal,
};

use crate::config::SshAuth;
use crate::observe::Observer;

/// The application's authentication policy and simulated shell factory.
pub struct Application {
    policy: SshAuth,
    profile: Profile,
    delay_secret: u64,
}

/// An observer that shares the packet log's failure accounting.
pub struct Log(pub Arc<Mutex<Observer>>);
impl honeypot::Observer for Log {
    fn record(&self, context: &ssh::Context<'_>, event: &ssh::Event) {
        self.0.lock().ssh(context, event);
    }
}

/// Build the SSH server using the persisted seed, or world entropy when absent.
pub fn server(
    fcx: &fictionet::Cx,
    policy: SshAuth,
    host_key: Option<[u8; 32]>,
    observer: Arc<Mutex<Observer>>,
) -> ssh::Server<honeypot::Observed<Application, Log>> {
    let seed = host_key.unwrap_or_else(|| {
        let mut seed = [0; 32];
        fcx.fill_random(&mut seed);
        seed
    });
    let key = Arc::new(HostKey::ed25519_from_seed(seed).expect("Ed25519 seed"));
    let mut profile = Profile::ubuntu_24_04();
    profile.motd = b"Welcome to Ubuntu 24.04 LTS (GNU/Linux 6.8.0-31-generic x86_64)\r\n\r\n * Documentation:  https://help.ubuntu.com\r\n * Management:     https://landscape.canonical.com\r\n * Support:        https://ubuntu.com/pro\r\n\r\n".to_vec();
    let transport = Transport::new(key.clone(), profile.identification.clone());
    let mut config = ssh::Config::new(key, profile.identification.clone());
    config.proposal = Some(profile.proposal(transport.proposal(), [0; 16]));
    config.login_grace = profile.login_grace;
    config.max_attempts = profile.max_attempts;
    config.banner = profile.banner.clone();
    ssh::Server {
        backlog: Some(4096),
        config: Arc::new(config),
        handler: Arc::new(honeypot::Observed {
            handler: Application {
                policy,
                profile,
                delay_secret: fcx.random_u64(),
            },
            observer: Log(observer),
        }),
        options: serve::ServeOptions {
            idle: Some(Duration::from_secs(300)),
            ..serve::ServeOptions::default()
        }
        .budget(fictionet::stdlib::layer::Budget::new(32 << 20)),
    }
}

impl ssh::Handler for Application {
    type Session = Shell;
    fn authenticate(
        &self,
        context: &ssh::Context<'_>,
        attempt: &ssh::AuthAttempt<'_>,
    ) -> ssh::AuthDecision {
        let accepted = match (&self.policy, &attempt.request.method) {
            (
                SshAuth::AnyCredentials,
                auth::Method::Password {
                    new_password: None, ..
                }
                | auth::Method::PublicKey { .. },
            ) => true,
            (
                SshAuth::PasswordOrPublicKey(password),
                auth::Method::Password {
                    password: offered,
                    new_password: None,
                },
            ) => offered == password,
            (SshAuth::PasswordOrPublicKey(_), auth::Method::PublicKey { .. }) => true,
            _ => false,
        };
        if accepted {
            ssh::AuthDecision::Accept
        } else {
            ssh::AuthDecision::Reject {
                methods: self.profile.authentication_methods.clone(),
                partial_success: false,
                delay: if matches!(attempt.request.method, auth::Method::None) {
                    Duration::ZERO
                } else if matches!(
                    &attempt.request.method,
                    auth::Method::Password { password, new_password: None }
                        if !password.is_empty() && password.len() <= 1024
                ) {
                    // A seeded epoch offset supplies PAM's seconds-based seed
                    // from the world clock without consulting the host clock.
                    let pam_seed = (self.delay_secret as u32)
                        .wrapping_add(context.now.since_start().as_secs() as u32);
                    password_failure_delay(
                        self.delay_secret,
                        attempt.request.user.as_bytes(),
                        pam_seed,
                        Duration::ZERO,
                    )
                } else {
                    authentication_delay(
                        self.delay_secret,
                        attempt.request.user.as_bytes(),
                        Duration::ZERO,
                    )
                },
            }
        }
    }
    fn configure(
        &self,
        _: &ssh::Context<'_>,
        _: u32,
        request: &connection::SessionRequest,
    ) -> bool {
        match request {
            connection::SessionRequest::Pty { .. } => true,
            connection::SessionRequest::Env { name, .. } => {
                name == b"LANG" || name.starts_with(b"LC_")
            }
            _ => false,
        }
    }
    fn open(
        &self,
        _: &ssh::Context<'_>,
        request: &ssh::SessionRequest,
        output: &mut ssh::Output,
    ) -> Option<Shell> {
        let user: String = request
            .user
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-'))
            .take(32)
            .collect();
        let user = if user.is_empty() {
            "ubuntu".to_owned()
        } else {
            user
        };
        match &request.program {
            ssh::Program::Exec(_) | ssh::Program::Subsystem(_) => {
                output.hangup();
                Some(Shell::new(user, request.pty.is_some()))
            }
            ssh::Program::Shell => {
                let shell = Shell::new(user, request.pty.is_some());
                put(output, self.profile.login_text(true, false));
                shell.prompt(output);
                Some(shell)
            }
        }
    }
}

impl ssh::Session for Shell {
    fn input(&mut self, _: &ssh::Context<'_>, bytes: &[u8], output: &mut ssh::Output) {
        let mut echo = Vec::new();
        for &byte in bytes {
            match self.terminal.push(byte, &mut echo) {
                Ok(Some(terminal::Event::Line(line))) if line.is_empty() => {
                    put(output, &echo);
                    echo.clear();
                    self.prompt(output);
                }
                Ok(Some(terminal::Event::Line(_) | terminal::Event::End)) | Err(_) => {
                    put(output, &echo);
                    output.hangup();
                    return;
                }
                Ok(Some(terminal::Event::Interrupt)) => {
                    put(output, &echo);
                    echo.clear();
                    self.prompt(output);
                }
                Ok(None) => {}
            }
        }
        put(output, &echo);
    }
    fn event(
        &mut self,
        context: &ssh::Context<'_>,
        event: &ssh::SessionEvent,
        output: &mut ssh::Output,
    ) {
        match event {
            ssh::SessionEvent::Eof => output.hangup(),
            ssh::SessionEvent::Signal(signal) if signal == "TERM" || signal == "KILL" => {
                output.hangup();
            }
            ssh::SessionEvent::Signal(signal) if signal == "INT" => {
                self.input(context, &[3], output);
            }
            _ => {}
        }
    }
    fn held(&self) -> usize {
        self.user.capacity() + self.terminal.held()
    }
}

/// A fake account and its terminal editor.
pub struct Shell {
    user: String,
    terminal: terminal::Terminal,
    pty: bool,
}
impl Shell {
    fn new(user: String, pty: bool) -> Self {
        let mut terminal = terminal::Terminal::new(8192);
        terminal.set_echo(pty);
        Self {
            user,
            terminal,
            pty,
        }
    }
    fn prompt(&self, output: &mut ssh::Output) {
        if self.pty {
            put(
                output,
                format!(
                    "{}@server:~{} ",
                    self.user,
                    if self.user == "root" { '#' } else { '$' }
                )
                .as_bytes(),
            );
        }
    }
}

fn put(output: &mut ssh::Output, bytes: &[u8]) {
    if output.write(bytes).is_err() {
        output.hangup();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssh::{Handler, Session};

    #[test]
    fn shell_accepts_editing_but_closes_on_submission() {
        let connection = serve::ConnInfo::new(
            1,
            "127.0.0.1:22".parse().unwrap(),
            "127.0.0.2:30000".parse().unwrap(),
        );
        let context = ssh::Context {
            connection: &connection,
            now: fictionet::time::Instant::ZERO,
        };
        for pty in [false, true] {
            for ending in [b"\r".as_slice(), b"\n", b"\r\n", b"\x04"] {
                let mut shell = Shell::new("root".into(), pty);
                let mut output = ssh::Output::default();
                for fragment in [b"un".as_slice(), b"ame", b"\x7f", b"\x15", b"id"] {
                    let available = output.available();
                    shell.input(&context, fragment, &mut output);
                    assert!(output.write(&[]).is_ok());
                    assert_eq!(output.available() < available, pty);
                }
                shell.input(&context, ending, &mut output);
                assert!(output.write(&[]).is_err());
            }
        }
        for input in [vec![4], vec![b'a'; 8193]] {
            let mut shell = Shell::new("root".into(), true);
            let mut output = ssh::Output::default();
            shell.input(&context, &input, &mut output);
            assert!(output.write(&[]).is_err());
        }
    }

    #[test]
    fn empty_and_erased_lines_allow_another_command() {
        let connection = serve::ConnInfo::new(
            1,
            "127.0.0.1:22".parse().unwrap(),
            "127.0.0.2:30000".parse().unwrap(),
        );
        let context = ssh::Context {
            connection: &connection,
            now: fictionet::time::Instant::ZERO,
        };
        for pty in [false, true] {
            let mut shell = Shell::new("root".into(), pty);
            let mut output = ssh::Output::default();
            for fragment in [b"\r".as_slice(), b"\n", b"\n", b"id\x15\r", b"x\x7f\n"] {
                shell.input(&context, fragment, &mut output);
                assert!(output.write(&[]).is_ok());
            }
            shell.input(&context, b"id\r\n", &mut output);
            assert!(output.write(&[]).is_err());
        }
    }

    #[test]
    fn exec_and_subsystems_close_immediately() {
        let application = Application {
            policy: SshAuth::AnyCredentials,
            profile: Profile::ubuntu_24_04(),
            delay_secret: 0,
        };
        let connection = serve::ConnInfo::new(
            1,
            "127.0.0.1:22".parse().unwrap(),
            "127.0.0.2:30000".parse().unwrap(),
        );
        let context = ssh::Context {
            connection: &connection,
            now: fictionet::time::Instant::ZERO,
        };
        for program in [
            ssh::Program::Exec(b"id; uname -a".to_vec()),
            ssh::Program::Exec(vec![0, 255]),
            ssh::Program::Subsystem("sftp".into()),
            ssh::Program::Subsystem("unknown".into()),
        ] {
            let mut output = ssh::Output::default();
            let request = ssh::SessionRequest {
                user: "root".into(),
                channel: 0,
                program,
                pty: None,
                environment: Vec::new(),
            };
            assert!(application.open(&context, &request, &mut output).is_some());
            assert!(output.write(&[]).is_err());
        }
    }
}
