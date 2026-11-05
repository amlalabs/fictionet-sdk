//! A simulated Ubuntu shell and read-only SFTP directory over the SSH hook.
//! All replies are made from world data; client bytes never reach a process,
//! a host file, a socket destination or an operating-system terminal.

use std::sync::Arc;
use std::time::Duration;

use fictionet::stdlib::codec::{Frames, Stream, Wire};
use fictionet::stdlib::protocols::{
    sftp,
    ssh::{
        auth, connection,
        transport::{HostKey, Transport},
    },
};
use fictionet::stdlib::services::{serve, ssh};
use fictionet::sync::Mutex;
use fictionet_extras::ssh::{Profile, authentication_delay, honeypot, terminal};

use crate::config::SshAuth;
use crate::observe::Observer;

const OS_RELEASE: &[u8] = b"PRETTY_NAME=\"Ubuntu 24.04 LTS\"\nNAME=\"Ubuntu\"\nVERSION_ID=\"24.04\"\nVERSION=\"24.04 LTS (Noble Numbat)\"\nID=ubuntu\nID_LIKE=debian\n";

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

/// Build the demo's SSH port server with a host key from the world's entropy.
pub fn server(
    fcx: &fictionet::Cx,
    policy: SshAuth,
    observer: Arc<Mutex<Observer>>,
) -> ssh::Server<honeypot::Observed<Application, Log>> {
    let mut seed = [0; 32];
    fcx.fill_random(&mut seed);
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
        },
    }
}

impl ssh::Handler for Application {
    type Session = Session;
    fn authenticate(
        &self,
        _: &ssh::Context<'_>,
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
    ) -> Option<Session> {
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
            ssh::Program::Subsystem(name) if name == "sftp" => Some(Session::Sftp {
                input: Stream::new(Frames::new()),
                initialized: false,
            }),
            ssh::Program::Subsystem(_) => None,
            ssh::Program::Exec(command) => {
                let mut shell = Shell::new(user, request.pty.is_some());
                let status = shell.command(command, output);
                output.exit(status);
                Some(Session::Shell(shell))
            }
            ssh::Program::Shell => {
                let shell = Shell::new(user, request.pty.is_some());
                put(output, self.profile.login_text(true, false));
                shell.prompt(output);
                Some(Session::Shell(shell))
            }
        }
    }
}

/// A simulated program's running state.
pub enum Session {
    /// A bounded line editor and a small command vocabulary.
    Shell(Shell),
    /// SFTP framing for an empty, read-only home directory.
    Sftp {
        input: Stream<Frames<sftp::Packet>>,
        initialized: bool,
    },
}

impl ssh::Session for Session {
    fn input(&mut self, _: &ssh::Context<'_>, bytes: &[u8], output: &mut ssh::Output) {
        match self {
            Session::Shell(shell) => {
                let mut echo = Vec::new();
                for &byte in bytes {
                    let event = shell.terminal.push(byte, &mut echo);
                    if !matches!(event, Ok(None)) {
                        put(output, &echo);
                        echo.clear();
                    }
                    match event {
                        Ok(Some(terminal::Event::Line(line))) => {
                            let status = shell.command(&line, output);
                            if line == b"exit" || line == b"logout" {
                                output.exit(status);
                                return;
                            }
                            shell.prompt(output);
                        }
                        Ok(Some(terminal::Event::Interrupt)) => shell.prompt(output),
                        Ok(Some(terminal::Event::End)) => {
                            output.exit(0);
                            return;
                        }
                        Err(_) => {
                            put(output, b"bash: input line too long\r\n");
                            output.exit(2);
                            return;
                        }
                        Ok(None) => {}
                    }
                }
                put(output, &echo);
            }
            Session::Sftp { input, initialized } => {
                if input.push(bytes) != bytes.len() {
                    output.exit(1);
                    return;
                }
                while let Some(packet) = input.next() {
                    let Ok(packet) = packet else {
                        output.exit(1);
                        return;
                    };
                    let Ok(request) = sftp::Request::from_packet(&packet) else {
                        output.exit(1);
                        return;
                    };
                    let response = match request {
                        sftp::Request::Init { .. } if !*initialized => {
                            *initialized = true;
                            sftp::Response::Version {
                                version: 3,
                                extensions: Vec::new(),
                            }
                        }
                        _ if !*initialized => {
                            output.exit(1);
                            return;
                        }
                        sftp::Request::Realpath { id, .. } => sftp::Response::Name {
                            id,
                            names: vec![sftp::NameEntry {
                                filename: b"/home/ubuntu".to_vec(),
                                longname: b"/home/ubuntu".to_vec(),
                                attrs: sftp::Attrs::default(),
                            }],
                        },
                        sftp::Request::Opendir { id, .. } => sftp::Response::Handle {
                            id,
                            handle: b"home".to_vec(),
                        },
                        sftp::Request::Readdir { id, .. } => {
                            sftp::Response::status(id, sftp::Status::Eof, "End of directory")
                        }
                        sftp::Request::Close { id, .. } => {
                            sftp::Response::status(id, sftp::Status::Ok, "")
                        }
                        other => {
                            let Some(id) = other.id() else {
                                output.exit(1);
                                return;
                            };
                            sftp::Response::status(
                                id,
                                sftp::Status::PermissionDenied,
                                "Permission denied",
                            )
                        }
                    };
                    match response.to_packet().and_then(|p| p.to_bytes()) {
                        Ok(bytes) => put(output, &bytes),
                        Err(_) => {
                            output.exit(1);
                            return;
                        }
                    }
                }
            }
        }
    }
    fn event(&mut self, _: &ssh::Context<'_>, event: &ssh::SessionEvent, output: &mut ssh::Output) {
        match event {
            ssh::SessionEvent::Eof => output.exit(0),
            ssh::SessionEvent::Signal(signal) if signal == "TERM" || signal == "KILL" => {
                output.exit(128 + if signal == "TERM" { 15 } else { 9 })
            }
            ssh::SessionEvent::Signal(signal) if signal == "INT" => {
                if let Session::Shell(shell) = self {
                    put(output, b"^C\r\n");
                    shell.prompt(output);
                }
            }
            _ => {}
        }
    }
    fn held(&self) -> usize {
        match self {
            Self::Shell(shell) => shell.terminal.held(),
            Self::Sftp { input, .. } => input.held(),
        }
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
    fn command(&mut self, command: &[u8], output: &mut ssh::Output) -> u32 {
        let Ok(command) = std::str::from_utf8(command) else {
            put(output, b"bash: invalid command\n");
            return 127;
        };
        let text = match command.trim() {
            "" | "exit" | "logout" | "true" => String::new(),
            "false" => return 1,
            "whoami" => format!("{}\n", self.user),
            "id" if self.user == "root" => "uid=0(root) gid=0(root) groups=0(root)\n".into(),
            "id" => format!("uid=1000({0}) gid=1000({0}) groups=1000({0}),27(sudo)\n", self.user),
            "pwd" => if self.user == "root" { "/root\n".into() } else { format!("/home/{}\n", self.user) },
            "hostname" => "server\n".into(),
            "uname" | "uname -s" => "Linux\n".into(),
            "uname -r" => "6.8.0-31-generic\n".into(),
            "uname -m" | "arch" => "x86_64\n".into(),
            "uname -a" => "Linux server 6.8.0-31-generic #31-Ubuntu SMP PREEMPT_DYNAMIC Sat Apr 20 00:40:06 UTC 2024 x86_64 x86_64 x86_64 GNU/Linux\n".into(),
            "cat /etc/os-release" => String::from_utf8_lossy(OS_RELEASE).into_owned(),
            "ls" | "ls -l" => String::new(),
            "ls -la" => "total 20\ndrwxr-x--- 2 ubuntu ubuntu 4096 Apr 25 12:00 .\ndrwxr-xr-x 3 root   root   4096 Apr 25 12:00 ..\n-rw-r--r-- 1 ubuntu ubuntu  220 Mar 31  2024 .bash_logout\n-rw-r--r-- 1 ubuntu ubuntu 3771 Mar 31  2024 .bashrc\n-rw-r--r-- 1 ubuntu ubuntu  807 Mar 31  2024 .profile\n".into(),
            "uptime" => " 12:04:19 up 3 days,  2:11,  1 user,  load average: 0.00, 0.01, 0.00\n".into(),
            "ps" | "ps aux" => "  PID TTY          TIME CMD\n 1201 pts/0    00:00:00 bash\n 1240 pts/0    00:00:00 ps\n".into(),
            "echo" => "\n".into(),
            c if c.starts_with("echo ") => format!("{}\n", &c[5..]),
            c => {
                let name: String = c.split_whitespace().next().unwrap_or("").chars().filter(|c| !c.is_control()).take(128).collect();
                let message = format!("bash: {name}: command not found\n");
                if output.stderr(message.as_bytes()).is_err() { output.exit(1); }
                return 127;
            }
        };
        if self.pty {
            put(output, text.replace('\n', "\r\n").as_bytes());
        } else {
            put(output, text.as_bytes());
        }
        0
    }
}

fn put(output: &mut ssh::Output, bytes: &[u8]) {
    if output.write(bytes).is_err() {
        output.exit(1);
    }
}
