//! `honeypot-aws`: the honeypot's EC2 instance, driven from the workstation
//! with the AWS CLI.
//!
//! `launch` creates one instance in eu-west-2 with two network interfaces.
//! The management interface has its own Elastic IP and a security group that
//! admits SSH from the launching workstation's address only. The data
//! interface has no public address and a security group with no rules. The
//! IDs of everything `launch` creates go to a state file outside the
//! repository, and every resource carries a tag with that launch's ID. Later
//! commands act only on recorded resources, and only after reading that tag
//! back from AWS.

mod aws;
mod provision;

use std::io::Write;
use std::net::Ipv4Addr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::Result;
use aws::{
    AllocationId, Aws, ImageId, InstanceId, Ipv4Cidr, KeyPairId, MacAddress, NetworkInterfaceId,
    SecurityGroupId, SubnetId, VpcId, carries, tag_specification,
};
use provision::{FirstBoot, Service};

pub use provision::musl_cc_arguments;

/// The tag key every launched resource carries; its value is the launch ID.
const LAUNCH_TAG: &str = "fictionet-honeypot";
const NAME: &str = "fictionet-honeypot";
const ZONE: &str = "eu-west-2a";
const INSTANCE_TYPE: &str = "m8i.large";
const IMAGE_PARAMETER: &str = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-6.18-x86_64";
const LOGIN: &str = "ec2-user";
const DASHBOARD_PORT: u16 = 8700;
/// Half of the m8i.large's 8 GiB, leaving the rest to Linux and SSH.
const MEMORY_MAX_MIB: u32 = 4096;
const MUSL: &str = "x86_64-unknown-linux-musl";
/// Set in the environment of the musl build, where this executable stands in
/// for the C compiler.
pub const MUSL_CC: &str = "FICTIONET_XTASK_MUSL_CC";

const USAGE: &str =
    "expected honeypot-aws launch, deploy, status, dashboard, stop, start or terminate";

pub fn run(args: &[String]) -> Result {
    let [command] = args else {
        return Err(USAGE.into());
    };
    let files = Files::locate()?;
    match command.as_str() {
        "launch" => launch(&Aws::signed_in()?, &files),
        "deploy" => deploy(&Aws::signed_in()?, &files),
        "status" => status(&Aws::signed_in()?, &files),
        "dashboard" => dashboard(&Aws::signed_in()?, &files),
        "stop" => stop(&Aws::signed_in()?, &files),
        "start" => start(&Aws::signed_in()?, &files),
        "terminate" => terminate(&Aws::signed_in()?, &files),
        _ => Err(USAGE.into()),
    }
}

/// Where the workstation keeps this honeypot's state and keys.
struct Files {
    state: PathBuf,
    known_hosts: PathBuf,
    ssh_dir: PathBuf,
}

impl Files {
    fn locate() -> Result<Self> {
        let home = PathBuf::from(std::env::var_os("HOME").ok_or("HOME is not set")?);
        let state_home = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local/state"));
        let dir = state_home.join("fictionet/honeypot-aws");
        Ok(Self {
            state: dir.join("state.json"),
            known_hosts: dir.join("known_hosts"),
            ssh_dir: home.join(".ssh"),
        })
    }

    fn load(&self) -> Result<State> {
        let text = std::fs::read(&self.state).map_err(|error| {
            format!(
                "no launched honeypot recorded at {} ({error}); run honeypot-aws launch",
                self.state.display()
            )
        })?;
        Ok(serde_json::from_slice(&text)?)
    }

    /// Writes the state whole, so an interrupted write leaves the last one.
    fn save(&self, state: &State) -> Result {
        let dir = self.state.parent().ok_or("state file has a directory")?;
        std::fs::create_dir_all(dir)?;
        let partial = self.state.with_extension("json.partial");
        std::fs::write(&partial, serde_json::to_vec_pretty(state)?)?;
        std::fs::rename(partial, &self.state)?;
        Ok(())
    }
}

/// Everything one launch created, recorded as each piece is created, so a
/// launch that stops halfway can still be terminated.
#[derive(Serialize, Deserialize)]
struct State {
    launch: String,
    subnet: SubnetId,
    vpc: VpcId,
    cidr: Ipv4Cidr,
    key: Option<Key>,
    management_group: Option<SecurityGroupId>,
    data_group: Option<SecurityGroupId>,
    data_interface: Option<DataInterface>,
    instance: Option<InstanceId>,
    management_address: Option<ElasticIp>,
    data_attached: bool,
    deployed_commit: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct Key {
    id: KeyPairId,
    name: String,
    private: PathBuf,
}

#[derive(Serialize, Deserialize)]
struct DataInterface {
    id: NetworkInterfaceId,
    mac: MacAddress,
    private_ip: Ipv4Addr,
}

#[derive(Serialize, Deserialize)]
struct ElasticIp {
    allocation: AllocationId,
    public_ip: Ipv4Addr,
}

impl State {
    fn name(&self, part: &str) -> String {
        format!("{NAME}-{part}-{}", self.launch)
    }

    fn ssh(&self, files: &Files) -> Result<Ssh> {
        let key = self.key.as_ref().ok_or("launch created no key pair")?;
        let address = self
            .management_address
            .as_ref()
            .ok_or("launch allocated no management address")?;
        Ok(Ssh {
            key: key.private.clone(),
            known_hosts: files.known_hosts.clone(),
            host: address.public_ip,
        })
    }

    fn service(&self) -> Result<Service> {
        let data = self
            .data_interface
            .as_ref()
            .ok_or("launch created no data interface")?;
        Ok(Service {
            address: data.private_ip,
            gateway: self.cidr.router(),
            memory_max_mib: MEMORY_MAX_MIB,
        })
    }
}

/// SSH to the instance's management address with this launch's key, pinning
/// the host key the first connection sees.
struct Ssh {
    key: PathBuf,
    known_hosts: PathBuf,
    host: Ipv4Addr,
}

impl Ssh {
    fn options(&self) -> Vec<String> {
        vec![
            "-i".into(),
            self.key.display().to_string(),
            "-o".into(),
            "IdentitiesOnly=yes".into(),
            "-o".into(),
            "BatchMode=yes".into(),
            "-o".into(),
            format!("UserKnownHostsFile={}", self.known_hosts.display()),
            "-o".into(),
            "StrictHostKeyChecking=accept-new".into(),
            "-o".into(),
            "ConnectTimeout=10".into(),
            // Amazon Linux's sshd offers no post-quantum key exchange, and
            // the client warns about that on every connection.
            "-o".into(),
            "LogLevel=ERROR".into(),
        ]
    }

    fn destination(&self) -> String {
        format!("{LOGIN}@{}", self.host)
    }

    fn command(&self, remote: &str) -> Command {
        let mut command = Command::new("ssh");
        command
            .args(self.options())
            .arg(self.destination())
            .arg(remote);
        command
    }

    /// Runs `remote` and returns its standard output.
    fn run(&self, remote: &str) -> Result<String> {
        let output = self.command(remote).stderr(Stdio::inherit()).output()?;
        if !output.status.success() {
            return Err(format!("ssh {remote:?} failed: {}", output.status).into());
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    /// Runs `remote` with `input` on its standard input.
    fn feed(&self, remote: &str, input: &[u8]) -> Result {
        let mut child = self
            .command(remote)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .ok_or("ssh has a standard input")?
            .write_all(input)?;
        let status = child.wait()?;
        if !status.success() {
            return Err(format!("ssh {remote:?} failed: {status}").into());
        }
        Ok(())
    }

    fn copy(&self, local: &Path, remote: &str) -> Result {
        let status = Command::new("scp")
            .args(self.options())
            .arg("-q")
            .arg(local)
            .arg(format!("{}:{remote}", self.destination()))
            .status()?;
        if !status.success() {
            return Err(format!("scp to {remote} failed: {status}").into());
        }
        Ok(())
    }

    /// Waits until sshd answers. A booting instance refuses connections for
    /// a while; this keeps asking.
    fn wait(&self) -> Result {
        println!("Waiting for SSH on {}", self.host);
        loop {
            let status = self
                .command("true")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()?;
            if status.success() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_secs(5));
        }
    }
}

fn checked(command: &mut Command) -> Result {
    let status = command.status()?;
    if !status.success() {
        return Err(format!("{command:?} failed: {status}").into());
    }
    Ok(())
}

/// The workstation's public IPv4 address, as AWS sees it.
fn workstation_address() -> Result<Ipv4Addr> {
    let output = Command::new("curl")
        .args([
            "--fail",
            "--silent",
            "--show-error",
            "https://checkip.amazonaws.com",
        ])
        .output()?;
    if !output.status.success() {
        return Err("cannot read this workstation's public address".into());
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().parse()?)
}

fn launch(aws: &Aws, files: &Files) -> Result {
    if files.state.exists() {
        return Err(format!(
            "a honeypot launch is already recorded at {}; terminate it first",
            files.state.display()
        )
        .into());
    }
    let workstation = workstation_address()?;
    let subnets: aws::Subnets = aws.read(&[
        "ec2",
        "describe-subnets",
        "--filters",
        "Name=default-for-az,Values=true",
        &format!("Name=availability-zone,Values={ZONE}"),
    ])?;
    let [subnet] = subnets.subnets.as_slice() else {
        return Err(format!("expected one default subnet in {ZONE}").into());
    };
    let image: aws::Parameter = aws.read(&["ssm", "get-parameter", "--name", IMAGE_PARAMETER])?;
    let image = ImageId::try_from(image.parameter.value)?;

    let launch = SystemTime::now()
        .duration_since(UNIX_EPOCH)?
        .as_secs()
        .to_string();
    let mut state = State {
        launch,
        subnet: subnet.subnet_id.clone(),
        vpc: subnet.vpc_id.clone(),
        cidr: subnet.cidr_block,
        key: None,
        management_group: None,
        data_group: None,
        data_interface: None,
        instance: None,
        management_address: None,
        data_attached: false,
        deployed_commit: None,
    };
    files.save(&state)?;
    println!(
        "Launch {} recorded at {}",
        state.launch,
        files.state.display()
    );

    // The private key is made here and never leaves the workstation.
    let key_name = state.name("key");
    let private = files.ssh_dir.join(&key_name);
    std::fs::create_dir_all(&files.ssh_dir)?;
    checked(
        Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", &key_name, "-f"])
            .arg(&private),
    )?;
    let public = private.with_extension("pub");
    let imported: aws::ImportedKeyPair = aws.read(&[
        "ec2",
        "import-key-pair",
        "--key-name",
        &key_name,
        "--public-key-material",
        &format!("fileb://{}", public.display()),
        "--tag-specifications",
        &tag_specification("key-pair", &key_name, &state.launch),
    ])?;
    state.key = Some(Key {
        id: imported.key_pair_id,
        name: key_name,
        private,
    });
    files.save(&state)?;

    let management_group = security_group(aws, &state, "management")?;
    state.management_group = Some(management_group.clone());
    files.save(&state)?;
    aws.act(&[
        "ec2",
        "authorize-security-group-ingress",
        "--group-id",
        management_group.as_str(),
        "--ip-permissions",
        &serde_json::json!([{
            "IpProtocol": "tcp", "FromPort": 22, "ToPort": 22,
            "IpRanges": [{"CidrIp": format!("{workstation}/32"), "Description": "SSH from the launching workstation"}],
        }])
        .to_string(),
    ])?;
    println!("Management security group {management_group}: SSH from {workstation} only");

    // The data group starts with AWS's allow-all egress rule; removing it
    // leaves the group with no rules in either direction.
    let data_group = security_group(aws, &state, "data")?;
    state.data_group = Some(data_group.clone());
    files.save(&state)?;
    aws.act(&[
        "ec2",
        "revoke-security-group-egress",
        "--group-id",
        data_group.as_str(),
        "--ip-permissions",
        &serde_json::json!([{"IpProtocol": "-1", "IpRanges": [{"CidrIp": "0.0.0.0/0"}]}])
            .to_string(),
    ])?;
    println!("Data security group {data_group}: no rules");

    let created: aws::CreatedNetworkInterface = aws.read(&[
        "ec2",
        "create-network-interface",
        "--subnet-id",
        state.subnet.as_str(),
        "--groups",
        data_group.as_str(),
        "--description",
        "Fictionet honeypot data interface",
        "--tag-specifications",
        &tag_specification("network-interface", &state.name("data"), &state.launch),
    ])?;
    let data = created.network_interface;
    state.data_interface = Some(DataInterface {
        id: data.network_interface_id,
        mac: data.mac_address,
        private_ip: data.private_ip_address,
    });
    files.save(&state)?;
    let data = state.data_interface.as_ref().expect("just recorded");
    println!(
        "Data interface {} ({}, {}), no public address",
        data.id, data.private_ip, data.mac
    );

    let user_data = FirstBoot {
        data_mac: data.mac.clone(),
    }
    .user_data();
    let key = state.key.as_ref().expect("recorded above");
    let reservation: aws::Reservation = aws.read(&[
        "ec2",
        "run-instances",
        "--image-id",
        image.as_str(),
        "--instance-type",
        INSTANCE_TYPE,
        "--count",
        "1",
        "--key-name",
        &key.name,
        "--network-interfaces",
        &serde_json::json!([{
            "DeviceIndex": 0, "SubnetId": state.subnet.as_str(),
            "Groups": [management_group.as_str()],
            "AssociatePublicIpAddress": false, "DeleteOnTermination": true,
        }])
        .to_string(),
        "--metadata-options",
        "HttpTokens=required,HttpPutResponseHopLimit=1,HttpEndpoint=enabled",
        "--user-data",
        &user_data,
        "--tag-specifications",
        &[
            tag_specification("instance", NAME, &state.launch),
            tag_specification("volume", NAME, &state.launch),
            tag_specification(
                "network-interface",
                &state.name("management"),
                &state.launch,
            ),
        ]
        .iter()
        .flat_map(|spec| serde_json::from_str::<Vec<serde_json::Value>>(spec).expect("JSON"))
        .collect::<serde_json::Value>()
        .to_string(),
    ])?;
    let [instance] = reservation.instances.as_slice() else {
        return Err("run-instances started other than one instance".into());
    };
    state.instance = Some(instance.instance_id.clone());
    files.save(&state)?;
    let instance_id = instance.instance_id.clone();
    println!("Instance {instance_id} ({INSTANCE_TYPE}, {image}) starting");
    aws.act(&[
        "ec2",
        "wait",
        "instance-running",
        "--instance-ids",
        instance_id.as_str(),
    ])?;

    let instance = described(aws, &state)?.ok_or("the new instance is missing")?;
    let management = instance
        .network_interfaces
        .iter()
        .find(|i| i.attachment.as_ref().is_some_and(|a| a.device_index == 0))
        .ok_or("the instance has no primary interface")?;
    let allocated: aws::AllocatedAddress = aws.read(&[
        "ec2",
        "allocate-address",
        "--domain",
        "vpc",
        "--tag-specifications",
        &tag_specification("elastic-ip", &state.name("management"), &state.launch),
    ])?;
    state.management_address = Some(ElasticIp {
        allocation: allocated.allocation_id.clone(),
        public_ip: allocated.public_ip,
    });
    files.save(&state)?;
    aws.act(&[
        "ec2",
        "associate-address",
        "--allocation-id",
        allocated.allocation_id.as_str(),
        "--network-interface-id",
        management.network_interface_id.as_str(),
    ])?;
    println!(
        "Management Elastic IP {} on {}",
        allocated.public_ip, management.network_interface_id
    );

    let ssh = state.ssh(files)?;
    ssh.wait()?;
    ssh.run("cloud-init status --wait >/dev/null")?;
    println!("First boot finished; attaching the data interface");

    let data = state.data_interface.as_ref().expect("recorded above");
    aws.act(&[
        "ec2",
        "attach-network-interface",
        "--network-interface-id",
        data.id.as_str(),
        "--instance-id",
        instance_id.as_str(),
        "--device-index",
        "1",
    ])?;
    loop {
        let interfaces: aws::NetworkInterfaces = aws.read(&[
            "ec2",
            "describe-network-interfaces",
            "--network-interface-ids",
            data.id.as_str(),
        ])?;
        let attached = interfaces.network_interfaces.iter().any(|i| {
            i.attachment
                .as_ref()
                .is_some_and(|a| a.device_index == 1 && a.status == "attached")
        });
        if attached {
            break;
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    state.data_attached = true;
    files.save(&state)?;
    // udev runs its rules for the new interface as it appears.
    ssh.run("sudo udevadm settle")?;
    println!("{}", data_interface_report(&ssh, &data.mac)?);
    println!(
        "Launched. Next: cargo xtask-host honeypot-aws deploy (state in {})",
        files.state.display()
    );
    Ok(())
}

fn security_group(aws: &Aws, state: &State, role: &str) -> Result<SecurityGroupId> {
    let name = state.name(role);
    let created: aws::CreatedSecurityGroup = aws.read(&[
        "ec2",
        "create-security-group",
        "--group-name",
        &name,
        "--description",
        &format!("Fictionet honeypot {role} interface"),
        "--vpc-id",
        state.vpc.as_str(),
        "--tag-specifications",
        &tag_specification("security-group", &name, &state.launch),
    ])?;
    Ok(created.group_id)
}

/// The recorded instance as AWS describes it now, after checking it carries
/// this launch's tag. `None` once AWS no longer knows the ID.
fn described(aws: &Aws, state: &State) -> Result<Option<aws::Instance>> {
    let id = state
        .instance
        .as_ref()
        .ok_or("launch started no instance")?;
    let reservations: aws::Reservations =
        match aws.read(&["ec2", "describe-instances", "--instance-ids", id.as_str()]) {
            Ok(reservations) => reservations,
            Err(failure) if failure.not_found() => return Ok(None),
            Err(failure) => return Err(failure.into()),
        };
    let instance = reservations
        .reservations
        .into_iter()
        .flat_map(|r| r.instances)
        .find(|i| &i.instance_id == id)
        .ok_or_else(|| format!("AWS did not describe {id}"))?;
    if !carries(&instance.tags, &state.launch) {
        return Err(format!(
            "{id} does not carry tag {LAUNCH_TAG}={}; refusing to act on it",
            state.launch
        )
        .into());
    }
    Ok(Some(instance))
}

/// The data interface as the instance's Linux sees it: its name, state and
/// addresses (there should be none).
fn data_interface_report(ssh: &Ssh, mac: &MacAddress) -> Result<String> {
    let name = ssh.run(&format!(
        "ip -o link | awk -v mac={mac} '$0 ~ mac {{sub(\":\", \"\", $2); print $2}}'"
    ))?;
    let name = name.trim();
    if name.is_empty() {
        return Ok(format!("Data interface {mac}: not present in Linux"));
    }
    let addresses = ssh.run(&format!("ip -o addr show dev {name}"))?;
    let link = ssh.run(&format!("ip -br link show dev {name}"))?;
    let ipv6 = ssh.run(&format!("cat /proc/sys/net/ipv6/conf/{name}/disable_ipv6"))?;
    Ok(format!(
        "Data interface {name} ({mac}): {}; IPv6 disabled: {}; addresses: {}",
        link.split_whitespace().nth(1).unwrap_or("unknown"),
        ipv6.trim() == "1",
        if addresses.trim().is_empty() {
            "none".to_owned()
        } else {
            addresses.trim().to_owned()
        }
    ))
}

fn deploy(aws: &Aws, files: &Files) -> Result {
    let mut state = files.load()?;
    let instance = described(aws, &state)?.ok_or("the recorded instance no longer exists")?;
    if instance.state.name != "running" {
        return Err(format!(
            "{} is {}; start it first",
            instance.instance_id, instance.state.name
        )
        .into());
    }
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .ok_or("xtask lives in the repository")?;
    let commit = commit(root)?;
    let binary = build(root)?;
    let service = state.service()?;
    let ssh = state.ssh(files)?;

    println!("Copying {} ({commit})", binary.display());
    ssh.copy(&binary, "honeypot.new")?;
    ssh.feed(
        &format!("sudo tee {} >/dev/null", provision::UNIT),
        service.unit().as_bytes(),
    )?;
    ssh.feed(
        &format!(
            "sudo install -D -m 0644 /dev/stdin {}",
            provision::COMMIT_FILE
        ),
        format!("{commit}\n").as_bytes(),
    )?;
    ssh.run(&format!(
        "sudo install -m 0755 -o root -g root honeypot.new {binary} && rm honeypot.new && \
         sudo systemctl daemon-reload && sudo systemctl enable --quiet honeypot && \
         sudo systemctl restart honeypot",
        binary = provision::BINARY
    ))?;
    state.deployed_commit = Some(commit.clone());
    files.save(&state)?;
    println!("Deployed {commit}: {}", service.command().join(" "));
    Ok(())
}

/// HEAD, marked when the working tree has changes HEAD does not hold.
fn commit(root: &Path) -> Result<String> {
    let git = |args: &[&str]| -> Result<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()?;
        if !output.status.success() {
            return Err(format!("git {} failed", args.join(" ")).into());
        }
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
    };
    let head = git(&["rev-parse", "HEAD"])?;
    let dirty = !git(&["status", "--porcelain", "--untracked-files=no"])?.is_empty();
    Ok(if dirty { format!("{head}-dirty") } else { head })
}

/// Builds the honeypot as a static musl executable. zig is the C compiler
/// for the crates with C in them; this executable passes their calls on to
/// it (see `musl_cc_arguments`).
fn build(root: &Path) -> Result<PathBuf> {
    let target_dir = std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root.join("target"));
    let target_dir = if target_dir.is_absolute() {
        target_dir
    } else {
        root.join(target_dir)
    };
    let cargo = std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into());
    let compiler = std::env::current_exe()?;
    checked(
        Command::new(cargo)
            .current_dir(root)
            .args([
                "build",
                "--locked",
                "--release",
                "-p",
                "honeypot-world",
                "--bin",
                "honeypot",
                "--target",
                MUSL,
            ])
            .env("CARGO_TARGET_DIR", &target_dir)
            .env(format!("CC_{}", MUSL.replace('-', "_")), &compiler)
            .env(MUSL_CC, "1"),
    )?;
    Ok(target_dir.join(MUSL).join("release/honeypot"))
}

/// Runs `zig cc` for the musl build, in place of this process.
pub fn musl_cc() -> Result {
    use std::os::unix::process::CommandExt;
    let error = Command::new("zig")
        .args(musl_cc_arguments(std::env::args_os().skip(1)))
        .env_remove(MUSL_CC)
        .exec();
    Err(format!("cannot run zig, the musl C compiler: {error}").into())
}

fn status(aws: &Aws, files: &Files) -> Result {
    let state = files.load()?;
    println!("Launch {} ({})", state.launch, files.state.display());
    let Some(instance) = described(aws, &state)? else {
        println!("Instance: gone");
        return Ok(());
    };
    println!(
        "Instance {} ({}): {}",
        instance.instance_id, instance.instance_type, instance.state.name
    );
    let mut interfaces: Vec<_> = instance.network_interfaces.iter().collect();
    interfaces.sort_by_key(|i| i.attachment.as_ref().map(|a| a.device_index));
    for interface in interfaces {
        let index = interface.attachment.as_ref().map(|a| a.device_index);
        let role = match index {
            Some(0) => "management",
            Some(1) => "data",
            _ => "other",
        };
        println!(
            "  {role} interface {}: private {}",
            interface.network_interface_id, interface.private_ip_address
        );
    }
    if let Some(address) = &state.management_address {
        println!("  management Elastic IP {}", address.public_ip);
    }
    if !state.data_attached {
        println!("  data interface not attached");
    }
    println!(
        "  deployed commit (recorded here): {}",
        state.deployed_commit.as_deref().unwrap_or("none")
    );
    if instance.state.name != "running" {
        return Ok(());
    }
    let ssh = state.ssh(files)?;
    if let Some(data) = &state.data_interface {
        println!("  {}", data_interface_report(&ssh, &data.mac)?);
    }
    let active = ssh.run("systemctl is-active honeypot || true")?;
    println!("  service: {}", active.trim());
    let commit = ssh.run(&format!(
        "cat {} 2>/dev/null || true",
        provision::COMMIT_FILE
    ))?;
    println!(
        "  commit on the instance: {}",
        Some(commit.trim())
            .filter(|c| !c.is_empty())
            .unwrap_or("none")
    );
    let journal = ssh.run("sudo journalctl -u honeypot -n 5 -o short-iso --no-pager --quiet")?;
    for line in journal.lines() {
        println!("    {line}");
    }
    Ok(())
}

fn dashboard(aws: &Aws, files: &Files) -> Result {
    let state = files.load()?;
    let instance = described(aws, &state)?.ok_or("the recorded instance no longer exists")?;
    if instance.state.name != "running" {
        return Err(format!("{} is {}", instance.instance_id, instance.state.name).into());
    }
    let ssh = state.ssh(files)?;
    println!("Dashboard at http://127.0.0.1:{DASHBOARD_PORT}/ until Ctrl-C");
    checked(
        Command::new("ssh")
            .args(ssh.options())
            .args([
                "-N",
                "-o",
                "ExitOnForwardFailure=yes",
                "-L",
                &format!("127.0.0.1:{DASHBOARD_PORT}:127.0.0.1:{DASHBOARD_PORT}"),
            ])
            .arg(ssh.destination()),
    )
}

fn stop(aws: &Aws, files: &Files) -> Result {
    let state = files.load()?;
    let instance = described(aws, &state)?.ok_or("the recorded instance no longer exists")?;
    let id = instance.instance_id.as_str();
    aws.act(&["ec2", "stop-instances", "--instance-ids", id])?;
    aws.act(&["ec2", "wait", "instance-stopped", "--instance-ids", id])?;
    println!("{id} stopped");
    Ok(())
}

fn start(aws: &Aws, files: &Files) -> Result {
    let state = files.load()?;
    let instance = described(aws, &state)?.ok_or("the recorded instance no longer exists")?;
    let id = instance.instance_id.as_str();
    aws.act(&["ec2", "start-instances", "--instance-ids", id])?;
    aws.act(&["ec2", "wait", "instance-running", "--instance-ids", id])?;
    state.ssh(files)?.wait()?;
    println!("{id} running");
    Ok(())
}

/// Deletes everything the launch recorded, newest first, after checking
/// each resource's tag. Each one leaves the state file as it goes, so an
/// interrupted terminate can be run again.
fn terminate(aws: &Aws, files: &Files) -> Result {
    let mut state = files.load()?;
    if let Some(instance) = described(aws, &state)? {
        let id = instance.instance_id.as_str();
        if instance.state.name != "terminated" {
            aws.act(&["ec2", "terminate-instances", "--instance-ids", id])?;
        }
        aws.act(&["ec2", "wait", "instance-terminated", "--instance-ids", id])?;
        println!("Instance {id} terminated");
    }
    state.instance = None;
    state.data_attached = false;
    files.save(&state)?;

    if let Some(address) = &state.management_address {
        let tagged: Option<aws::Addresses> = gone_if_missing(aws.read(&[
            "ec2",
            "describe-addresses",
            "--allocation-ids",
            address.allocation.as_str(),
        ]))?;
        if let Some(tagged) = tagged {
            require_tag(
                tagged.addresses.iter().map(|a| &a.tags[..]),
                &state,
                &address.allocation,
            )?;
            gone_if_missing(aws.act(&[
                "ec2",
                "release-address",
                "--allocation-id",
                address.allocation.as_str(),
            ]))?;
        }
        println!("Elastic IP {} released", address.public_ip);
    }
    state.management_address = None;
    files.save(&state)?;

    if let Some(data) = &state.data_interface {
        let id = data.id.as_str();
        let tagged: Option<aws::NetworkInterfaces> = gone_if_missing(aws.read(&[
            "ec2",
            "describe-network-interfaces",
            "--network-interface-ids",
            id,
        ]))?;
        if let Some(tagged) = tagged {
            require_tag(
                tagged.network_interfaces.iter().map(|i| &i.tags[..]),
                &state,
                &data.id,
            )?;
            // Detaching from the terminated instance takes a moment.
            aws.act(&[
                "ec2",
                "wait",
                "network-interface-available",
                "--network-interface-ids",
                id,
            ])?;
            gone_if_missing(aws.act(&[
                "ec2",
                "delete-network-interface",
                "--network-interface-id",
                id,
            ]))?;
        }
        println!("Data interface {id} deleted");
    }
    state.data_interface = None;
    files.save(&state)?;

    for group in [state.data_group.take(), state.management_group.take()]
        .into_iter()
        .flatten()
    {
        let tagged: Option<aws::SecurityGroups> = gone_if_missing(aws.read(&[
            "ec2",
            "describe-security-groups",
            "--group-ids",
            group.as_str(),
        ]))?;
        if let Some(tagged) = tagged {
            require_tag(
                tagged.security_groups.iter().map(|g| &g.tags[..]),
                &state,
                &group,
            )?;
            gone_if_missing(aws.act(&[
                "ec2",
                "delete-security-group",
                "--group-id",
                group.as_str(),
            ]))?;
        }
        println!("Security group {group} deleted");
        files.save(&state)?;
    }

    if let Some(key) = &state.key {
        let tagged: Option<aws::KeyPairs> = gone_if_missing(aws.read(&[
            "ec2",
            "describe-key-pairs",
            "--key-pair-ids",
            key.id.as_str(),
        ]))?;
        if let Some(tagged) = tagged {
            require_tag(
                tagged.key_pairs.iter().map(|k| &k.tags[..]),
                &state,
                &key.id,
            )?;
            gone_if_missing(aws.act(&[
                "ec2",
                "delete-key-pair",
                "--key-pair-id",
                key.id.as_str(),
            ]))?;
        }
        for path in [key.private.clone(), key.private.with_extension("pub")] {
            match std::fs::remove_file(&path) {
                Err(error) if error.kind() != std::io::ErrorKind::NotFound => {
                    return Err(error.into());
                }
                _ => {}
            }
        }
        println!("Key pair {} deleted, here and in AWS", key.name);
    }
    state.key = None;
    files.save(&state)?;

    for path in [&files.known_hosts, &files.state] {
        match std::fs::remove_file(path) {
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    println!("Launch {} terminated; nothing of it is left", state.launch);
    Ok(())
}

/// A described or deleted resource that AWS no longer knows is already gone.
fn gone_if_missing<T>(result: std::result::Result<T, aws::Failure>) -> Result<Option<T>> {
    match result {
        Ok(value) => Ok(Some(value)),
        Err(failure) if failure.not_found() => Ok(None),
        Err(failure) => Err(failure.into()),
    }
}

fn require_tag<'a>(
    mut tags: impl Iterator<Item = &'a [aws::Tag]>,
    state: &State,
    id: &impl std::fmt::Display,
) -> Result {
    if tags.any(|tags| carries(tags, &state.launch)) {
        Ok(())
    } else {
        Err(format!(
            "{id} does not carry tag {LAUNCH_TAG}={}; refusing to delete it",
            state.launch
        )
        .into())
    }
}
