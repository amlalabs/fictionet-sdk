//! The AWS CLI as typed calls: resource identifiers, the responses the
//! honeypot commands read, and the CLI's failures by error code.

use std::fmt;
use std::net::Ipv4Addr;
use std::path::PathBuf;
use std::process::Command;

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::Result;

pub const REGION: &str = "eu-west-2";

macro_rules! resource_ids {
    ($($(#[$doc:meta])* $name:ident = $prefix:literal;)*) => {$(
        $(#[$doc])*
        #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(try_from = "String", into = "String")]
        pub struct $name(String);

        impl TryFrom<String> for $name {
            type Error = String;
            fn try_from(id: String) -> std::result::Result<Self, String> {
                let suffix = id.strip_prefix($prefix).unwrap_or_default();
                if suffix.is_empty() || !suffix.bytes().all(|b| b.is_ascii_alphanumeric()) {
                    return Err(format!("{id:?} is not a {} ID", stringify!($name)));
                }
                Ok(Self(id))
            }
        }

        impl From<$name> for String {
            fn from(id: $name) -> String {
                id.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl $name {
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    )*};
}

resource_ids! {
    InstanceId = "i-";
    SecurityGroupId = "sg-";
    NetworkInterfaceId = "eni-";
    AllocationId = "eipalloc-";
    KeyPairId = "key-";
    SubnetId = "subnet-";
    VpcId = "vpc-";
    ImageId = "ami-";
}

/// An Ethernet address as EC2 reports it: six lowercase hex pairs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct MacAddress(String);

impl TryFrom<String> for MacAddress {
    type Error = String;
    fn try_from(mac: String) -> std::result::Result<Self, String> {
        let pairs: Vec<_> = mac.split(':').collect();
        if pairs.len() != 6
            || !pairs
                .iter()
                .all(|p| p.len() == 2 && p.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err(format!("{mac:?} is not a MAC address"));
        }
        Ok(Self(mac.to_ascii_lowercase()))
    }
}

impl From<MacAddress> for String {
    fn from(mac: MacAddress) -> String {
        mac.0
    }
}

impl fmt::Display for MacAddress {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// An IPv4 subnet, as `a.b.c.d/n`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Ipv4Cidr {
    pub network: Ipv4Addr,
    pub prefix: u8,
}

impl TryFrom<String> for Ipv4Cidr {
    type Error = String;
    fn try_from(text: String) -> std::result::Result<Self, String> {
        let invalid = || format!("{text:?} is not an IPv4 CIDR block");
        let (address, prefix) = text.split_once('/').ok_or_else(invalid)?;
        let address: Ipv4Addr = address.parse().map_err(|_| invalid())?;
        let prefix: u8 = prefix.parse().map_err(|_| invalid())?;
        if prefix > 30 {
            return Err(invalid());
        }
        let mask = u32::MAX << (32 - prefix);
        Ok(Self {
            network: Ipv4Addr::from(u32::from(address) & mask),
            prefix,
        })
    }
}

impl From<Ipv4Cidr> for String {
    fn from(cidr: Ipv4Cidr) -> String {
        format!("{}/{}", cidr.network, cidr.prefix)
    }
}

impl Ipv4Cidr {
    /// The VPC router: the subnet's network address plus one.
    pub fn router(self) -> Ipv4Addr {
        Ipv4Addr::from(u32::from(self.network) + 1)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Tag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Subnets {
    pub subnets: Vec<Subnet>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Subnet {
    pub subnet_id: SubnetId,
    pub vpc_id: VpcId,
    pub cidr_block: Ipv4Cidr,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Parameter {
    pub parameter: ParameterValue,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ParameterValue {
    pub value: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct ImportedKeyPair {
    pub key_pair_id: KeyPairId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeyPairs {
    pub key_pairs: Vec<KeyPair>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct KeyPair {
    #[serde(default)]
    pub tags: Vec<Tag>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreatedSecurityGroup {
    pub group_id: SecurityGroupId,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SecurityGroups {
    pub security_groups: Vec<SecurityGroup>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SecurityGroup {
    #[serde(default)]
    pub tags: Vec<Tag>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct CreatedNetworkInterface {
    pub network_interface: NetworkInterface,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkInterfaces {
    pub network_interfaces: Vec<NetworkInterface>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct NetworkInterface {
    pub network_interface_id: NetworkInterfaceId,
    pub mac_address: MacAddress,
    pub private_ip_address: Ipv4Addr,
    pub attachment: Option<Attachment>,
    #[serde(default, alias = "TagSet")]
    pub tags: Vec<Tag>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Attachment {
    pub device_index: u32,
    pub status: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Reservation {
    pub instances: Vec<Instance>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Reservations {
    pub reservations: Vec<Reservation>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Instance {
    pub instance_id: InstanceId,
    pub instance_type: String,
    pub state: InstanceState,
    #[serde(default)]
    pub network_interfaces: Vec<NetworkInterface>,
    #[serde(default)]
    pub tags: Vec<Tag>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct InstanceState {
    pub name: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct AllocatedAddress {
    pub allocation_id: AllocationId,
    pub public_ip: Ipv4Addr,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Addresses {
    pub addresses: Vec<Address>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct Address {
    #[serde(default)]
    pub tags: Vec<Tag>,
}

/// A failed CLI call. `code` is the service's error code, such as
/// `InvalidInstanceID.NotFound`, when the CLI reported one.
#[derive(Debug)]
pub struct Failure {
    pub code: Option<String>,
    pub message: String,
}

impl Failure {
    fn parse(stderr: &str) -> Self {
        let code = stderr
            .split_once("An error occurred (")
            .and_then(|(_, rest)| rest.split_once(')'))
            .map(|(code, _)| code.to_owned());
        Self {
            code,
            message: stderr.trim().to_owned(),
        }
    }

    pub fn not_found(&self) -> bool {
        self.code
            .as_deref()
            .is_some_and(|c| c.ends_with("NotFound"))
    }
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for Failure {}

/// The AWS CLI, always in the honeypot's region.
pub struct Aws {
    exe: PathBuf,
}

impl Aws {
    /// The CLI from `~/.local/bin`, where its installer puts it, or else from
    /// `PATH`. Stops unless the session's credentials still work.
    pub fn signed_in() -> Result<Self> {
        let local = std::env::var_os("HOME")
            .map(|home| PathBuf::from(home).join(".local/bin/aws"))
            .filter(|path| path.is_file());
        let aws = Self {
            exe: local.unwrap_or_else(|| "aws".into()),
        };
        // The identity itself names the account, so it is read and dropped.
        aws.call(&["sts", "get-caller-identity"])
            .map_err(|_| "AWS login expired: run aws login")?;
        Ok(aws)
    }

    fn call(&self, args: &[&str]) -> std::result::Result<Vec<u8>, Failure> {
        let output = Command::new(&self.exe)
            .args(args)
            .args(["--region", REGION, "--output", "json", "--no-cli-pager"])
            .output()
            .map_err(|error| Failure {
                code: None,
                message: format!("cannot run {}: {error}", self.exe.display()),
            })?;
        if !output.status.success() {
            return Err(Failure::parse(&String::from_utf8_lossy(&output.stderr)));
        }
        Ok(output.stdout)
    }

    /// One EC2 (or other service) call whose JSON response is `T`.
    pub fn read<T: DeserializeOwned>(&self, args: &[&str]) -> std::result::Result<T, Failure> {
        let stdout = self.call(args)?;
        serde_json::from_slice(&stdout).map_err(|error| Failure {
            code: None,
            message: format!("unexpected response to aws {}: {error}", args.join(" ")),
        })
    }

    /// One call whose response, if any, is not needed.
    pub fn act(&self, args: &[&str]) -> std::result::Result<(), Failure> {
        self.call(args).map(drop)
    }
}

/// The `--tag-specifications` value that names a resource and marks it as
/// this launch's.
pub fn tag_specification(resource_type: &str, name: &str, launch: &str) -> String {
    serde_json::json!([{
        "ResourceType": resource_type,
        "Tags": [
            {"Key": "Name", "Value": name},
            {"Key": super::LAUNCH_TAG, "Value": launch},
        ],
    }])
    .to_string()
}

/// Whether `tags` mark a resource as belonging to `launch`.
pub fn carries(tags: &[Tag], launch: &str) -> bool {
    tags.iter()
        .any(|tag| tag.key == super::LAUNCH_TAG && tag.value == launch)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_parse_only_with_their_prefix() {
        assert!(InstanceId::try_from("i-0abc123".to_owned()).is_ok());
        for bad in ["sg-0abc", "i-", "i-0ab c", "i-0ab;rm", ""] {
            assert!(InstanceId::try_from(bad.to_owned()).is_err(), "{bad}");
        }
        let id: SecurityGroupId = serde_json::from_str("\"sg-0123abcd\"").unwrap();
        assert_eq!(serde_json::to_string(&id).unwrap(), "\"sg-0123abcd\"");
        assert!(serde_json::from_str::<SecurityGroupId>("\"eni-0123\"").is_err());
    }

    #[test]
    fn mac_addresses_are_six_hex_pairs() {
        let mac = MacAddress::try_from("0A:1b:2c:3d:4e:5F".to_owned()).unwrap();
        assert_eq!(mac.to_string(), "0a:1b:2c:3d:4e:5f");
        for bad in [
            "0a:1b:2c:3d:4e",
            "0a:1b:2c:3d:4e:5g",
            "0a:1b:2c:3d:4e:5f\"",
            "",
        ] {
            assert!(MacAddress::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    #[test]
    fn the_router_is_the_first_address_of_the_masked_network() {
        let cidr = Ipv4Cidr::try_from("172.31.16.0/20".to_owned()).unwrap();
        assert_eq!(cidr.router(), Ipv4Addr::new(172, 31, 16, 1));
        let unaligned = Ipv4Cidr::try_from("10.0.5.77/24".to_owned()).unwrap();
        assert_eq!(unaligned.network, Ipv4Addr::new(10, 0, 5, 0));
        assert_eq!(unaligned.router(), Ipv4Addr::new(10, 0, 5, 1));
        for bad in ["10.0.0.0", "10.0.0.0/33", "10.0.0.0/31", "ten/8"] {
            assert!(Ipv4Cidr::try_from(bad.to_owned()).is_err(), "{bad}");
        }
    }

    #[test]
    fn failures_keep_the_service_error_code() {
        let failure = Failure::parse(
            "\nAn error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation: gone\n",
        );
        assert_eq!(failure.code.as_deref(), Some("InvalidInstanceID.NotFound"));
        assert!(failure.not_found());
        assert!(!Failure::parse("Unable to locate credentials").not_found());
    }

    #[test]
    fn tags_mark_only_their_own_launch() {
        let spec: serde_json::Value =
            serde_json::from_str(&tag_specification("instance", "fictionet-honeypot", "42"))
                .unwrap();
        let tags: Vec<Tag> = serde_json::from_value(spec[0]["Tags"].clone()).unwrap();
        assert!(carries(&tags, "42"));
        assert!(!carries(&tags, "43"));
        assert!(
            tags.iter()
                .any(|t| t.key == "Name" && t.value == "fictionet-honeypot")
        );
    }
}
