//! The workstation resources and pinned coding agents.

use fictionet_demo::kit::{Guest, desktop};

pub use fictionet_demo::kit::desktop::CLAUDE_VERSION;
/// Codex's standalone package for x86-64 Linux (musl), the one OpenAI's
/// installer unpacks: the CLI with its ripgrep and bubblewrap. Its sha256 is
/// the digest the release lists on GitHub and on releases.openai.com.
pub const CODEX_VERSION: &str = "0.163.0";
const CODEX_SHA256: &str = "df22dac1f24b7927e817e8b113067fbe1caa586aba7554247fabd49464cf9c96";

pub fn workstation(hostname: &str, user: &str, site: &str) -> Guest {
    desktop::browser(hostname, user, &format!("https://{site}/"))
        .resources(4, 4096)
        .file(
            "/etc/claude-code/managed-settings.json",
            0o644,
            desktop::CLAUDE_SETTINGS,
        )
        .file("/opt/install-agents.sh", 0o755, install_agents())
        .run("bash /opt/install-agents.sh")
}

fn install_agents() -> String {
    format!(
        "#!/bin/bash\n\
         set -euo pipefail\n\
         # The coding agents, from their vendors' release servers, each checked\n\
         # against its pinned sha256; sha256sum -c stops the script on a mismatch.\n\
         # Both go in /usr/local/bin, on PATH in every shell and session.\n\
         started=$SECONDS\n\
         work=$(mktemp -d)\n\
         {claude}\
         curl -fsSLo \"$work/codex.tar.zst\" \
           https://releases.openai.com/codex/releases/{CODEX_VERSION}/\
             codex-package-x86_64-unknown-linux-musl.tar.zst\n\
         echo \"{CODEX_SHA256}  $work/codex.tar.zst\" | sha256sum -c -\n\
         install -d /opt/codex\n\
         tar --zstd -xf \"$work/codex.tar.zst\" --no-same-owner -C /opt/codex\n\
         ln -sf /opt/codex/bin/codex /usr/local/bin/codex\n\
         echo \"coding agents: $(cat \"$work/claude.zst\" \"$work/codex.tar.zst\" | wc -c) \
           bytes in $((SECONDS - started)) s\"\n\
         rm -rf \"$work\"\n",
        claude = desktop::install_claude(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::seed;

    #[test]
    fn desktop_setup_precedes_agent_installation() {
        let guest = workstation("workstation", "analyst", "intranet.northwind.internal");
        guest.validate().unwrap();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: None,
        });
        assert!(
            data.find("bash /opt/setup-desktop.sh").unwrap()
                < data.find("bash /opt/install-agents.sh").unwrap()
        );
        assert!(data.contains("/etc/claude-code/managed-settings.json"));
        assert!(data.contains(&fictionet::stdlib::codec::base64::encode(
            install_agents().as_bytes()
        )));
    }
}
