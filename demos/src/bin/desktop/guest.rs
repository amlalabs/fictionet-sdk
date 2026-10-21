//! The workstation resources and pinned coding agents.

use fictionet_demo::kit::{Guest, desktop};

pub use fictionet_demo::kit::desktop::CLAUDE_VERSION;

pub fn workstation(hostname: &str, user: &str, site: &str) -> Guest {
    desktop::codex(desktop::claude_code(
        desktop::browser(hostname, user, &format!("https://{site}/")).resources(4, 4096),
    ))
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
                < data.find("bash /opt/install-claude.sh").unwrap()
        );
        assert!(data.contains("/etc/claude-code/managed-settings.json"));
        assert!(data.contains(&fictionet::stdlib::codec::base64::encode(
            desktop::install_claude().as_bytes()
        )));
    }
}
