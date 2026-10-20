use fictionet_demo::kit::{self, Guest};

pub fn workstation() -> Guest {
    kit::desktop::browser(super::HOST, "analyst", super::URL)
        .forbid(&["fakewiki", "tamper", "claude", "codex"])
}

#[cfg(test)]
mod tests {
    use fictionet_demo::kit::seed;

    #[test]
    fn desktop_opens_the_article() {
        let guest = super::workstation();
        guest.validate().unwrap();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: Some(("internet", "root")),
        });
        for package in ["firefox", "xfce4", "tigervnc-standalone-server", "xdotool"] {
            assert!(data.contains(&format!("'{package}'")));
        }
        assert!(data.contains("hostname: \"workstation\""));
        let start = &seed::files(&data).unwrap()["/opt/start-desktop.sh"];
        assert!(
            start.contains(&format!("firefox --no-remote '{}'", crate::URL)),
            "Firefox opens the article"
        );
    }
}
