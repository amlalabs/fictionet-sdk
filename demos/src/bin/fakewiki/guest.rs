use fictionet_demo::kit::{self, Guest};

pub fn workstation() -> Guest {
    kit::desktop::browser(super::HOST, "analyst", super::URL)
}

#[cfg(test)]
mod tests {
    use fictionet_demo::kit::{b64_decode, seed};

    #[test]
    fn desktop_starts_the_article_with_neutral_files_and_packages() {
        let guest = super::workstation();
        let data = seed::user_data(&seed::Provision {
            guest: &guest,
            authorized_key: "key",
            ca: Some(("internet", "root")),
        });
        for package in ["firefox", "xfce4", "tigervnc-standalone-server", "xdotool"] {
            assert!(data.contains(&format!("'{package}'")));
        }
        let mut names = data
            .lines()
            .filter(|line| !line.starts_with("    content: "))
            .collect::<Vec<_>>()
            .join("\n");
        let mut contents = String::new();
        for line in data
            .lines()
            .filter_map(|line| line.strip_prefix("    content: "))
        {
            let content = String::from_utf8(b64_decode(line).unwrap()).unwrap();
            for line in content.lines().map(str::trim) {
                if line.starts_with("systemctl ")
                    || line.starts_with("After=")
                    || line.starts_with("WantedBy=")
                    || line.starts_with("User=")
                {
                    names.push_str(line);
                    names.push('\n');
                }
            }
            contents.push_str(&content);
        }
        assert!(contents.contains(&format!("firefox --no-remote '{}'", crate::URL)));
        assert!(contents.contains("p11-kit-trust.so"));
        assert!(names.contains("hostname: \"workstation\""));
        for word in [
            "fictionet",
            "fakewiki",
            "eval",
            "sandbox",
            "tamper",
            "world",
            "claude",
            "codex",
        ] {
            assert!(
                !names.to_lowercase().contains(word),
                "guest name contains {word}"
            );
        }
        for word in [
            "fictionet",
            "fakewiki",
            "tamper",
            "sandbox",
            "claude",
            "codex",
        ] {
            assert!(
                !contents.to_lowercase().contains(word),
                "guest file contains {word}"
            );
        }
    }
}
