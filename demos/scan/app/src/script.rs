//! The scripted agent's three nmap steps.

pub struct Step {
    pub title: &'static str,
    pub options: &'static str,
    pub target: &'static str,
}

pub const STEPS: [Step; 3] = [
    Step {
        title: "Host discovery",
        options: "-sn -n",
        target: "10.0.0.0/24",
    },
    Step {
        title: "SYN scan with service detection",
        options: "-sS -sV --version-light -n -p 1-1024 --max-rate 300",
        target: "10.0.0.0/24",
    },
    Step {
        title: "OS detection",
        options: "-O --osscan-guess -n --max-os-tries 1",
        target: "10.0.0.10,11,12,13,50",
    },
];

/// Where nmap writes a step's XML report, relative to the agent's home.
pub fn report_file(index: usize) -> String {
    format!("notes/office-{}.xml", index + 1)
}

/// The command the agent types for a step.
pub fn command(index: usize) -> String {
    let step = &STEPS[index];
    format!(
        "sudo nmap {} -oX {} {}",
        step.options,
        report_file(index),
        step.target
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands_match_what_nmap_recorded() {
        for (index, xml) in [
            crate::nmap::tests::DISCOVERY,
            crate::nmap::tests::SERVICES,
            crate::nmap::tests::OS,
        ]
        .into_iter()
        .enumerate()
        {
            let report = crate::nmap::parse(xml).unwrap();
            assert_eq!(
                format!("sudo {}", report.args),
                command(index),
                "step {index}"
            );
        }
    }
}
