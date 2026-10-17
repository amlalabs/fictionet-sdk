use crate::process::{Cleanup, Result, capture, cmd, run as execute};

pub fn build(file: &str, target: &str, tag: &str) -> Result {
    execute(
        cmd(
            "docker",
            &["build", "-f", file, "--target", target, "-t", tag],
        )
        .arg(crate::root()),
    )
}

pub fn run(args: &[String]) -> Result {
    match args {
        [] => {
            artifactory()?;
            hosted()
        }
        [target] if target == "artifactory" => artifactory(),
        [target] if target == "hosted" => hosted(),
        _ => Err("usage: cargo xtask images [artifactory|hosted]".into()),
    }
}

fn artifactory() -> Result {
    for target in ["world", "attach", "agent"] {
        build(
            "examples/artifactory/docker/Dockerfile",
            target,
            &format!("fictionet-artifactory-{target}:dev"),
        )?;
    }
    Ok(())
}

fn hosted() -> Result {
    execute(&mut cmd("python3", &["examples/hosted/package_harbor.py"]))?;
    build(
        "tests/docker/web/Dockerfile",
        "runtime",
        "fictionet-hosted-build:dev",
    )?;
    let id = capture(&mut cmd(
        "docker",
        &["create", "fictionet-hosted-build:dev"],
    ))?;
    let mut cleanup = Cleanup::default();
    cleanup.push(cmd("docker", &["rm", id.trim()]));
    let result = (|| {
        for dir in [
            "examples/hosted/bin",
            "examples/hosted/harbor/fictionet-web/environment/bin",
        ] {
            std::fs::create_dir_all(crate::root().join(dir))?;
            for binary in ["fictionet", "web_world"] {
                execute(&mut cmd(
                    "docker",
                    &[
                        "cp",
                        "-q",
                        &format!("{}:/usr/local/bin/{binary}", id.trim()),
                        &format!("{dir}/"),
                    ],
                ))?;
            }
        }
        println!("Copied fictionet and web_world into the hosted and Harbor environments");
        Ok(())
    })();
    cleanup.finish(result)
}
