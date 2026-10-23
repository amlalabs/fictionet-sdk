use fictionet::stdlib::protocols::dns::{op::ResponseCode, rr::RecordType};
use fictionet_test_support::sandbox::machine;
use std::sync::Arc;

#[tokio::test]
async fn prepared_workstations_have_no_software_download_routes() {
    fictionet::lab(fictionet::Seed::from_u64(9), |cx| async move {
        let seed = web_world::pages::Seed::builtin("web")?;
        let start = web_world::world_start(&seed.date)?;
        let pages = Arc::new(
            web_world::pages::Pages::copied(
                seed.clone(),
                &std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                    .join("../../../extras/tests/fixtures"),
                &["https://sky.org/".into()],
                None,
            )
            .map_err(fictionet::Error::msg)?,
        );
        let world = web_world::World {
            pages,
            ..web_world::World::new(&cx, seed, start)?
        };
        let (attacher, attachments) = fictionet::attachments();
        let log = Arc::new(fictionet_extras::log::Log::new(
            Box::new(std::io::sink()),
            &[],
            |s| s,
        ));
        let net = fictionet_search_demo::network::build(&world, &cx, log, None)?;
        net.start(&cx, attachments)?;
        let guest = machine(
            &cx,
            attacher.attach("workstation")?,
            "10.0.0.2".parse::<std::net::Ipv4Addr>()?,
        );
        for host in [
            "archive.ubuntu.com",
            "security.ubuntu.com",
            "packages.mozilla.org",
            "downloads.claude.ai",
            "releases.openai.com",
        ] {
            let response = guest
                .lookup(&cx, "10.0.0.1".parse()?, host, RecordType::A)
                .await?;
            assert_eq!(
                response.metadata.response_code,
                ResponseCode::NXDomain,
                "{host}"
            );
            assert!(response.answers.is_empty(), "{host}");
        }
        let response = guest
            .lookup(&cx, "10.0.0.1".parse()?, "sky.org", RecordType::A)
            .await?;
        assert_eq!(response.answers.len(), 1);
        cx.cancel();
        Ok(())
    })
    .await
    .unwrap();
}
