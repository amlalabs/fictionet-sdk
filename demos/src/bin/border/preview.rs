//! Serves the VM's page with an in-process workstation and real world traffic.

use super::{
    Error,
    client::Client,
    control::{self, Control},
    guest::HOSTNAME,
};
use border_world::{certs, log::Log};
use fictionet::{RunOptions, Seed, events::Fanout, stdlib::services::ca::Ca};
use fictionet_demo::kit;
use fictionet_observe::{
    DashboardObserver, DashboardOptions,
    page::{
        Containment, Host, HostState, HostStatus, Labels, Page, Server, StateLimits, StateTopic,
    },
};
use std::{path::Path, sync::Arc};
use tokio::sync::{mpsc, oneshot};

type Request = oneshot::Sender<Result<(), String>>;
pub struct Preview {
    pub server: Server,
    screen: kit::preview::Console,
    requests: mpsc::Sender<Request>,
    stop: oneshot::Sender<()>,
    worker: tokio::task::JoinHandle<fictionet::Result>,
    log: Log,
}
impl Preview {
    pub async fn traffic(&self) -> Result<(), Error> {
        let (send, reply) = oneshot::channel();
        self.requests.send(send).await?;
        reply.await?.map_err(Into::into)
    }
    pub async fn shutdown(self) -> Result<(), Error> {
        self.stop()
            .await?
            .shutdown(std::time::Duration::from_secs(2))
            .await;
        Ok(())
    }
    /// Ends the world and its log. The page keeps serving the final state.
    pub async fn stop(self) -> Result<Server, Error> {
        let _ = self.stop.send(());
        self.worker.await??;
        self.log.finish()?;
        Ok(self.server)
    }
}

pub async fn start(out: &Path) -> Result<Preview, Error> {
    std::fs::create_dir_all(out)?;
    let scenario = control::scenario();
    let control = Control::new(&scenario)?;
    let log = Log::start(
        Box::new(super::results::Writer::new(
            std::fs::File::create(out.join("log.jsonl"))?,
            control.results.clone(),
        )),
        scenario.clone(),
    );
    let dashboard = DashboardObserver::new(DashboardOptions::demo());
    let screen = kit::preview::Console::new();
    let status = StateTopic::new(StateLimits::default());
    status.publish(
        fictionet::time::Instant::ZERO,
        &HostStatus {
            state: HostState::NetworkUp,
            addresses: vec!["192.168.1.2".into()],
            screen: true,
            terminal: false,
        },
    )?;
    let server = control
        .page(
            Page::new("Border", dashboard.handle())
                .host(
                    Host::new(HOSTNAME)
                        .sandbox(HOSTNAME)
                        .status(status)
                        .console(screen.clone()),
                )
                .standard_panels(),
        )
        .containment(StateTopic::<Containment>::new(StateLimits::default()))
        .labels(Labels::default())
        .bind_loopback(0)
        .await?;
    println!("Page: {}", server.url());
    let options = RunOptions::new(Seed::random()).observer(Arc::new(Fanout::new(vec![
        dashboard.observer(),
        Arc::new(log.clone()),
        Arc::new(control.view.clone()),
    ])));
    let world_log = log.clone();
    let (requests, mut receiver) = mpsc::channel::<Request>(1);
    let (stop, stopped) = oneshot::channel();
    let (ready, started) = oneshot::channel();
    let worker = tokio::spawn(fictionet::run(options, move |cx| async move {
        world_log.attach(&cx);
        let ca = Ca::new(&cx, certs::LAB_CA_NAME)?;
        let ids = border_world::identities(&cx, &ca)?;
        control
            .view
            .certificates(cx.now(), super::certificates::Certificates::new(&ids)?);
        let (attacher, attachments) = fictionet::attachments();
        let routing = border_world::start(&cx, scenario, ids, attachments)?;
        let route = routing.clone();
        cx.spawn(move |cx| control.serve(cx, route));
        let mut client = Client::new(&cx, &attacher, &ca)?;
        client.bgp(&cx).await?;
        client.story(&cx, routing.mode()).await?;
        let _ = ready.send(());
        cx.spawn(move |cx| async move {
            while let Some(reply) = cx
                .race(None, receiver.recv())
                .await
                .map_err(|_| fictionet::Cancelled)?
            {
                let result = client.story(&cx, routing.mode()).await;
                let _ = reply.send(result.map_err(|e| e.to_string()));
            }
            Ok(())
        });
        let _ = cx.race(None, stopped).await;
        cx.cancel();
        Ok(())
    }));
    if started.await.is_err() {
        worker.await??;
        return Err("the client stopped before startup completed".into());
    }
    Ok(Preview {
        server,
        screen,
        requests,
        stop,
        worker,
        log,
    })
}

pub async fn run() -> Result<(), Error> {
    let out = std::env::temp_dir().join(format!("border-page-{}", kit::random_uuid()));
    let preview = start(&out).await?;
    println!("Output: {}", out.display());
    println!(
        "In-process scripted client; no VM, so the screen says NO VM. Its story signs in, checks the balance and runs traceroute on the route the page shows. Change the route on the page between runs."
    );
    let mut input =
        kit::preview::Input::stdin(kit::preview::Story::OnEnter, Some(preview.screen.clone()))?;
    while input.run().await {
        preview.traffic().await?;
        println!("Client checks complete.");
    }
    preview.shutdown().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use fictionet_demo::kit::client::PageClient;
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn real_traffic_reaches_the_page_after_hijack_and_restore() {
        let dir = std::env::temp_dir().join(format!(
            "border-client-{}",
            fictionet_demo::kit::random_uuid()
        ));
        let preview = start(&dir).await.unwrap();
        let client = PageClient::from_url(preview.server.url()).unwrap();
        client.bootstrap().await.unwrap();
        let reply = super::super::story::set_route(&client, "hijack", "hijack", 0)
            .await
            .unwrap();
        assert_eq!(reply["status"], "applied");
        preview.traffic().await.unwrap();
        super::super::story::observed(&client, true).await.unwrap();
        // The VM run's Chromium condition holds on the page this traffic made.
        let url = preview.server.url().to_owned();
        let shot = dir.join("page-hijacked.png");
        tokio::task::spawn_blocking(move || {
            fictionet_demo::kit::shot::capture(
                &url,
                &shot,
                super::super::story::HIJACKED_PAGE,
                std::time::Duration::from_secs(30),
            )
        })
        .await
        .unwrap()
        .unwrap();
        let reply = super::super::story::set_route(&client, "restore", "legitimate", 1)
            .await
            .unwrap();
        assert_eq!(reply["status"], "applied");
        preview.traffic().await.unwrap();
        super::super::story::observed(&client, false).await.unwrap();
        let tls: serde_json::Value = client.get_json("/api/state/tls").await.unwrap();
        assert_eq!(tls["value"]["lost"], 0);
        let sessions = tls["value"]["sessions"]["rows"].as_array().unwrap();
        assert_eq!(sessions.len(), 7, "{sessions:?}");
        for session in sessions {
            assert_eq!(session["gaps"], 0);
            for key in ["versions", "ciphers", "groups"] {
                let offered = session["offered"][key].as_array().unwrap();
                let chosen = session["chosen"][key].as_array().unwrap();
                assert_eq!(chosen.len(), 1);
                assert!(offered.contains(&chosen[0]), "{session}");
            }
        }
        let results: serde_json::Value = client.get_json("/api/state/results").await.unwrap();
        assert_eq!(results["value"]["invalid"], 0);
        assert_eq!(results["value"]["dropped"], 0);
        let lines = results["value"]["rows"].as_array().unwrap();
        assert!(lines.iter().any(|l| l["type"] == "http"
            && l["served_by"] == "impostor"
            && l["carries_password"] == true));
        // After the world ends, the guest link is closed and keeps its last,
        // three-hop traceroute from the restored route.
        let server = preview.stop().await.unwrap();
        let link = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                let state: serde_json::Value = client.get_json("/api/state/border").await.unwrap();
                let links = state["value"]["links"].as_array().unwrap().clone();
                if let Some(link) = links
                    .into_iter()
                    .find(|l| l["sandbox"] == HOSTNAME && l["ended_ms"].is_u64())
                {
                    return link;
                }
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .expect("the guest link did not close after the world ended");
        assert_eq!(link["trace"]["complete"], true, "{link}");
        let hops: Vec<_> = link["trace"]["hops"]
            .as_array()
            .unwrap()
            .iter()
            .map(|h| h["address"].as_str().unwrap().to_owned())
            .collect();
        assert_eq!(
            hops,
            [
                super::super::control::scenario().gateway().to_string(),
                "84.21.44.1".into(),
                "84.21.44.10".into()
            ]
        );
        server.shutdown(std::time::Duration::from_secs(2)).await;
        let written: Vec<serde_json::Value> = std::fs::read_to_string(dir.join("log.jsonl"))
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        for line in lines {
            assert!(written.contains(line));
        }
        std::fs::remove_dir_all(dir).unwrap();
    }
}
