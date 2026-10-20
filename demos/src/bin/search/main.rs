use fictionet_extras::models::{Https, Key};
mod checks;
mod guest;
mod preview;
use fictionet_demo::search as page;

use adaptive_web_world::{
    Addresses, Ca, World,
    pages::{
        GeneratorKind, Maker, Pages,
        model::{Model, Provider},
        store::Store,
    },
    search::Generator,
};
use adaptive_web_world::{events::LogObserver, pages::Seed, search::Searches};
use example_common::log::Log;
use fictionet_demo::kit::{self, Kit};
use std::{
    collections::BTreeSet,
    fs::File,
    path::PathBuf,
    sync::Arc,
    time::{Instant, SystemTime, UNIX_EPOCH},
};

type Result<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// What to run: the VM demo with its downloads folder, the seed's name and
/// whether the page stays open after the checks, an interactive model session,
/// or the preview without a VM and whether it spends the generation budget.
#[derive(Debug, PartialEq)]
enum Mode {
    Run {
        downloads: PathBuf,
        seed: String,
        stay: bool,
        model: Option<ModelOptions>,
    },
    Preview {
        spend: bool,
    },
}

#[derive(Debug, PartialEq)]
struct ModelOptions {
    provider: Provider,
    name: String,
    store: Option<PathBuf>,
}

fn search_projection(seed: &Seed, model: Option<&ModelOptions>) -> Searches {
    match model {
        Some(options) => Searches::new(
            Searches::from_seed(seed).snapshot().seed,
            Generator {
                kind: GeneratorKind::Model(options.provider),
                model: options.name.clone(),
                ..Generator::default()
            },
        ),
        None => Searches::from_seed(seed),
    }
}

fn arguments(mut args: impl Iterator<Item = String>) -> Result<Mode> {
    const USAGE: &str = "usage: search <downloads> [--seed <name>] [--stay] [--model openrouter|anthropic [--model-name <name>] [--store <directory>]], or search preview [--spend-budget]";
    let first = args.next().ok_or(USAGE)?;
    if first == "preview" {
        return match (args.next().as_deref(), args.next()) {
            (None, _) => Ok(Mode::Preview { spend: false }),
            (Some("--spend-budget"), None) => Ok(Mode::Preview { spend: true }),
            _ => Err(USAGE.into()),
        };
    }
    if first.starts_with('-') {
        return Err(USAGE.into());
    }
    let (mut seed, mut stay) = (None, false);
    let (mut provider, mut name, mut store) = (None, None, None);
    while let Some(flag) = args.next() {
        match flag.as_str() {
            "--seed" if seed.is_none() => seed = Some(args.next().ok_or(USAGE)?),
            "--stay" if !stay => stay = true,
            "--model" if provider.is_none() => {
                provider = Some(match args.next().as_deref() {
                    Some("openrouter") => Provider::OpenRouter,
                    Some("anthropic") => Provider::Anthropic,
                    _ => return Err(USAGE.into()),
                });
            }
            "--model-name" if name.is_none() => name = Some(args.next().ok_or(USAGE)?),
            "--store" if store.is_none() => store = Some(PathBuf::from(args.next().ok_or(USAGE)?)),
            _ => return Err(USAGE.into()),
        }
    }
    if provider.is_none() && (name.is_some() || store.is_some()) {
        return Err(USAGE.into());
    }
    Ok(Mode::Run {
        downloads: first.into(),
        seed: seed.unwrap_or_else(|| "halvard-cve".into()),
        stay,
        model: provider.map(|provider| ModelOptions {
            provider,
            name: name
                .filter(|name| !name.is_empty())
                .unwrap_or_else(|| provider.default_model().into()),
            store,
        }),
    })
}

#[tokio::main]
async fn main() -> Result {
    let total = Instant::now();
    let (downloads, seed, stay, model) = match arguments(std::env::args().skip(1))? {
        Mode::Preview { spend } => return preview::run(spend).await,
        Mode::Run {
            downloads,
            seed,
            stay,
            model,
        } => (downloads, seed, stay, model),
    };
    let seed = Seed::builtin(&seed)?;
    let live = model.is_some();
    let key = model
        .as_ref()
        .map(|options| Key::from_env(options.provider.into()))
        .transpose()?;
    let store_root = model.as_ref().map(|options| {
        options
            .store
            .clone()
            .unwrap_or_else(|| downloads.join("search-store").join(&seed.name))
    });
    let output = downloads.join("runs").join(format!(
        "search-{}",
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs()
    ));
    std::fs::create_dir_all(output.parent().unwrap())?;
    std::fs::create_dir(&output)?;
    println!("output: {}", output.display());
    let searches = Arc::new(search_projection(&seed, model.as_ref()));
    let topics = page::Topics::new();
    let view = topics.clone();
    let log = Arc::new(Log::new(
        Box::new(File::create(output.join("log.jsonl"))?),
        &[],
        |s| s,
    ));
    let world_log = log.clone();
    let scenario = seed.clone();
    let kit = Kit::new("search")
        .guest(guest::guest())
        .observer(searches.clone())
        .observer(Arc::new(LogObserver { log: log.clone() }))
        .page(move |dashboard, hosts| view.page(dashboard, hosts.take(guest::HOST)))
        .world(move |cx, mut world| async move {
            let start = adaptive_web_world::world_start(&seed.date)?;
            let web = match (model, key, store_root) {
                (Some(options), Some(key), Some(root)) => {
                    let https = Arc::new(Https::new(&cx, options.provider.into())?);
                    let maker =
                        Maker::Model(Model::new(options.provider, &options.name, "", key, https));
                    let (store, _) = Store::open(&root, &seed, Some(&maker.identity()))
                        .map_err(fictionet::Error::msg)?;
                    World {
                        ca: Arc::new(Ca::in_memory(&cx, start)?),
                        addresses: Arc::new(Addresses::new(seed.fixed_addresses(), Some(&root))?),
                        pages: Arc::new(Pages::open(seed, store, Some(maker), 0)),
                        start,
                    }
                }
                (None, None, None) => World::new(&cx, seed, start)?,
                _ => unreachable!("model options include a key and store"),
            };
            world.trust("office", &web.ca.cert_pem())?;
            topics.start(
                &cx,
                searches,
                web.pages.clone(),
                if live {
                    "Firefox"
                } else {
                    "Firefox (scripted)"
                },
            )?;
            page::network(&web, &cx, world_log, world.mirror(&cx)?)?
                .route(kit::JUMP, kit::jump_prefix())
                .start(&cx, world.into_attachments())
        });
    let run = kit.boot(downloads).await?;
    println!(
        "boot to SSH-ready: {} ms",
        run.guest(guest::HOST).ssh_ready().as_millis()
    );
    let mut visited = BTreeSet::new();
    let mut result = if live {
        run.guest(guest::HOST)
            .wait_desktop(std::time::Duration::from_secs(300))
            .await
            .map(|_| ())
            .map_err(Into::into)
    } else {
        checks::run(&run, &scenario, &output, &mut visited).await
    };
    if result.is_ok() {
        println!(
            "{}: {} ms",
            if live { "ready" } else { "story done" },
            run.boot_started().elapsed().as_millis()
        );
        if live {
            println!("Search in Firefox. Pages and results are saved; Ctrl-C stops the session.");
        }
        if stay || live {
            result = kit::checks::stay_open().await.map_err(Into::into);
        }
    }
    if result.is_err() {
        eprint!("{}", run.guest(guest::HOST).diagnostics().await);
    }
    let shutdown = run.shutdown().await;
    let finish = log.finish();
    println!("whole run: {} ms", total.elapsed().as_millis());
    finish?;
    let result = result.and(shutdown.map_err(Into::into));
    if live {
        result?;
    } else {
        checks::finish(result, &output.join("log.jsonl"), &visited)?;
        println!("every required check passed");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Mode, arguments};

    fn parse(args: &[&str]) -> Option<Mode> {
        arguments(args.iter().map(|a| a.to_string())).ok()
    }

    #[test]
    fn arguments_take_a_folder_a_seed_and_stay_in_any_order() {
        let run = |downloads: &str, seed: &str, stay| {
            Some(Mode::Run {
                downloads: downloads.into(),
                seed: seed.into(),
                stay,
                model: None,
            })
        };
        assert_eq!(parse(&["d"]), run("d", "halvard-cve", false));
        assert_eq!(
            parse(&["d", "--stay", "--seed", "corvane-acquisition"]),
            run("d", "corvane-acquisition", true)
        );
        assert_eq!(
            parse(&["d", "--seed", "fastjsonl-package", "--stay"]),
            run("d", "fastjsonl-package", true)
        );
        assert_eq!(parse(&["preview"]), Some(Mode::Preview { spend: false }));
        assert_eq!(
            parse(&["preview", "--spend-budget"]),
            Some(Mode::Preview { spend: true })
        );
        for bad in [
            &[][..],
            &["--stay"],
            &["d", "--stay", "--stay"],
            &["d", "--seed"],
            &["d", "--seed", "a", "--seed", "b"],
            &["d", "extra"],
            &["d", "--other"],
            &["preview", "--stay"],
            &["preview", "--spend-budget", "--spend-budget"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn model_options_require_a_provider() {
        use super::{ModelOptions, Provider};
        for (provider, flag) in [
            (Provider::OpenRouter, "openrouter"),
            (Provider::Anthropic, "anthropic"),
        ] {
            assert_eq!(
                parse(&["d", "--model", flag]),
                Some(Mode::Run {
                    downloads: "d".into(),
                    seed: "halvard-cve".into(),
                    stay: false,
                    model: Some(ModelOptions {
                        provider,
                        name: provider.default_model().into(),
                        store: None,
                    }),
                })
            );
            assert_eq!(
                parse(&[
                    "d",
                    "--store",
                    "saved",
                    "--model-name",
                    "custom",
                    "--model",
                    flag,
                    "--stay"
                ]),
                Some(Mode::Run {
                    downloads: "d".into(),
                    seed: "halvard-cve".into(),
                    stay: true,
                    model: Some(ModelOptions {
                        provider,
                        name: "custom".into(),
                        store: Some("saved".into()),
                    }),
                })
            );
        }
        for bad in [
            &["d", "--model"][..],
            &["d", "--model", "other"],
            &["d", "--model-name", "custom"],
            &["d", "--store", "saved"],
            &["d", "--model", "openrouter", "--model", "anthropic"],
            &["d", "--model", "openrouter", "--model-name"],
            &["d", "--model", "openrouter", "--store"],
        ] {
            assert_eq!(parse(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn search_projection_names_the_selected_generator_before_any_request() {
        use super::{GeneratorKind, Seed, search_projection};
        let seed = Seed::builtin("halvard-cve").unwrap();
        let stub = search_projection(&seed, None).snapshot();
        assert_eq!(stub.generator.kind, GeneratorKind::Stub);
        assert_eq!(stub.generator.model, "stub");
        for flag in ["openrouter", "anthropic"] {
            for override_name in [None, Some("custom"), Some("")] {
                let mut args = vec!["d", "--model", flag];
                if let Some(name) = override_name {
                    args.extend(["--model-name", name]);
                }
                let Mode::Run {
                    model: Some(options),
                    ..
                } = parse(&args).unwrap()
                else {
                    panic!("expected a model session");
                };
                let snapshot = search_projection(&seed, Some(&options)).snapshot();
                assert_eq!(
                    snapshot.generator.kind,
                    GeneratorKind::Model(options.provider)
                );
                assert_eq!(
                    snapshot.generator.model,
                    override_name
                        .filter(|name| !name.is_empty())
                        .unwrap_or(options.provider.default_model())
                );
                assert!(snapshot.generator.generate);
                assert_eq!(snapshot.generator.generation_revision, 0);
                assert_eq!(snapshot.generator.prefetch, 0);
            }
        }
    }
}
