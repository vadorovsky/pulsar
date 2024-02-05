use anyhow::{Context, Result};
use engine_api::client::EngineApiClient;
use futures_util::StreamExt;
use pulsar_core::pdk::Event;
use rules_engine::{
    dsl,
    engine::{parse_rule, UserRule},
};

mod term_print;

use crate::{
    cli::pulsar::{Commands, Config, ModuleConfigKV, Monitor, PulsarCliOpts},
    pulsar::term_print::TermPrintable,
};

pub async fn pulsar_cli_run(options: &PulsarCliOpts) -> Result<()> {
    log::trace!("Pulsar CLI Options: {:?}", options);

    let engine_api_client = if let Some(api_server) = &options.api_server {
        EngineApiClient::unix(api_server.clone())?
    } else {
        EngineApiClient::new()?
    };

    log::trace!("Command received: {:?}", options.command);

    match &options.command {
        Commands::Status => engine_api_client.list_modules().await?.term_print(),
        Commands::Start { module_name } => {
            engine_api_client.start(module_name).await?;
            "Module started".to_string().term_print()
        }
        Commands::Restart { module_name } => {
            engine_api_client.restart(module_name).await?;
            "Module restarted".to_string().term_print()
        }
        Commands::Stop { module_name } => {
            engine_api_client.stop(module_name).await?;
            "Module stopped".to_string().term_print()
        }
        Commands::Config(Config { all, module, set }) => match (all, module, set) {
            (true, _, _) => engine_api_client.get_configs().await?.term_print(),
            (_, Some(module), _) => engine_api_client
                .get_module_config(module)
                .await?
                .term_print(),
            (
                _,
                _,
                Some(ModuleConfigKV {
                    module_name,
                    key,
                    value,
                }),
            ) => {
                engine_api_client
                    .set_module_config(module_name, key.clone(), value.clone())
                    .await?;
                "Configuration updated".to_string().term_print()
            }
            _ => unreachable!(),
        },
        Commands::Monitor(Monitor {
            all,
            filter_type,
            filter_condition,
        }) => {
            let rule = match filter_type {
                Some(filter_type) => match filter_condition {
                    Some(filter_condition) => {
                        let parser = dsl::dsl::ConditionParser::new();
                        let (_discriminant, rule) = parse_rule(
                            &parser,
                            // TODO(vadorovsky): Provide some other API for creating ad-hoc rules.
                            UserRule {
                                name: "".to_owned(),
                                r#type: filter_type.to_owned(),
                                condition: filter_condition.to_owned(),
                            },
                        )?;
                        let rule = rule.compile::<Event>()?;
                        Some(rule)
                    }
                    None => {
                        return Err(anyhow::anyhow!(
                            "--filter-condition is required when --filter-type is provided"
                        ))
                    }
                },
                None => {
                    if filter_condition.is_some() {
                        return Err(anyhow::anyhow!(
                            "--filter-type is required when --filter-condition is provided"
                        ));
                    }
                    None
                }
            };

            let mut stream = engine_api_client.event_monitor().await?;

            while let Some(ws_read) = stream.next().await {
                match ws_read {
                    Ok(event) => {
                        if let Some(ref rule) = rule {
                            if rule.is_match(&event) {
                                println!("{:#}", event);
                            }
                        } else if *all || event.header().threat.is_some() {
                            println!("{:#}", event);
                        }
                    }
                    Err(e) => return Err(e).context("error reading from websocket"),
                }
            }

            Err(anyhow::anyhow!("event stream ended"))
        }
    }?;

    Ok(())
}
