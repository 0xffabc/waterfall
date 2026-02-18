use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

pub mod arg_config;
pub mod aux_config;
pub mod socket;
pub mod strategy;
pub mod weak_range;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum NetworkProtocol {
    UDP,
    TCP,
}

use libc::exit;
use quick_xml::se::Serializer;
use serde::{Deserialize, Serialize};

static CONFIG: LazyLock<Mutex<Option<AuxConfig>>> = LazyLock::new(|| Mutex::new(None));

use crate::core::arg_config::Args;
use crate::core::aux_config::AuxConfig;

use clap::Parser;

use notify::{Event, RecursiveMode, Result, Watcher};

pub fn core_launch_task() -> Result<()> {
    let (tx, rx) = std::sync::mpsc::channel::<Result<Event>>();

    let mut watcher = notify::recommended_watcher(tx)?;

    let path = Args::parse().config;

    watcher.watch(Path::new(&path), RecursiveMode::Recursive)?;

    for res in rx {
        match res {
            Ok(_) => {
                let mut lock = CONFIG.lock().unwrap();

                *lock = Some(load_config());

                info!("Config hot-reloaded!");
            }
            Err(e) => error!("Error while watching the config file: {e:?}"),
        }
    }

    Ok(())
}

fn create_config() {
    let path = Args::parse().config;

    let mut buffer = String::new();

    let default = AuxConfig::default();

    let mut ser = Serializer::with_root(&mut buffer, None).expect("Failed to init serializer0");

    ser.indent(' ', 4);
    ser.expand_empty_elements(true);

    let _result = default.serialize(ser).expect("Serialization failed!");

    fs::write(&path, buffer).expect("Failed to write the file");
}

fn load_config() -> AuxConfig {
    let path = Args::parse().config;

    info!("Loading config file {path:?}");

    let mut xml_data = String::new();

    let file = File::open(&path);

    match file {
        Ok(mut file) => {
            file.read_to_string(&mut xml_data)
                .expect("Failed to read file");
        }

        Err(_) => {
            debug!("Config file not found! Creating a new one");

            create_config();

            debug!("A fresh config has been made! Rerun waterfall or edit the specified config");

            unsafe {
                exit(0);
            }
        }
    }

    let config: AuxConfig = quick_xml::de::from_str(&xml_data).expect("Failed to deserialize");

    config
}

pub fn parse_args() -> AuxConfig {
    let mut lock = CONFIG.lock().unwrap();

    match lock.clone() {
        Some(config) => config,
        None => {
            *lock = Some(load_config());

            lock.as_ref().unwrap().clone()
        }
    }
}
