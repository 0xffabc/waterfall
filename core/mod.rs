use std::fs::{self, File};
use std::io::Read;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

pub mod arg_config;
pub mod aux_config;
pub mod blockmarker;
pub mod router;
pub mod socket;
pub mod strategy;
pub mod weak_range;

use futures::channel::mpsc;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum NetworkProtocol {
    UDP,
    TCP,
}

use quick_xml::se::Serializer;
use serde::{Deserialize, Serialize};

static CONFIG: LazyLock<Mutex<Option<AuxConfig>>> = LazyLock::new(|| Mutex::new(None));

use crate::core::arg_config::Args;
use crate::core::aux_config::AuxConfig;

use clap::Parser;

#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "sparc64",
    target_arch = "loongarch64",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_env = "musl",
)))]
use notify::{RecommendedWatcher, RecursiveMode, Result, Watcher};

use futures::{SinkExt, StreamExt};

#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "sparc64",
    target_arch = "loongarch64",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_env = "musl",
)))]
pub async fn core_launch_task() -> Result<()> {
    let (mut tx, mut rx) = mpsc::channel(1);

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            futures::executor::block_on(async {
                tx.send(res).await.unwrap();
            })
        },
        notify::Config::default(),
    )?;

    let path = Args::parse().config;

    watcher.watch(Path::new(&path), RecursiveMode::Recursive)?;

    while let Some(res) = rx.next().await {
        match res {
            Ok(_) => {
                let mut lock = match CONFIG.lock() {
                    Err(e) => e.into_inner(),
                    Ok(guard) => guard,
                };

                *lock = Some(load_config());

                info!("Config hot-reloaded!");
            }
            Err(e) => error!("Error while watching the config file: {e:?}"),
        }
    }

    Ok(())
}

#[cfg(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "sparc64",
    target_arch = "loongarch64",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_env = "musl",
))]
pub async fn core_launch_task() -> anyhow::Result<()> {
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

            std::process::exit(0);
        }
    }

    let config: AuxConfig = quick_xml::de::from_str(&xml_data).unwrap_or_else(|_| {
        error!("Failed to load waterfall-proxy config: Loading a default one instead!");

        AuxConfig::default()
    });

    config
}

pub fn parse_args() -> AuxConfig {
    let mut lock = match CONFIG.lock() {
        Err(e) => e.into_inner(),
        Ok(guard) => guard,
    };

    match lock.clone() {
        Some(config) => config,
        None => {
            *lock = Some(load_config());

            lock.as_ref().unwrap().clone()
        }
    }
}
