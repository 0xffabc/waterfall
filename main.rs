use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::Result;

use log::{Level, LevelFilter, Log};
use tokio::net::TcpListener;
use wfblmark::start_cleanup_task;
use wfcipu::parsers::ip::supports_ipv6;
use wfconfig::{aux_config::AuxConfig, core_launch_task, parse_args};
use wfdns::test_dns_servers;
use wfsocks::socks5_proxy;
use wftamper::service::compile_patterns;

#[macro_use]
extern crate log;

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
async fn spawn_hot_reloader() {
    tokio::spawn(async {
        core_launch_task()
            .await
            .expect("Config hot-reloader daemon has fallen");
    });
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
async fn spawn_hot_reloader() {
    warn!("Hot reloading is not available on dangerous targets");
}

struct WaterfallLogger;

impl Log for WaterfallLogger {
    fn enabled(&self, _metadata: &log::Metadata) -> bool {
        true
    }

    fn log(&self, record: &log::Record) {
        let color = match record.level() {
            Level::Error => "\x1b[31m",
            Level::Warn => "\x1b[33m",
            Level::Info => "\x1b[32m",
            Level::Debug => "\x1b[34m",
            Level::Trace => "\x1b[37m",
        };

        let time = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(e) => e.as_micros(),
            Err(_) => 666,
        };

        println!(
            "[{time}] [{color}{}\x1b[0m] {}",
            record.level(),
            record.args()
        );
    }

    fn flush(&self) {}
}

static WF_LOGGER: WaterfallLogger = WaterfallLogger;

#[tokio::main(flavor = "multi_thread", worker_threads = 12)]
async fn main() -> Result<()> {
    unsafe {
        std::env::set_var("RUST_LOG", "TRACE");
    }

    log::set_max_level(LevelFilter::Trace);

    if let Err(e) = log::set_logger(&WF_LOGGER) {
        eprintln!("Logging is not available: {e}");
    }

    spawn_hot_reloader().await;
    start_cleanup_task();

    info!(
        "Waterfall is starting {} IPv6 support",
        if supports_ipv6() { "with" } else { "without" }
    );

    test_dns_servers().await;

    let config: AuxConfig = parse_args();

    compile_patterns(
        config
            .pattern_options
            .patterns
            .iter()
            .map(|rule| (rule.pattern.clone(), rule.replacement.clone()))
            .collect(),
    )
    .await;

    debug!("Working with a config: {config:?}");

    let listener: TcpListener = TcpListener::bind(
        format!(
            "{}:{}",
            config.bind_options.bind_host, config.bind_options.bind_port
        )
        .replace("\"", "")
        .replace("\"", ""),
    )
    .await?;

    info!(
        "Socks5 proxy bound at {}:{}",
        config.bind_options.bind_host, config.bind_options.bind_port
    );

    if config.bind_options.iface_ipv4 != "default".to_string() {
        info!(
            "OK! I'll bind every IPv4 socket to interface {}, just as you've said",
            config.bind_options.iface_ipv4
        );
    }

    if config.bind_options.iface_ipv6 != "default".to_string() {
        info!(
            "OK! I'll bind every IPv6 socket to interface {}, just as you've said",
            config.bind_options.iface_ipv6
        );
    }

    loop {
        let (client, _) = listener.accept().await?;

        tokio::spawn(async move {
            let _ = socks5_proxy(client).await;
        });
    }
}
