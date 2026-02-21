mod core;
mod desync;
mod socks;
mod tamper;

use anyhow::Result;
use iprobe::ipv6;

use crate::core::aux_config::AuxConfig;
use crate::core::strategy::Strategies;
use crate::desync::disoob::{Disoob, DisorderedOOB, Oob2};
use crate::desync::disorder::{Disorder, Disorder2, DisorderD};
use crate::desync::fake::{Fake, Fake2Disorder, FakeD, FakeInsert, FakeMD, FakeSurround, Meltdown};
use crate::desync::fragtls::FragTls;
use crate::desync::oob::{Oob, OobD, OobStream};
use crate::desync::split::Split;
use crate::desync::strategy_core::StrategyExecutor;
use crate::desync::strategy_core::*;
use crate::desync::utils::doh::test_dns_servers;
use crate::desync::utils::random::make_random_vec;
use crate::desync::utils::random::Random;
use crate::desync::utils::sni::Sni;
use crate::desync::utils::utils;

use crate::desync::utils::ip::IpParser;

use crate::desync::utils::filter::Whitelist;
use crate::tamper::service::{compile_patterns, process_packet};

use tokio::net::TcpListener;

use std::time::{self, Duration};

async fn execute_l4_bypasses<'a>(
    socket: &mut tokio::net::TcpStream,
    config: &'a AuxConfig,
    current_data: &'a mut Vec<u8>,
    sni_data: &'a (u32, u32),
) -> Result<()> {
    if sni_data != &(0, 0) && config.fake_packet_options.fake_clienthello {
        utils::send_drop(
            &socket,
            [
                &[
                    0x16, 0x03, 0x01, 0x00, 0xa5, 0x01, 0x00, 0x00, 0xa1, 0x03, 0x03, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 2, 0x00, 0x0a, 0x01, 0x00, 0x00, 16, 0x00,
                    0x00, 0x00, 0x28,
                ],
                config.fake_packet_options.fake_clienthello_sni.as_bytes(),
            ]
            .concat(),
        );
    }

    for strategy_raw in &config.strategies {
        if &None == strategy_raw {
            continue;
        }

        let strategy = strategy_raw.as_ref().unwrap().clone();

        if strategy.add_sni && sni_data == &(0, 0) {
            continue;
        }

        let filter_result = Whitelist::check_whitelist(
            &Some(
                (strategy.filter_sni.items)
                    .iter()
                    .map(|e| e.value.clone())
                    .collect::<Vec<_>>(),
            ),
            sni_data,
            current_data.as_slice(),
        );

        if let Ok(result) = filter_result {
            if !result {
                continue;
            }
        } else {
            warn!("Website blocked per filter rules");

            continue;
        }

        if let Some(ref protocol) = strategy.filter_protocol {
            if protocol != &core::NetworkProtocol::TCP {
                continue;
            }
        }

        if let Ok(addr) = socket.peer_addr() {
            if let Some(ref port) = strategy.filter_port {
                let addr_port: u16 = addr.port();

                if let Some(end_port) = port.end {
                    if addr_port > end_port {
                        continue;
                    }
                }

                if addr_port < port.start {
                    continue;
                }
            }
        }

        info!("Applying strategy {:?}", strategy.method);

        match strategy.method {
            Strategies::NONE => {}
            Strategies::SPLIT => {
                let send_data: Vec<Vec<u8>> =
                    Split::get_split_packet(&current_data, strategy, &sni_data);

                Split::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::DISORDER => {
                let send_data: Vec<Vec<u8>> =
                    DisorderD::<Disorder>::get_split_packet(&current_data, strategy, &sni_data);

                Disorder::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::DISORDER2 => {
                let send_data: Vec<Vec<u8>> =
                    DisorderD::<Disorder2>::get_split_packet(&current_data, strategy, &sni_data);

                Disorder2::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::FAKE => {
                let send_data: Vec<Vec<u8>> =
                    FakeD::<Fake>::get_split_packet(&current_data, strategy, &sni_data);

                Fake::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::FAKEMD => {
                let send_data: Vec<Vec<u8>> =
                    FakeD::<FakeMD>::get_split_packet(&current_data, strategy, &sni_data);

                FakeMD::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::FAKE2INSERT => {
                let send_data: Vec<Vec<u8>> =
                    FakeD::<FakeInsert>::get_split_packet(&current_data, strategy, &sni_data);

                FakeInsert::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::FAKE2DISORDER => {
                let send_data: Vec<Vec<u8>> =
                    FakeD::<Fake2Disorder>::get_split_packet(&current_data, strategy, &sni_data);

                Fake2Disorder::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::FAKESURROUND => {
                let send_data: Vec<Vec<u8>> =
                    FakeD::<FakeSurround>::get_split_packet(&current_data, strategy, &sni_data);

                FakeSurround::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::MELTDOWN => {
                let send_data =
                    FakeD::<Meltdown>::get_split_packet(&current_data, strategy, &sni_data);

                Meltdown::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::MELTDOWNUDP => {}
            Strategies::TRAIL => {}
            Strategies::OOB => {
                let send_data: Vec<Vec<u8>> =
                    OobD::<Oob>::get_split_packet(&current_data, strategy, &sni_data);

                Oob::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::OOBSTREAMHELL => {
                let send_data: Vec<Vec<u8>> =
                    OobD::<OobStream>::get_split_packet(&current_data, strategy, &sni_data);

                OobStream::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::DISOOB => {
                let send_data: Vec<Vec<u8>> =
                    DisorderedOOB::<Disoob>::get_split_packet(&current_data, strategy, &sni_data);

                Disoob::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::OOB2 => {
                let send_data: Vec<Vec<u8>> =
                    DisorderedOOB::<Oob2>::get_split_packet(&current_data, strategy, &sni_data);

                Oob2::execute_strategy(send_data, current_data, socket).await?;
            }
            Strategies::FRAGTLS => {
                FragTls::execute_strategy(current_data, strategy, sni_data);
            }
        }
    }

    if config.socket_options.so_disable_sack {
        utils::disable_sack(&socket);
    }

    if config.fake_packet_options.fake_packet_random {
        utils::send_drop(&socket, make_random_vec(32 as usize, 0xDEAD));
    }

    Ok(())
}

fn execute_l5_bypasses(data: &[u8]) -> Vec<u8> {
    let current_data = tamper::edit_http(data.to_vec());

    current_data
}

async fn execute_l7_bypasses(config: &AuxConfig) {
    let mut rand: Random = Random::new(
        (time::SystemTime::now()
            .duration_since(time::SystemTime::UNIX_EPOCH)
            .unwrap()
            .as_millis()
            % 255)
            .try_into()
            .unwrap(),
    );

    let rand_num: u64 = rand.next_rand().into();

    let jitter_millis: u64 = config
        .socket_options
        .so_l7_packet_jitter_max
        .try_into()
        .unwrap_or(u64::MAX);

    if jitter_millis > 0 {
        let random_jitter: u64 = ((rand_num * jitter_millis) / 256u64).into();

        tokio::time::sleep(Duration::from_millis(random_jitter)).await;
    }
}

pub async fn client_hook<'a>(
    socket: &'a mut tokio::net::TcpStream,
    data: &'a [u8],
) -> Result<Vec<u8>> {
    let config = core::parse_args();

    let sni_data = Sni::parse_sni_index(Vec::from(data));

    let mut l5_data = execute_l5_bypasses(data);

    process_packet(&mut l5_data).await?;
    execute_l4_bypasses(socket, &config, &mut l5_data, &sni_data).await?;
    execute_l7_bypasses(&config).await;

    Ok(l5_data)
}

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
        crate::core::core_launch_task()
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

#[tokio::main(flavor = "multi_thread", worker_threads = 12)]
async fn main() -> Result<()> {
    unsafe {
        std::env::set_var("RUST_LOG", "INFO");
    }

    spawn_hot_reloader().await;

    pretty_env_logger::init_timed();

    info!(
        "Waterfall is starting {} IPv6 support",
        if ipv6() { "with" } else { "without" }
    );

    test_dns_servers().await;

    let config: AuxConfig = core::parse_args();

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
            let _ = socks::socks5_proxy(client).await;
        });
    }
}
