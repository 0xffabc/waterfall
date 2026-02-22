use anyhow::{anyhow, Result};
use ipnetwork::IpNetwork;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::net::{IpAddr, SocketAddr};
use tokio::net::{TcpSocket, TcpStream};

use crate::router::Router;
use std::io::Read;
use wfconfig::aux_config::{RouterRuleScope, RouterRuleType, SocketOptions};
use wfconfig::parse_args;

use log::info;
use wfblmark::is_16kb_blocked;

pub struct SocketOps();

fn checkis16kbaccepted(conditional: &str, sni: String) -> bool {
    let mut split = conditional.splitn(2, ' ');

    let opt_action_type = split.next();
    let opt_exec = split.next();

    if opt_action_type.is_some() && opt_exec.is_some() {
        let vsplit = opt_exec.unwrap().split(',').collect::<Vec<_>>();

        return !vsplit.contains(&sni.as_str());
    };

    opt_action_type.is_some_and(|x| x == "if16kb")
}

fn checkiscidraccepted(conditional: &str) -> bool {
    let mut split = conditional.splitn(2, ' ');

    let opt_action_type = split.next();

    opt_action_type.is_some_and(|x| x == "cidr")
}

impl SocketOps {
    pub fn new_proxied(addr: SocketAddr, proxy0: String) -> Result<TcpStream> {
        info!("{addr:?} is being forwarded to proxy {proxy0}");

        let mut socket = std::net::TcpStream::connect(
            proxy0
                .to_socket_addrs()?
                .next()
                .ok_or(anyhow!("No addrs"))?,
        )?;

        let mut buf = [0u8; 512];

        socket.write_all(&[0x05, 0x01, 0x00])?;

        socket.read(&mut buf)?;

        let mut connreq = Vec::with_capacity(22);

        connreq.extend_from_slice(&[0x05, 0x01, 0x00]);

        match addr {
            SocketAddr::V4(v4) => {
                connreq.push(0x01);
                connreq.extend_from_slice(&v4.ip().octets());
                connreq.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                connreq.push(0x04);
                connreq.extend_from_slice(&v6.ip().octets());
                connreq.extend_from_slice(&v6.port().to_be_bytes());
            }
        }

        socket.write_all(&connreq)?;
        socket.read(&mut buf)?;

        Ok(TcpStream::from_std(socket)?)
    }

    pub fn ifname2ip_win(ifname: String) -> Result<IpAddr> {
        let adapters = ipconfig::get_adapters()?;

        adapters
            .iter()
            .find(|a| a.friendly_name() == &ifname)
            .ok_or(anyhow!("Adapter not found"))?
            .ip_addresses()
            .first()
            .ok_or(anyhow!("No IP for adapter {ifname}"))
            .copied()
    }

    pub async fn connect_socket(sni: String, addr: SocketAddr) -> Result<TcpStream> {
        let config = parse_args();

        let rules = Router::query_router_rules(&config, &RouterRuleType::Forward);

        for rule in rules {
            if rule.scope != RouterRuleScope::IP {
                continue;
            }

            let ip = addr.ip();

            let should_route = if checkis16kbaccepted(&rule.rule_match, sni.clone()) {
                is_16kb_blocked(SocketAddr::new(ip, 443)).await
            } else if checkiscidraccepted(&rule.rule_match) {
                let network = rule.rule_match.parse::<IpNetwork>()?;

                network.contains(ip)
            } else {
                false
            };

            if should_route {
                let mut split = rule.exec.splitn(2, ' ');

                if let (Some(action_type), Some(exec)) = (split.next(), split.next()) {
                    match action_type {
                        "socks5" => return SocketOps::new_proxied(addr, exec.to_string()),
                        "block" => {
                            return Err(anyhow!("Connection aborted by a router rule"));
                        }
                        _ => {
                            info!(
                                "Skipping bad action type for exec {split:?} in pattern {}",
                                &rule.rule_match
                            );

                            continue;
                        }
                    }
                }
            }
        }

        let bind_options = parse_args().bind_options;

        let (tsocket, device_name) = match addr {
            SocketAddr::V4(_) => (TcpSocket::new_v4()?, bind_options.iface_ipv4.clone()),
            SocketAddr::V6(_) => (TcpSocket::new_v6()?, bind_options.iface_ipv6.clone()),
        };

        #[cfg(any(target_os = "android", target_os = "fuchsia", target_os = "linux"))]
        {
            if &device_name != "default" {
                tsocket.bind_device(Some(device_name.as_bytes()))?;
            }
        }

        #[cfg(any(
            target_os = "ios",
            target_os = "macos",
            target_os = "tvos",
            target_os = "watchos"
        ))]
        {
            if &device_name != "default" {
                use libc::if_nametoindex;

                let ifindex = std::num::NonZeroU32::new(unsafe {
                    libc::if_nametoindex(device_name.as_ptr() as *const _)
                });

                tsocket.bind_device(Some(&ifindex.to_ne_bytes()))?;
            }
        }

        #[cfg(target_os = "windows")]
        {
            let ip = Self::ifname2ip_win(device_name)?;

            let addr = std::net::SocketAddr::new(ip, 0);

            tsocket.bind(addr)?;
        }

        let SocketOptions {
            so_recv_size,
            so_send_size,
            ..
        } = parse_args().socket_options;

        tsocket.set_recv_buffer_size(so_recv_size as u32)?;
        tsocket.set_send_buffer_size(so_send_size as u32)?;
        tsocket.set_nodelay(true)?;
        tsocket.set_keepalive(true)?;

        let stream = tsocket.connect(addr).await?;

        Ok(stream)
    }
}
