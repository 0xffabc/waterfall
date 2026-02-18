use anyhow::{anyhow, Result};
use glob::Pattern;
use socket2::{Domain, Protocol, Socket, Type};
use std::io::Write;
use std::net::SocketAddr;
use std::net::ToSocketAddrs;
use std::thread;
use std::time::Duration;
use tokio::net::TcpStream;

use crate::core::aux_config::{RouterRuleScope, RouterRuleType, SocketOptions};
use crate::core::parse_args;
use crate::core::router::Router;
use socket2_ext::{AddressBinding, BindDeviceOption};
use std::io::Read;

pub struct SocketOps();

impl SocketOps {
    fn cutoff_options(so_clone: Socket, so_opt_cutoff: u64) {
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(so_opt_cutoff));

            so_clone.set_recv_buffer_size(16653).unwrap();
            so_clone.set_send_buffer_size(16653).unwrap();
        });
    }

    pub fn new_proxied(addr: SocketAddr, proxy0: String) -> TcpStream {
        let mut socket = std::net::TcpStream::connect(
            proxy0
                .to_socket_addrs()
                .expect("Wrong proxy IP")
                .next()
                .expect("Bad IP resolver"),
        )
        .expect("Socks5 proxy is unreachable");

        let mut temp_buf = [0u8; 64];

        let _ = socket.write_all(&vec![0x05, 1, 0]);
        let _ = socket.read(&mut temp_buf);

        let mut connreq = vec![0x05, 0x01, 0x00];

        if addr.is_ipv4() {
            connreq.push(0x01);
        } else if addr.is_ipv6() {
            connreq.push(0x04);
        } else {
            connreq.push(0x03);
        }

        match addr {
            SocketAddr::V4(v4) => {
                connreq.push(0x04);
                connreq.extend_from_slice(&v4.ip().octets());
                connreq.extend_from_slice(&v4.port().to_be_bytes());
            }
            SocketAddr::V6(v6) => {
                connreq.push(0x06);
                connreq.extend_from_slice(&v6.ip().octets());
                connreq.extend_from_slice(&v6.port().to_be_bytes());
            }
        }

        let _ = socket.read(&mut temp_buf);

        TcpStream::from_std(socket).expect("This shouldn't have happened")
    }

    pub fn connect_socket(addr: SocketAddr) -> Result<TcpStream> {
        let domain_type = if addr.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };

        trace!("Connecting to IPADDR {addr:?}");

        let config = parse_args();

        let rules = Router::query_router_rules(&config, &RouterRuleType::Forward);

        for rule in rules {
            if rule.scope != RouterRuleScope::IP {
                continue;
            }

            let pattern = Pattern::new(&rule.rule_match)
                .expect("Invalid rule, thank god I'm going to panic the whole program");

            if pattern.matches(&addr.to_string()) {
                let mut split = rule.exec.splitn(2, ' ');

                if let (Some(action_type), Some(exec)) = (split.next(), split.next()) {
                    match action_type {
                        "socks5" => return Ok(SocketOps::new_proxied(addr, exec.to_string())),
                        "block" => {
                            return Err(anyhow!("Connection aborted by a router rule"));
                        }
                        _ => continue,
                    }
                }
            }

            break;
        }

        let socket = Socket::new(domain_type, Type::STREAM, Some(Protocol::TCP))?;

        let interface = parse_args().bind_options.bind_iface;

        if &interface != "default" {
            socket.bind_to_device(BindDeviceOption::v4(&interface))?;
        }

        let SocketOptions {
            so_recv_size,
            so_send_size,
            so_opt_cutoff,
            ..
        } = parse_args().socket_options;

        socket.set_recv_buffer_size(so_recv_size)?;
        socket.set_send_buffer_size(so_send_size)?;
        socket.set_nodelay(true)?;
        socket.set_keepalive(true)?;

        Self::cutoff_options(socket.try_clone().unwrap(), so_opt_cutoff);

        if domain_type == Domain::IPV6 {
            socket.set_only_v6(false)?;
        }

        socket.connect(&addr.into())?;

        let tcp_stream: std::net::TcpStream = socket.into();

        Ok(TcpStream::from_std(tcp_stream).expect("This shouldn't have happened"))
    }
}
