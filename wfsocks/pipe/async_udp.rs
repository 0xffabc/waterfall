use anyhow::Result;
use log::{debug, error, warn};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::Mutex;

fn parse_ipdata(buffer: &[u8]) -> Option<(SocketAddr, usize)> {
    match buffer[3] {
        1 => {
            if buffer.len() < 10 {
                return None;
            }

            let addr = SocketAddr::new(
                IpAddr::V4(Ipv4Addr::new(buffer[4], buffer[5], buffer[6], buffer[7])),
                u16::from_be_bytes([buffer[8], buffer[9]]),
            );

            Some((addr, 10))
        }
        4 => {
            if buffer.len() < 22 {
                return None;
            }

            let mut octets = [0u8; 16];

            octets.copy_from_slice(&buffer[4..20]);

            let addr = SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([buffer[20], buffer[21]]),
            );

            Some((addr, 22))
        }
        _ => {
            return None;
        }
    }
}

fn parse_udp_msg(buffer: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if buffer.len() < 4 {
        debug!("Buffer shortage {}", buffer.len());

        return None;
    }

    if buffer[0..3] != [0, 0, 0] {
        debug!("Received frag {:?}", &buffer[0..3]);

        return None;
    }

    let (addr, data_start) = parse_ipdata(buffer)?;

    let data = &buffer[data_start..];

    Some((addr, data))
}

fn wrap_udp_response(data: &[u8], dest: SocketAddr) -> Vec<u8> {
    let mut response = Vec::with_capacity(25 + data.len());

    response.extend_from_slice(&[0, 0, 0]);

    match dest {
        SocketAddr::V4(addr) => {
            response.push(1);
            response.extend_from_slice(&addr.ip().octets());
        }
        SocketAddr::V6(addr) => {
            response.push(4);
            response.extend_from_slice(&addr.ip().octets());
        }
    }

    response.extend_from_slice(&dest.port().to_be_bytes());
    response.extend_from_slice(data);

    response
}

struct Relay {
    upstream: Arc<UdpSocket>,
    last_used: tokio::time::Instant,
}

pub async fn pipe_udp(control: TcpStream, relay: UdpSocket) -> Result<()> {
    let relay = Arc::new(relay);

    let relays = Arc::new(Mutex::new(HashMap::<(SocketAddr, SocketAddr), Relay>::new()));

    let (shutdown_tx, mut shutdown_rx) = tokio::sync::mpsc::channel(1);

    tokio::select! {
        _ = {
            let shutdown_tx = shutdown_tx.clone();

            tokio::spawn(async move {
                let mut control = control;
                let mut buf = [0; 1];

                match control.read(&mut buf).await {
                    Ok(0) => {
                        let _ = shutdown_tx.send(()).await;
                    }
                    Ok(n) => {
                        warn!("Unhandled data {n}");
                    }
                    Err(e) => {
                        error!("CM UDP Task error: {}", e);

                        let _ = shutdown_tx.send(()).await;
                    }
                }
            })
        } => { }
        _ = {
            let relay = relay.clone();
            let relays = relays.clone();

            tokio::spawn(async move {
                let mut buf = [0; 65535];

                loop {
                    tokio::select! {
                        result = relay.recv_from(&mut buf) => {
                            match result {
                                Ok((size, client_addr)) => {
                                    if let Some((dest_addr, data)) = parse_udp_msg(&buf[..size]) {
                                        handle_udp_packet(&relay, &relays, client_addr, dest_addr, data).await;
                                    }
                                }

                                Err(e) => {
                                    error!("Protocol error {}", e);

                                    break;
                                }
                            }
                        }
                        _ = shutdown_rx.recv() => {
                            break;
                        }
                    }
                }
            })
        } => { }
        _ = {
            let relays = relays.clone();

            tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));

                loop {
                    interval.tick().await;

                    let mut relays = relays.lock().await;

                    let now = tokio::time::Instant::now();

                    relays.retain(|_key, relay| {
                        now.duration_since(relay.last_used) <= Duration::from_secs(300)
                    });
                }
            })
        } => { }
    }

    Ok(())
}

async fn handle_udp_packet(
    relay: &Arc<UdpSocket>,
    flows: &Arc<Mutex<HashMap<(SocketAddr, SocketAddr), Relay>>>,
    client_addr: SocketAddr,
    dest_addr: SocketAddr,
    data: &[u8],
) {
    let key = (client_addr, dest_addr);

    let mut flows_guard = flows.lock().await;

    if let Some(flow) = flows_guard.get_mut(&key) {
        flow.last_used = tokio::time::Instant::now();

        match flow.upstream.send_to(data, dest_addr).await {
            Ok(_sent) => {}
            Err(e) => {
                error!("Flow relay error {}", e);

                flows_guard.remove(&key);
            }
        }
    } else {
        match create_new_relay_controller(relay, client_addr, dest_addr).await {
            Ok(flow) => match flow.upstream.send_to(data, dest_addr).await {
                Ok(_sent) => {
                    flows_guard.insert(key, flow);
                }
                Err(e) => {
                    error!("No init {}", e);
                }
            },
            Err(e) => {
                error!("CFLow error init {}", e);
            }
        }
    }
}

async fn create_new_relay_controller(
    relay: &Arc<UdpSocket>,
    client_addr: SocketAddr,
    dest_addr: SocketAddr,
) -> Result<Relay> {
    let upstream = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);

    let flow = Relay {
        upstream: upstream.clone(),
        last_used: tokio::time::Instant::now(),
    };

    let relay = relay.clone();

    tokio::spawn(async move {
        let mut buf = [0; 65535];

        loop {
            match upstream.recv_from(&mut buf).await {
                Ok((size, _src_addr)) => {
                    let response = wrap_udp_response(&buf[..size], dest_addr);

                    match relay.send_to(&response, client_addr).await {
                        Ok(_sent) => {}
                        Err(e) => {
                            error!("send_to err udp {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("recv_from udp error {}", e);

                    break;
                }
            }
        }
    });

    Ok(flow)
}
