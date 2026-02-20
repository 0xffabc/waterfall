use crate::core::parse_args;
use crate::core::router::{Router, RouterInterjectionStatus};
use crate::core::socket::SocketOps;
use crate::socks::pipe::async_pipe::pipe_sockets;
use crate::socks::pipe::async_udp::pipe_udp;
use crate::IpParser;

mod pipe;

use std::net::{IpAddr, SocketAddr};

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

pub async fn socks5_proxy(mut client: TcpStream) -> Result<()> {
    let mut buffer = [0; 64];

    client.read(&mut buffer).await?;
    client.write_all(&[5, 0]).await?;
    client.read(&mut buffer).await?;

    let config = parse_args();

    let router_responce = Router::interject_dns(config, &buffer).await?;

    let parsed_data: IpParser = match router_responce {
        RouterInterjectionStatus::Allow => IpParser::parse(&buffer).await?,
        RouterInterjectionStatus::AutoResolved(parsed) => parsed,
    };

    if parsed_data.is_udp {
        info!("Got a UDP associate");

        let relay = UdpSocket::bind("0.0.0.0:0").await?;

        let addr = relay.local_addr()?;

        let mut packet: Vec<u8> = vec![5, 0, 0];

        let ip_type = match addr.ip() {
            IpAddr::V4(_) => 1u8,
            IpAddr::V6(_) => 4u8,
        };

        let ip: Vec<u8> = match addr.ip() {
            IpAddr::V4(ip) => ip.octets().to_vec(),
            IpAddr::V6(ip) => ip.octets().to_vec(),
        };

        let port = match addr {
            SocketAddr::V4(ip) => ip.port().to_be_bytes().to_vec(),
            SocketAddr::V6(ip) => ip.port().to_be_bytes().to_vec(),
        };

        packet.extend_from_slice(&[ip_type]);
        packet.extend_from_slice(&ip);
        packet.extend_from_slice(&port);

        client.write_all(&packet).await?;

        return pipe_udp(client, relay).await;
    }

    let mut packet = vec![5, 0, 0, parsed_data.dest_addr_type];

    if parsed_data.dest_addr_type == 3 {
        packet.push(parsed_data.host_unprocessed.len() as u8);
    }

    packet.extend_from_slice(&parsed_data.host_unprocessed);
    packet.extend_from_slice(&parsed_data.port.to_be_bytes());

    if parsed_data.dest_addr_type != 1
        && parsed_data.dest_addr_type != 3
        && parsed_data.dest_addr_type != 4
    {
        packet[1] = 0x08;

        client.write_all(&packet).await?;

        return Err(anyhow!(
            "Unknown destination type: {}",
            &parsed_data.dest_addr_type
        ));
    }

    let sock_addr = match parsed_data.host_raw.len() {
        4 => {
            let ip_bytes: [u8; 4] = unsafe { *(parsed_data.host_raw.as_ptr() as *const [u8; 4]) };

            SocketAddr::new(ip_bytes.into(), parsed_data.port)
        }
        16 => {
            let ip_bytes: [u8; 16] = unsafe { *(parsed_data.host_raw.as_ptr() as *const [u8; 16]) };

            SocketAddr::new(ip_bytes.into(), parsed_data.port)
        }
        _ => return Err(anyhow!("No IP")),
    };

    let server_socket = SocketOps::connect_socket(sock_addr);

    match server_socket {
        Ok(socket) => {
            client.write_all(&packet).await?;

            drop(packet);

            tokio::spawn(async move {
                let _ = pipe_sockets(client, socket).await;
            });
        }
        Err(error) => {
            error!("Connection aborted: {error} with an address {sock_addr}");
        }
    }

    Ok(())
}
