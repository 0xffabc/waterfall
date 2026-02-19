use crate::core::parse_args;
use crate::core::router::{Router, RouterInterjectionStatus};
use crate::core::socket::SocketOps;
use crate::socks::pipe::pipe_sockets;
use crate::IpParser;

mod pipe;

use std::net::SocketAddr;

use anyhow::{anyhow, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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

    let mut packet = vec![5, 0, 0, parsed_data.dest_addr_type];

    packet.push(parsed_data.host_unprocessed.len() as u8);

    packet.extend_from_slice(&parsed_data.host_unprocessed);
    packet.extend_from_slice(&parsed_data.port.to_be_bytes());

    if parsed_data.is_udp {
        todo!();
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
            error!("Connection aborted: {error}");
        }
    }

    Ok(())
}
