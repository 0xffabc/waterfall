use crate::core::router::{Router, RouterInterjectionStatus};
use crate::core::socket::SocketOps;
use crate::core::{self, parse_args};
use crate::IpParser;

use std::io;
use std::{
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpStream},
    thread,
};

struct BufReaderHook<R, F> {
    inner: BufReader<R>,
    hook: F,
    socket: TcpStream,
    hops: u64,
    max_hops: u64,
}

impl<R: Read, F> Read for BufReaderHook<R, F>
where
    F: Fn(&TcpStream, &[u8]) -> Vec<u8> + Send + Sync + 'static,
{
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let size = self.inner.read(buf)?;

        if size == 0 || self.max_hops <= self.hops {
            return Ok(size);
        }

        let processed = (self.hook)(&self.socket, &buf[..size]);

        buf[..processed.len()].copy_from_slice(&processed);

        self.hops += 1;

        Ok(processed.len())
    }
}

pub fn socks5_proxy(
    proxy_client: &mut TcpStream,
    client_hook: impl Fn(&TcpStream, &[u8]) -> Vec<u8> + std::marker::Sync + std::marker::Send + 'static,
) {
    proxy_client
        .try_clone()
        .and_then(|mut client| {
            let mut buffer = [0; 64];

            client.read(&mut buffer)?;
            client.write_all(&[5, 0])?;
            client.read(&mut buffer)?;

            let config = parse_args();

            let router_responce = Router::interject_dns(config, &buffer);

            let parsed_data: IpParser = match router_responce {
                RouterInterjectionStatus::Allow => IpParser::parse(&buffer),
                RouterInterjectionStatus::AutoResolved(parsed) => parsed,
            };

            let mut packet = vec![5, 0, 0, parsed_data.dest_addr_type];

            packet.push(parsed_data.host_unprocessed.len() as u8);

            packet.extend_from_slice(&parsed_data.host_unprocessed);
            packet.extend_from_slice(&parsed_data.port.to_be_bytes());

            if parsed_data.is_udp {
                todo!();
            }

            match parsed_data.host_raw.len() {
                4 => {
                    let ip_bytes: [u8; 4] =
                        unsafe { *(parsed_data.host_raw.as_ptr() as *const [u8; 4]) };

                    Some(SocketAddr::new(ip_bytes.into(), parsed_data.port))
                }
                16 => {
                    let ip_bytes: [u8; 16] =
                        unsafe { *(parsed_data.host_raw.as_ptr() as *const [u8; 16]) };

                    Some(SocketAddr::new(ip_bytes.into(), parsed_data.port))
                }
                _ => None,
            }
            .and_then(|sock_addr| {
                let server_socket = SocketOps::connect_socket(sock_addr);

                match server_socket {
                    Ok(mut socket) => {
                        client.write_all(&packet).ok()?;

                        drop(packet);

                        socket.set_nodelay(true).ok()?;

                        let client_reader = client.try_clone().ok()?;
                        let socket_reader = socket.try_clone().ok()?;

                        let mut processor = BufReaderHook {
                            inner: BufReader::new(client_reader),
                            hook: client_hook,
                            socket: socket.try_clone().ok()?,
                            hops: 0,
                            max_hops: core::parse_args().desync_options.packet_hop,
                        };

                        thread::spawn(move || {
                            drop(io::copy(&mut BufReader::new(socket_reader), &mut client));
                        });

                        thread::spawn(move || {
                            drop(io::copy(&mut processor, &mut socket));
                        });
                    }
                    Err(error) => {
                        error!("Connection aborted: {error}");
                    }
                }

                Some(())
            })
            .unwrap_or(());
            Ok(())
        })
        .unwrap_or(());
}
