use anyhow::Result;
use std::net::IpAddr;

use crate::desync::utils::doh::DOHResolver;

#[derive(Debug, Clone)]
pub struct IpParser {
    pub host_raw: Vec<u8>,
    pub host_unprocessed: Vec<u8>,
    pub port: u16,
    pub dest_addr_type: u8,
    pub is_udp: bool,
}

impl IpParser {
    #[allow(mismatched_lifetime_syntaxes)]
    pub async fn parse<'b>(buffer: &'b [u8]) -> Result<IpParser> {
        let dest_addr_type = buffer[3];
        let is_udp = buffer[1] == 0x03;

        match dest_addr_type {
            1 => {
                if buffer.len() < 10 {
                    warn!("Buffer length for IPv4 is less than 10...");

                    return Ok(IpParser {
                        dest_addr_type,
                        host_raw: vec![0, 0, 0, 0],
                        host_unprocessed: vec![0, 0, 0, 0],
                        port: 0,
                        is_udp,
                    });
                }

                Ok(IpParser {
                    dest_addr_type,
                    host_raw: buffer[4..8].to_vec(),
                    host_unprocessed: buffer[4..8].to_vec(),
                    port: u16::from_be_bytes([buffer[8], buffer[9]]),
                    is_udp,
                })
            }
            3 => {
                let domain_length = buffer[4] as usize;

                if 6 + domain_length >= buffer.len() {
                    warn!("Domain length {domain_length} is more than lowest buffer length without header {}...", buffer.len() - 6);

                    return Ok(IpParser {
                        dest_addr_type,
                        host_raw: vec![0, 0, 0, 0],
                        host_unprocessed: vec![0, 0, 0, 0],
                        port: 0,
                        is_udp,
                    });
                }

                let domain = &buffer[5..5 + domain_length];
                let port =
                    u16::from_be_bytes([buffer[5 + domain_length], buffer[6 + domain_length]]);

                if let Ok(domain_str) = std::str::from_utf8(domain) {
                    if let Ok(ip_addr) = domain_str.parse::<IpAddr>() {
                        let ip_buffer = match ip_addr {
                            IpAddr::V4(ip) => ip.octets().to_vec(),
                            IpAddr::V6(ip) => ip.octets().to_vec(),
                        };

                        return Ok(IpParser {
                            dest_addr_type,
                            host_raw: ip_buffer,
                            host_unprocessed: domain.to_vec(),
                            port,
                            is_udp,
                        });
                    }

                    match DOHResolver::doh_resolver(domain_str.to_string()).await {
                        Ok(ip) => {
                            if let Ok(ip_addr) = ip.parse::<IpAddr>() {
                                let ip_buffer = match ip_addr {
                                    IpAddr::V4(ip) => ip.octets().to_vec(),
                                    IpAddr::V6(ip) => ip.octets().to_vec(),
                                };

                                return Ok(IpParser {
                                    dest_addr_type,
                                    host_raw: ip_buffer,
                                    host_unprocessed: domain.to_vec(),
                                    port,
                                    is_udp,
                                });
                            }
                        }

                        Err(error) => {
                            error!("DoH resolver error: {error}");
                        }
                    }
                }

                Ok(IpParser {
                    dest_addr_type,
                    host_raw: vec![0, 0, 0, 0],
                    host_unprocessed: domain.to_vec(),
                    port,
                    is_udp,
                })
            }
            4 => {
                if buffer.len() < 22 {
                    return Ok(IpParser {
                        dest_addr_type,
                        host_raw: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        host_unprocessed: vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
                        port: 0,
                        is_udp,
                    });
                }

                Ok(IpParser {
                    dest_addr_type,
                    host_raw: buffer[4..20].to_vec(),
                    host_unprocessed: buffer[4..20].to_vec(),
                    port: u16::from_be_bytes([buffer[20], buffer[21]]),
                    is_udp,
                })
            }
            _ => panic!("Waterfall got an unsupported SOCKS5 dest type: {dest_addr_type}"),
        }
    }
}
