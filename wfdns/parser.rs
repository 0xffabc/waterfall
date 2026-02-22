use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::{anyhow, Result};
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use rusdig::{Query, RecordType};
use wfcipu::parsers::ip::{supports_ipv6, IpParser};

use crate::DOHResolver;

use log::{error, warn};

const CUSTOM_ENGINE: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, general_purpose::NO_PAD);

pub fn create_queries(domain: &str) -> Result<Vec<String>> {
    let mut queries = vec![];

    for record_type in [RecordType::A, RecordType::AAAA] {
        let query = Query::for_name(domain, record_type);
        let query_bytes = query.as_bytes()?;
        let b64 = CUSTOM_ENGINE.encode(query_bytes);

        queries.push(b64);
    }

    Ok(queries)
}

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
            let port = u16::from_be_bytes([buffer[5 + domain_length], buffer[6 + domain_length]]);

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
        _ => Ok(IpParser {
            dest_addr_type,
            host_raw: vec![0, 0, 0, 0],
            host_unprocessed: vec![0, 0, 0, 0],
            port: 13437,
            is_udp,
        }),
    }
}

/* https://lib.rs/crates/rusdig "Parsing a Response:" */
pub fn parse_dns_response(response_bytes: &[u8]) -> Result<SocketAddr> {
    let response = Query::from_bytes(response_bytes)?;

    let mut ips: Vec<SocketAddr> = vec![];

    if response.flags.successful() {
        for answer in &response.resource_answers {
            match answer.entry_type().ok_or(anyhow!("No entry"))? {
                rusdig::RecordType::A => {
                    let ipv4 = answer.data_as_ipv4()?;

                    ips.push(SocketAddr::V4(SocketAddrV4::new(ipv4, 443)));
                }

                rusdig::RecordType::AAAA => {
                    let ipv6 = answer.data_as_ipv6()?;

                    ips.push(SocketAddr::V6(SocketAddrV6::new(ipv6, 443, 0, 0)));
                }

                _ => {}
            }
        }
    } else {
        return Err(anyhow!("Bad DNS record"));
    }

    /* Try to find and return an IPv6, if the specified interface supports it */

    if supports_ipv6() {
        let ipv6_ip = ips.iter().find(|e| e.is_ipv6());

        match ipv6_ip {
            Some(ip) => return Ok(*ip),
            None => {}
        }
    }

    let ipv4_ip = ips.iter().find(|e| e.is_ipv4());

    Ok(*(ipv4_ip.ok_or(anyhow!("No IPv4 available on the DNS"))?))
}
