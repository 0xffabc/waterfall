use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use anyhow::{anyhow, Result};
use base64::{
    alphabet,
    engine::{self, general_purpose},
    Engine as _,
};
use iprobe::ipv6;
use rusdig::{Query, RecordType};

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

    if ipv6() {
        let ipv6_ip = ips.iter().find(|e| e.is_ipv6());

        match ipv6_ip {
            Some(ip) => return Ok(*ip),
            None => {}
        }
    }

    let ipv4_ip = ips.iter().find(|e| e.is_ipv4());

    Ok(*(ipv4_ip.ok_or(anyhow!("No IPv4 available on the DNS"))?))
}
