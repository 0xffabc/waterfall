use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};

use curl::easy::Easy;
use socket2::SockAddr;

use crate::{core::parse_args, desync::utils::ip::IpUtils};

pub struct DOHResolver();

impl DOHResolver {
    pub fn doh_resolver(domain: String) -> Result<String, std::string::String> {
        let config = parse_args();

        if !config.dns_options.integrated_doh_enabled {
            let addrs = format!("{}:443", domain).to_socket_addrs();

            match addrs {
                Ok(mut addresses) => {
                    match addresses.next() {
                        Some(n) => {
                            warn!("The ISP will see that you've accessed {domain} -> {n}");

                            return Ok(n.to_string().replace(":443", ""));
                        }

                        None => error!("No addresses for {domain} from system DNS"),
                    };
                }

                Err(error) => error!(
                    "Failed to query {domain} through system DNS. Falling back to integrated one. ({error})"
                ),
            }
        }

        let cf_dns: &str = "https://dns.google/resolve?name={}&type=A";

        let mut easy = Easy::new();
        let mut response_data = Vec::new();

        easy.url(&cf_dns.replace("{}", &domain))
            .map_err(|n| n.to_string())?;

        easy.http_headers({
            let mut headers = curl::easy::List::new();
            headers
                .append("accept: application/dns-json")
                .map_err(|n| n.to_string())?;

            headers
        })
        .map_err(|n| n.to_string())?;

        let mut transfer = easy.transfer();

        transfer
            .write_function(|data| {
                response_data.extend_from_slice(data);
                Ok(data.len())
            })
            .map_err(|n| n.to_string())?;

        transfer.perform().map_err(|n| n.to_string())?;

        drop(transfer);

        IpUtils::find_ip(response_data).ok_or(String::new())
    }
}
