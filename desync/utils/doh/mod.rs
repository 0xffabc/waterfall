use curl::easy::Easy;

use crate::{core::parse_args, desync::utils::ip::IpUtils};

use anyhow::{anyhow, Result};

pub struct DOHResolver();

impl DOHResolver {
    pub async fn doh_resolver(domain: String) -> Result<String> {
        let config = parse_args();

        if !config.dns_options.integrated_doh_enabled {
            let mut addrs = tokio::net::lookup_host(format!("{}:443", domain)).await?;

            match addrs.next() {
                Some(n) => {
                    warn!("The ISP will see that you've accessed {domain} -> {n}");

                    return Ok(n.to_string().replace(":443", ""));
                }

                None => error!("No addresses for {domain} from system DNS"),
            };
        }

        let result: anyhow::Result<Vec<u8>> = tokio::task::spawn_blocking(move || {
            let cf_dns: &str = "https://dns.google/resolve?name={}&type=A";

            let mut easy = Easy::new();
            let mut response_data = Vec::new();

            easy.url(&cf_dns.replace("{}", &domain))?;

            easy.http_headers({
                let mut headers = curl::easy::List::new();
                headers.append("accept: application/dns-json")?;

                headers
            })?;

            let mut transfer = easy.transfer();

            transfer.write_function(|data| {
                response_data.extend_from_slice(data);

                Ok(data.len())
            })?;

            transfer.perform()?;

            drop(transfer);

            return Ok(response_data);
        })
        .await?;

        Ok(IpUtils::find_ip(result?).ok_or(anyhow!("No IP"))?)
    }
}
