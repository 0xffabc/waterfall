use std::sync::OnceLock;

use crate::{
    core::parse_args,
    desync::utils::doh::parser::{create_queries, parse_dns_response},
};

use ureq;

static DNS_SERVERS: OnceLock<Vec<String>> = OnceLock::new();

pub async fn test_dns_servers() {
    let servers = [
        "https://cloudflare-dns.com/dns-query?dns={}",
        "https://mozilla.cloudflare-dns.com/dns-query?dns={}",
        "https://dns.google/dns-query?dns={}",
        "https://dns.quad9.net/dns-query?dns={}",
        "https://freedns.controld.com/p0?dns={}",
    ];

    let mut working_servers = vec![];

    for server in servers {
        let query = create_queries("discord.com").unwrap()[0].clone();

        let result = DOHResolver::resolve_with(server, query).await;

        match result {
            Ok(_) => {
                info!("[OK] {server} passed the test");

                working_servers.push(server.to_string());
            }

            Err(err) => {
                error!("DNS resolver test error: {err}");
            }
        }
    }

    DNS_SERVERS.set(working_servers).unwrap();
}

use anyhow::{anyhow, Result};

pub struct DOHResolver();

pub mod parser;

impl DOHResolver {
    async fn resolve_with(dns_server: &str, data: String) -> Result<Vec<u8>> {
        let url = dns_server.replace("{}", &data);

        let result = tokio::task::spawn_blocking(move || {
            let bytes = ureq::get(&url)
                .header("accept", "application/dns-message")
                .call()?
                .body_mut()
                .read_to_vec()?;

            Ok::<Vec<u8>, anyhow::Error>(bytes)
        })
        .await??;

        Ok(result)
    }

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

        let queries = create_queries(&domain)?;
        let mut tasks = vec![];

        for dns in DNS_SERVERS
            .get()
            .ok_or(anyhow!("DNS_SERVERS aren't initialized yet"))?
        {
            for query in queries.clone() {
                let task = Self::resolve_with(dns, query);

                tasks.push(task);
            }
        }

        let (result, _, _) = futures::future::select_all(
            tasks
                .into_iter()
                .map(|task| {
                    Box::pin(async move {
                        match task.await {
                            Ok(value) => Some(value),
                            Err(_) => None,
                        }
                    })
                })
                .collect::<Vec<_>>(),
        )
        .await;

        let response =
            parse_dns_response(result.ok_or(anyhow!("Failed to parse message"))?.as_slice())?;

        Ok(response.to_string().replace(":443", ""))
    }
}
