use std::sync::OnceLock;

use crate::{
    core::parse_args,
    desync::utils::doh::parser::{create_queries, parse_dns_response},
};

#[cfg(not(any(
    target_arch = "mips",
    target_arch = "mips64",
    target_arch = "powerpc",
    target_arch = "powerpc64",
    target_arch = "riscv64",
    target_arch = "s390x",
    target_arch = "sparc64",
    target_arch = "loongarch64",
    target_os = "solaris",
    target_os = "illumos",
    target_os = "freebsd",
    target_os = "netbsd",
    target_os = "openbsd",
    target_os = "dragonfly",
    target_env = "musl",
)))]
use curl::easy::Easy;

static DNS_SERVERS: OnceLock<Vec<String>> = OnceLock::new();

pub async fn test_dns_servers() {
    let config = parse_args();

    let servers = config.dns_options.doh_servers;

    let mut working_servers = vec![];

    for server in servers {
        let query = create_queries("discord.com").unwrap()[0].clone();

        let result = DOHResolver::resolve_with(&server.url, query).await;

        match result {
            Ok(_) => {
                info!("[OK] {server:?} passed the test");

                working_servers.push(server.url);
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
    #[cfg(not(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "sparc64",
        target_arch = "loongarch64",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_env = "musl",
    )))]
    async fn resolve_with(dns_server: &str, data: String) -> Result<Vec<u8>> {
        let url = dns_server.replace("{}", &data);

        let result: Result<Vec<u8>> = tokio::task::spawn_blocking(move || {
            let mut easy = Easy::new();
            let mut response_data = Vec::new();

            easy.url(&url)?;

            easy.http_headers({
                let mut headers = curl::easy::List::new();
                headers.append("accept: application/dns-message")?;

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

        result
    }

    #[cfg(any(
        target_arch = "mips",
        target_arch = "mips64",
        target_arch = "powerpc",
        target_arch = "powerpc64",
        target_arch = "riscv64",
        target_arch = "s390x",
        target_arch = "sparc64",
        target_arch = "loongarch64",
        target_os = "solaris",
        target_os = "illumos",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly",
        target_env = "musl",
    ))]
    async fn resolve_with(dns_server: &str, data: String) -> Result<Vec<u8>> {
        panic!("DoH multiplexer is not available on targets without direct OpenSSL support");
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

        let mut tasks: Vec<_> = tasks
            .into_iter()
            .map(|task| {
                Box::pin(async move {
                    match task.await {
                        Ok(bytes) => match parse_dns_response(&bytes) {
                            Ok(addr) => Some(addr.ip().to_string()),
                            Err(_) => None,
                        },
                        Err(_) => None,
                    }
                })
            })
            .collect();

        while !tasks.is_empty() {
            let (result, _index, remaining) = futures::future::select_all(tasks).await;

            if let Some(ip) = result {
                return Ok(ip);
            }

            tasks = remaining;
        }

        Err(anyhow!(
            "Every DNS query was failed for {domain}. Consider creating a FakeDNS record manually."
        ))
    }
}
