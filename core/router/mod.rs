use glob::Pattern;

use crate::{
    core::aux_config::{AuxConfig, RouterRule, RouterRuleScope, RouterRuleType},
    desync::utils::ip::IpParser,
};

use anyhow::Result;

pub struct Router();

pub enum RouterInterjectionStatus {
    Allow,
    AutoResolved(IpParser),
}

impl Router {
    pub fn query_router_rules<'a>(
        config: &'a AuxConfig,
        rule_type: &RouterRuleType,
    ) -> Vec<&'a RouterRule> {
        config
            .router_options
            .rules
            .iter()
            .filter(|n| &n.rule_type == rule_type)
            .collect()
    }

    pub fn router_process<'a>(
        ref rule_type: RouterRuleType,
        exec: String,
        host_unprocessed: Vec<u8>,
    ) -> RouterInterjectionStatus {
        match rule_type {
            RouterRuleType::FakeDNS => {
                let is_ipv6 = exec.contains(':') && !exec.contains('.');

                let vec: Vec<u8> = if is_ipv6 {
                    let addr = exec.parse::<std::net::Ipv6Addr>()
                        .expect("Failed to parse requested IPv6 address. Make sure the address is an actual IPv6.");

                    addr.octets().to_vec()
                } else {
                    exec.split('.').map(|n| {
                        n.parse::<u8>()
                            .expect("Failed to parse requested FakeDNS integer as u8. Make sure the address is an actual IPv4.")
                    }).collect()
                };

                RouterInterjectionStatus::AutoResolved(IpParser {
                    host_raw: vec.clone(),
                    host_unprocessed: host_unprocessed,
                    port: 443,
                    dest_addr_type: if is_ipv6 { 4 } else { 3 },
                    is_udp: false,
                })
            }

            type_ => {
                error!("DNS Router doesn't support {type_:?}");

                RouterInterjectionStatus::Allow
            }
        }
    }

    pub async fn interject_dns<'a>(
        ref config: AuxConfig,
        ref buffer: impl AsRef<[u8]>,
    ) -> Result<RouterInterjectionStatus> {
        let rules = Self::query_router_rules(config, &RouterRuleType::FakeDNS);

        let ip_parser_result = IpParser::parse_no_resolve(buffer.as_ref()).await?;

        for rule in rules {
            if rule.scope != RouterRuleScope::DnsQuery {
                continue;
            }

            let pattern = match Pattern::new(&rule.rule_match) {
                Ok(pattern) => pattern,
                Err(_) => return Ok(RouterInterjectionStatus::Allow),
            };

            if pattern.matches(
                String::from_utf8_lossy(&ip_parser_result.host_unprocessed)
                    .into_owned()
                    .as_ref(),
            ) {
                return Ok(Self::router_process(
                    rule.rule_type.clone(),
                    rule.exec.clone(),
                    ip_parser_result.host_unprocessed,
                ));
            }
        }

        Ok(RouterInterjectionStatus::Allow)
    }
}
