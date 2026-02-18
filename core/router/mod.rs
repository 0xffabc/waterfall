use glob::Pattern;

use crate::{
    core::aux_config::{AuxConfig, RouterRule, RouterRuleScope, RouterRuleType},
    desync::utils::ip::IpParser,
};

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
    ) -> RouterInterjectionStatus {
        match rule_type {
            RouterRuleType::FakeDNS => {
                let vec = exec.as_bytes().to_vec();

                RouterInterjectionStatus::AutoResolved(IpParser {
                    host_raw: vec.clone(),
                    host_unprocessed: vec,
                    port: 443,
                    dest_addr_type: 1,
                    is_udp: false,
                })
            }

            type_ => {
                error!("DNS Router doesn't support {type_:?}");

                RouterInterjectionStatus::Allow
            }
        }
    }

    pub fn interject_dns<'a>(
        ref config: AuxConfig,
        ref buffer: impl AsRef<[u8]>,
    ) -> RouterInterjectionStatus {
        let rules = Self::query_router_rules(config, &RouterRuleType::Forward);

        let ip_parser_result = IpParser::parse(buffer.as_ref());

        for rule in rules {
            if rule.scope != RouterRuleScope::DnsQuery {
                continue;
            }

            let pattern = match Pattern::new(&rule.rule_match) {
                Ok(pattern) => pattern,
                Err(_) => return RouterInterjectionStatus::Allow,
            };

            if pattern.matches(
                String::from_utf8_lossy(&ip_parser_result.host_raw)
                    .into_owned()
                    .as_ref(),
            ) {
                return Self::router_process(rule.rule_type.clone(), rule.exec.clone());
            }
        }

        RouterInterjectionStatus::Allow
    }
}
