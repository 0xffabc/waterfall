use glob::Pattern;

use crate::core::{
    aux_config::{RouterRuleScope, RouterRuleType},
    parse_args,
    router::Router,
};

pub struct Whitelist();

impl Whitelist {
    pub fn check_whitelist(
        config: &Option<Vec<String>>,
        sni_data: &(u32, u32),
        data: &[u8],
    ) -> Result<bool, String> {
        if let Some(whitelist_sni_list) = config {
            if sni_data != &(0, 0) {
                let start = sni_data.0 as usize;
                let end = sni_data.1 as usize;

                if data.len() <= end {
                    return Ok(false);
                }

                let sni_slice = &data[start..end];

                let sni_string = String::from_utf8_lossy(sni_slice).to_string();

                debug!("Visiting SNI {sni_string}");

                let config = parse_args();

                let rules = Router::query_router_rules(&config, &RouterRuleType::Forward);

                for rule in rules {
                    if rule.scope != RouterRuleScope::SNI {
                        continue;
                    }

                    let pattern = Pattern::new(&rule.rule_match)
                        .expect("Invalid rule, thank god I'm going to panic the whole program");

                    if pattern.matches(&sni_string.to_string()) {
                        let mut split = rule.exec.splitn(2, ' ');

                        if let (Some(action_type), Some(_exec)) = (split.next(), split.next()) {
                            match action_type {
                                "block" => {
                                    return Err("Connection aborted per SNI filter".to_string());
                                }

                                types => {
                                    error!("Unsupported action for SNI: {types:?}")
                                }
                            }
                        }
                    }

                    break;
                }

                if whitelist_sni_list
                    .iter()
                    .position(|r| sni_string.contains(r))
                    .is_none()
                {
                    return Ok(false);
                }
            }

            if sni_data == &(0, 0) {
                return Ok(false);
            }
        }

        return Ok(true);
    }
}
