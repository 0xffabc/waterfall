use serde::{Deserialize, Serialize};

use crate::core::{
    strategy::{FilterSniList, Strategy},
    weak_range::WeakRange,
};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum WhiteListedSNI {
    Domain,
    Path,
    File,
}

#[derive(Debug, Serialize, Deserialize, PartialEq, Clone)]
pub struct WhiteListedSNIWrapper {
    #[serde(rename = "@list")]
    pub list: WhiteListedSNI,
    #[serde(rename = "@value")]
    pub value: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct BindOptions {
    #[serde(default = "default_bind_host", rename = "@host")]
    pub bind_host: String,
    #[serde(default = "default_bind_port", rename = "@port")]
    pub bind_port: u16,

    #[serde(default = "default_bind_iface", rename = "@iface-ipv4")]
    pub iface_ipv4: String,
    #[serde(default = "default_bind_iface", rename = "@iface-ipv6")]
    pub iface_ipv6: String,

    #[serde(default = "default_bind_iface_mtu", rename = "@iface-mtu")]
    pub bind_iface_mtu: u32,
    #[serde(default = "default_bind_iface_ipv4", rename = "@iface-ipv4-ip")]
    pub bind_iface_ipv4: String,
    #[serde(default = "default_bind_iface_ipv6", rename = "@iface-ipv6-ip")]
    pub bind_iface_ipv6: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct FakePacketOptions {
    #[serde(default = "default_fake_packet_ttl", rename = "@ttl")]
    pub fake_packet_ttl: u8,
    #[serde(default = "default_fake_packet_sni", rename = "@sni")]
    pub fake_packet_sni: String,
    #[serde(default, rename = "@only-oob")]
    pub fake_as_oob: bool,

    #[serde(default, rename = "@protocol-http")]
    pub fake_packet_send_http: bool,
    #[serde(default = "default_fake_packet_host", rename = "@protocol-http-host")]
    pub fake_packet_host: String,
    #[serde(
        default = "default_fake_packet_override_data",
        skip_serializing_if = "Option::is_none",
        rename = "@override-data"
    )]
    pub fake_packet_override_data: Option<Vec<u8>>,
    #[serde(default, rename = "send-twice")]
    pub fake_packet_double: bool,
    #[serde(default, rename = "@send-reversed")]
    pub fake_packet_reversed: bool,
    #[serde(default, rename = "@send-random-garbage")]
    pub fake_packet_random: bool,
    #[serde(default, rename = "@send-clienthello")]
    pub fake_clienthello: bool,
    #[serde(default = "default_fake_clienthello_sni", rename = "@clienthello-sni")]
    pub fake_clienthello_sni: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct SocketOptions {
    #[serde(default = "default_so_recv_size", rename = "@recv-size")]
    pub so_recv_size: usize,
    #[serde(default = "default_so_send_size", rename = "@send-size")]
    pub so_send_size: usize,
    #[serde(default = "default_so_opt_cutoff", rename = "@desync-cutoff-ms")]
    pub so_opt_cutoff: u64,

    #[serde(
        default = "default_l7_packet_jitter_max",
        rename = "@packet-delay-jitter"
    )]
    pub so_l7_packet_jitter_max: u64,

    #[serde(default, rename = "@disable-sack")]
    pub so_disable_sack: bool,

    #[serde(default = "default_oob_streamhell_data", rename = "@oob-hell-data")]
    pub so_oob_streamhell_data: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct HttpOptions {
    #[serde(default, rename = "@host-mixcaps")]
    pub http_host_cmix: bool,
    #[serde(default, rename = "@host-remove-space")]
    pub http_host_rmspace: bool,
    #[serde(default, rename = "@host-space")]
    pub http_host_space: bool,
    #[serde(default, rename = "@domain-mixcaps")]
    pub http_domain_cmix: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DesyncOptions {
    #[serde(default = "default_disorder_packet_ttl", rename = "@packet-ttl")]
    pub disorder_packet_ttl: u8,
    #[serde(default = "default_default_ttl", rename = "@default-ttl")]
    pub default_ttl: u8,
    #[serde(default = "default_out_of_band_charid", rename = "@out-of-band-charid")]
    pub out_of_band_charid: u8,
    #[serde(default = "default_packet_hop", rename = "@packet-hops-max")]
    pub packet_hop: u64,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub enum RouterRuleScope {
    DnsQuery,
    SNI,
    IP,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub enum RouterRuleType {
    Forward,
    FakeDNS,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct RouterRule {
    #[serde(rename = "@scope")]
    pub scope: RouterRuleScope,
    #[serde(rename = "@type")]
    pub rule_type: RouterRuleType,
    #[serde(rename = "@match")]
    pub rule_match: String,
    #[serde(rename = "@exec")]
    pub exec: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct PatternRule {
    #[serde(rename = "@pattern")]
    pub pattern: String,
    #[serde(rename = "@replacement")]
    pub replacement: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct RouterOptions {
    #[serde(default = "default_rules")]
    pub rules: Vec<RouterRule>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct PatternOptions {
    #[serde(default = "default_patterns")]
    pub patterns: Vec<PatternRule>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct AuxConfig {
    pub bind_options: BindOptions,
    pub fake_packet_options: FakePacketOptions,
    pub socket_options: SocketOptions,
    pub http_options: HttpOptions,
    pub desync_options: DesyncOptions,
    pub dns_options: DnsOptions,
    pub router_options: RouterOptions,
    pub pattern_options: PatternOptions,

    #[serde(default = "default_whitelist_sni")]
    pub whitelist_sni: bool,
    #[serde(default = "whitelist_sni_list")]
    pub whitelist_sni_list: Vec<WhiteListedSNIWrapper>,

    #[serde(default)]
    pub strategies: Vec<Option<Strategy>>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub struct DohServer {
    #[serde(rename = "@url")]
    pub url: String,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct DnsOptions {
    #[serde(
        default = "default_integrated_doh_enabled",
        rename = "@integrated_doh_enabled"
    )]
    pub integrated_doh_enabled: bool,
    #[serde(default = "default_doh_servers")]
    pub doh_servers: Vec<DohServer>,
}

impl Default for AuxConfig {
    fn default() -> Self {
        Self {
            bind_options: BindOptions {
                bind_host: default_bind_host(),
                bind_port: default_bind_port(),
                iface_ipv4: default_bind_iface(),
                iface_ipv6: default_bind_iface(),
                bind_iface_mtu: default_bind_iface_mtu(),
                bind_iface_ipv4: default_bind_iface_ipv4(),
                bind_iface_ipv6: default_bind_iface_ipv6(),
            },
            dns_options: DnsOptions {
                integrated_doh_enabled: default_integrated_doh_enabled(),
                doh_servers: vec![
                    DohServer {
                        url: "https://cloudflare-dns.com/dns-query?dns={}".to_string(),
                    },
                    DohServer {
                        url: "https://mozilla.cloudflare-dns.com/dns-query?dns={}".to_string(),
                    },
                    DohServer {
                        url: "https://dns.google/dns-query?dns={}".to_string(),
                    },
                    DohServer {
                        url: "https://dns.quad9.net/dns-query?dns={}".to_string(),
                    },
                    DohServer {
                        url: "https://freedns.controld.com/p0?dns={}".to_string(),
                    },
                ],
            },
            fake_packet_options: FakePacketOptions {
                fake_packet_ttl: default_fake_packet_ttl(),
                fake_packet_sni: default_fake_packet_sni(),
                fake_as_oob: false,
                fake_packet_send_http: false,
                fake_packet_host: default_fake_packet_host(),
                fake_packet_override_data: default_fake_packet_override_data(),
                fake_packet_double: false,
                fake_packet_reversed: false,
                fake_packet_random: false,
                fake_clienthello: false,
                fake_clienthello_sni: default_fake_clienthello_sni(),
            },
            socket_options: SocketOptions {
                so_recv_size: default_so_recv_size(),
                so_send_size: default_so_send_size(),
                so_opt_cutoff: default_so_opt_cutoff(),
                so_l7_packet_jitter_max: default_l7_packet_jitter_max(),
                so_disable_sack: false,
                so_oob_streamhell_data: default_oob_streamhell_data(),
            },
            router_options: RouterOptions {
                rules: vec![RouterRule {
                    scope: RouterRuleScope::SNI,
                    rule_type: RouterRuleType::Forward,
                    rule_match: "*.discord.com".to_string(),
                    exec: "socks5 127.0.0.1:9050".to_string(),
                }],
            },
            http_options: HttpOptions {
                http_host_cmix: false,
                http_host_rmspace: false,
                http_host_space: false,
                http_domain_cmix: false,
            },
            desync_options: DesyncOptions {
                disorder_packet_ttl: default_disorder_packet_ttl(),
                default_ttl: default_default_ttl(),
                out_of_band_charid: default_out_of_band_charid(),
                packet_hop: default_packet_hop(),
            },
            pattern_options: PatternOptions {
                patterns: vec![PatternRule {
                    pattern: "x796F75747562652E636F6D".to_string(),
                    replacement: "x626C6F676765722E636F6D".to_string(),
                }],
            },
            whitelist_sni: default_whitelist_sni(),
            whitelist_sni_list: whitelist_sni_list(),
            strategies: vec![Some(Strategy {
                method: crate::core::strategy::Strategies::FRAGTLS,
                base_index: 3,
                add_sni: true,
                add_host: false,
                subtract: false,
                filter_port: Some(WeakRange {
                    start: 442,
                    end: None,
                }),
                filter_protocol: Some(crate::core::NetworkProtocol::TCP),
                filter_sni: FilterSniList {
                    items: vec![
                        WhiteListedSNIWrapper {
                            list: WhiteListedSNI::Domain,
                            value: "youtube.com".to_string(),
                        },
                        WhiteListedSNIWrapper {
                            list: WhiteListedSNI::Domain,
                            value: "discord.com".to_string(),
                        },
                        WhiteListedSNIWrapper {
                            list: WhiteListedSNI::Domain,
                            value: "discordapp.com".to_string(),
                        },
                        WhiteListedSNIWrapper {
                            list: WhiteListedSNI::Domain,
                            value: "googlevideo.com".to_string(),
                        },
                    ],
                },
            })],
        }
    }
}

fn default_bind_host() -> String {
    "127.0.0.1".to_string()
}

fn default_bind_port() -> u16 {
    443
}

fn default_bind_iface() -> String {
    "default".to_string()
}

fn default_bind_iface_mtu() -> u32 {
    1500
}

fn default_bind_iface_ipv4() -> String {
    "0.0.0.0".to_string()
}

fn default_bind_iface_ipv6() -> String {
    "::".to_string()
}

fn default_fake_packet_ttl() -> u8 {
    64
}

fn default_fake_packet_sni() -> String {
    "yandex.ru".to_string()
}

fn default_fake_packet_host() -> String {
    "yandex.ru".to_string()
}

fn default_fake_clienthello_sni() -> String {
    "yandex.ru".to_string()
}

fn default_oob_streamhell_data() -> String {
    "yandex.ru".to_string()
}

fn default_disorder_packet_ttl() -> u8 {
    8
}

fn default_out_of_band_charid() -> u8 {
    23
}

fn default_so_recv_size() -> usize {
    65535
}

fn default_so_send_size() -> usize {
    65535
}

fn default_so_opt_cutoff() -> u64 {
    200
}

fn default_default_ttl() -> u8 {
    4
}

fn default_packet_hop() -> u64 {
    3
}

fn default_l7_packet_jitter_max() -> u64 {
    0
}

fn default_whitelist_sni() -> bool {
    true
}

fn whitelist_sni_list() -> Vec<WhiteListedSNIWrapper> {
    vec!["discord.com", "youtube.com", "googlevideo.com"]
        .iter()
        .map(|n| WhiteListedSNIWrapper {
            list: WhiteListedSNI::Domain,
            value: n.to_string(),
        })
        .collect::<Vec<_>>()
}

fn default_fake_packet_override_data() -> Option<Vec<u8>> {
    None
}

fn default_integrated_doh_enabled() -> bool {
    true
}

fn default_patterns() -> Vec<PatternRule> {
    vec![]
}

fn default_rules() -> Vec<RouterRule> {
    vec![]
}

fn default_doh_servers() -> Vec<DohServer> {
    vec![]
}
