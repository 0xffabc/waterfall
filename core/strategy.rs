use serde::{Deserialize, Serialize};

use crate::core::{aux_config::WhiteListedSNIWrapper, weak_range::WeakRange, NetworkProtocol};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Strategies {
    NONE,
    SPLIT,
    DISORDER,
    FAKE,
    FAKEMD,
    FAKESURROUND,
    FAKE2DISORDER,
    FAKE2INSERT,
    DISORDER2,
    OOB2,
    OOB,
    DISOOB,
    OOBSTREAMHELL,
    MELTDOWN,
    TRAIL,
    MELTDOWNUDP,
    FRAGTLS,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case", deny_unknown_fields)]
pub struct Strategy {
    #[serde(rename = "@type")]
    pub method: Strategies,
    #[serde(rename = "@offset")]
    pub base_index: i64,
    #[serde(rename = "@add-sni")]
    pub add_sni: bool,
    #[serde(rename = "@add-host")]
    pub add_host: bool,
    #[serde(rename = "@negative_offset")]
    pub subtract: bool,
    pub filter_protocol: Option<NetworkProtocol>,
    pub filter_port: Option<WeakRange>,
    pub filter_sni: FilterSniList,
}

#[derive(Debug, Clone, Default, Deserialize, PartialEq, Serialize)]
pub struct FilterSniList {
    #[serde(rename = "$value")]
    pub items: Vec<WhiteListedSNIWrapper>,
}
