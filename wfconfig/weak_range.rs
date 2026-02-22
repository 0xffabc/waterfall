use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub struct WeakRange {
    pub start: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub end: Option<u16>,
}
