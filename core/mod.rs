use std::fs::{self, File};
use std::io::Read;

pub mod aux_config;
pub mod socket;
pub mod strategy;
pub mod weak_range;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub enum NetworkProtocol {
    UDP,
    TCP,
}

use libc::exit;
use quick_xml::se::Serializer;
use serde::{Deserialize, Serialize};

use crate::core::aux_config::AuxConfig;

fn create_config() {
    let mut buffer = String::new();

    let default = AuxConfig::default();

    let mut ser = Serializer::with_root(&mut buffer, None).expect("Failed to init serializer0");

    ser.indent(' ', 4);
    ser.expand_empty_elements(true);

    let _result = default.serialize(ser).expect("Serialization failed!");

    fs::write("./config.xml", buffer).expect("Failed to write the file");
}

pub fn parse_args() -> AuxConfig {
    let mut xml_data = String::new();

    let file = File::open("./config.xml");

    match file {
        Ok(mut file) => {
            file.read_to_string(&mut xml_data)
                .expect("Failed to read file");
        }

        Err(_) => {
            debug!("Config file not found! Creating a new one");

            create_config();

            debug!(
                "A fresh config has been made! Rerun waterfall or edit the config: ./config.xml"
            );

            unsafe {
                exit(0);
            }
        }
    }

    let config: AuxConfig = quick_xml::de::from_str(&xml_data).expect("Failed to deserialize");

    config
}
