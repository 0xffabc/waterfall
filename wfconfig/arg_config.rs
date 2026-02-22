use std::{path::PathBuf, str::FromStr};

pub struct Args {
    pub config: PathBuf,
}

impl Args {
    pub fn parse() -> Args {
        let mut args = std::env::args();

        Args {
            config: PathBuf::from_str(&args.nth(1).unwrap_or("config.xml".to_string()))
                .expect("Failed to create PathBuf"),
        }
    }
}
