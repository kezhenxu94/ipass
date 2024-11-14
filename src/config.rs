use serde::{Deserialize, Serialize};
use tokio::io;

#[allow(deprecated)]
use std::env::home_dir;

use base64::prelude::*;

use crate::util;
#[derive(Debug, Deserialize, Serialize)]
pub struct PassConfig {
    pub username: String,
    pub shared_key: String,
}

impl PassConfig {
    pub fn new(username: String, shared_key: String) -> Self {
        Self {
            username,
            shared_key,
        }
    }

    pub fn save(&self) {
        #[allow(deprecated)]
        let path = home_dir().unwrap().join(".ipass");
        std::fs::create_dir_all(&path).expect("Failed to create ipass config directory");
        let path = path.join("config.json");
        let content = serde_json::to_string(self).expect("Failed to serialize config");
        std::fs::write(path, content).expect("Failed to write to config file");
    }

    pub fn decryption_key(&self) -> [u8; 16] {
        let shared_key = BASE64_STANDARD.decode(self.shared_key.as_str()).unwrap();
        shared_key[..16].try_into().unwrap()
    }
}

impl PassConfig {
    pub fn load() -> io::Result<Self> {
        #[allow(deprecated)]
        let path = home_dir().unwrap().join(".ipass/config.json");
        let content = std::fs::read_to_string(path)?;
        let config: Self =
            serde_json::from_str(&content).expect("parse config file in JSON format");
        if config.shared_key.is_empty() {
            let ipass_cli = util::my_cli();
            return Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!(
                    "session is not authenticated, please run `{} auth` to authenticate",
                    ipass_cli
                ),
            ));
        }
        Ok(config)
    }
}
