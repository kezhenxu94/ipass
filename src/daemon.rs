use log::info;
use std::io::{Read, Write};
#[allow(deprecated)]
use std::{
    path::Path,
    process::{Command, Stdio},
};
use tokio::{io, net::UdpSocket};

use serde::{Deserialize, Serialize};
use tokio::select;

use core::str;

use crate::{config::PassConfig, StartArgs};

#[derive(Debug, Deserialize, Serialize)]
struct PasswordManager {
    name: String,
    description: String,
    path: String,
    #[serde(alias = "type")]
    typ: String,
    allowed_extensions: Option<Vec<String>>,
}

impl Default for PasswordManager {
    fn default() -> Self {
        let path = [
            "/Library/Application Support/Mozilla/NativeMessagingHosts/com.apple.passwordmanager.json",
            "/Library/Google/Chrome/NativeMessagingHosts/com.apple.passwordmanager.json",
        ]
        .iter()
        .find(|path| Path::new(path).exists())
        .expect("no passwordmanager config file");
        let content = std::fs::read_to_string(path).expect("read passwordmanager config file");
        serde_json::from_str(&content).expect("parse passwordmanager config file")
    }
}

pub async fn start(args: StartArgs) -> io::Result<()> {
    let password_manager = PasswordManager::default();

    let mut pm_process = Command::new(&password_manager.path)
        .arg(".")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let stdin = pm_process.stdin.as_mut().expect("get pm process stdin");
    let stdout = pm_process.stdout.as_mut().expect("get pm process stdout");

    let socket = UdpSocket::bind(format!("127.0.0.1:{}", args.port)).await?;
    let port = socket.local_addr()?.port();
    info!("Daemon is listening on port: {}", port);

    let mut buf = [0; 4096];

    loop {
        select! {
            _ = tokio::signal::ctrl_c() => {
                PassConfig::new("".to_owned(), "".to_owned()).save();
                break;
            }
            result = socket.recv_from(&mut buf[4..]) => {
                let (len, addr) = result?;

                buf[..4].copy_from_slice(&(len as u32).to_le_bytes());
                stdin.write_all(&buf[..len + 4])?;

                stdout.read_exact(&mut buf[..4])?;
                let len = u32::from_le_bytes(buf[..4].try_into().unwrap()) as usize;
                stdout.read_exact(&mut buf[4..len + 4])?;

                socket.send_to(&buf[4..len + 4], addr).await?;
            }
        }
    }

    Ok(())
}
