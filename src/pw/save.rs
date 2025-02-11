use serde_json::json;
use tokio::io;
use tokio::net::UdpSocket;

use crate::config::PassConfig;
use crate::types::*;
use crate::SaveArgs;

pub async fn save(args: SaveArgs) -> io::Result<()> {
    let config = match PassConfig::load() {
        Ok(config) => config,
        Err(err) => return Err(err),
    };

    let req = json!(SavePasswordReq {
        cmd: Cmd::SavePassword,
        tab_id: 0,
        frame_id: 0,
        payload: SavePasswordPayload {
            qid: "CmdSavePassword".to_owned(),
            smsg: SMSGReq {
                tid: config.username,
                sdata: SavePasswordData {
                    url: args.url,
                    username: args.username,
                    password: args.password,
                },
            },
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(
            req.to_string().as_bytes(),
            format!("127.0.0.1:{}", args.port),
        )
        .await?;

    let mut buf = [0; 65536];
    let (len, _) = socket.recv_from(&mut buf).await?;
    let res: SavePasswordRes = serde_json::from_slice(&buf[..len]).unwrap();

    println!("{}", json!(res.payload.smsg.sdata));

    Ok(())
}
