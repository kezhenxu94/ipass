use log::debug;
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

    // Stage 1: Save the login name
    let stage1_req = json!(SaveStage1Req {
        cmd: Cmd::SaveStage1LoginName,
        tab_id: 0,
        frame_id: 0,
        payload: SaveStage1Payload {
            qid: "CmdSaveStage1LoginName".to_owned(),
            smsg: SMSGReq {
                tid: config.username.clone(),
                sdata: SaveStage1Data {
                    act: Action::Search,
                    url: args.url.clone(),
                    username: args.username.clone(),
                },
            },
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(
            stage1_req.to_string().as_bytes(),
            format!("127.0.0.1:{}", args.port),
        )
        .await?;

    let mut buf = [0; 65536];
    let (len, _) = socket.recv_from(&mut buf).await?;
    debug!(
        "Received stage1 response: {}",
        std::str::from_utf8(&buf[..len]).unwrap()
    );
    let stage1_res: SaveStage1Res = serde_json::from_slice(&buf[..len]).unwrap();
    debug!("Stage1 response: {:#?}", stage1_res);

    // Stage 2: Save the password
    let save_req = json!(SavePasswordReq {
        cmd: Cmd::NewAccount4URL,
        tab_id: 0,
        frame_id: 0,
        payload: SavePasswordPayload {
            qid: "CmdNewAccount4URL".to_owned(),
            smsg: SMSGReq {
                tid: config.username,
                sdata: SavePasswordData {
                    act: Action::MaybeAdd,
                    url: String::new(),
                    usr: String::new(),
                    pwd: String::new(),
                    nurl: args.url,
                    nusr: args.username,
                    npwd: args.password,
                },
            },
        }
    });

    socket
        .send_to(
            save_req.to_string().as_bytes(),
            format!("127.0.0.1:{}", args.port),
        )
        .await?;

    let (len, _) = socket.recv_from(&mut buf).await?;
    debug!(
        "Received save response: {}",
        std::str::from_utf8(&buf[..len]).unwrap()
    );
    println!("Password saved successfully");

    Ok(())
}
