use std::net::UdpSocket;

use serde_json::json;
use tokio::io;

use crate::{config::PassConfig, types::*, GetArgs};

pub async fn get(args: GetArgs) -> io::Result<()> {
    let config = match PassConfig::load() {
        Ok(config) => config,
        Err(err) => return Err(err),
    };

    let req = json!(GetLoginNamesForURLReq {
        cmd: Cmd::GetPasswordForLoginName,
        tab_id: 0,
        frame_id: 0,
        url: args.url.clone(),
        payload: GetLoginPasswordForURLPayload {
            qid: "CmdGetPassword4LoginName".to_owned(),
            smsg: SMSGReq {
                tid: config.username,
                sdata: ActURLUser {
                    act: Action::Search,
                    url: args.url.clone(),
                    username: args.username,
                },
            },
        }
    });

    let socket = UdpSocket::bind("127.0.0.1:0").expect("bind to address");
    socket
        .send_to(
            req.to_string().as_bytes(),
            format!("127.0.0.1:{}", args.port),
        )
        .expect("send request to socket");

    let mut buf = [0; 65536];
    let (len, _) = socket.recv_from(&mut buf).expect("receive data");
    let res = serde_json::from_slice::<GetLoginPasswordForURLRes>(&buf[..len]).unwrap();

    println!("{}", json!(res.payload.smsg.sdata));

    Ok(())
}
