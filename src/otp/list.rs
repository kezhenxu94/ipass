use log::{debug, log_enabled};
use std::net::UdpSocket;

use serde_json::json;
use tokio::io;

use crate::{config::PassConfig, types::*, OtpArgs};

pub async fn get(args: OtpArgs) -> io::Result<()> {
    let config = match PassConfig::load() {
        Ok(config) => config,
        Err(err) => return Err(err),
    };

    let urls = if args.url.starts_with("http://") || args.url.starts_with("https://") {
        vec![args.url]
    } else {
        vec![format!("http://{}", args.url)]
    };
    let req = json!(GetOTPReq {
        cmd: Cmd::DidFillOneTimeCode,
        tab_id: 0,
        frame_id: 0,
        payload: GetOTPForURLPayload {
            qid: "CmdDidFillOneTimeCode".to_owned(),
            smsg: SMSGReq {
                tid: config.username,
                sdata: ActFrameURLsType {
                    act: Action::Search,
                    urls,
                    typ: "oneTimeCodes".to_owned(),
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

    if log_enabled!(log::Level::Debug) {
        debug!(
            "OTP response: {}",
            std::str::from_utf8(&buf[..len]).unwrap()
        );
    }

    let res = serde_json::from_slice::<GetOTPForURLRes>(&buf[..len])?;

    println!("{}", json!(res.payload.smsg.sdata));

    Ok(())
}
