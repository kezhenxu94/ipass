use crate::types::auth::*;
use crate::types::*;
use base64::prelude::*;
use config::PassConfig;
use log::info;
use num::{BigInt, Num};
use rand::RngCore;
use serde_json::json;
use tokio::{io, net::UdpSocket};

use crate::*;

pub async fn auth(args: AuthArgs) -> io::Result<()> {
    let group_prime = BigInt::from_str_radix(r#"FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"#, 16).unwrap();
    let group_generator = BigInt::from_bytes_be(num_bigint::Sign::Plus, &[5]);

    let mut rng = rand::thread_rng();
    let mut buf = [0u8; 16];
    rng.fill_bytes(&mut buf);
    let username_b64 = BASE64_STANDARD.encode(buf);

    let mut buf = [0u8; 32];
    rng.fill_bytes(&mut buf);
    let pkey = buf;

    let pub_key = srp::powmod(
        &group_generator.clone(),
        &(BigInt::from_bytes_be(num_bigint::Sign::Plus, buf.as_slice())),
        &group_prime.clone(),
    )
    .to_bytes_be();

    let pub_b64 = BASE64_STANDARD.encode(&pub_key.1);

    let req = json!(Request {
        cmd: Cmd::HandShake,
        msg: Message {
            qid: "m0".to_owned(),
            pake: ChallengePake {
                tid: username_b64.to_owned(),
                msg: MsgType::ClientKeyExchange,
                a: pub_b64,
                ver: "1.0".to_owned(),
                proto: [1].to_vec(),
            },
            hstbrsr: "Arc".to_owned(),
        },
    });

    let socket = UdpSocket::bind("127.0.0.1:0").await?;
    socket
        .send_to(
            req.to_string().as_bytes(),
            format!("127.0.0.1:{}", args.port),
        )
        .await?;

    let mut buf = [0; 1024];
    let (len, _) = socket.recv_from(&mut buf).await?;
    let res: Response<ChallengeMsg> = serde_json::from_slice(&buf[..len]).unwrap();

    if let Some(error) = verify_challenge_response(&res, &username_b64) {
        return error;
    }

    let server_pub_key = BASE64_STANDARD.decode(res.payload.pake.b).unwrap();
    let salt = BASE64_STANDARD.decode(res.payload.pake.s).unwrap();
    let password = rpassword::prompt_password("Enter PIN: ").unwrap();
    let new_key = srp::pre_master_secret(
        &pub_key.1,
        &pkey,
        &server_pub_key,
        &username_b64,
        &password,
        &salt,
    );

    let config = PassConfig::new(
        username_b64.clone(),
        BASE64_STANDARD.encode(new_key.clone()),
    );
    config.save();

    let m = srp::compute_m(&username_b64, &salt, &pub_key.1, &server_pub_key, &new_key);
    let req = json!(Request {
        cmd: Cmd::HandShake,
        msg: Message {
            hstbrsr: "Arc".to_owned(),
            qid: "m2".to_owned(),
            pake: VerifyPakeReq {
                tid: username_b64.to_owned(),
                msg: MsgType::ClientVerification,
                m: BASE64_STANDARD.encode(m),
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
    let (len, _) = socket.recv_from(&mut buf).await?;
    let res = serde_json::from_slice::<Response<VerifyMsg>>(&buf[..len]).unwrap();

    if res.payload.pake.tid != username_b64 {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid server hello: destined to another session",
        ));
    }

    if let Some(error_code) = res.payload.pake.error_code {
        if error_code > 0 {
            return Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid server hello: error code: {}", error_code),
            ));
        }
    }

    if res.payload.pake.msg != MsgType::ServerVerification {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid server hello: unexpected message type",
        ));
    }

    info!("Challenge verified, config updated");

    Ok(())
}

fn verify_challenge_response(
    response: &Response<ChallengeMsg>,
    username_b64: &String,
) -> Option<Result<(), std::io::Error>> {
    if response.payload.pake.tid != *username_b64 {
        return Some(Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid server hello: destined to another session",
        )));
    }
    if let Some(error_code) = response.payload.pake.error_code {
        if error_code > 0 {
            return Some(Err(io::Error::new(
                io::ErrorKind::Other,
                format!("Invalid server hello: error code: {}", error_code),
            )));
        }
    }
    if response.payload.pake.msg != MsgType::ServerKeyExchange {
        return Some(Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid server hello: unexpected message type",
        )));
    }
    if response.payload.pake.proto != SecretSessionVersion::SrpWithRfcVerification {
        return Some(Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid server hello: unsupported protocol",
        )));
    }

    if let Some(version) = response.payload.pake.version.as_ref() {
        if version != "1.0" {
            return Some(Err(io::Error::new(
                io::ErrorKind::Other,
                "Invalid server hello: unsupported version",
            )));
        }
    }
    None
}
