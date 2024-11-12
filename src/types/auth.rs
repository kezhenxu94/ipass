use std::fmt::Debug;

use super::b64;
use super::Cmd;
use super::MsgType;
use super::SecretSessionVersion;
use serde::{de::DeserializeOwned, Deserialize, Serialize};

#[derive(Debug, Deserialize, Serialize)]
pub struct Request<MSG> {
    pub cmd: Cmd,
    pub msg: MSG,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Response<PL> {
    pub cmd: Cmd,
    pub payload: PL,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Message<PA: Debug + Serialize + DeserializeOwned> {
    #[serde(rename = "QID")]
    pub qid: String,
    #[serde(rename = "PAKE", with = "b64")]
    pub pake: PA,
    #[serde(rename = "HSTBRSR")]
    pub hstbrsr: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyPakeReq {
    #[serde(rename = "TID")]
    pub tid: String,
    #[serde(rename = "MSG")]
    pub msg: MsgType,
    #[serde(rename = "M")]
    pub m: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct VerifyMsg {
    #[serde(rename = "QID")]
    pub qid: String,
    #[serde(rename = "PAKE", with = "b64")]
    pub pake: VerifyPakeRes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VerifyPakeRes {
    #[serde(rename = "TID")]
    pub tid: String,
    #[serde(rename = "MSG")]
    pub msg: MsgType,
    #[serde(rename = "ErrCode")]
    pub error_code: Option<u8>,
    #[serde(rename = "HAMK")]
    pub hamk: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct ChallengeMsg {
    #[serde(rename = "QID")]
    pub qid: String,
    #[serde(rename = "PAKE", with = "b64")]
    pub pake: ChallengePayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengePayload {
    #[serde(rename = "ErrCode")]
    pub error_code: Option<u8>,
    #[serde(rename = "TID")]
    pub tid: String,
    #[serde(rename = "MSG")]
    pub msg: MsgType,
    #[serde(rename = "B")]
    pub b: String,
    #[serde(rename = "PROTO")]
    pub proto: SecretSessionVersion,
    #[serde(rename = "VER")]
    pub version: Option<String>,

    pub s: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ChallengePake {
    #[serde(rename = "TID")]
    pub tid: String,
    #[serde(rename = "MSG")]
    pub msg: MsgType,
    #[serde(rename = "A")]
    pub a: String,
    #[serde(rename = "VER")]
    pub ver: String,
    #[serde(rename = "PROTO")]
    pub proto: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_serialize() {
        let req = Request {
            msg: Message {
                qid: "m0".to_owned(),
                pake: ChallengePake {
                    tid: "tid".to_owned(),
                    msg: MsgType::ServerKeyExchange,
                    a: "a".to_owned(),
                    ver: "1.0".to_owned(),
                    proto: [1].to_vec(),
                },
                hstbrsr: "Arc".to_owned(),
            },
            cmd: Cmd::HandShake,
        };
        let serialized = json!(req);

        assert_eq!(
            serialized.to_string(),
            "{\"cmd\":2,\"msg\":{\"HSTBRSR\":\"Arc\",\"PAKE\":\"eyJBIjoiYSIsIk1TRyI6MSwiUFJPVE8iOlsxXSwiVElEIjoidGlkIiwiVkVSIjoiMS4wIn0=\",\"QID\":\"m0\"}}"
        );
    }

    #[test]
    fn test_deserialize() {
        let raw = r#"
        {"cmd":2,"payload":{"QID":"m0","PAKE":"eyJNU0ciOjEsIlBST1RPIjowLCJzIjoiNnpMYkU5elU0NlJBVEpXUkREV1pcL1E9PSIsIkIiOiI2SmlBVGh6c04wWW96YW81Ym96QXRBREdjak9abjhcL0RMRW04cUtVeTh5QUpYR1VMZW5RRGxQVUMxRks2NWdPN2dIcHZ5cU9DYlFhblRiM1ZDZW9LYXhEUUZwXC9uaDJaRlk5eVlIa3RJalkrRkxxSWVWVXd3TmlwbEZIa3ZCWFZMRTR6cHhsZmt3ZkhVS2VxWUJXbkJJXC9jQ2dmN0FJZFgxaXM1S2JGTUdWdlhONWdqMnVMcjZmZ0hFbEp0WXlBYjJ3R1Q3ek96STMzS2JsZnNpdDNrdGZ3Mms4UzdoNm9BMEc2N2NBNFN1R016Mm1RdFBCUndoNnBWd000emk2dFo0cnpoc0JCM1Z1MUJWK245ZzNuXC80UXZlK0gzOGxuWEJocHg2elRWUGNxM3dXeklVbG41ZmJkNnJmSlZuYnFXelBHelgycFFleHJyOUpFQkhMdnR5YzZST2FzRFwvbUZMdUNUaG1LVG4xbjJNaTVPWkZITU1aUFRJb05CaU9sQzNPYnBBU2JnSklPRmhNaGxrSkFnQk9mamJmM2RqREZuaEIxS2g0VzZVYUpXdDJjXC9wTW9nNUNxOTZIRVNHXC8xVlVZS2dJTGlcL256RVRRbHNrQkRTU0ZXV0w2eFRFb0h2WWZ4dittK2FPa05kWmpUUzZQQ2VWTGZpWU9nRDg4S3dJajhxIiwiVElEIjoiZWpBRTBaalp4NDdxbkpJckIyTTZ1UT09In0="}}
        "#;
        let response: Response<ChallengeMsg> = serde_json::from_str(raw).unwrap();
        assert!(response.cmd == Cmd::HandShake);
        assert!(response.payload.pake.tid == "ejAE0ZjZx47qnJIrB2M6uQ==");
        assert!(response.payload.pake.b == "6JiAThzsN0Yozao5bozAtADGcjOZn8/DLEm8qKUy8yAJXGULenQDlPUC1FK65gO7gHpvyqOCbQanTb3VCeoKaxDQFp/nh2ZFY9yYHktIjY+FLqIeVUwwNiplFHkvBXVLE4zpxlfkwfHUKeqYBWnBI/cCgf7AIdX1is5KbFMGVvXN5gj2uLr6fgHElJtYyAb2wGT7zOzI33Kblfsit3ktfw2k8S7h6oA0G67cA4SuGMz2mQtPBRwh6pVwM4zi6tZ4rzhsBB3Vu1BV+n9g3n/4Qve+H38lnXBhpx6zTVPcq3wWzIUln5fbd6rfJVnbqWzPGzX2pQexrr9JEBHLvtyc6ROasD/mFLuCThmKTn1n2Mi5OZFHMMZPTIoNBiOlC3ObpASbgJIOFhMhlkJAgBOfjbf3djDFnhB1Kh4W6UaJWt2c/pMog5Cq96HESG/1VUYKgILi/nzETQlskBDSSFWWL6xTEoHvYfxv+m+aOkNdZjTS6PCeVLfiYOgD88KwIj8q");
    }
}
