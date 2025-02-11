pub mod auth;

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_repr::*;

#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq)]
pub enum Cmd {
    HandShake = 2,
    GetLoginNamesForURL = 4,
    GetPasswordForLoginName = 5,
    NewAccount4URL = 6,
    SaveStage1LoginName = 7,
    DidFillOneTimeCode = 17,
}

#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq)]
pub enum Action {
    Search = 2,
    MaybeAdd = 4,
    GhostSearch = 5,
}

#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq)]
pub enum MsgType {
    ClientKeyExchange = 0,
    ServerKeyExchange = 1,
    ClientVerification = 2,
    ServerVerification = 3,
}

#[repr(u8)]
#[derive(Debug, Serialize_repr, Deserialize_repr, PartialEq)]
pub enum SecretSessionVersion {
    SrpWithOldVerification = 0,
    SrpWithRfcVerification = 1,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLoginNamesForURLReq<P: Serialize + DeserializeOwned> {
    pub cmd: Cmd,
    #[serde(rename = "tabId")]
    pub tab_id: u32,
    #[serde(rename = "frameId")]
    pub frame_id: u32,
    pub url: String,
    #[serde(with = "jsonstring")]
    pub payload: P,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetOTPReq<P: Serialize + DeserializeOwned> {
    pub cmd: Cmd,
    #[serde(rename = "tabId")]
    pub tab_id: u32,
    #[serde(rename = "frameId")]
    pub frame_id: u32,
    #[serde(with = "jsonstring")]
    pub payload: P,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLoginNamesForURLRes {
    pub cmd: Cmd,
    #[serde(rename = "tabId")]
    pub tab_id: u32,
    #[serde(rename = "frameId")]
    pub frame_id: u32,
    pub payload: GetLoginNamesForURLPayloadRes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLoginPasswordForURLRes {
    pub cmd: Cmd,
    #[serde(rename = "tabId")]
    pub tab_id: u32,
    #[serde(rename = "frameId")]
    pub frame_id: u32,
    pub payload: GetLoginPasswordForURLPayloadRes,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetOTPForURLRes {
    pub cmd: Cmd,
    #[serde(rename = "tabId")]
    pub tab_id: u32,
    #[serde(rename = "frameId")]
    pub frame_id: u32,
    pub payload: GetOTPForURLPayloadRes,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginEntry {
    #[serde(alias = "USR")]
    pub user: String,
    pub sites: Vec<String>,
    #[serde(alias = "PWD")]
    pub password: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LoginEntries {
    #[serde(alias = "Entries")]
    pub entries: Option<Vec<LoginEntry>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OTPEntry {
    pub username: String,
    pub source: String,
    pub domain: String,
    pub code: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OTPEntries {
    #[serde(alias = "Entries")]
    pub entries: Option<Vec<OTPEntry>>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLoginNamesForURLPayload {
    #[serde(rename = "QID")]
    pub qid: String,
    #[serde(rename = "SMSG")]
    pub smsg: SMSGReq<ActURL>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLoginPasswordForURLPayload {
    #[serde(rename = "QID")]
    pub qid: String,
    #[serde(rename = "SMSG")]
    pub smsg: SMSGReq<ActURLUser>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetOTPForURLPayload {
    #[serde(rename = "QID")]
    pub qid: String,
    #[serde(rename = "SMSG")]
    pub smsg: SMSGReq<ActFrameURLsType>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetOTPForURLPayloadRes {
    #[serde(rename = "SMSG")]
    pub smsg: SMSGRes<OTPEntries>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLoginPasswordForURLPayloadRes {
    #[serde(rename = "SMSG")]
    pub smsg: SMSGRes<LoginEntries>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActURL {
    #[serde(rename = "ACT")]
    pub act: Action,
    #[serde(rename = "URL")]
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActURLUser {
    #[serde(rename = "ACT")]
    pub act: Action,
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(rename = "USR")]
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActFrameURLsType {
    #[serde(rename = "ACT")]
    pub act: Action,
    #[serde(rename = "TYPE")]
    pub typ: String,
    #[serde(rename = "frameURLs")]
    pub urls: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ActURLUserRes {
    #[serde(rename = "USR")]
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GetLoginNamesForURLPayloadRes {
    #[serde(rename = "SMSG")]
    pub smsg: SMSGRes<LoginEntries>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SMSGReq<T: Serialize + DeserializeOwned> {
    #[serde(rename = "TID")]
    pub tid: String,
    #[serde(rename = "SDATA", with = "crypto")]
    pub sdata: T,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SMSGRes<T: Serialize + DeserializeOwned> {
    #[serde(rename = "TID")]
    pub tid: String,
    #[serde(rename = "SDATA", with = "crypto")]
    pub sdata: T,
}

pub mod b64 {
    use base64::prelude::*;
    use log::{debug, log_enabled};
    use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::json;

    pub fn serialize<S: Serializer, V: Serialize>(v: &V, s: S) -> Result<S::Ok, S::Error> {
        let base64 = BASE64_STANDARD.encode(json!(v).to_string());
        String::serialize(&base64, s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, DE: std::fmt::Debug + DeserializeOwned>(
        d: D,
    ) -> Result<DE, D::Error> {
        let base64 = String::deserialize(d)?;
        if log_enabled!(log::Level::Debug) {
            debug!("Decoding base64: {}", base64);
        }
        let b64decoded = BASE64_STANDARD.decode(base64).unwrap();
        let de: DE = serde_json::from_slice(&b64decoded).unwrap();
        if log_enabled!(log::Level::Debug) {
            debug!("Deserialized: {:?}", de);
        }
        Ok(de)
    }
}

mod jsonstring {
    use log::{debug, log_enabled};
    use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::json;

    pub fn serialize<S: Serializer, V: Serialize>(v: &V, s: S) -> Result<S::Ok, S::Error> {
        json!(v).to_string().serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, DE: DeserializeOwned>(
        d: D,
    ) -> Result<DE, D::Error> {
        let base64 = String::deserialize(d)?;
        if log_enabled!(log::Level::Debug) {
            debug!("Deserializing JSON string: {}", base64);
        }
        let de: DE = serde_json::from_slice(base64.as_bytes()).unwrap();
        Ok(de)
    }
}

mod crypto {
    use crate::config::PassConfig;
    use aead::{array::typenum, Aead, KeyInit};
    use aes_gcm::aes::Aes128;
    use aes_gcm::AesGcm;
    use base64::prelude::*;
    use log::{debug, log_enabled};
    use rand::RngCore;
    use serde::{de::DeserializeOwned, Deserialize, Deserializer, Serialize, Serializer};
    use serde_json::json;
    type Aes256GcmWith16BitNonce = AesGcm<Aes128, typenum::U16>;

    pub fn serialize<S: Serializer, V: Serialize>(v: &V, s: S) -> Result<S::Ok, S::Error> {
        let config = match PassConfig::load() {
            Ok(config) => config,
            Err(err) => return Err(serde::ser::Error::custom(err)),
        };
        let key = config.decryption_key();

        let sdata = json!(v);

        let mut iv = [0u8; 16];
        let mut rng = rand::thread_rng();
        rng.fill_bytes(&mut iv);

        let cipher = Aes256GcmWith16BitNonce::new_from_slice(&key[..]).unwrap();

        let mut encrypted = cipher
            .encrypt(&iv.into(), sdata.to_string().as_bytes())
            .expect("encrypt data");
        encrypted = [encrypted.as_slice(), &iv[..16]].concat();

        String::serialize(&BASE64_STANDARD.encode(&encrypted), s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>, DE: DeserializeOwned>(
        d: D,
    ) -> Result<DE, D::Error> {
        let config = match PassConfig::load() {
            Ok(config) => config,
            Err(err) => return Err(serde::de::Error::custom(err)),
        };
        let key = config.decryption_key();

        let cipher = Aes256GcmWith16BitNonce::new_from_slice(&key[..]).unwrap();
        let sdata = BASE64_STANDARD
            .decode(String::deserialize(d)?)
            .expect("base64 decode payload sdata");
        let iv = sdata[..16].try_into().expect("parse first 16 bytes to iv");
        let decrypted = cipher.decrypt(iv, &sdata[16..]).expect("decrypt response");
        if log_enabled!(log::Level::Debug) {
            debug!(
                "Decrypted string: {}",
                std::str::from_utf8(&decrypted).unwrap()
            );
        }
        let de: DE = serde_json::from_slice(&decrypted).unwrap();
        Ok(de)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveStage1Data {
    #[serde(rename = "ACT")]
    pub act: Action,
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(rename = "USR")]
    pub username: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveStage1Req {
    pub cmd: Cmd,
    #[serde(rename = "tabId")]
    pub tab_id: i32,
    #[serde(rename = "frameId")]
    pub frame_id: i32,
    pub payload: SaveStage1Payload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveStage1Payload {
    #[serde(rename = "QID")]
    pub qid: String,
    #[serde(rename = "SMSG")]
    pub smsg: SMSGReq<SaveStage1Data>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveStage1Res {
    pub cmd: Cmd,
    pub payload: SaveStage1ResPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveStage1ResPayload {
    #[serde(rename = "SMSG")]
    pub smsg: SMSGRes<SaveStage1ResData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SaveStage1ResData {
    #[serde(rename = "STATUS")]
    pub status: i32,
    #[serde(rename = "RequiresUserAuthenticationToFill")]
    pub requires_user_authentication_to_fill: bool,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavePasswordReq {
    pub cmd: Cmd,
    #[serde(rename = "tabId")]
    pub tab_id: i32,
    #[serde(rename = "frameId")]
    pub frame_id: i32,
    pub payload: SavePasswordPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavePasswordPayload {
    #[serde(rename = "QID")]
    pub qid: String,
    #[serde(rename = "SMSG")]
    pub smsg: SMSGReq<SavePasswordData>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavePasswordData {
    #[serde(rename = "ACT")]
    pub act: Action,
    #[serde(rename = "URL")]
    pub url: String,
    #[serde(rename = "USR")]
    pub usr: String,
    #[serde(rename = "PWD")]
    pub pwd: String,
    #[serde(rename = "NURL")]
    pub nurl: String,
    #[serde(rename = "NUSR")]
    pub nusr: String,
    #[serde(rename = "NPWD")]
    pub npwd: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavePasswordRes {
    pub cmd: Cmd,
    pub payload: SavePasswordResPayload,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SavePasswordResPayload {
    #[serde(rename = "SMSG")]
    pub smsg: SMSGRes<String>,
}
