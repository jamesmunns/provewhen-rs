use std::ops::Deref;

use base64;
use ring::signature;
use untrusted;

use datetime_utils::ProveWhenTime;
use key_types::{SignResponse, raw_msg_to_signable, nonce, RANDOM};
use errors::Result;

pub struct SingleKeySet {
    pub time_generated: ProveWhenTime,
    pub pub_key_base64: String,
    rendered_kp: signature::Ed25519KeyPair,
}

impl Default for SingleKeySet {
    fn default() -> Self {
        Self::new()
    }
}

impl SingleKeySet {
    pub fn new() -> Self {
        Self::from_time(ProveWhenTime::now())
    }

    pub fn from_time(time: ProveWhenTime) -> Self {
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(RANDOM.deref()).unwrap();

        let key_pair =
            signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&pkcs8_bytes)).unwrap();

        let pk = base64::encode(key_pair.public_key_bytes());

        SingleKeySet {
            time_generated: time,
            pub_key_base64: pk,
            rendered_kp: key_pair,
        }
    }

    fn keypair(&self) -> &signature::Ed25519KeyPair {
        &self.rendered_kp
    }

    fn sign_base64(&self, msg: &str) -> String {
        base64::encode(&self.keypair().sign(msg.as_bytes()))
    }

    pub fn sign(&self, now: ProveWhenTime, msg: &str) -> Result<SignResponse> {
        let msg_nonce = nonce()?;

        // Mangle the message a bit
        let msg_to_sign = raw_msg_to_signable(&now, msg, &msg_nonce);

        let sg = self.sign_base64(&msg_to_sign);
        let kt = self.time_generated.clone();
        let pk = self.pub_key_base64.clone();

        Ok(SignResponse {
            timestamp: now,
            key_time: kt,
            public_key: pk,
            message: msg.into(),
            signature: sg,
            nonce: msg_nonce,
        })
    }
}