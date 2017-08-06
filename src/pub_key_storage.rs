use errors::*;
use chrono::prelude::*;
use std::collections::VecDeque;
use ring::{rand, signature};
use base64;
use untrusted;

#[derive(Serialize, Deserialize, Clone)]
pub struct SingleKeySet {
    pub time_generated: String,
    pub pub_key_base64: String,
    pkcs8_base64: String,
}

#[derive(Serialize, Deserialize)]
pub struct KeyDB {
    keys: VecDeque<SingleKeySet>, // TODO, probably some kind of tree for faster lookup
}

impl SingleKeySet {
    pub fn new() -> Self {
        let now = Utc::now();

        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

        // Normally the application would store the PKCS#8 file persistently. Later
        // it would read the PKCS#8 file from persistent storage to use it.

        let key_pair =
           signature::Ed25519KeyPair::from_pkcs8(
                    untrusted::Input::from(&pkcs8_bytes)).unwrap();

        let pk = base64::encode(key_pair.public_key_bytes());
        let pkcs8 = base64::encode(&pkcs8_bytes[..]);

        SingleKeySet {
            time_generated: format!("{}", now),
            pub_key_base64: pk,
            pkcs8_base64: pkcs8,
        }
    }

    pub fn sign_base64(&self, msg: &str) -> Result<String> {
        // TODO: Its probably silly to decode the key pair every time.
        // I probably want to impl ser/de manually so I can still persist this
        // to a file, but also carry around a Ed25519KeyPair
        let pkcs8 = base64::decode(&self.pkcs8_base64)
            .chain_err(|| "Failed to decode stored pksc8")?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(
            untrusted::Input::from(&pkcs8)
        ).chain_err(|| "Failed to generate pkcs8")?;

        Ok(base64::encode(&key_pair.sign(msg.as_bytes())))
    }

    pub fn wipe_private(&mut self) {
        unsafe {
            for b in self.pkcs8_base64.as_bytes_mut() {
                *b = 0;
            }
        }
    }
}

impl Default for KeyDB {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyDB {
    pub fn new() -> Self {
        let mut vd = VecDeque::new();
        vd.push_front(SingleKeySet::new());

        Self {
            keys: vd,
        }
    }

    pub fn get_current(&self) -> Option<&SingleKeySet> {
        // TODO - rotate keys on access if hourly rollover
        self.keys.get(0)
    }
}