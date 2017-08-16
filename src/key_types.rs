use std::cmp::{Ord, Ordering};
use std::ops::Deref;

use base64;
use ring::rand::SecureRandom;
use ring::{self, signature};
use untrusted;

use datetime_utils::ProveWhenTime;
use errors::*;

lazy_static! {
    pub static ref RANDOM: ring::rand::SystemRandom = {
        let r = ring::rand::SystemRandom::new();
        // Warm up the random number generator
        r.fill(&mut [0 as u8; 4096]).expect("failed to initialize random");
        r
    };
}

pub fn nonce() -> Result<String> {
    // Generate a nonce from 256 bits of random data
    let mut data = [0u8; 32];
    RANDOM
        .deref()
        .fill(&mut data[..])
        .chain_err(|| "Failed to generate nonce")?;
    Ok(format!("provewhen.io:{}", base64::encode(&data[..])))
}

#[derive(Serialize, Deserialize)]
pub struct SingleKeySet {
    pub time_generated: ProveWhenTime,
    pub pub_key_base64: String,
    pkcs8_base64: String,

    #[serde(skip)]
    rendered_kp: Option<signature::Ed25519KeyPair>,
}

#[derive(Serialize, Deserialize, Eq, Clone)]
pub struct TimedPublicKey {
    time: ProveWhenTime,
    public_key: String, // Base64 Public Key
}


// TODO - from SingleKeySet
impl TimedPublicKey {
    pub fn new(time: ProveWhenTime, public_key: String) -> Self {
        Self {
            time: time,
            public_key: public_key,
        }
    }
    pub fn time(&self) -> &ProveWhenTime {
        &self.time
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

impl Clone for SingleKeySet {
    fn clone(&self) -> Self {
        Self {
            time_generated: self.time_generated.clone(),
            pub_key_base64: self.pub_key_base64.clone(),
            pkcs8_base64: self.pkcs8_base64.clone(),
            rendered_kp: None,
        }
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
        let pkcs8 = base64::encode(&pkcs8_bytes[..]);

        SingleKeySet {
            time_generated: time,
            pub_key_base64: pk,
            pkcs8_base64: pkcs8,
            rendered_kp: Some(key_pair),
        }
    }

    pub fn keypair_cache(&mut self) -> Result<()> {
        if self.rendered_kp.is_none() {
            let pkcs8 = base64::decode(&self.pkcs8_base64)
                .chain_err(|| "Failed to decode stored pksc8")?;

            let key_pair = signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&pkcs8))
                .chain_err(|| "Failed to generate pkcs8")?;

            self.rendered_kp = Some(key_pair);
        }

        Ok(())
    }

    fn try_keypair(&self) -> Result<&signature::Ed25519KeyPair> {
        Ok(self.rendered_kp
            .as_ref()
            .ok_or(Error::from("Keypair not cached"))?)
    }

    pub fn sign_base64(&self, msg: &str) -> Result<String> {
        Ok(base64::encode(&self.try_keypair()?.sign(msg.as_bytes())))
    }
}

impl Ord for TimedPublicKey {
    fn cmp(&self, other: &Self) -> Ordering {
        self.time.cmp(&other.time)
    }
}

impl PartialOrd for TimedPublicKey {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for TimedPublicKey {
    fn eq(&self, other: &Self) -> bool {
        self.time == other.time
    }
}
