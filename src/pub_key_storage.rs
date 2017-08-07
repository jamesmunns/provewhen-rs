use errors::*;
use std::collections::BTreeMap;
use ring::{rand, signature};
use base64;
use untrusted;
use datetime_utils::ProveWhenTime;

#[derive(Serialize, Deserialize)]
pub struct SingleKeySet {
    pub time_generated: String,
    pub pub_key_base64: String,
    pkcs8_base64: String,

    #[serde(skip)]
    rendered_kp: Option<signature::Ed25519KeyPair>,
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

#[derive(Serialize, Deserialize)]
pub struct KeyDB {
    current_key: SingleKeySet,

    // Key: rfc3339 datetime, Value: Base64 ed25519 public key
    old_keys: BTreeMap<String, String>,
}

impl SingleKeySet {
    pub fn new() -> Self {
        // Lie about what time it is
        let fake_now = ProveWhenTime::now().floored();

        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

        let key_pair =
            signature::Ed25519KeyPair::from_pkcs8(untrusted::Input::from(&pkcs8_bytes)).unwrap();

        let pk = base64::encode(key_pair.public_key_bytes());
        let pkcs8 = base64::encode(&pkcs8_bytes[..]);

        SingleKeySet {
            time_generated: fake_now.to_string(),
            pub_key_base64: pk,
            pkcs8_base64: pkcs8,
            rendered_kp: Some(key_pair),
        }
    }

    fn keypair_cache(&mut self) -> Result<()> {
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

impl Default for KeyDB {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyDB {
    pub fn new() -> Self {
        Self {
            old_keys: BTreeMap::new(),
            current_key: SingleKeySet::new(),
        }
    }

    pub fn render_keypairs(&mut self) -> Result<()> {
        self.current_key.keypair_cache()?;
        Ok(())
    }

    pub fn get_current(&mut self) -> &SingleKeySet {
        if time_to_switch(&self.current_key.time_generated) {
            // Cloning removes the rendered keypair
            let old = self.current_key.clone();

            self.current_key = SingleKeySet::new();

            let _ = self.old_keys.insert(old.time_generated, old.pub_key_base64);
        }

        &self.current_key
    }

    pub fn verify(
        &self,
        timestamp: &str,
        alleged_pk_base64: &str,
        alleged_sig_base64: &str,
        message: &str,
    ) -> Result<()> {
        // Does a key exist for that time?
        let (_, pk_base64) = self.get_public_key_by_time(timestamp)?;

        // Does the alleged key match ours?
        if pk_base64 != alleged_pk_base64 {
            bail!("Key mismatch!");
        }

        // Now decode sig and pk
        let pk = base64::decode(&pk_base64).chain_err(|| "failed to decode")?;
        let alleged_sig = base64::decode(alleged_sig_base64)
            .chain_err(|| "failed to decode")?;

        signature::verify(
            &signature::ED25519,
            untrusted::Input::from(&pk),
            untrusted::Input::from(message.as_bytes()),
            untrusted::Input::from(&alleged_sig),
        ).chain_err(|| "Signature mismatch!")
    }

    pub fn get_public_key_by_time(&self, needle: &str) -> Result<(String, String)> {
        let rtime = ProveWhenTime::from_str(needle)?.floored().to_string();

        if self.current_key.time_generated == rtime {
            Ok((rtime, self.current_key.pub_key_base64.clone()))
        } else if let Some(key) = self.old_keys.get(&rtime) {
            Ok((rtime, key.clone()))
        } else {
            bail!("No matching key!")
        }
    }
}

fn time_to_switch(time: &str) -> bool {
    let cur_key_time = match ProveWhenTime::from_str(time) {
        Ok(time) => time,
        _ => {
            return true;
        }
    };

    cur_key_time != ProveWhenTime::now().floored()
}
