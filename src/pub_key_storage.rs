use errors::*;
use chrono::NaiveTime;
use chrono::prelude::*;
use chrono::DateTime;
use std::collections::{BTreeMap};
use ring::{rand, signature};
use base64;
use untrusted;

#[derive(Serialize, Deserialize)]
pub struct SingleKeySet {
    pub time_generated: String,
    pub pub_key_base64: String,
    pkcs8_base64: String,

    #[serde(skip)]
    rendered_kp: Option<signature::Ed25519KeyPair>
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

    // TODO: Should old keys retain `pkcs8_base64`? Probably okay to forget...
    old_keys: BTreeMap<String, SingleKeySet>,
}

fn floored_hour_date_time<T: TimeZone>(datetime: &DateTime<T>) -> DateTime<T> {
    datetime
        .date()
        .and_time(NaiveTime::from_hms(
            datetime.hour(), 0, 0)).unwrap()
}

impl SingleKeySet {
    pub fn new() -> Self {
        // Lie about what time it is
        let now = Utc::now();
        let fake_now = floored_hour_date_time(&now);

        let rng = rand::SystemRandom::new();
        let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).unwrap();

        let key_pair =
           signature::Ed25519KeyPair::from_pkcs8(
                    untrusted::Input::from(&pkcs8_bytes)).unwrap();

        let pk = base64::encode(key_pair.public_key_bytes());
        let pkcs8 = base64::encode(&pkcs8_bytes[..]);

        SingleKeySet {
            time_generated: fake_now.to_rfc3339(),
            pub_key_base64: pk,
            pkcs8_base64: pkcs8,
            rendered_kp: Some(key_pair),
        }
    }

    fn keypair_cache(&mut self) -> Result<()> {
        if self.rendered_kp.is_none() {
            let pkcs8 = base64::decode(&self.pkcs8_base64)
                .chain_err(|| "Failed to decode stored pksc8")?;

            let key_pair =
               signature::Ed25519KeyPair::from_pkcs8(
                        untrusted::Input::from(&pkcs8))
               .chain_err(|| "Failed to generate pkcs8")?;

            self.rendered_kp = Some(key_pair);
        }

        Ok(())
    }

    fn try_keypair(&self) -> Result<&signature::Ed25519KeyPair> {
        Ok(self.rendered_kp.as_ref().ok_or(Error::from("Keypair not cached"))?)
    }

    pub fn sign_base64(&self, msg: &str) -> Result<String> {
        Ok(base64::encode(&self.try_keypair()?.sign(msg.as_bytes())))
    }

    #[allow(dead_code)]
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
        Self {
            old_keys: BTreeMap::new(),
            current_key: SingleKeySet::new(),
        }
    }

    pub fn render_keypairs(&mut self) -> Result<()> {
        self.current_key.keypair_cache()?;
        // for mut keyset in self.old_keys.values_mut() {
        //     keyset.keypair_cache()?;
        // }
        Ok(())
    }

    pub fn get_current(&mut self) -> &SingleKeySet {
        if time_to_switch(&self.current_key.time_generated) {
            // Cloning removes the rendered keypair
            let old = self.current_key.clone();

            self.current_key = SingleKeySet::new();

            let _ = self.old_keys.insert(
                old.time_generated.clone(),
                old
            );
        }

        &self.current_key
    }

    pub fn verify(&self, timestamp: &str, alleged_pk_base64: &str, alleged_sig_base64: &str, message: &str) -> Result<()> {
        // Does a key exist for that time?
        let (_, pk_base64) = self.get_public_key_by_time(timestamp)?;

        // Does the alleged key match ours?
        if pk_base64 != alleged_pk_base64 {
            bail!("Key mismatch!");
        }

        // Now decode sig and pk
        let pk = base64::decode(&pk_base64)
            .chain_err(|| "failed to decode")?;
        let alleged_sig = base64::decode(alleged_sig_base64)
            .chain_err(|| "failed to decode")?;

        signature::verify(
            &signature::ED25519,
            untrusted::Input::from(&pk),
            untrusted::Input::from(message.as_bytes()),
            untrusted::Input::from(&alleged_sig)
        ).chain_err(|| "Signature mismatch!")
    }

    pub fn get_public_key_by_time(&self, needle: &str) -> Result<(String, String)> {
        let rtime = floored_hour_date_time(
            &DateTime::parse_from_rfc3339(needle)
                .chain_err(|| "Failed to parse time")?).to_rfc3339();

        if self.current_key.time_generated == rtime {
            Ok((rtime, self.current_key.pub_key_base64.clone()))
        } else if let Some(key) = self.old_keys.get(&rtime) {
            Ok((rtime, key.pub_key_base64.clone()))
        } else {
            bail!("No matching key!")
        }
    }
}

fn time_to_switch(time: &str) -> bool {
    let now = Utc::now();
    let generated = match DateTime::parse_from_rfc3339(time) {
        Ok(time) => time,
        _ => {
            return true;
        }
    };

    !((now.date() == generated.date()) &&
      (now.hour() == generated.hour()))
}