use errors::*;
use chrono::{self, NaiveTime};
use chrono::prelude::*;
use chrono::DateTime;
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

        // Normally the application would store the PKCS#8 file persistently. Later
        // it would read the PKCS#8 file from persistent storage to use it.

        let key_pair =
           signature::Ed25519KeyPair::from_pkcs8(
                    untrusted::Input::from(&pkcs8_bytes)).unwrap();

        let pk = base64::encode(key_pair.public_key_bytes());
        let pkcs8 = base64::encode(&pkcs8_bytes[..]);

        SingleKeySet {
            time_generated: fake_now.to_rfc3339(),
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

    pub fn get_current(&mut self) -> &SingleKeySet {
        // There is always one
        let current_time = self.keys.get(0).unwrap().time_generated.clone();

        if time_to_switch(&current_time) {
            self.keys.push_front(SingleKeySet::new());
        }

        self.keys.get(0).unwrap()
    }

    pub fn get_public_key_by_time(&self, needle: &str) -> Result<(String, String)> {
        let rtime = floored_hour_date_time(
            &DateTime::parse_from_rfc3339(needle)
                .chain_err(|| "Failed to parse time")?);

        // TODO: Yeah, this really shouldn't be a linear search,
        // especially since I have to parse every time item
        let key = self.keys.iter().find(|key| {
            DateTime::parse_from_rfc3339(&key.time_generated).unwrap() == rtime
        }).ok_or(Error::from("No matching key!"))?;

        Ok((rtime.to_rfc3339(), key.pub_key_base64.clone()))
    }
}

fn time_to_switch(time: &str) -> bool {
    let now = Utc::now();
    let generated = match DateTime::parse_from_rfc3339(time) {
        Ok(time) => time,
        _ => {
            println!("bad parse");
            return true;
        }
    };

    !((now.date() == generated.date()) &&
      (now.hour() == generated.hour()))
}