use ring::signature;
use base64;
use untrusted;

use datetime_utils::{DateTimeRange, ProveWhenTime};
use errors::*;
use key_types::*;

#[derive(Serialize, Deserialize)]
pub struct KeyDB {
    #[serde(skip)]
    current_key: SingleKeySet,

    old_keys: Vec<TimedPublicKey>,
}

impl Default for KeyDB {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyDB {
    pub fn new() -> Self {
        let mut new = Self {
            old_keys: Vec::new(),
            current_key: SingleKeySet::new(),
        };

        new.log_current_key();

        new
    }

    fn rotate(&mut self, new: SingleKeySet) {
        self.current_key = new;
        self.log_current_key();
    }

    pub fn get_current(&mut self) -> &SingleKeySet {
        if self.time_to_switch() {
            self.rotate(SingleKeySet::new());
        }

        &self.current_key
    }

    pub fn range(&self, start: &ProveWhenTime, end: &ProveWhenTime) -> Result<&[TimedPublicKey]> {
        if end < start {
            bail!("malformed request")
        }

        let lbound = self.old_keys
            .binary_search_by_key(start.inner(), |ref i| i.time().inner().clone());
        let rbound = self.old_keys
            .binary_search_by_key(end.inner(), |ref i| i.time().inner().clone());

        let lbound = match lbound {
            Ok(n) => n,
            Err(n) if n > self.old_keys.len() => bail!("Bad Binary Search!"),
            Err(n) => n,
        };
        let rbound = match rbound {
            Ok(n) => n,
            Err(n) if n > self.old_keys.len() => bail!("Bad Binary Search!"),
            Err(n) => n,
        };

        Ok(&self.old_keys[lbound..rbound])
    }

    pub fn verify(
        &self,
        timestamp: &ProveWhenTime,
        alleged_pk_base64: &str,
        alleged_sig_base64: &str,
        message: &str,
    ) -> Result<()> {
        // Does a key exist for that time?
        let pk_base64 = self.get_public_key_by_time(timestamp)?.public_key().to_string();

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

    pub fn get_public_key_by_time(&self, rtime: &ProveWhenTime) -> Result<TimedPublicKey> {
        if ProveWhenTime::now() < *rtime {
            // Time is in the future
            bail!("Cannot provide future keys");
        }

        /////////////////////////////////////////////////
        // NOTE: Order matters in this block!
        /////////////////////////////////////////////////
        match self.old_keys
            .binary_search_by_key(rtime.inner(), |ref i| i.time().inner().clone())
        {
            // An exact match was found for the key
            Ok(n) => Ok(self.old_keys[n].clone()),

            // The search fell off the left end of the list
            Err(0) => bail!("Time is before recorded history"),

            // The search fell WAY off the right end of the list,
            // probably not possible (unless a bug in binary_search)
            Err(n) if n > self.old_keys.len() => bail!("What?"),

            // The search didn't find an exact match, so we can take the
            // item "to the left", which is the "price is right" match:
            // closest without going over, including if n == old_keys.len()
            Err(n) => Ok(self.old_keys[n - 1].clone()),
        }


    }

    fn log_current_key(&mut self) {
        self.old_keys.push(TimedPublicKey::from_single_keyset(&self.current_key));
    }

    /// Should be called some time between deserialization and use
    pub fn defrost(&mut self) -> Result<()> {
        // Ensure the key storage is sorted
        self.old_keys.sort();

        let latest = match self.old_keys.last().cloned() {
            Some(k) => {
                // Make sure the current key exists in the old list
                if *k.public_key() != self.current_key.pub_key_base64 {
                    self.log_current_key();
                }

                k
            },
            None => {
                // All code after this is processing old keys, nothing
                // more to do
                self.log_current_key();
                return Ok(())
            },
        };


        // Fill in between last run and current
        let filler = DateTimeRange::new(
            latest.time(),
            &self.current_key.time_generated,
        ).map(|time| SingleKeySet::from_time(time))
            .collect::<Vec<SingleKeySet>>();

        // Insert all the old keys
        for key_pair in filler {
            self.old_keys
                .push(TimedPublicKey::from_single_keyset(&key_pair));
        }

        Ok(())
    }

    fn time_to_switch(&self) -> bool {
        self.current_key.time_generated < ProveWhenTime::now().floored()
    }
}
