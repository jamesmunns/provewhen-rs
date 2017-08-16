use ring::signature;
use base64;
use untrusted;

use datetime_utils::{DateTimeRange, ProveWhenTime};
use errors::*;
use key_types::*;

#[derive(Serialize, Deserialize)]
pub struct KeyDB {
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
        Self {
            old_keys: Vec::new(),
            current_key: SingleKeySet::new(),
        }
    }

    fn rotate(&mut self, new: SingleKeySet) {
        // Cloning removes the rendered keypair
        let old = self.current_key.clone();

        self.current_key = new;
        self.old_keys
            .push(TimedPublicKey::new(old.time_generated, old.pub_key_base64));
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
            Err(n) => n,
        };
        let rbound = match rbound {
            Ok(n) => n,
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

    // TODO - return TimedPublicKey
    pub fn get_public_key_by_time(&self, rtime: &ProveWhenTime) -> Result<(ProveWhenTime, String)> {
        if ProveWhenTime::now() < *rtime {
            // Time is in the future
            bail!("Cannot provide future keys");
        } else if self.current_key.time_generated < *rtime {
            // Time is in between now and current key
            return Ok((
                self.current_key.time_generated.clone(),
                self.current_key.pub_key_base64.clone(),
            ));
        }

        // NOTE: Order matters in this block
        match self.old_keys
            .binary_search_by_key(rtime.inner(), |ref i| i.time().inner().clone())
        {
            // An exact match was found for the key
            Ok(n) => Ok((
                self.old_keys[n].time().clone(),
                self.old_keys[n].public_key().into(),
            )),

            // The search fell off the left end of the list
            Err(0) => bail!("Time is before recorded history"),

            // The search fell off the right end of the list
            Err(n) if n >= self.old_keys.len() => bail!("What?"),

            // The search didn't find an exact match, so we can take the
            // item "to the left", which is the "price is right" match:
            // closest without going over
            Err(n) => Ok((
                self.old_keys[n - 1].time().clone(),
                self.old_keys[n - 1].public_key().into(),
            )),
        }


    }

    /// Should be called some time between deserialization and use
    pub fn defrost(&mut self) -> Result<()> {
        // Ensure the key storage is sorted
        self.old_keys.sort();

        // TODO - fill in any gaps?

        // Fill in between last run and current
        let mut filler = DateTimeRange::new(
            &self.current_key.time_generated,
            &ProveWhenTime::now().floored(),
        ).map(|time| (time.clone(), SingleKeySet::from_time(time)))
            .collect::<Vec<(ProveWhenTime, SingleKeySet)>>();

        // Take the last (most recent) item. If there are no items,
        // then the serialized current_key should be retained as current
        let (_, keeper) = match filler.pop() {
            Some(last) => last,
            None => {
                // Nothing in the list, just rerender the serialized current key
                self.current_key.keypair_cache()?;
                return Ok(());
            }
        };

        // Insert the oldest key first to maintain order
        self.rotate(keeper);

        // Insert all the old keys
        for (time, key_pair) in filler {
            self.old_keys
                .push(TimedPublicKey::new(time, key_pair.pub_key_base64));
        }

        Ok(())
    }

    fn time_to_switch(&self) -> bool {
        self.current_key.time_generated < ProveWhenTime::now().floored()
    }
}
