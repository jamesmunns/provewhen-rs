use std::cmp::{Ord, Ordering};
use rand::{thread_rng, sample};

use datetime_utils::ProveWhenTime;

use key_types::{PROOF_MESSAGES, SignResponse, SingleKeySet};

#[derive(Serialize, Deserialize, Eq, Clone)]
pub struct TimedPublicKey {
    time: ProveWhenTime,
    public_key: String, // Base64 Public Key
    proof: SignResponse
}

impl TimedPublicKey {
    pub fn time(&self) -> &ProveWhenTime {
        &self.time
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    pub fn from_single_keyset(key: &SingleKeySet) -> Self {
        let sample = sample(&mut thread_rng(), PROOF_MESSAGES.iter(), 1);
        let proof = key.sign(key.time_generated.clone(), &sample[0]).unwrap();

        TimedPublicKey {
            time: key.time_generated.clone(),
            public_key: key.pub_key_base64.clone(),
            proof: proof,
        }
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