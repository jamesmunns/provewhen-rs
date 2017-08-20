use std::ops::Deref;
use std::path::PathBuf;

use base64;
use ring::rand::{SecureRandom, SystemRandom};
use mvdb::helpers::just_load;

use datetime_utils::ProveWhenTime;
use errors::*;

mod timed_public_key;
mod single_key_set;

// Re-export types
pub use self::timed_public_key::TimedPublicKey;
pub use self::single_key_set::SingleKeySet;

#[derive(Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct SignResponse {
    pub timestamp: ProveWhenTime, // rfc3339 timestamp
    pub key_time: ProveWhenTime,  // rfc3339 timestamp
    pub public_key: String,       // base64 encoded Ed25519 public key
    pub message: String,          // utf8 data
    pub signature: String,        // base64 encoded Ed25519 signature
    pub nonce: String,            // "provewhen.io:<256bits of random as base64>"
}

#[derive(Deserialize)]
struct ProofMessages {
    messages: Vec<String>,
}

// lazy-load random text strings used for proof messages
lazy_static! {
    pub static ref PROOF_MESSAGES: Vec<String> = {
        let fname = PathBuf::from("../tt_snips.json");
        let x: ProofMessages = just_load(&fname).expect("failed to load snips");
        x.messages
    };
}

// lazy-load a "global" random number generator
lazy_static! {
    pub static ref RANDOM: SystemRandom = {
        let r = SystemRandom::new();
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



pub fn raw_msg_to_signable(timestamp: &ProveWhenTime, message: &str, nonce: &str) -> String {
    format!("{};{};{}", timestamp.as_str(), message, nonce)
}
