pub use key_types::{SignResponse, TimedPublicKey};

#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String, // utf8 data
}

pub type VerifyRequest = SignResponse;
pub type KeyResponse = TimedPublicKey;

#[derive(Serialize, Deserialize)]
pub struct KeyRangeResponse {
    pub keys: Vec<KeyResponse>,
}
