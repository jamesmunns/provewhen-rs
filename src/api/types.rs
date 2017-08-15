use datetime_utils::ProveWhenTime;

#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String, // utf8 data
}

#[derive(Serialize, Deserialize)]
pub struct SignResponse {
    pub timestamp: ProveWhenTime, // rfc3339 timestamp
    pub key_time: ProveWhenTime,  // rfc3339 timestamp
    pub public_key: String,       // base64 encoded Ed25519 public key
    pub message: String,          // utf8 data
    pub signature: String,        // base64 encoded Ed25519 signature
    pub nonce: String,            // "provewhen.io:<256bits of random as base64>"
}

pub type VerifyRequest = SignResponse;

#[derive(Serialize, Deserialize)]
pub struct KeyResponse {
    pub public_key: String,      // base64 encoded Ed25519 public key
    pub key_time: ProveWhenTime, // rfc3339 timestamp
}

#[derive(Serialize, Deserialize)]
pub struct KeyRangeResponse {
    pub keys: Vec<KeyResponse>,
}
