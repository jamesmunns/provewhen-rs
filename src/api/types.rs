
#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String,    // utf8 data
}

#[derive(Serialize, Deserialize)]
pub struct SignResponse {
    pub timestamp: String,  // rfc3339 timestamp
    pub key_time: String,   // rfc3339 timestamp
    pub public_key: String, // base64 encoded Ed25519 public key
    pub message: String,    // utf8 data
    pub signature: String,  // base64 encoded Ed25519 signature
}

pub type VerifyRequest = SignResponse;

#[derive(Serialize, Deserialize)]
pub struct KeyResponse {
    pub public_key: String, // base64 encoded Ed25519 public key
    pub key_time: String,   // rfc3339 timestamp
}