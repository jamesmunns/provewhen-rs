
#[derive(Serialize, Deserialize)]
pub struct SignRequest {
    pub message: String,
}

#[derive(Serialize, Deserialize)]
pub struct SignResponse {
    pub timestamp: String,
    pub key_time: String,
    pub public_key: String,
    pub message: String,
    pub signature: String,
}