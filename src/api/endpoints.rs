use chrono::prelude::*;
use mvdb::Mvdb;
use rocket::State;
use rocket_contrib::{Json, Value};

use api::types::*;
use errors as echain;
use pub_key_storage::KeyDB;

#[get("/hello", format = "application/json")]
pub fn hello() -> Result<Json<String>, echain::Error> {
    Ok(Json("Hello!".into()))
}

#[post("/sign", format = "application/json", data = "<message>")]
pub fn sign(
    message: Json<SignRequest>,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<SignResponse>, echain::Error> {
    let now = Utc::now();

    let (sg, kt, pk) = keydb.access_mut(|db| {
        let signer = db.get_current();
        let sg = signer.sign_base64(&message.message);
        let kt = signer.time_generated.clone();
        let pk = signer.pub_key_base64.clone();
        (sg, kt, pk)
    })?;

    Ok(Json(SignResponse {
        timestamp: now.to_rfc3339(),
        key_time: kt,
        public_key: pk,
        message: message.message.clone(),
        signature: sg?,
    }))
}

#[get("/key/time/<time>", format = "application/json")]
pub fn key_time(
    time: String,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<KeyResponse>, echain::Error> {
    let rslt = keydb.access(|db| db.get_public_key_by_time(&time))??;

    Ok(Json(KeyResponse {
        public_key: rslt.1,
        key_time: rslt.0,
    }))
}

#[post("/verify", format = "application/json", data = "<message>")]
pub fn verify(
    message: Json<VerifyRequest>,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<Value>, echain::Error> {
    keydb.access(|db| {
        db.verify(
            &message.timestamp,
            &message.public_key,
            &message.signature,
            &message.message,
        )
    })??;

    Ok(Json(json!({
        "result": "ok"
    })))
}
