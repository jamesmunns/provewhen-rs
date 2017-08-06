use chrono::prelude::*;
use mvdb::Mvdb;
use rocket::State;
use rocket_contrib::Json;

use api::types::*;
use errors as echain;
use errors::ResultExt;
use pub_key_storage::{KeyDB, SingleKeySet};

#[get("/hello", format = "application/json")]
pub fn hello() -> Result<Json<String>, echain::Error> {
    Ok(Json("Hello!".into()))
}

#[post("/sign", format = "application/json", data = "<message>")]
pub fn sign(
    message: Json<SignRequest>,
    keydb: State<Mvdb<KeyDB>>
) -> Result<Json<SignResponse>, echain::Error> {
    let now = Utc::now();

    let mut signer = keydb.access_mut(|db| {
        db.get_current().clone()
    })?;

    let sig = signer.sign_base64(&message.message)?;

    // TODO: Is this good enough?
    signer.wipe_private();

    Ok(Json(SignResponse {
        timestamp: now.to_rfc3339(),
        key_time: signer.time_generated.clone(),
        public_key: signer.pub_key_base64.clone(),
        message: message.message.clone(),
        signature: sig,
    }))
}

#[get("/key/time/<time>", format = "application/json")]
pub fn key_time(
    time: String,
    keydb: State<Mvdb<KeyDB>>
) -> Result<Json<KeyResponse>, echain::Error> {
    let rslt = keydb.access(|db| {
        db.get_public_key_by_time(&time)
    })??;

    Ok(Json(KeyResponse{
        public_key: rslt.1,
        key_time: rslt.0,
    }))
}