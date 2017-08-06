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

    let mut signer = keydb.access(|db| {
        match db.get_current() {
            Some(signer) => Ok(signer.clone()),
            None => Err(echain::Error::from("No key present!")),
        }
    })??;

    let sig = signer.sign_base64(&message.message)?;

    // TODO: Is this good enough?
    signer.wipe_private();

    Ok(Json(SignResponse {
        timestamp: format!("{}", now),
        key_time: signer.time_generated.clone(),
        public_key: signer.pub_key_base64.clone(),
        message: message.message.clone(),
        signature: sig,
    }))
}