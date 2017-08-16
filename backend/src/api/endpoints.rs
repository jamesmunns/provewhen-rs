use mvdb::Mvdb;
use rocket::State;
use rocket_contrib::{Json, Value};

use api::types::*;
use errors as echain;
use pub_key_storage::KeyDB;
use key_types::nonce;
use datetime_utils::ProveWhenTime;

fn raw_msg_to_signable(timestamp: &ProveWhenTime, message: &str, nonce: &str) -> String {
    format!("{};{};{}", timestamp.as_str(), message, nonce)
}

#[get("/hello", format = "application/json")]
pub fn hello() -> Result<Json<String>, echain::Error> {
    Ok(Json("Hello!".into()))
}

#[post("/sign", format = "application/json", data = "<message>")]
pub fn sign(
    message: Json<SignRequest>,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<SignResponse>, echain::Error> {
    let now = ProveWhenTime::now();
    let msg_nonce = nonce()?;

    // Mangle the message a bit
    let msg_to_sign = raw_msg_to_signable(&now, &message.message, &msg_nonce);

    let (sg, kt, pk) = keydb.access_mut(|db| {
        let signer = db.get_current();
        let sg = signer.sign_base64(&msg_to_sign);
        let kt = signer.time_generated.clone();
        let pk = signer.pub_key_base64.clone();
        (sg, kt, pk)
    })?;

    Ok(Json(SignResponse {
        timestamp: now,
        key_time: kt,
        public_key: pk,
        message: message.message.clone(),
        signature: sg?,
        nonce: msg_nonce,
    }))
}

#[get("/key/time/<time>", format = "application/json")]
pub fn key_time(
    time: ProveWhenTime,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<KeyResponse>, echain::Error> {
    let rslt = keydb.access(|db| db.get_public_key_by_time(&time))??;

    Ok(Json(KeyResponse {
        public_key: rslt.1,
        key_time: rslt.0,
    }))
}

#[get("/key/time/<start>/<end>", format = "application/json")]
pub fn key_time_range(
    start: ProveWhenTime,
    end: ProveWhenTime,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<KeyRangeResponse>, echain::Error> {
    let rslt: echain::Result<Vec<KeyResponse>> = keydb.access(|db| {
        Ok(
            db.range(&start, &end)?
            .iter()
            .take(50) // limit to 50 responses
            .map(|kr| {
                KeyResponse {
                    public_key: kr.public_key().into(),
                    key_time: kr.time().clone(),
                }
            })
            .collect(),
        )
    })?;

    Ok(Json(KeyRangeResponse { keys: rslt? }))
}

#[post("/verify", format = "application/json", data = "<message>")]
pub fn verify(
    message: Json<VerifyRequest>,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<Value>, echain::Error> {
    let reassemble = raw_msg_to_signable(&message.timestamp, &message.message, &message.nonce);

    keydb.access(|db| {
        db.verify(
            &message.timestamp,
            &message.public_key,
            &message.signature,
            &reassemble,
        )
    })??;

    Ok(Json(json!({
        "result": "ok"
    })))
}


// use std::io;
// use std::path::{Path, PathBuf};
// use rocket::response::NamedFile;

// #[get("/")]
// pub fn index() -> io::Result<NamedFile> {
//     NamedFile::open("static/index.html")
// }

// #[get("/<file..>", rank = 2)]
// pub fn files(file: PathBuf) -> Option<NamedFile> {
//     NamedFile::open(Path::new("static/").join(file)).ok()
// }
