use mvdb::Mvdb;
use rocket::State;
use rocket_contrib::{Json, Value};

use api::types::*;
use errors as echain;
use pub_key_storage::KeyDB;
use datetime_utils::ProveWhenTime;

#[get("/hello", format = "application/json")]
pub fn hello() -> Result<Json<String>, echain::Error> {
    Ok(Json("Hello!".into()))
}

#[post("/sign", format = "application/json", data = "<message>")]
pub fn sign(
    message: Json<SignRequest>,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<SignResponse>, echain::Error> {
    let sgd = keydb.access_mut(|db| {
        let signer = db.get_current();
        signer.sign(ProveWhenTime::now(), &message.message)
    })?;

    Ok(Json(sgd?))
}

#[get("/key/time/<time>", format = "application/json")]
pub fn key_time(
    time: ProveWhenTime,
    keydb: State<Mvdb<KeyDB>>,
) -> Result<Json<KeyResponse>, echain::Error> {
    let rslt = keydb.access(|db| db.get_public_key_by_time(&time))??;

    Ok(Json(rslt))
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
            .cloned()
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

    keydb.access(|db| {
        db.verify(&message)
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
