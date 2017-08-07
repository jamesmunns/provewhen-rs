#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

extern crate ring;
extern crate untrusted;
extern crate mvdb;
extern crate base64;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate chrono;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate rocket_contrib;
extern crate rocket;

mod pub_key_storage;
mod api;
mod errors;
mod datetime_utils;

use std::path::Path;
use mvdb::Mvdb;
use pub_key_storage::KeyDB;

fn main() {
    let kpath = Path::new("keystore.json");
    let keystore = Mvdb::from_file_or_default_pretty(&kpath).expect("Failed to load key database");

    // render keypairs on load
    keystore
        .access_mut(|db: &mut KeyDB| db.render_keypairs())
        .unwrap()
        .unwrap();

    api::setup_rocket(keystore).launch();
}

// --------
