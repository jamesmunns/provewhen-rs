#![feature(plugin, custom_derive)]
#![plugin(rocket_codegen)]

// NOTE: Used to zero keys:
#![feature(str_mut_extras)]

extern crate ring;
extern crate untrusted;
extern crate mvdb;
extern crate base64;
#[macro_use] extern crate serde_derive;
extern crate serde;
extern crate chrono;
#[macro_use]
extern crate error_chain;
#[macro_use]
extern crate rocket_contrib;
extern crate rocket;

mod pub_key_storage;
mod demo;
mod api;
mod errors;

use std::path::Path;
use mvdb::Mvdb;

fn main() {
    let kpath = Path::new("keystore.json");
    let keystore = Mvdb::from_file_or_default_pretty(&kpath)
        .expect("Failed to load key database");



    api::setup_rocket(keystore).launch();
}

// --------