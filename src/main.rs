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
#[macro_use]
extern crate lazy_static;

mod pub_key_storage;
mod api;
mod errors;
mod datetime_utils;
mod key_types;

use std::path::Path;
use std::thread;
use std::time::Duration;

use mvdb::Mvdb;
use pub_key_storage::KeyDB;

fn main() {
    let kpath = Path::new("keystore.json");
    let keystore = Mvdb::from_file_pretty(&kpath).expect("Failed to load key database");

    // Generate a nonce to force random generator to be initialized
    key_types::nonce().expect("Failed to init random");

    // render keypairs on load
    println!("Defrosting...");
    keystore
        .access_mut(|db: &mut KeyDB| db.defrost())
        .unwrap()
        .unwrap();
    println!("Ready to eat!");

    let ks2 = keystore.clone();

    let rkt_hdl = thread::spawn(|| { api::setup_rocket(keystore).launch(); });

    rotator(ks2);

    rkt_hdl.join().unwrap();
}

// --------

fn rotator(db: Mvdb<KeyDB>) {
    loop {
        db.access_mut(|db| {
            let _ = db.get_current();
            ()
        }).expect("Keystore access failed!");

        // TODO - add jitter
        thread::sleep(Duration::from_secs(180));
    }
}
