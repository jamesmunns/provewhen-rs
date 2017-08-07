use rocket;
use mvdb::Mvdb;
use pub_key_storage::KeyDB;

pub mod endpoints;
pub mod types;

pub fn setup_rocket(keydb: Mvdb<KeyDB>) -> rocket::Rocket {
    rocket::ignite()
        .mount(
            "/api/v1/",
            routes![
                endpoints::hello,

                endpoints::sign,
                endpoints::key_time,
                endpoints::verify,
            ],
        )
        .manage(keydb)
}
