use rocket::request::Request;
use rocket::response::{Response, Responder};
use std::io::Cursor;
use rocket::http::{Status, ContentType};
use mvdb;

error_chain!{
    links {
        Mvdb(mvdb::errors::Error, mvdb::errors::ErrorKind);
    }
}

// Implement `Responder` for `error_chain`'s `Error` type
// that we just generated
impl<'r> Responder<'r> for Error {
    fn respond_to(self, _: &Request) -> ::std::result::Result<Response<'r>, Status> {
        // Render the whole error chain to a single string
        let mut rslt = String::new();

        #[cfg(debug_assertions)]
        {
            rslt += &format!("Error: {}", self);
            self.iter().skip(1).map(|ce| rslt += &format!(", caused by: {}", ce)).collect::<Vec<_>>();
        }

        #[cfg(not(debug_assertions))]
        {
            rslt += "request failed";
        }

        // Create JSON response
        let resp = json!({
            "status": "failure",
            "message": rslt,
        }).to_string();

        // Respond. The `Ok` here is a bit of a misnomer. It means we
        // successfully created an error response
        Ok(Response::build()
            .status(Status::BadRequest)
            .header(ContentType::JSON)
            .sized_body(Cursor::new(resp))
            .finalize())
    }
}