// use mvdb::Mvdb;
// use ring::{rand, signature};
// use std::path::Path;
// use base64;
// use untrusted;
// use mvdb;

// #[derive(Serialize, Deserialize, Debug, Clone)]
// struct Something {
//     pkcs8: String,
//     public_key: String,
//     message: String,
//     signature: String,
// }

// pub fn run2() -> Result<()> {
//     let dbp = Path::new("demo.json");
//     let db: Mvdb<Something> = Mvdb::from_file_pretty(&dbp)?;

//     let smth = db.access(|db| (*db).clone())?;

//     // let pkcs8 = base64::decode(&smth.pkcs8).chain_err(|| "")?;

//     let msg = smth.message.as_bytes();
//     let sig = base64::decode(&smth.signature).chain_err(|| "")?;
//     let pk  = base64::decode(&smth.public_key).chain_err(|| "")?;

//     signature::verify(
//         &signature::ED25519,
//         untrusted::Input::from(&pk),
//         untrusted::Input::from(&msg),
//         untrusted::Input::from(&sig)).chain_err(|| "")?;

//     println!("yiss");

//     Ok(())

// }

// pub fn run() -> Result<()> {
//     // Generate a key pair in PKCS#8 (v2) format.
//     let rng = rand::SystemRandom::new();
//     let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng).chain_err(|| "")?;

//     // Normally the application would store the PKCS#8 file persistently. Later
//     // it would read the PKCS#8 file from persistent storage to use it.

//     let key_pair =
//        signature::Ed25519KeyPair::from_pkcs8(
//                 untrusted::Input::from(&pkcs8_bytes)).chain_err(|| "")?;

//     // println!("Key pair {:?}", key_pair);

//     // Sign the message "hello, world".
//     const MESSAGE: &'static [u8] = b"hello, world";
//     let sig = key_pair.sign(MESSAGE);

//     // Normally an application would extract the bytes of the signature and
//     // send them in a protocol message to the peer(s). Here we just get the
//     // public key key directly from the key pair.
//     let peer_public_key_bytes = key_pair.public_key_bytes();
//     let sig_bytes = sig.as_ref();

//     // Verify the signature of the message using the public key. Normally the
//     // verifier of the message would parse the inputs to `signature::verify`
//     // out of the protocol message(s) sent by the signer.
//     let peer_public_key = untrusted::Input::from(peer_public_key_bytes);
//     let msg = untrusted::Input::from(MESSAGE);
//     let sig = untrusted::Input::from(sig_bytes);

//     signature::verify(&signature::ED25519, peer_public_key, msg, sig).chain_err(|| "")?;

//     let db_file = Path::new("demo.json");
//     let contents = Something {
//         pkcs8: base64::encode(&pkcs8_bytes[..]),
//         public_key: base64::encode(&peer_public_key_bytes[..]),
//         message: String::from_utf8_lossy(MESSAGE).into(),
//         signature: base64::encode(&sig_bytes[..]),
//     };
//     mvdb::Mvdb::new_pretty(contents, &db_file)?;
//     Ok(())
// }
