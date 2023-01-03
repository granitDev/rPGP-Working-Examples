#![allow(non_snake_case)]
use anyhow::{Context, Result};
use pgp::{
    composed::message::Message, composed::signed_key::*, crypto::sym::SymmetricKeyAlgorithm,
    Deserializable,
};
use rand::prelude::*;
use std::{fs, io::Cursor};

// While the keys used in this example are unique for each "person", the key password is the same for both
const PUBLIC_KEY_FILE: &'static str = "./key_files/pub.asc";
const SECRET_KEY_FILE: &'static str = "./key_files/sec.asc";
const MSG_FILE_NAME: &'static str = "encrypted_message.txt";
const SECRET_MSG: &'static str = "This is the secret message!";

fn main() -> Result<()> {
    println!(" Original Message: {}", &SECRET_MSG);

    _ = encrypt_message(SECRET_MSG, PUBLIC_KEY_FILE).context("encrypting message")?;

    let encrypted_msg =
        fs::read_to_string(MSG_FILE_NAME).context("Reading encrypted message from file")?;
    let decrypted_msg = decrypt_message(&encrypted_msg.as_str(), SECRET_KEY_FILE)?;

    println!("Decrypted Message: {}", &decrypted_msg);

    Ok(())
}

fn encrypt_message(msg: &str, pubkey_file: &str) -> Result<String> {
    let pubkey = fs::read_to_string(pubkey_file)
        .context("Trying to load public key for Person Two from file")?;
    let (pubkey, _) = SignedPublicKey::from_string(pubkey.as_str())?;

    // Requires a file name as the first arg, in this case I pass "none", as it's not used typically, it's just meta data
    let msg = Message::new_literal("none", msg);

    let armored = generate_armored_string(msg, pubkey)?;
    _ = fs::write(&MSG_FILE_NAME, &armored).context("Writing encrypted message to file")?;

    Ok(armored)
}

fn generate_armored_string(msg: Message, pk: SignedPublicKey) -> Result<String> {
    let mut rng = StdRng::from_entropy();
    let new_msg = msg.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pk])?;
    Ok(new_msg.to_armored_string(None)?)
}

fn decrypt_message(armored: &str, seckey_file: &str) -> Result<String> {
    let seckey = fs::read_to_string(seckey_file)?;
    let (seckey, _) = SignedSecretKey::from_string(seckey.as_str())?;

    let buf = Cursor::new(armored);
    let (msg, _) = Message::from_armor_single(buf)?;
    let (decryptor, _) = msg
        .decrypt(|| String::from(""), || String::from(""), &[&seckey])
        .context("Decrypting the message")?;

    for msg in decryptor {
        let bytes = msg?.get_content()?.unwrap();
        let clear = String::from_utf8(bytes)?;
        if String::len(&clear) > 0 {
            return Ok(clear);
        }
    }

    Err(anyhow::Error::msg("Failed to find message"))
}
