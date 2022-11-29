#![allow(non_snake_case)]
use anyhow::{Context, Result};
use pgp::{
    armor, composed::message::Message, composed::signed_key::*, crypto::sym::SymmetricKeyAlgorithm,
    Deserializable,
};
use rand::prelude::*;
use std::{fs, io::Cursor};

// While the keys used in this example are unique for each "person", the key password is the same for both
const PASSWORD: &str = "qwerty";

fn main() -> Result<()> {
    println!("Hello, rPGP!");
    ptwd(); // Prints the working directory

    let p1_original_msg = "This is a secret message!";
    let p1_message_file = person1_encrypt_msg_for_person1(p1_original_msg)?;
    println!("File path: {}", p1_message_file);
    let p1_armored_msg = fs::read_to_string(p1_message_file)?;
    println!("Armored Msg: {}", p1_armored_msg);

    let decoded_msg = person2_decrypt_msg_from_person1(&p1_armored_msg.as_str())?;

    println!("Original: {}", &p1_original_msg);
    println!("Decoded: {}", &decoded_msg);
    // assert_eq!(&p1_original_msg, &decoded_msg);

    // let pubkey = fs::read_to_string("./key_files/public.key")
    //     .context("Trying to load public key from file")?;
    // let server_pubkey = SignedPublicKey::from_string(pubkey.as_str())?;

    // let msg = "This is a secret!";
    // let msg = Message::new_literal("./key_files/message.txt", msg);
    // println!("{:?}", &msg);

    // let mut rng = StdRng::from_entropy();
    // msg.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&server_pubkey.0])?;
    // let armored = msg.to_armored_string(None).unwrap();
    // _ = fs::write("em.txt", armored)?;
    // println!("{}", armored);

    // let _auth_req = requests::AuthRequest::from_auth_cmd(&auth);
    Ok(())
}

fn person1_encrypt_msg_for_person1(msg: &str) -> Result<String> {
    let pubkey = fs::read_to_string("./key_files/person_two/pub.asc")
        .context("Trying to load public key for Person Two from file")?;
    let (pubkey, _) = SignedPublicKey::from_string(pubkey.as_str())?;

    // Requires a file name as the first arg, in this case I pass "none", as it's not used typically, it's just meta data
    let msg = Message::new_literal("none", msg);
    // println!("{:?}", &msg);

    let armored = generate_armored_string(msg, pubkey)?;
    let message_file = "p1_armored_message.txt";
    _ = fs::write(&message_file, armored)?;

    Ok(message_file.to_string())
}

fn generate_armored_string(msg: Message, pk: SignedPublicKey) -> Result<String> {
    let mut rng = StdRng::from_entropy();
    msg.encrypt_to_keys(&mut rng, SymmetricKeyAlgorithm::AES128, &[&pk])?;
    Ok(msg.to_armored_string(None)?)
}

fn person2_decrypt_msg_from_person1(armored: &str) -> Result<String> {
    println!("Decrypting: {}", armored);
    let seckey = fs::read_to_string("./key_files/person_two/sec.asc")?;
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

// Print the working directory
fn ptwd() {
    let pwd = std::env::current_dir()
        .unwrap()
        .as_os_str()
        .to_str()
        .unwrap()
        .to_string();
    println!("Working dir: {}", pwd);
}
