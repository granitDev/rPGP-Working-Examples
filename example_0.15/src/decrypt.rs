//! Decrypts a message using a secret key
use pgp::{composed::message::Message, Deserializable, SignedSecretKey};
use std::io::Cursor;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum DecryptError {
    #[error("Failed to convert bytes to string: {0}")]
    Utf8Error(#[from] std::string::FromUtf8Error),
    #[error("No content in decrypted message")]
    NoContent,
    #[error("PGP error: {0}")]
    PgpError(#[from] pgp::errors::Error),
    #[error("Failed to read decrypted data: {0}")]
    ReadDecryptedDataError(String),
}

/// Decrypts a message using a secret key
pub fn decrypt(msg: Message, secret_key: &SignedSecretKey) -> Result<String, DecryptError> {
    let decrypted = msg.decrypt(|| String::new(), &[secret_key])?.0;
    let bytes = decrypted
        .get_content()?
        .ok_or_else(|| DecryptError::NoContent)?;
    Ok(String::from_utf8(bytes)?)
}

/// Decrypts a message using a secret key passed as a string
pub fn decrypt_str(armored_msg: &str, seckey_str: &str) -> Result<String, DecryptError> {
    let msg = Message::from_armor_single(Cursor::new(armored_msg))?.0;
    let (privkey, _) = SignedSecretKey::from_string(seckey_str)?;
    decrypt(msg, &privkey)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decrypt() {
        let plain_msg = "Testing testing this is a secret";
        let sec_key_armored = r"-----BEGIN PGP PRIVATE KEY BLOCK-----

xcLYBGO/IWQBCADTNp9PoOhiutuTDrs2dQy1/eXNhbneIigtmlgcdWeNdBwI6aLK
GGCK65Qh7l/pvvBlIG0fFJ9TTBRXllTN6tVXfUUDJUPzvHRzNObLdHHoRk2L/5BQ
XDkZmDYzsYQQpBP20QXJHUUyl/NT+PvRHB/HijAjb7AYRrEEBCZhstGytb82fcsN
H3DFFTKiIz55sE9agE6n0GJBGJRgleyvDIIePYg7S5lp04t1QwFKUX5fgCq3YG4c
vUWxpPaIl8Xh8ZgJZHUMxK1z9dYtOrUbW8faKVj0YnQdwTNERkloUsOFdiqpC5u3
xm8gkTWPVpBRZguYPajRL/o5EMw3UmXgK6l3ABEBAAEAB/4xwCMEcaVrZBJGcGje
qfGFiLmxkHc4gJkwLLPmeC0dH6Ve4BGNQvKypkztNSX4fBZJ67poYMYqq7f67Zkq
K8923TX9SLDZ36EaZfKbJ+GQ0caAXIFUvHRit/zEbmLqPIvLTm7rcW6UPUB+nh5K
ojJGISG3px42iag2hve3eZR1YHaKYbfxddcCzc6nF9sgUNxkfrkylBuvSWIUmXuX
yENJN7cwhKVxgeFioWsVzqe9gGS//1SK1ZQwgf5RmJXRvqizmV2GsxJw9SYnh8Yd
kwNc8wQg9rBQqQuPTvhCwoNqvWWgLVgooSSQPjDJA9GwUZ77WkKtb8KGDvV5MpI2
+OwBBADs5UeCcJp8I2DXIPh51KlJlhdfH1OLGaJoj7/Upo7gc8SPw4wQk/4FeTcP
UwmQPtLLCWHJ6db6w2ztsMhm5IumTBZdydtyuHzh7K8BsJHyhvuRJZdT2J8nE9w7
tWzXbj6d/W2skB68gwvwjZiOIYwbQB3330VOvbzms6omJaSDdwQA5D8htvSMYJAt
wgaOezW8TU18ypA+Yespqkx1CzntvCzNcLpIttGiEQMuS10w63SBOWX812fyw1vV
P9MAngS0INUZ7v7XocgqaaK87Ti4eKxgF/kRYsfjX/JZk52GlJ/8Bm8Jq/31hWK4
Lje2K2DM/6r4mnI3Wk7xMvkvGXHfigED/0oS2tPBgxd1ePzwHtVNbBsIEMytRB5Y
2B1WtifcAmjxBSl21SIBjyKF5VAc1KIXXNbMcDjOf9nSFOkiqEN4qdBdqvi5JiIW
zUuXPFkHDpWs6nHGuk0kJYQ9DAV0OWXZmjZVxgxWlKePl8LzISmKy/ip21sUHQ/f
LdM7iLFVessBQ+3NIFNlcnZlciA8YWRtaW5AZ2xvYnVzbWVkaWNhbC5jb20+wsCA
BBABCAAqAhkBBQJjvyFnAhsCAgsJARUBFhYhBF0HE8hnOZjb2z0cunS+GYNzhFO7
AAoJEHS+GYNzhFO7loAH/j/DEw4Xuque+JXRD/GX51RP8mh5tSf3stZZXBVV5JTm
0eFEi1XEig9CqKNXvgdN667pJDpmNYuqZ8eLLmcK1Dv54N5gu7vjy4CBRPcrfhHQ
XaJXlo2VmrkZytMmXghVzhkVDYR6ppEvC0gFxz2iP2xkW4RzSoT3EbiNxNiw6N91
ww7SzIJy0+52i9eHNUL3mD1DqwOlsSWC8gcXZAh+Fi2vdvQTucjP8Bbu8rZn0aMc
ML0DCwFzq8c9eSy78E/Qr0Q2IiavO8doxNHYV+MOqzaT9mQYuOKyCGLlB/cBUj9W
V2VfJKcDZiVqc9A/wOZKCLaeOJUjmeVTVPGkZrJ4hMo=
=0FMi
-----END PGP PRIVATE KEY BLOCK-----";

        let encrypted_msg = "-----BEGIN PGP MESSAGE-----
Version: BCPG v1.58

hQEMA3S+GYNzhFO7AQf/f8VS7AN4rwxrLsncynA8JrMzAyJRbCjRZja0jEd0bylb
GGH0Fpy0gPqqlR5FRS20M51o2CmaUv2oY3kJkabBca548fTzTv9VOwtnAYcYt+fy
dwxImBd9Ucy+z5Obct/YFIXIoY+DvHNq4QZBW9dC3sIBCUuYsX8ukDkoFS30J2Li
xo+v+UYXJg6ki+cfjEHQTSAIsuF9jfQlJmhs/UGMUQKf6nXfwMpc3p0KayIVv3je
h+nsAIycNgjQPvMQJ1AMskuZiuD6LBB687pUSdowtkmpdBY6xvzd6y/qO9C/IIbO
9j6ZsfA66Z/6Ol+sKVrlgfweJYKgWcsAKmCdM8AQqdJpAbpEFHHDpjO9T0mWmB63
nX4jlknFe/XztC6foMTCoCzcTPpYTgygBInP2hAor0qbeqjs8UbhjrJmkaId4jqB
84yOs2fLP0E8k5sAHb+izFbUQZ7ojl7YMxNVcoLDYK1RgHPfKZxcMSS8
=PI/n
-----END PGP MESSAGE-----";

        let decrypted_msg = decrypt_str(encrypted_msg, sec_key_armored).unwrap();
        assert_eq!(decrypted_msg, plain_msg);
    }
}
