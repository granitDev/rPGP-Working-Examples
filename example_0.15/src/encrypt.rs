//! Encrypts a message using a public key
use pgp::{
    composed::message::Message, composed::signed_key::*, crypto::sym::SymmetricKeyAlgorithm,
    ArmorOptions, Deserializable,
};
use rand::prelude::*;
use thiserror::Error as ThisError;

#[derive(Debug, ThisError)]
pub enum EncryptError {
    #[error("PGP error: {0}")]
    PgpError(#[from] pgp::errors::Error),
}

/// Encrypts a message using a public key
pub fn encrypt(msg: &str, public_key: &SignedPublicKey) -> Result<String, EncryptError> {
    let message = Message::new_literal("none", msg);
    let mut rng = StdRng::from_entropy();

    let encrypted =
        message.encrypt_to_keys_seipdv1(&mut rng, SymmetricKeyAlgorithm::AES128, &[public_key])?;
    Ok(encrypted.to_armored_string(ArmorOptions::default())?)
}

/// Encrypts a message using a public key passed as a string
pub fn encrypt_str(msg: &str, pubkey_str: &str) -> Result<String, EncryptError> {
    let (pubkey, _) = SignedPublicKey::from_string(pubkey_str)?;
    encrypt(msg, &pubkey)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decrypt;

    #[test]
    fn test_encrypt() {
        let plain_msg = "Testing testing this is a secret";
        let pub_key_armored = r"-----BEGIN PGP PUBLIC KEY BLOCK-----

xsBNBGO/IWQBCADTNp9PoOhiutuTDrs2dQy1/eXNhbneIigtmlgcdWeNdBwI6aLK
GGCK65Qh7l/pvvBlIG0fFJ9TTBRXllTN6tVXfUUDJUPzvHRzNObLdHHoRk2L/5BQ
XDkZmDYzsYQQpBP20QXJHUUyl/NT+PvRHB/HijAjb7AYRrEEBCZhstGytb82fcsN
H3DFFTKiIz55sE9agE6n0GJBGJRgleyvDIIePYg7S5lp04t1QwFKUX5fgCq3YG4c
vUWxpPaIl8Xh8ZgJZHUMxK1z9dYtOrUbW8faKVj0YnQdwTNERkloUsOFdiqpC5u3
xm8gkTWPVpBRZguYPajRL/o5EMw3UmXgK6l3ABEBAAHNIFNlcnZlciA8YWRtaW5A
Z2xvYnVzbWVkaWNhbC5jb20+wsCABBABCAAqAhkBBQJjvyFnAhsCAgsJARUBFhYh
BF0HE8hnOZjb2z0cunS+GYNzhFO7AAoJEHS+GYNzhFO7loAH/j/DEw4Xuque+JXR
D/GX51RP8mh5tSf3stZZXBVV5JTm0eFEi1XEig9CqKNXvgdN667pJDpmNYuqZ8eL
LmcK1Dv54N5gu7vjy4CBRPcrfhHQXaJXlo2VmrkZytMmXghVzhkVDYR6ppEvC0gF
xz2iP2xkW4RzSoT3EbiNxNiw6N91ww7SzIJy0+52i9eHNUL3mD1DqwOlsSWC8gcX
ZAh+Fi2vdvQTucjP8Bbu8rZn0aMcML0DCwFzq8c9eSy78E/Qr0Q2IiavO8doxNHY
V+MOqzaT9mQYuOKyCGLlB/cBUj9WV2VfJKcDZiVqc9A/wOZKCLaeOJUjmeVTVPGk
ZrJ4hMo=
=BSg2
-----END PGP PUBLIC KEY BLOCK-----";

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

        let encrypted = encrypt_str(plain_msg, pub_key_armored).unwrap();
        let decrypted = decrypt::decrypt_str(encrypted.as_str(), sec_key_armored).unwrap();
        assert_eq!(decrypted, plain_msg);
    }
}
