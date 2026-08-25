//! Key derivation and authenticated encryption.
//!
//! Argon2id turns a password (and an optional keyfile pepper) into a 32-byte
//! key. XChaCha20-Poly1305 seals the plaintext under that key with the file
//! header as associated data.
//!
//! Keyfile construction: the keyfile bytes are hashed with BLAKE2b-256 and the
//! 32-byte digest is passed to Argon2id as its optional secret (the "pepper" /
//! keyed-Argon2 input). The digest is never stored, so without the keyfile the
//! derived key differs and the AEAD tag check fails. An empty/absent keyfile
//! means plain Argon2id with no secret.

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::digest::consts::U32;
use blake2::{Blake2b, Digest};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::format::{KEY_LEN, KdfParams, NONCE_LEN};

/// Poly1305 tag length in bytes.
pub const TAG_LEN: usize = 16;

/// Fill a buffer from the operating system CSPRNG.
pub fn fill_random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|_| Error::Random)
}

/// Hash keyfile bytes into the 32-byte Argon2id secret.
pub fn keyfile_secret(keyfile: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hasher = Blake2b::<U32>::new();
    hasher.update(keyfile);
    let mut digest = hasher.finalize();
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&digest);
    // Wipe the pepper off the stack. Only the Zeroizing copy should survive.
    digest.as_mut_slice().zeroize();
    out
}

/// Derive the 32-byte key with Argon2id, honoring the supplied parameters.
pub fn derive_key(
    params: &KdfParams,
    salt: &[u8],
    password: &[u8],
    secret: Option<&[u8]>,
) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    params.validate()?;
    let p = Params::new(params.m_cost, params.t_cost, params.p_cost, Some(KEY_LEN))
        .map_err(|_| Error::InvalidParams)?;
    let argon = match secret {
        Some(secret) => Argon2::new_with_secret(secret, Algorithm::Argon2id, Version::V0x13, p)
            .map_err(|_| Error::Kdf)?,
        None => Argon2::new(Algorithm::Argon2id, Version::V0x13, p),
    };
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    argon
        .hash_password_into(password, salt, &mut key[..])
        .map_err(|_| Error::Kdf)?;
    Ok(key)
}

/// Encrypt `plaintext` under `key` with `aad` as associated data.
pub fn seal(key: &[u8; KEY_LEN], nonce: &[u8], aad: &[u8], plaintext: &[u8]) -> Result<Vec<u8>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::MalformedHeader);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    cipher
        .encrypt(
            xnonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Auth)
}

/// Decrypt and verify `ciphertext` under `key` with `aad` as associated data.
pub fn open(
    key: &[u8; KEY_LEN],
    nonce: &[u8],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Zeroizing<Vec<u8>>> {
    if nonce.len() != NONCE_LEN {
        return Err(Error::MalformedHeader);
    }
    let cipher = XChaCha20Poly1305::new(Key::from_slice(key));
    let xnonce = XNonce::from_slice(nonce);
    let plaintext = cipher
        .decrypt(
            xnonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::Auth)?;
    Ok(Zeroizing::new(plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Known-answer vector. Fixed params, salt, nonce, password, aad and
    // plaintext must always produce this exact ciphertext. A change here means
    // the algorithm, its parameters, or the wiring changed underneath us.
    const KAT_HEX: &str =
        "ae457fb8901ed0aeba9755be2f66d4cc8f809d975402bba2fb4ed10b8296b238b56114ba";

    struct Kat {
        params: KdfParams,
        salt: [u8; 16],
        nonce: [u8; NONCE_LEN],
        password: &'static [u8],
        aad: &'static [u8],
        plaintext: &'static [u8],
    }

    fn kat_inputs() -> Kat {
        Kat {
            params: KdfParams::new(32, 1, 1),
            salt: [0x42u8; 16],
            nonce: [0x24u8; NONCE_LEN],
            password: b"correct horse battery staple",
            aad: b"daemon-wallet-vault header",
            plaintext: b"deterministic vector",
        }
    }

    #[test]
    fn known_answer_vector() {
        let k = kat_inputs();
        let key = derive_key(&k.params, &k.salt, k.password, None).unwrap();
        let ct = seal(&key, &k.nonce, k.aad, k.plaintext).unwrap();
        assert_eq!(hex::encode(&ct), KAT_HEX);

        let round = open(&key, &k.nonce, k.aad, &ct).unwrap();
        assert_eq!(&round[..], k.plaintext);
    }

    #[test]
    fn keyfile_changes_the_key() {
        let k = kat_inputs();
        let plain = derive_key(&k.params, &k.salt, k.password, None).unwrap();
        let secret = keyfile_secret(b"a keyfile");
        let keyed = derive_key(&k.params, &k.salt, k.password, Some(&secret[..])).unwrap();
        assert_ne!(&plain[..], &keyed[..]);
    }

    #[test]
    fn wrong_aad_fails_to_open() {
        let k = kat_inputs();
        let key = derive_key(&k.params, &k.salt, k.password, None).unwrap();
        let ct = seal(&key, &k.nonce, k.aad, k.plaintext).unwrap();
        let bad = open(&key, &k.nonce, b"different aad", &ct);
        assert!(matches!(bad, Err(Error::Auth)));
    }
}
