//! Web Push message encryption (RFC 8291, with the `aes128gcm` content coding of RFC 8188), for `UnifiedPush`
//! endpoints: the push server only carries ciphertext, readable by the device that made the keys.

use ring::rand::{SecureRandom, SystemRandom};
use ring::{aead, agreement, hkdf};

/// The device's keys, as it registered them.
pub struct Keys<'a> {
    /// The device's P-256 public key (65 bytes, uncompressed).
    pub p256dh: &'a [u8],
    /// The device's authentication secret (16 bytes).
    pub auth: &'a [u8],
}

#[derive(Debug, thiserror::Error)]
#[error("encrypting a push: {0}")]
pub struct Error(&'static str);

/// A length for HKDF's output.
struct Len(usize);

impl hkdf::KeyType for Len {
    fn len(&self) -> usize {
        self.0
    }
}

fn expand(prk: &hkdf::Prk, info: &[&[u8]], out: &mut [u8]) -> Result<(), Error> {
    prk.expand(info, Len(out.len()))
        .and_then(|okm| okm.fill(out))
        .map_err(|_| Error("HKDF"))
}

/// The record size written in the header: one record holds the whole message.
const RECORD_SIZE: u32 = 4096;

/// Encrypts `plaintext` for the device: the body of the push request, sent with `Content-Encoding: aes128gcm`.
pub fn encrypt(keys: &Keys<'_>, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    if keys.p256dh.len() != 65 || keys.auth.len() != 16 {
        return Err(Error("the device's keys have the wrong size"));
    }
    // One record, with its padding delimiter and the tag, must fit.
    if plaintext.len() + 1 + 16 > RECORD_SIZE as usize {
        return Err(Error("the message is too large"));
    }
    let random = SystemRandom::new();
    let ephemeral = agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &random)
        .map_err(|_| Error("generating a key"))?;
    let public = ephemeral
        .compute_public_key()
        .map_err(|_| Error("the ephemeral public key"))?;
    let public = public.as_ref();
    let mut salt = [0_u8; 16];
    random.fill(&mut salt).map_err(|_| Error("random"))?;

    let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, keys.p256dh);
    let mut ikm = [0_u8; 32];
    agreement::agree_ephemeral(ephemeral, &peer, |secret| {
        // IKM = HKDF(auth, ecdh_secret, "WebPush: info" || 0 || ua_public || as_public, 32)
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, keys.auth).extract(secret);
        expand(&prk, &[b"WebPush: info\0", keys.p256dh, public], &mut ikm)
    })
    .map_err(|_| Error("the device's public key"))??;

    let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, &salt).extract(&ikm);
    let mut cek = [0_u8; 16];
    expand(&prk, &[b"Content-Encoding: aes128gcm\0"], &mut cek)?;
    let mut nonce = [0_u8; 12];
    expand(&prk, &[b"Content-Encoding: nonce\0"], &mut nonce)?;

    let key = aead::LessSafeKey::new(
        aead::UnboundKey::new(&aead::AES_128_GCM, &cek).map_err(|_| Error("the content key"))?,
    );
    // The last (and only) record's padding delimiter is 2.
    let mut record = Vec::with_capacity(plaintext.len() + 17);
    record.extend_from_slice(plaintext);
    record.push(2);
    key.seal_in_place_append_tag(
        aead::Nonce::assume_unique_for_key(nonce),
        aead::Aad::empty(),
        &mut record,
    )
    .map_err(|_| Error("sealing"))?;

    // salt (16) || record size (4) || key id length (1) || key id (the sender's public key) || records
    let mut body = Vec::with_capacity(21 + public.len() + record.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(u8::try_from(public.len()).map_err(|_| Error("key id"))?);
    body.extend_from_slice(public);
    body.extend_from_slice(&record);
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The device's side, as a receiver does it: derives the same key from its private key and opens the record.
    fn decrypt(
        private: agreement::EphemeralPrivateKey,
        p256dh: &[u8],
        auth: &[u8],
        body: &[u8],
    ) -> Vec<u8> {
        let salt = &body[..16];
        let id_len = body[20] as usize;
        let sender = &body[21..21 + id_len];
        let mut record = body[21 + id_len..].to_vec();
        let peer = agreement::UnparsedPublicKey::new(&agreement::ECDH_P256, sender);
        let mut ikm = [0_u8; 32];
        agreement::agree_ephemeral(private, &peer, |secret| {
            let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, auth).extract(secret);
            expand(&prk, &[b"WebPush: info\0", p256dh, sender], &mut ikm).unwrap();
        })
        .unwrap();
        let prk = hkdf::Salt::new(hkdf::HKDF_SHA256, salt).extract(&ikm);
        let mut cek = [0_u8; 16];
        expand(&prk, &[b"Content-Encoding: aes128gcm\0"], &mut cek).unwrap();
        let mut nonce = [0_u8; 12];
        expand(&prk, &[b"Content-Encoding: nonce\0"], &mut nonce).unwrap();
        let key = aead::LessSafeKey::new(aead::UnboundKey::new(&aead::AES_128_GCM, &cek).unwrap());
        let plain = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::empty(),
                &mut record,
            )
            .unwrap();
        assert_eq!(plain.last(), Some(&2), "the last record's delimiter");
        plain[..plain.len() - 1].to_vec()
    }

    #[test]
    fn the_device_reads_what_was_encrypted_for_it() {
        let random = SystemRandom::new();
        let private =
            agreement::EphemeralPrivateKey::generate(&agreement::ECDH_P256, &random).unwrap();
        let p256dh = private.compute_public_key().unwrap().as_ref().to_vec();
        let auth = [7_u8; 16];
        let body = encrypt(
            &Keys {
                p256dh: &p256dh,
                auth: &auth,
            },
            b"wake up",
        )
        .unwrap();
        assert_eq!(&body[16..20], &4096_u32.to_be_bytes());
        assert_eq!(decrypt(private, &p256dh, &auth, &body), b"wake up");
    }

    #[test]
    fn keys_of_the_wrong_size_are_refused() {
        assert!(
            encrypt(
                &Keys {
                    p256dh: &[4; 64],
                    auth: &[0; 16]
                },
                b"x"
            )
            .is_err()
        );
    }
}
