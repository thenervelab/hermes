use std::path::Path;

use crypto_box::{
    aead::{Aead, AeadCore, OsRng},
    SalsaBox, SecretKey,
};
use x25519_dalek::PublicKey;
use zeroize::Zeroize;

use crate::error::{HermesError, Result};

/// Helper struct wrapping an X25519 Public Key retrieved from the AccountProfile pallet.
#[derive(Clone, Debug, PartialEq)]
pub struct EncryptionPubKey(pub Vec<u8>);

impl EncryptionPubKey {
    pub fn as_x25519(&self) -> Result<PublicKey> {
        if self.0.len() != 32 {
            return Err(HermesError::Encryption(format!(
                "Invalid public key length: expected 32, got {}",
                self.0.len()
            )));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&self.0);
        Ok(PublicKey::from(arr))
    }
}

/// Parses an on-chain encryption key from AccountProfile into a
/// `crypto_box::PublicKey` suitable for NaCl SealedBox operations.
///
/// Accepts either raw 32-byte keys or hex-encoded keys (with optional "0x" prefix).
pub fn parse_onchain_encryption_key(raw: &[u8]) -> Result<crypto_box::PublicKey> {
    // If exactly 32 bytes and not valid UTF-8, treat as raw key bytes
    if raw.len() == 32 && std::str::from_utf8(raw).is_err() {
        let mut arr = [0u8; 32];
        arr.copy_from_slice(raw);
        return Ok(crypto_box::PublicKey::from(arr));
    }

    // Otherwise, try hex-encoded (with optional "0x" prefix)
    if let Ok(hex_str) = std::str::from_utf8(raw) {
        let hex_str = hex_str.strip_prefix("0x").unwrap_or(hex_str);

        let decoded = hex::decode(hex_str).map_err(|e| {
            HermesError::Encryption(format!("Failed to hex-decode encryption key: {}", e))
        })?;

        if decoded.len() != 32 {
            return Err(HermesError::Encryption(format!(
                "Encryption key must be 32 bytes after hex decode, got {}",
                decoded.len()
            )));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&decoded);
        return Ok(crypto_box::PublicKey::from(arr));
    }

    Err(HermesError::Encryption(format!(
        "Encryption key must be 32 raw bytes or hex-encoded, got {} bytes",
        raw.len()
    )))
}

/// Loads a 32-byte X25519 secret key from a file on disk.
pub fn load_encryption_secret_key(path: &Path) -> Result<SecretKey> {
    let mut bytes = std::fs::read(path).map_err(|e| {
        HermesError::Config(format!(
            "Failed to read encryption key from {:?}: {}",
            path, e
        ))
    })?;

    if bytes.len() != 32 {
        bytes.zeroize();
        return Err(HermesError::Config(format!(
            "Encryption key at {:?} must be exactly 32 bytes, got {}",
            path,
            bytes.len()
        )));
    }

    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    bytes.zeroize();

    let sk = SecretKey::from(arr);
    arr.zeroize();
    Ok(sk)
}

/// Encrypts plaintext using NaCl SealedBox (ephemeral X25519 DH + XSalsa20-Poly1305).
///
/// The ciphertext includes a 32-byte ephemeral public key + 16-byte Poly1305 MAC + encrypted data.
/// Only the holder of `recipient_pub`'s corresponding secret key can decrypt.
pub fn seal(plaintext: &[u8], recipient_pub: &crypto_box::PublicKey) -> Result<Vec<u8>> {
    let ephemeral_secret = SecretKey::generate(&mut OsRng);
    let ephemeral_public = ephemeral_secret.public_key();

    let salsa_box = SalsaBox::new(recipient_pub, &ephemeral_secret);
    let nonce = <SalsaBox as AeadCore>::generate_nonce(&mut OsRng);

    let ciphertext = salsa_box
        .encrypt(&nonce, plaintext)
        .map_err(|e| HermesError::Encryption(format!("SealedBox encrypt failed: {}", e)))?;

    // Wire format: [32-byte ephemeral pubkey] [24-byte nonce] [ciphertext]
    let mut sealed = Vec::with_capacity(32 + 24 + ciphertext.len());
    sealed.extend_from_slice(ephemeral_public.as_bytes());
    sealed.extend_from_slice(&nonce);
    sealed.extend_from_slice(&ciphertext);
    Ok(sealed)
}

/// Decrypts a SealedBox ciphertext using the recipient's keypair.
///
/// Expects wire format: \[32-byte ephemeral pubkey\] \[24-byte nonce\] \[ciphertext\]
pub fn open(
    sealed: &[u8],
    _recipient_pub: &crypto_box::PublicKey,
    recipient_secret: &SecretKey,
) -> Result<Vec<u8>> {
    if sealed.len() < 32 + 24 {
        return Err(HermesError::Encryption(
            "Sealed box too short (need at least 56 bytes for ephemeral key + nonce)".into(),
        ));
    }

    let mut ephemeral_bytes = [0u8; 32];
    ephemeral_bytes.copy_from_slice(&sealed[..32]);
    let ephemeral_pub = crypto_box::PublicKey::from(ephemeral_bytes);

    let nonce = crypto_box::Nonce::from_slice(&sealed[32..56]);

    let salsa_box = SalsaBox::new(&ephemeral_pub, recipient_secret);

    let plaintext = salsa_box
        .decrypt(nonce, &sealed[56..])
        .map_err(|e| HermesError::Encryption(format!("SealedBox decrypt failed: {}", e)))?;

    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_seal_and_open_roundtrip() {
        let recipient_sk = SecretKey::generate(&mut OsRng);
        let recipient_pk = recipient_sk.public_key();

        let plaintext = b"Hello, E2E encrypted world!";
        let sealed = seal(plaintext, &recipient_pk).unwrap();

        // Sealed should be larger than plaintext
        assert!(sealed.len() > plaintext.len());

        let decrypted = open(&sealed, &recipient_pk, &recipient_sk).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let recipient_sk = SecretKey::generate(&mut OsRng);
        let recipient_pk = recipient_sk.public_key();

        let wrong_sk = SecretKey::generate(&mut OsRng);
        let wrong_pk = wrong_sk.public_key();

        let plaintext = b"Secret message";
        let sealed = seal(plaintext, &recipient_pk).unwrap();

        let result = open(&sealed, &wrong_pk, &wrong_sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_sealed_too_short() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();

        let result = open(&[0u8; 10], &pk, &sk);
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_onchain_encryption_key_hex() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let hex_str = hex::encode(pk.as_bytes());

        let parsed = parse_onchain_encryption_key(hex_str.as_bytes()).unwrap();
        assert_eq!(parsed.as_bytes(), pk.as_bytes());
    }

    #[test]
    fn test_parse_onchain_encryption_key_with_0x_prefix() {
        let sk = SecretKey::generate(&mut OsRng);
        let pk = sk.public_key();
        let hex_str = format!("0x{}", hex::encode(pk.as_bytes()));

        let parsed = parse_onchain_encryption_key(hex_str.as_bytes()).unwrap();
        assert_eq!(parsed.as_bytes(), pk.as_bytes());
    }

    #[test]
    fn test_parse_onchain_encryption_key_invalid_length() {
        let result = parse_onchain_encryption_key(b"aabbccdd");
        assert!(result.is_err());
    }

    #[test]
    fn test_load_encryption_secret_key() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("test.key");

        let sk = SecretKey::generate(&mut OsRng);
        std::fs::write(&key_path, sk.to_bytes()).unwrap();

        let loaded = load_encryption_secret_key(&key_path).unwrap();
        assert_eq!(loaded.to_bytes(), sk.to_bytes());
    }

    #[test]
    fn test_load_encryption_secret_key_wrong_size() {
        let dir = tempfile::tempdir().unwrap();
        let key_path = dir.path().join("bad.key");
        std::fs::write(&key_path, &[0u8; 16]).unwrap();

        let result = load_encryption_secret_key(&key_path);
        assert!(result.is_err());
    }

    /// Full E2E test: build a HermesMessage, seal it, wrap in outer envelope,
    /// then decrypt and deserialize — exactly what send_message_encrypted +
    /// spawn_listener do in production.
    #[test]
    fn test_hermes_message_encrypt_decrypt_roundtrip() {
        use crate::network::message::HermesMessage;

        // Simulate recipient keygen (done once at registration)
        let recipient_sk = SecretKey::generate(&mut OsRng);
        let recipient_pk = recipient_sk.public_key();

        // --- Sender side (send_message_encrypted) ---
        let inner_msg = HermesMessage {
            action: "secret_ping".to_string(),
            sender_ss58: "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY".to_string(),
            payload: b"Hello E2E".to_vec(),
        };
        let plaintext = serde_json::to_vec(&inner_msg).unwrap();
        let ciphertext = seal(&plaintext, &recipient_pk).unwrap();

        let outer_msg = HermesMessage {
            action: "encrypted_message".to_string(),
            sender_ss58: inner_msg.sender_ss58.clone(),
            payload: ciphertext,
        };

        // Simulate wire serialization
        let wire_bytes = serde_json::to_vec(&outer_msg).unwrap();

        // --- Receiver side (spawn_listener) ---
        let received: HermesMessage = serde_json::from_slice(&wire_bytes).unwrap();
        assert_eq!(received.action, "encrypted_message");

        let decrypted_bytes = open(&received.payload, &recipient_pk, &recipient_sk).unwrap();
        let decrypted_msg: HermesMessage = serde_json::from_slice(&decrypted_bytes).unwrap();

        assert_eq!(decrypted_msg.action, "secret_ping");
        assert_eq!(
            decrypted_msg.sender_ss58,
            "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY"
        );
        assert_eq!(decrypted_msg.payload, b"Hello E2E");
    }

    /// Verify that tampered ciphertext is rejected.
    #[test]
    fn test_hermes_message_tampered_ciphertext_fails() {
        use crate::network::message::HermesMessage;

        let recipient_sk = SecretKey::generate(&mut OsRng);
        let recipient_pk = recipient_sk.public_key();

        let inner_msg = HermesMessage {
            action: "secret".to_string(),
            sender_ss58: "5Alice".to_string(),
            payload: b"important data".to_vec(),
        };
        let plaintext = serde_json::to_vec(&inner_msg).unwrap();
        let mut ciphertext = seal(&plaintext, &recipient_pk).unwrap();

        // Flip a byte in the ciphertext portion (after the 56-byte header)
        if ciphertext.len() > 60 {
            ciphertext[60] ^= 0xff;
        }

        let result = open(&ciphertext, &recipient_pk, &recipient_sk);
        assert!(
            result.is_err(),
            "Tampered ciphertext should fail decryption"
        );
    }
}
