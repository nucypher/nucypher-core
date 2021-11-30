use alloc::boxed::Box;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    decrypt_original, decrypt_reencrypted, encrypt, Capsule, DecryptionError, EncryptionError,
    PublicKey, ReencryptionError, SecretKey, VerifiedCapsuleFrag,
};

/// Encrypted message prepared for re-encryption.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct MessageKit {
    pub(crate) capsule: Capsule,
    ciphertext: Box<[u8]>,
}

impl MessageKit {
    /// Creates a new encrypted message for the given policy key.
    pub fn new(
        policy_encrypting_key: &PublicKey,
        plaintext: &[u8],
    ) -> Result<Self, EncryptionError> {
        let (capsule, ciphertext) = encrypt(policy_encrypting_key, plaintext)?;
        Ok(Self {
            capsule,
            ciphertext,
        })
    }

    /// Decrypts the message using the original (Alice's) key.
    pub fn decrypt(&self, sk: &SecretKey) -> Result<Box<[u8]>, DecryptionError> {
        decrypt_original(sk, &self.capsule, &self.ciphertext)
    }

    /// Decrypts the message using the Bob's key and re-encrypted capsule frags.
    pub fn decrypt_reencrypted(
        &self,
        sk: &SecretKey,
        policy_encrypting_key: &PublicKey,
        cfrags: &[VerifiedCapsuleFrag],
    ) -> Result<Box<[u8]>, ReencryptionError> {
        decrypt_reencrypted(
            sk,
            policy_encrypting_key,
            &self.capsule,
            cfrags,
            &self.ciphertext,
        )
    }
}
