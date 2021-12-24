use alloc::boxed::Box;
use alloc::string::String;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    decrypt_original, decrypt_reencrypted, encrypt, Capsule, DecryptionError, EncryptionError,
    PublicKey, ReencryptionError, SecretKey, VerifiedCapsuleFrag,
};

use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

/// Encrypted message prepared for re-encryption.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct MessageKit {
    /// Encapsulated symmetric key for this message.
    pub capsule: Capsule,
    #[serde(with = "serde_bytes")]
    ciphertext: Box<[u8]>,
}

impl MessageKit {
    /// Creates a new encrypted message for the given policy key.
    pub fn new(policy_encrypting_key: &PublicKey, plaintext: &[u8]) -> Self {
        let (capsule, ciphertext) = match encrypt(policy_encrypting_key, plaintext) {
            Ok(result) => result,
            Err(err) => match err {
                // For now this is the only error that can happen during encryption,
                // and there's really no point in propagating it.
                EncryptionError::PlaintextTooLarge => panic!("encryption failed - out of memory?"),
            },
        };
        Self {
            capsule,
            ciphertext,
        }
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

impl<'a> ProtocolObjectInner<'a> for MessageKit {
    fn brand() -> [u8; 4] {
        *b"MKit"
    }

    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn unversioned_to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(&self)
    }

    fn unversioned_from_bytes(minor_version: u16, bytes: &[u8]) -> Option<Result<Self, String>> {
        if minor_version == 0 {
            Some(messagepack_deserialize(bytes))
        } else {
            None
        }
    }
}

impl<'a> ProtocolObject<'a> for MessageKit {}
