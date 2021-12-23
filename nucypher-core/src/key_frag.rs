use alloc::boxed::Box;
use alloc::string::String;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    decrypt_original, encrypt, Capsule, DecryptionError, EncryptionError, KeyFrag, PublicKey,
    SecretKey, SerializableToArray, Signature, Signer, VerifiedKeyFrag,
};

use crate::hrac::HRAC;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, DeserializationError, ProtocolObject,
    ProtocolObjectInner,
};

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
struct AuthorizedKeyFrag {
    signature: Signature,
    kfrag: KeyFrag,
}

impl AuthorizedKeyFrag {
    fn new(signer: &Signer, hrac: &HRAC, verified_kfrag: &VerifiedKeyFrag) -> Self {
        // Alice makes plain to Ursula that, upon decrypting this message,
        // this particular KFrag is authorized for use in the policy identified by this HRAC.

        // TODO (rust-umbral#73): add VerifiedKeyFrag::unverify()?
        let kfrag = verified_kfrag.to_unverified();

        let signature = signer.sign(&[hrac.as_ref(), kfrag.to_array().as_ref()].concat());

        Self { signature, kfrag }
    }

    pub fn verify(
        &self,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> Option<VerifiedKeyFrag> {
        if !self.signature.verify(
            publisher_verifying_key,
            &[hrac.as_ref(), self.kfrag.to_array().as_ref()].concat(),
        ) {
            return None;
        }

        // Ursula has no side channel to get the KeyFrag author's key,
        // so verifying the keyfrag is useless.
        Some(self.kfrag.clone().skip_verification())
    }
}

impl<'a> ProtocolObjectInner<'a> for AuthorizedKeyFrag {
    fn brand() -> [u8; 4] {
        *b"AKFr"
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

impl<'a> ProtocolObject<'a> for AuthorizedKeyFrag {}

#[allow(clippy::enum_variant_names)]
pub enum KeyFragDecryptionError {
    DecryptionFailed(DecryptionError),
    DeserializationFailed(DeserializationError),
    VerificationFailed,
}

/// Encrypted and signed key frag.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyFrag {
    capsule: Capsule,
    ciphertext: Box<[u8]>,
}

impl EncryptedKeyFrag {
    /// Encrypts and signs a key frag.
    pub fn new(
        signer: &Signer,
        recipient_key: &PublicKey,
        hrac: &HRAC,
        verified_kfrag: &VerifiedKeyFrag,
    ) -> Result<Self, EncryptionError> {
        let auth_kfrag = AuthorizedKeyFrag::new(signer, hrac, verified_kfrag);
        // Using Umbral for asymmetric encryption here for simplicity,
        // even though we do not plan to re-encrypt the capsule.
        let (capsule, ciphertext) = encrypt(recipient_key, &auth_kfrag.to_bytes())?;
        Ok(Self {
            capsule,
            ciphertext,
        })
    }

    /// Decrypts and verifies a key frag.
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> Result<VerifiedKeyFrag, KeyFragDecryptionError> {
        let auth_kfrag_bytes = decrypt_original(sk, &self.capsule, &self.ciphertext)
            .map_err(KeyFragDecryptionError::DecryptionFailed)?;
        let auth_kfrag = AuthorizedKeyFrag::from_bytes(&auth_kfrag_bytes)
            .map_err(KeyFragDecryptionError::DeserializationFailed)?;
        auth_kfrag
            .verify(hrac, publisher_verifying_key)
            .ok_or(KeyFragDecryptionError::VerificationFailed)
    }
}

impl<'a> ProtocolObjectInner<'a> for EncryptedKeyFrag {
    fn brand() -> [u8; 4] {
        *b"EKFr"
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

impl<'a> ProtocolObject<'a> for EncryptedKeyFrag {}
