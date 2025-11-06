use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use serde::{Deserialize, Serialize};
use serde_encoded_bytes::{Base64, SliceLike};
use umbral_pre::{
    decrypt_original, encrypt, Capsule, DecryptionError as UmbralDecryptionError, EncryptionError,
    KeyFrag, PublicKey, SecretKey, Signature, Signer, VerifiedKeyFrag,
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

fn signed_message(hrac: &HRAC, kfrag: &KeyFrag) -> Vec<u8> {
    [hrac.as_ref(), messagepack_serialize(kfrag).as_ref()].concat()
}

impl AuthorizedKeyFrag {
    fn new(signer: &Signer, hrac: &HRAC, verified_kfrag: VerifiedKeyFrag) -> Self {
        // Alice makes plain to Ursula that, upon decrypting this message,
        // this particular KFrag is authorized for use in the policy identified by this HRAC.

        // TODO (rust-umbral#73): add VerifiedKeyFrag::unverify()?
        let kfrag = verified_kfrag.unverify();

        let signature = signer.sign(&signed_message(hrac, &kfrag));

        Self { signature, kfrag }
    }

    fn verify(self, hrac: &HRAC, publisher_verifying_key: &PublicKey) -> Option<VerifiedKeyFrag> {
        if !self
            .signature
            .verify(publisher_verifying_key, &signed_message(hrac, &self.kfrag))
        {
            return None;
        }

        // Ursula has no side channel to get the KeyFrag author's key,
        // so verifying the keyfrag is useless.
        Some(self.kfrag.skip_verification())
    }
}

impl<'a> ProtocolObjectInner<'a> for AuthorizedKeyFrag {
    fn brand() -> [u8; 4] {
        *b"AKFr"
    }

    fn version() -> (u16, u16) {
        (3, 0)
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
#[derive(Debug)]
pub enum DecryptionError {
    DecryptionFailed(UmbralDecryptionError),
    DeserializationFailed(DeserializationError),
    VerificationFailed,
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DecryptionFailed(err) => write!(f, "decryption failed: {err}"),
            Self::DeserializationFailed(err) => write!(f, "deserialization failed: {err}"),
            Self::VerificationFailed => write!(f, "verification failed"),
        }
    }
}

/// Encrypted and signed key frag.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedKeyFrag {
    capsule: Capsule,
    #[serde(with = "SliceLike::<Base64>")]
    ciphertext: Box<[u8]>,
}

impl EncryptedKeyFrag {
    /// Encrypts and signs a key frag.
    pub fn new(
        signer: &Signer,
        recipient_key: &PublicKey,
        hrac: &HRAC,
        verified_kfrag: VerifiedKeyFrag,
    ) -> Self {
        let auth_kfrag = AuthorizedKeyFrag::new(signer, hrac, verified_kfrag);
        // Using Umbral for asymmetric encryption here for simplicity,
        // even though we do not plan to re-encrypt the capsule.
        let (capsule, ciphertext) = match encrypt(recipient_key, &auth_kfrag.to_bytes()) {
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

    /// Decrypts and verifies a key frag.
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> Result<VerifiedKeyFrag, DecryptionError> {
        let auth_kfrag_bytes = decrypt_original(sk, &self.capsule, &self.ciphertext)
            .map_err(DecryptionError::DecryptionFailed)?;
        let auth_kfrag = AuthorizedKeyFrag::from_bytes(&auth_kfrag_bytes)
            .map_err(DecryptionError::DeserializationFailed)?;
        auth_kfrag
            .verify(hrac, publisher_verifying_key)
            .ok_or(DecryptionError::VerificationFailed)
    }
}

impl<'a> ProtocolObjectInner<'a> for EncryptedKeyFrag {
    fn brand() -> [u8; 4] {
        *b"EKFr"
    }

    fn version() -> (u16, u16) {
        (3, 0)
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
