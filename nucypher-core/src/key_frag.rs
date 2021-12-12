use alloc::boxed::Box;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    decrypt_original, encrypt, Capsule, DeserializableFromArray, EncryptionError, KeyFrag,
    PublicKey, SecretKey, SerializableToArray, Signature, Signer, VerifiedKeyFrag,
};

use crate::hrac::HRAC;
use crate::serde::{DeserializableFromBytes, ProtocolObject, SerializableToBytes};

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
        let kfrag = KeyFrag::from_array(&verified_kfrag.to_array()).unwrap();

        let signature =
            signer.sign(&[hrac.to_array().as_ref(), kfrag.to_array().as_ref()].concat());

        Self { signature, kfrag }
    }

    pub fn verify(
        &self,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> Option<VerifiedKeyFrag> {
        if !self.signature.verify(
            publisher_verifying_key,
            &[hrac.to_array().as_ref(), self.kfrag.to_array().as_ref()].concat(),
        ) {
            return None;
        }

        // Ursula has no side channel to get the KeyFrag author's key,
        // so verifying the keyfrag is useless.
        // TODO (rust-umbral#73): assuming here that VerifiedKeyFrag and KeyFrag have the same byte representation;
        // would it be more clear if `kfrag` had some method like `force_verify()`?
        VerifiedKeyFrag::from_verified_bytes(&self.kfrag.to_array()).ok()
    }
}

impl ProtocolObject for AuthorizedKeyFrag {}

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
    ) -> Option<VerifiedKeyFrag> {
        let auth_kfrag_bytes = decrypt_original(sk, &self.capsule, &self.ciphertext).ok()?;
        let auth_kfrag = AuthorizedKeyFrag::from_bytes(&auth_kfrag_bytes).ok()?;
        auth_kfrag.verify(hrac, publisher_verifying_key)
    }
}

impl ProtocolObject for EncryptedKeyFrag {}
