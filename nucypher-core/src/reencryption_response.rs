use alloc::boxed::Box;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    Capsule, CapsuleFrag, PublicKey, SerializableToArray, Signature, Signer, VerifiedCapsuleFrag,
};

use crate::serde::ProtocolObject;

/// A response from Ursula with reencrypted capsule frags.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencryptionResponse {
    cfrags: Box<[CapsuleFrag]>,
    signature: Signature,
}

fn signed_message(capsules: &[Capsule], cfrags: &[CapsuleFrag]) -> Vec<u8> {
    let capsule_bytes = capsules.iter().fold(Vec::<u8>::new(), |mut acc, capsule| {
        acc.extend(capsule.to_array().as_ref());
        acc
    });

    let cfrag_bytes = cfrags.iter().fold(Vec::<u8>::new(), |mut acc, cfrag| {
        acc.extend(cfrag.to_array().as_ref());
        acc
    });

    [capsule_bytes, cfrag_bytes].concat()
}

impl ReencryptionResponse {
    /// Creates and signs a new reencryption response.
    pub fn new(signer: &Signer, capsules: &[Capsule], vcfrags: &[VerifiedCapsuleFrag]) -> Self {
        // un-verify
        let cfrags: Vec<_> = vcfrags
            .iter()
            .map(|vcfrag| vcfrag.to_unverified())
            .collect();

        let signature = signer.sign(&signed_message(capsules, &cfrags));

        ReencryptionResponse {
            cfrags: cfrags.into_boxed_slice(),
            signature,
        }
    }

    /// Verifies the reencryption response and returns the contained kfrags on success.
    pub fn verify(
        &self,
        capsules: &[Capsule],
        alice_verifying_key: &PublicKey,
        ursula_verifying_key: &PublicKey,
        policy_encrypting_key: &PublicKey,
        bob_encrypting_key: &PublicKey,
    ) -> Option<Box<[VerifiedCapsuleFrag]>> {
        if capsules.len() != self.cfrags.len() {
            // Mismatched number of capsules and cfrags
            return None;
        }

        // Validate re-encryption signature
        if !self.signature.verify(
            ursula_verifying_key,
            &signed_message(capsules, &self.cfrags),
        ) {
            return None;
        }

        let vcfrags = self
            .cfrags
            .iter()
            .zip(capsules.iter())
            .map(|(cfrag, capsule)| {
                cfrag.verify(
                    capsule,
                    alice_verifying_key,
                    policy_encrypting_key,
                    bob_encrypting_key,
                )
            })
            .collect::<Result<Vec<_>, _>>();

        vcfrags.ok().map(|vcfrags| vcfrags.into_boxed_slice())
    }
}

impl ProtocolObject for ReencryptionResponse {}
