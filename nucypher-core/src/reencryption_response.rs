use alloc::boxed::Box;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    Capsule, CapsuleFrag, DeserializableFromArray, SerializableToArray, Signature, Signer,
    VerifiedCapsuleFrag,
};

/// A response from Ursula with reencrypted capsule frags.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
struct ReencryptionResponse {
    cfrags: Box<[CapsuleFrag]>,
    signature: Signature,
}

impl ReencryptionResponse {
    pub fn new(capsules: &[Capsule], vcfrags: &[VerifiedCapsuleFrag], signer: &Signer) -> Self {
        let capsule_bytes = capsules.iter().fold(Vec::<u8>::new(), |mut acc, capsule| {
            acc.extend(capsule.to_array().as_ref());
            acc
        });

        // un-verify
        let cfrags: Vec<_> = vcfrags
            .iter()
            .map(|vcfrag| CapsuleFrag::from_array(&vcfrag.to_array()).unwrap())
            .collect();

        let cfrag_bytes = cfrags.iter().fold(Vec::<u8>::new(), |mut acc, cfrag| {
            acc.extend(cfrag.to_array().as_ref());
            acc
        });

        let signature = signer.sign(&[capsule_bytes, cfrag_bytes].concat());

        ReencryptionResponse {
            cfrags: cfrags.into_boxed_slice(),
            signature,
        }
    }
}
