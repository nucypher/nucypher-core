use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};
use umbral_pre::{Capsule, CapsuleFrag, PublicKey, Signature, Signer, VerifiedCapsuleFrag};

use crate::conditions::{Conditions, Context};
use crate::hrac::HRAC;
use crate::key_frag::EncryptedKeyFrag;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};
use crate::VerificationError;

/// A request for an Ursula to reencrypt for several capsules.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct ReencryptionRequest {
    /// Capsules to re-encrypt.
    pub capsules: Box<[Capsule]>,
    /// Policy HRAC.
    pub hrac: HRAC,
    /// Key frag encrypted for the Ursula.
    pub encrypted_kfrag: EncryptedKeyFrag,
    /// Publisher's verifying key.
    pub publisher_verifying_key: PublicKey,
    /// Recipient's (Bob's) verifying key.
    pub bob_verifying_key: PublicKey,
    /// A blob of bytes containing decryption conditions for this message.
    pub conditions: Option<Conditions>,
    /// A blob of bytes containing context required to evaluate conditions.
    pub context: Option<Context>,
}

impl ReencryptionRequest {
    /// Creates a new reencryption request.
    pub fn new(
        capsules: &[Capsule],
        hrac: &HRAC,
        encrypted_kfrag: &EncryptedKeyFrag,
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        conditions: Option<&Conditions>,
        context: Option<&Context>,
    ) -> Self {
        Self {
            capsules: capsules.to_vec().into(),
            hrac: *hrac,
            encrypted_kfrag: encrypted_kfrag.clone(),
            publisher_verifying_key: *publisher_verifying_key,
            bob_verifying_key: *bob_verifying_key,
            conditions: conditions.cloned(),
            context: context.cloned(),
        }
    }
}

impl<'a> ProtocolObjectInner<'a> for ReencryptionRequest {
    fn brand() -> [u8; 4] {
        *b"ReRq"
    }

    fn version() -> (u16, u16) {
        (2, 0)
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

impl<'a> ProtocolObject<'a> for ReencryptionRequest {}

/// A response from Ursula with reencrypted capsule frags.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ReencryptionResponse {
    cfrags: Box<[CapsuleFrag]>,
    signature: Signature,
}

fn message_to_sign(capsules: &[Capsule], cfrags: &[CapsuleFrag]) -> Vec<u8> {
    let capsule_bytes = capsules.iter().fold(Vec::<u8>::new(), |mut acc, capsule| {
        acc.extend(messagepack_serialize(capsule).as_ref());
        acc
    });

    let cfrag_bytes = cfrags.iter().fold(Vec::<u8>::new(), |mut acc, cfrag| {
        acc.extend(messagepack_serialize(cfrag).as_ref());
        acc
    });

    [capsule_bytes, cfrag_bytes].concat()
}

impl ReencryptionResponse {
    /// Creates and signs a new reencryption response.
    pub fn new<'a>(
        signer: &Signer,
        capsules_and_vcfrags: impl IntoIterator<Item = (&'a Capsule, VerifiedCapsuleFrag)>,
    ) -> Self {
        let (capsules, vcfrags): (Vec<_>, Vec<_>) = capsules_and_vcfrags.into_iter().unzip();

        // un-verify
        let cfrags: Vec<_> = vcfrags
            .into_iter()
            .map(|vcfrag| vcfrag.unverify())
            .collect();

        let capsules: Vec<_> = capsules.into_iter().cloned().collect();

        let signature = signer.sign(&message_to_sign(&capsules, &cfrags));

        ReencryptionResponse {
            cfrags: cfrags.into_boxed_slice(),
            signature,
        }
    }

    /// Verifies the reencryption response and returns the contained kfrags on success.
    pub fn verify(
        self,
        capsules: &[Capsule],
        alice_verifying_key: &PublicKey,
        ursula_verifying_key: &PublicKey,
        policy_encrypting_key: &PublicKey,
        bob_encrypting_key: &PublicKey,
    ) -> Result<Box<[VerifiedCapsuleFrag]>, VerificationError> {
        if capsules.len() != self.cfrags.len() {
            // Mismatched number of capsules and cfrags
            return Err(VerificationError);
        }

        // Validate re-encryption signature
        if !self.signature.verify(
            ursula_verifying_key,
            &message_to_sign(capsules, &self.cfrags),
        ) {
            return Err(VerificationError);
        }

        let vcfrags = self
            .cfrags
            .into_vec()
            .into_iter()
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

        // From the above statement we get a list of (CapsuleFragVerificationError, CapsuleFrag)
        // in the error case, but at this point nobody's interested in that.
        vcfrags
            .map(|vcfrags| vcfrags.into_boxed_slice())
            .map_err(|_err| VerificationError)
    }
}

impl<'a> ProtocolObjectInner<'a> for ReencryptionResponse {
    fn brand() -> [u8; 4] {
        *b"ReRs"
    }

    fn version() -> (u16, u16) {
        (2, 0)
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

impl<'a> ProtocolObject<'a> for ReencryptionResponse {}

#[cfg(test)]
mod tests {
    use umbral_pre::SecretKey;
    use umbral_pre::{encrypt, generate_kfrags, Signer};

    use crate::{Conditions, Context, EncryptedKeyFrag, HRAC};

    use super::ReencryptionRequest;

    #[test]
    fn conditions_and_context_are_different() {
        let some_secret = SecretKey::random();
        let some_trinket = some_secret.public_key();

        let _another_secret = SecretKey::random();
        let another_trinket = some_secret.public_key();

        let encryption_result = encrypt(&some_trinket, b"peace at dawn");

        let (capsule, _ciphertext) = encryption_result.unwrap();

        let hrac = HRAC::new(&some_trinket, &another_trinket, &[42]);

        let signer = Signer::new(SecretKey::random());

        let verified_kfrags =
            generate_kfrags(&some_secret, &another_trinket, &signer, 5, 8, true, true);
        let verified_kfrags_vector = verified_kfrags.into_vec();
        let one_verified_krag_in_particular = verified_kfrags_vector[0].clone();
        let encrypted_kfrag = EncryptedKeyFrag::new(
            &signer,
            &another_trinket,
            &hrac,
            one_verified_krag_in_particular,
        );

        let request = ReencryptionRequest::new(
            &[capsule],
            &hrac,
            &encrypted_kfrag,
            &some_trinket,
            &another_trinket,
            Some(&Conditions::new("abcd")),
            Some(&Context::new("efgh")),
        );
        let conditions = request.conditions.unwrap();
        assert_eq!(conditions.as_ref(), "abcd");

        let context = request.context.unwrap();
        assert_eq!(context.as_ref(), "efgh");
    }
}
