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
pub struct ThresholdDecryptionRequest {
    /// The ID of the ritual.
    pub ritual_id: u16,
    /// The ciphertext to generate a decryption share for.
    pub ciphertext: Box<[u8]>,
    /// A blob of bytes containing decryption conditions for this message.
    pub conditions: Option<Conditions>,
    /// A blob of bytes containing context required to evaluate conditions.
    pub context: Option<Context>,

}

impl ThresholdDecryptionRequest {
    /// Creates a new reencryption request.
    pub fn new(
        ritual_id: u16,
        ciphertext: &[u8],
        conditions: Option<&Conditions>,
        context: Option<&Context>,
    ) -> Self {
        Self {
            ritual_id,
            ciphertext: ciphertext.to_vec().into(),
            conditions: conditions.cloned(),
            context: context.cloned(),
        }
    }
}

impl<'a> ProtocolObjectInner<'a> for ThresholdDecryptionRequest {
    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn brand() -> [u8; 4] {
        *b"ThRq"
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

impl<'a> ProtocolObject<'a> for ThresholdDecryptionRequest {}

/// A response from Ursula with reencrypted capsule frags.
#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct ThresholdDecryptionResponse {
    pub decryption_share: Box<[u8]>,
}

impl ThresholdDecryptionResponse {
    /// Creates and signs a new reencryption response.
    pub fn new<'a>(
        decryption_share: Box<[u8]>,
    ) -> Self {
        ThresholdDecryptionResponse {
            decryption_share: decryption_share,
        }
    }
}


impl<'a> ProtocolObjectInner<'a> for ThresholdDecryptionResponse {
    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn brand() -> [u8; 4] {
        *b"ThRs"
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

impl<'a> ProtocolObject<'a> for ThresholdDecryptionResponse {}
