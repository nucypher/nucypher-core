use alloc::boxed::Box;
use alloc::string::String;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    decrypt_original, encrypt, serde_bytes, Capsule, EncryptionError, PublicKey, SecretKey,
};

use crate::conditions::{Conditions, Context};
use crate::key_frag::DecryptionError;

use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

/// The ferveo variant to use for the decryption share derivation.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Copy, Clone)]
pub enum FerveoVariant {
    /// the simple variant requires n/n shares to decrypt
    SIMPLE,
    /// the precomputed variant requires m/n shares to decrypt
    PRECOMPUTED,
}

/// A request for an Ursula to derive a decryption share.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize)]
pub struct ThresholdDecryptionRequest {
    /// The ID of the ritual.
    pub ritual_id: u16,
    /// The ciphertext to generate a decryption share for.
    #[serde(with = "serde_bytes::as_base64")]
    pub ciphertext: Box<[u8]>,
    /// A blob of bytes containing decryption conditions for this message.
    pub conditions: Option<Conditions>,
    /// A blob of bytes containing context required to evaluate conditions.
    pub context: Option<Context>,
    /// The ferveo variant to use for the decryption share derivation.
    pub variant: FerveoVariant,
}

impl ThresholdDecryptionRequest {
    /// Creates a new decryption request.
    pub fn new(
        ritual_id: u16,
        ciphertext: &[u8],
        conditions: Option<&Conditions>,
        context: Option<&Context>,
        variant: FerveoVariant,
    ) -> Self {
        Self {
            ritual_id,
            ciphertext: ciphertext.to_vec().into(),
            conditions: conditions.cloned(),
            context: context.cloned(),
            variant,
        }
    }

    /// Encrypts the decryption request.
    pub fn encrypt(&self, encrypting_key: &PublicKey) -> EncryptedThresholdDecryptionRequest {
        EncryptedThresholdDecryptionRequest::new(encrypting_key, self)
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

/// An encrypted request for an Ursula to derive a decryption share.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedThresholdDecryptionRequest {
    /// TODO Umbral for now - but change
    capsule: Capsule,
    #[serde(with = "serde_bytes::as_base64")]
    ciphertext: Box<[u8]>,
}

impl EncryptedThresholdDecryptionRequest {
    fn new(
        encrypting_key: &PublicKey,
        threshold_decryption_request: &ThresholdDecryptionRequest,
    ) -> Self {
        // TODO: using Umbral for encryption to avoid introducing more crypto primitives.
        let (capsule, ciphertext) =
            match encrypt(encrypting_key, &threshold_decryption_request.to_bytes()) {
                Ok(result) => result,
                Err(err) => match err {
                    // For now this is the only error that can happen during encryption,
                    // and there's really no point in propagating it.
                    EncryptionError::PlaintextTooLarge => {
                        panic!("encryption failed - out of memory?")
                    }
                },
            };
        Self {
            capsule,
            ciphertext,
        }
    }

    /// Decrypts the decryption request
    pub fn decrypt(&self, sk: &SecretKey) -> Result<ThresholdDecryptionRequest, DecryptionError> {
        let decryption_request_bytes = decrypt_original(sk, &self.capsule, &self.ciphertext)
            .map_err(DecryptionError::DecryptionFailed)?;
        let decryption_request = ThresholdDecryptionRequest::from_bytes(&decryption_request_bytes)
            .map_err(DecryptionError::DeserializationFailed)?;
        Ok(decryption_request)
    }
}

impl<'a> ProtocolObjectInner<'a> for EncryptedThresholdDecryptionRequest {
    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn brand() -> [u8; 4] {
        *b"ETRq"
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

impl<'a> ProtocolObject<'a> for EncryptedThresholdDecryptionRequest {}

/// A response from Ursula with a derived decryption share.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct ThresholdDecryptionResponse {
    /// The decryption share to include in the response.
    #[serde(with = "serde_bytes::as_base64")]
    pub decryption_share: Box<[u8]>,
}

impl ThresholdDecryptionResponse {
    /// Creates and a new decryption response.
    pub fn new(decryption_share: &[u8]) -> Self {
        ThresholdDecryptionResponse {
            decryption_share: decryption_share.to_vec().into(),
        }
    }

    /// Encrypts the decryption response.
    pub fn encrypt(&self, encrypting_key: &PublicKey) -> EncryptedThresholdDecryptionResponse {
        EncryptedThresholdDecryptionResponse::new(encrypting_key, self)
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

/// An encrypted response from Ursula with a derived decryption share.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedThresholdDecryptionResponse {
    /// TODO Umbral for now - but change
    capsule: Capsule,
    #[serde(with = "serde_bytes::as_base64")]
    ciphertext: Box<[u8]>,
}

impl EncryptedThresholdDecryptionResponse {
    fn new(
        encrypting_key: &PublicKey,
        threshold_decryption_response: &ThresholdDecryptionResponse,
    ) -> Self {
        // TODO: using Umbral for encryption to avoid introducing more crypto primitives.
        let (capsule, ciphertext) =
            match encrypt(encrypting_key, &threshold_decryption_response.to_bytes()) {
                Ok(result) => result,
                Err(err) => match err {
                    // For now this is the only error that can happen during encryption,
                    // and there's really no point in propagating it.
                    EncryptionError::PlaintextTooLarge => {
                        panic!("encryption failed - out of memory?")
                    }
                },
            };
        Self {
            capsule,
            ciphertext,
        }
    }

    /// Decrypts the decryption request
    pub fn decrypt(&self, sk: &SecretKey) -> Result<ThresholdDecryptionResponse, DecryptionError> {
        let decryption_response_bytes = decrypt_original(sk, &self.capsule, &self.ciphertext)
            .map_err(DecryptionError::DecryptionFailed)?;
        let decryption_response =
            ThresholdDecryptionResponse::from_bytes(&decryption_response_bytes)
                .map_err(DecryptionError::DeserializationFailed)?;
        Ok(decryption_response)
    }
}

impl<'a> ProtocolObjectInner<'a> for EncryptedThresholdDecryptionResponse {
    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn brand() -> [u8; 4] {
        *b"ETRs"
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

impl<'a> ProtocolObject<'a> for EncryptedThresholdDecryptionResponse {}
