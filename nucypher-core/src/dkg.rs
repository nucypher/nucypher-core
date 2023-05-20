use alloc::boxed::Box;
use alloc::string::String;

use serde::{Deserialize, Serialize};
use umbral_pre::{decrypt_original, encrypt, serde_bytes, Capsule, PublicKey, SecretKey};

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
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
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
    pub fn encrypt(
        &self,
        request_encrypting_key: &PublicKey,
        response_encrypting_key: &PublicKey,
    ) -> EncryptedThresholdDecryptionRequest {
        EncryptedThresholdDecryptionRequest::new(
            self,
            request_encrypting_key,
            response_encrypting_key,
        )
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

/// A request for an Ursula to derive a decryption share that specifies the key to encrypt Ursula's response.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct E2EThresholdDecryptionRequest {
    /// The decryption request.
    pub decryption_request: ThresholdDecryptionRequest,
    /// The key to encrypt the corresponding decryption response.
    pub response_encrypting_key: PublicKey,
}

impl E2EThresholdDecryptionRequest {
    /// Create E2E decryption request.
    pub fn new(
        decryption_request: &ThresholdDecryptionRequest,
        response_encrypting_key: &PublicKey,
    ) -> Self {
        Self {
            decryption_request: decryption_request.clone(),
            response_encrypting_key: *response_encrypting_key,
        }
    }
}

impl<'a> ProtocolObjectInner<'a> for E2EThresholdDecryptionRequest {
    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn brand() -> [u8; 4] {
        *b"E2eR"
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

impl<'a> ProtocolObject<'a> for E2EThresholdDecryptionRequest {}

/// An encrypted request for an Ursula to derive a decryption share.
#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedThresholdDecryptionRequest {
    /// ID of the ritual
    pub ritual_id: u16,
    /// TODO Umbral for now - but change
    capsule: Capsule,
    #[serde(with = "serde_bytes::as_base64")]
    ciphertext: Box<[u8]>,
}

impl EncryptedThresholdDecryptionRequest {
    fn new(
        request: &ThresholdDecryptionRequest,
        request_encrypting_key: &PublicKey,
        response_encrypting_key: &PublicKey,
    ) -> Self {
        let e2e_decryption_request =
            E2EThresholdDecryptionRequest::new(request, response_encrypting_key);
        // TODO: using Umbral for encryption to avoid introducing more crypto primitives.
        let (capsule, ciphertext) =
            encrypt(request_encrypting_key, &e2e_decryption_request.to_bytes())
                .expect("encryption failed - out of memory?");
        let ritual_id = request.ritual_id;
        Self {
            ritual_id,
            capsule,
            ciphertext,
        }
    }

    /// Decrypts the decryption request
    pub fn decrypt(
        &self,
        sk: &SecretKey,
    ) -> Result<E2EThresholdDecryptionRequest, DecryptionError> {
        let decryption_request_bytes = decrypt_original(sk, &self.capsule, &self.ciphertext)
            .map_err(DecryptionError::DecryptionFailed)?;
        let decryption_request =
            E2EThresholdDecryptionRequest::from_bytes(&decryption_request_bytes)
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
            encrypt(encrypting_key, &threshold_decryption_response.to_bytes())
                .expect("encryption failed - out of memory?");
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

#[cfg(test)]
mod tests {
    use umbral_pre::encrypt;
    use umbral_pre::SecretKey;

    use crate::{
        Conditions, Context, EncryptedThresholdDecryptionRequest,
        EncryptedThresholdDecryptionResponse, FerveoVariant, ProtocolObject,
        ThresholdDecryptionRequest, ThresholdDecryptionResponse,
    };

    #[test]
    fn threshold_decryption_request() {
        let ritual_id = 0;

        let request_secret = SecretKey::random();
        let request_encrypting_key = request_secret.public_key();

        let response_secret = SecretKey::random();
        let response_encrypting_key = response_secret.public_key();

        let random_secret_key = SecretKey::random();

        let encryption_result = encrypt(&random_secret_key.public_key(), b"The Tyranny of Merit");

        let (_capsule, _ciphertext) = encryption_result.unwrap();

        let request = ThresholdDecryptionRequest::new(
            ritual_id,
            &_ciphertext,
            Some(&Conditions::new("abcd")),
            Some(&Context::new("efgh")),
            FerveoVariant::SIMPLE,
        );

        let encrypted_request = request.encrypt(&request_encrypting_key, &response_encrypting_key);

        let encrypted_request_bytes = encrypted_request.to_bytes();
        let encrypted_request_from_bytes =
            EncryptedThresholdDecryptionRequest::from_bytes(&encrypted_request_bytes).unwrap();

        assert_eq!(encrypted_request_from_bytes.ritual_id, ritual_id);

        let e2e_request = encrypted_request_from_bytes
            .decrypt(&request_secret)
            .unwrap();
        assert_eq!(response_encrypting_key, e2e_request.response_encrypting_key);
        assert_eq!(request, e2e_request.decryption_request);

        // wrong secret key used
        assert!(encrypted_request_from_bytes
            .decrypt(&response_secret)
            .is_err());

        assert!(encrypted_request_from_bytes
            .decrypt(&random_secret_key)
            .is_err());
    }

    #[test]
    fn threshold_decryption_response() {
        let response_secret = SecretKey::random();
        let response_encrypting_key = response_secret.public_key();

        let decryption_share = b"The Tyranny of Merit";

        let response = ThresholdDecryptionResponse::new(decryption_share);

        let encrypted_response = response.encrypt(&response_encrypting_key);

        let encrypted_response_bytes = encrypted_response.to_bytes();
        let encrypted_response_from_bytes =
            EncryptedThresholdDecryptionResponse::from_bytes(&encrypted_response_bytes).unwrap();

        let decrypted_response = encrypted_response_from_bytes
            .decrypt(&response_secret)
            .unwrap();
        assert_eq!(response, decrypted_response);
        assert_eq!(
            response.decryption_share,
            decrypted_response.decryption_share
        );

        // wrong secret key used
        let random_secret_key = SecretKey::random();
        assert!(encrypted_response_from_bytes
            .decrypt(&random_secret_key)
            .is_err());
    }
}
