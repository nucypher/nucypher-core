use alloc::boxed::Box;
use alloc::string::String;

use ferveo::api::{CiphertextHeader, FerveoVariant};
use serde::{Deserialize, Serialize};
use umbral_pre::serde_bytes;

use crate::access_control::AccessControlPolicy;
use crate::conditions::Context;
use crate::session::key::{SessionSharedSecret, SessionStaticKey};
use crate::session::{decrypt_with_shared_secret, encrypt_with_shared_secret, DecryptionError};
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

/// A request for an Ursula to derive a decryption share.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdDecryptionRequest {
    /// The ID of the ritual.
    pub ritual_id: u32,
    /// The ciphertext to generate a decryption share for.
    pub ciphertext_header: CiphertextHeader,
    /// The associated access control metadata.
    pub acp: AccessControlPolicy,
    /// A blob of bytes containing context required to evaluate conditions.
    pub context: Option<Context>,
    /// The ferveo variant to use for the decryption share derivation.
    pub variant: FerveoVariant,
}

impl ThresholdDecryptionRequest {
    /// Creates a new decryption request.
    pub fn new(
        ritual_id: u32,
        ciphertext_header: &CiphertextHeader,
        acp: &AccessControlPolicy,
        context: Option<&Context>,
        variant: FerveoVariant,
    ) -> Self {
        Self {
            ritual_id,
            ciphertext_header: ciphertext_header.clone(),
            acp: acp.clone(),
            context: context.cloned(),
            variant,
        }
    }

    /// Encrypts the decryption request.
    pub fn encrypt(
        &self,
        shared_secret: &SessionSharedSecret,
        requester_public_key: &SessionStaticKey,
    ) -> EncryptedThresholdDecryptionRequest {
        EncryptedThresholdDecryptionRequest::new(self, shared_secret, requester_public_key)
    }
}

impl<'a> ProtocolObjectInner<'a> for ThresholdDecryptionRequest {
    fn version() -> (u16, u16) {
        (4, 0)
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
    /// ID of the ritual
    pub ritual_id: u32,

    /// Public key of requester
    pub requester_public_key: SessionStaticKey,

    #[serde(with = "serde_bytes::as_base64")]
    /// Encrypted request
    ciphertext: Box<[u8]>,
}

impl EncryptedThresholdDecryptionRequest {
    fn new(
        request: &ThresholdDecryptionRequest,
        shared_secret: &SessionSharedSecret,
        requester_public_key: &SessionStaticKey,
    ) -> Self {
        let ciphertext = encrypt_with_shared_secret(shared_secret, &request.to_bytes())
            .expect("encryption failed - out of memory?");
        Self {
            ritual_id: request.ritual_id,
            requester_public_key: *requester_public_key,
            ciphertext,
        }
    }

    /// Decrypts the decryption request
    pub fn decrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> Result<ThresholdDecryptionRequest, DecryptionError> {
        let decryption_request_bytes = decrypt_with_shared_secret(shared_secret, &self.ciphertext)?;
        let decryption_request = ThresholdDecryptionRequest::from_bytes(&decryption_request_bytes)
            .map_err(DecryptionError::DeserializationFailed)?;
        Ok(decryption_request)
    }
}

impl<'a> ProtocolObjectInner<'a> for EncryptedThresholdDecryptionRequest {
    fn version() -> (u16, u16) {
        (2, 0)
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
    /// The ID of the ritual.
    pub ritual_id: u32,

    /// The decryption share to include in the response.
    #[serde(with = "serde_bytes::as_base64")]
    pub decryption_share: Box<[u8]>,
}

impl ThresholdDecryptionResponse {
    /// Creates and a new decryption response.
    pub fn new(ritual_id: u32, decryption_share: &[u8]) -> Self {
        ThresholdDecryptionResponse {
            ritual_id,
            decryption_share: decryption_share.to_vec().into(),
        }
    }

    /// Encrypts the decryption response.
    pub fn encrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> EncryptedThresholdDecryptionResponse {
        EncryptedThresholdDecryptionResponse::new(self, shared_secret)
    }
}

impl<'a> ProtocolObjectInner<'a> for ThresholdDecryptionResponse {
    fn version() -> (u16, u16) {
        (2, 0)
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
    /// The ID of the ritual.
    pub ritual_id: u32,

    #[serde(with = "serde_bytes::as_base64")]
    ciphertext: Box<[u8]>,
}

impl EncryptedThresholdDecryptionResponse {
    fn new(response: &ThresholdDecryptionResponse, shared_secret: &SessionSharedSecret) -> Self {
        let ciphertext = encrypt_with_shared_secret(shared_secret, &response.to_bytes())
            .expect("encryption failed - out of memory?");
        Self {
            ritual_id: response.ritual_id,
            ciphertext,
        }
    }

    /// Decrypts the decryption request
    pub fn decrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> Result<ThresholdDecryptionResponse, DecryptionError> {
        let decryption_response_bytes =
            decrypt_with_shared_secret(shared_secret, &self.ciphertext)?;
        let decryption_response =
            ThresholdDecryptionResponse::from_bytes(&decryption_response_bytes)
                .map_err(DecryptionError::DeserializationFailed)?;
        Ok(decryption_response)
    }
}

impl<'a> ProtocolObjectInner<'a> for EncryptedThresholdDecryptionResponse {
    fn version() -> (u16, u16) {
        (2, 0)
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
    use crate::access_control::AccessControlPolicy;
    use crate::conditions::{Conditions, Context};
    use crate::session::key::SessionStaticSecret;
    use crate::test_utils::util::random_dkg_pubkey;
    use crate::versioning::ProtocolObject;
    use crate::{
        AuthenticatedData, EncryptedThresholdDecryptionRequest,
        EncryptedThresholdDecryptionResponse, ThresholdDecryptionRequest,
        ThresholdDecryptionResponse,
    };
    use ferveo::api::{encrypt as ferveo_encrypt, FerveoVariant, SecretBox};

    #[test]
    fn threshold_decryption_request() {
        for variant in [FerveoVariant::Simple, FerveoVariant::Precomputed] {
            let ritual_id = 0;

            let service_secret = SessionStaticSecret::random();

            let requester_secret = SessionStaticSecret::random();
            let requester_public_key = requester_secret.public_key();

            let dkg_pk = random_dkg_pubkey();
            let message = "The Tyranny of Merit".as_bytes().to_vec();
            let aad = "my-add".as_bytes();
            let ciphertext = ferveo_encrypt(SecretBox::new(message), aad, &dkg_pk).unwrap();

            let auth_data = AuthenticatedData::new(&dkg_pk, &Conditions::new("abcd"));

            let authorization = b"self_authorization";
            let acp = AccessControlPolicy::new(&auth_data, authorization);

            let ciphertext_header = ciphertext.header().unwrap();

            let request = ThresholdDecryptionRequest::new(
                ritual_id,
                &ciphertext_header,
                &acp,
                Some(&Context::new("efgh")),
                variant,
            );

            // requester encrypts request to send to service
            let service_public_key = service_secret.public_key();
            let requester_shared_secret =
                requester_secret.derive_shared_secret(&service_public_key);
            let encrypted_request =
                request.encrypt(&requester_shared_secret, &requester_public_key);

            // mimic serialization/deserialization over the wire
            let encrypted_request_bytes = encrypted_request.to_bytes();
            let encrypted_request_from_bytes =
                EncryptedThresholdDecryptionRequest::from_bytes(&encrypted_request_bytes).unwrap();

            assert_eq!(encrypted_request_from_bytes.ritual_id, ritual_id);
            assert_eq!(
                encrypted_request_from_bytes.requester_public_key,
                requester_public_key
            );

            // service decrypts request
            let service_shared_secret = service_secret
                .derive_shared_secret(&encrypted_request_from_bytes.requester_public_key);
            assert_eq!(
                service_shared_secret.as_bytes(),
                requester_shared_secret.as_bytes()
            );
            let decrypted_request = encrypted_request_from_bytes
                .decrypt(&service_shared_secret)
                .unwrap();
            assert_eq!(decrypted_request, request);

            // wrong shared key used
            let random_secret_key = SessionStaticSecret::random();
            let random_shared_secret =
                random_secret_key.derive_shared_secret(&requester_public_key);
            assert!(encrypted_request_from_bytes
                .decrypt(&random_shared_secret)
                .is_err());
        }
    }

    #[test]
    fn threshold_decryption_response() {
        let ritual_id = 5;

        let service_secret = SessionStaticSecret::random();
        let requester_secret = SessionStaticSecret::random();

        let decryption_share = b"The Tyranny of Merit";

        let response = ThresholdDecryptionResponse::new(ritual_id, decryption_share);

        // service encrypts response to send back
        let requester_public_key = requester_secret.public_key();

        let service_shared_secret = service_secret.derive_shared_secret(&requester_public_key);
        let encrypted_response = response.encrypt(&service_shared_secret);
        assert_eq!(encrypted_response.ritual_id, ritual_id);

        // mimic serialization/deserialization over the wire
        let encrypted_response_bytes = encrypted_response.to_bytes();
        let encrypted_response_from_bytes =
            EncryptedThresholdDecryptionResponse::from_bytes(&encrypted_response_bytes).unwrap();

        // requester decrypts response
        let service_public_key = service_secret.public_key();
        let requester_shared_secret = requester_secret.derive_shared_secret(&service_public_key);
        assert_eq!(
            requester_shared_secret.as_bytes(),
            service_shared_secret.as_bytes()
        );
        let decrypted_response = encrypted_response_from_bytes
            .decrypt(&requester_shared_secret)
            .unwrap();
        assert_eq!(response, decrypted_response);
        assert_eq!(response.ritual_id, ritual_id);
        assert_eq!(
            response.decryption_share,
            decrypted_response.decryption_share
        );

        // wrong shared key used
        let random_secret_key = SessionStaticSecret::random();
        let random_shared_secret = random_secret_key.derive_shared_secret(&requester_public_key);
        assert!(encrypted_response_from_bytes
            .decrypt(&random_shared_secret)
            .is_err());
    }
}
