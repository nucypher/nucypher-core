use alloc::boxed::Box;
use alloc::string::String;
use core::fmt;
use generic_array::typenum::Unsigned;
use ferveo::api::Ciphertext;

use crate::conditions::{Conditions, Context};
use serde::{Deserialize, Serialize};
use umbral_pre::serde_bytes; // TODO should this be in umbral?
use x25519_dalek::{PublicKey, SharedSecret};

use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, DeserializationError, ProtocolObject,
    ProtocolObjectInner,
};

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};

/// Errors during encryption.
#[derive(Debug)]
pub enum EncryptionError {
    /// Given plaintext is too large for the backend to handle.
    PlaintextTooLarge,
}

impl fmt::Display for EncryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::PlaintextTooLarge => write!(f, "Plaintext is too large to encrypt"),
        }
    }
}

/// Errors during decryption.
#[derive(Debug)]
pub enum DecryptionError {
    /// Ciphertext (which should be prepended by the nonce) is shorter than the nonce length.
    CiphertextTooShort,
    /// The ciphertext and the attached authentication data are inconsistent.
    /// This can happen if:
    /// - an incorrect key is used,
    /// - the ciphertext is modified or cut short,
    /// - an incorrect authentication data is provided on decryption.
    AuthenticationFailed,
    /// Unable to create object from decrypted ciphertext
    DeserializationFailed(DeserializationError),
}

impl fmt::Display for DecryptionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CiphertextTooShort => write!(f, "The ciphertext must include the nonce"),
            Self::AuthenticationFailed => write!(
                f,
                "Decryption of ciphertext failed: \
                either someone tampered with the ciphertext or \
                you are using an incorrect decryption key."
            ),
            Self::DeserializationFailed(err) => write!(f, "deserialization failed: {}", err),
        }
    }
}

type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;

fn encrypt_with_shared_secret(
    shared_secret: &SharedSecret,
    plaintext: &[u8],
) -> Result<Box<[u8]>, EncryptionError> {
    let key = Key::from_slice(shared_secret.as_ref());
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut result = nonce.to_vec();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_err| EncryptionError::PlaintextTooLarge)?;
    result.extend(ciphertext);
    Ok(result.into_boxed_slice())
}

fn decrypt_with_shared_secret(
    shared_secret: &SharedSecret,
    ciphertext: &Box<[u8]>,
) -> Result<Box<[u8]>, DecryptionError> {
    let nonce_size = <NonceSize as Unsigned>::to_usize();
    let buf_size = ciphertext.as_ref().len();
    if buf_size < nonce_size {
        return Err(DecryptionError::CiphertextTooShort);
    }
    let nonce = Nonce::from_slice(&ciphertext.as_ref()[..nonce_size]);
    let encrypted_data = &ciphertext.as_ref()[nonce_size..];

    let key = Key::from_slice(shared_secret.as_ref());
    let cipher = ChaCha20Poly1305::new(&key);
    let plaintext = cipher
        .decrypt(&nonce, encrypted_data.as_ref())
        .map_err(|_err| DecryptionError::AuthenticationFailed)?;
    Ok(plaintext.into_boxed_slice())
}

/// The ferveo variant to use for the decryption share derivation.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Copy, Clone)]
pub enum FerveoVariant {
    /// The simple variant requires m of n shares to decrypt
    SIMPLE,
    /// The precomputed variant requires n of n shares to decrypt
    PRECOMPUTED,
}

/// A request for an Ursula to derive a decryption share.
#[derive(PartialEq, Eq, Debug, Clone, Serialize, Deserialize)]
pub struct ThresholdDecryptionRequest {
    /// The ID of the ritual.
    pub ritual_id: u16,
    /// The ciphertext to generate a decryption share for.
    pub ciphertext: Ciphertext,
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
        ciphertext: &Ciphertext,
        conditions: Option<&Conditions>,
        context: Option<&Context>,
        variant: FerveoVariant,
    ) -> Self {
        Self {
            ritual_id,
            ciphertext: ciphertext.clone(),
            conditions: conditions.cloned(),
            context: context.cloned(),
            variant,
        }
    }

    /// Encrypts the decryption request.
    pub fn encrypt(
        &self,
        shared_secret: &SharedSecret,
        requester_public_key: &PublicKey,
    ) -> EncryptedThresholdDecryptionRequest {
        EncryptedThresholdDecryptionRequest::new(self, shared_secret, requester_public_key)
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
    /// ID of the ritual
    pub ritual_id: u16,

    #[serde(with = "serde_bytes::as_base64")]
    /// Public key of requester
    /// TODO this should not be Box
    pub requester_public_key: Box<[u8]>,

    #[serde(with = "serde_bytes::as_base64")]
    /// Encrypted request
    ciphertext: Box<[u8]>,
}

impl EncryptedThresholdDecryptionRequest {
    fn new(
        request: &ThresholdDecryptionRequest,
        shared_secret: &SharedSecret,
        requester_public_key: &PublicKey,
    ) -> Self {
        let ciphertext = encrypt_with_shared_secret(shared_secret, &request.to_bytes())
            .expect("encryption failed - out of memory?");
        Self {
            ritual_id: request.ritual_id,
            requester_public_key: requester_public_key.to_bytes().to_vec().into_boxed_slice(),
            ciphertext,
        }
    }

    /// Decrypts the decryption request
    pub fn decrypt(
        &self,
        shared_secret: &SharedSecret,
    ) -> Result<ThresholdDecryptionRequest, DecryptionError> {
        let decryption_request_bytes = decrypt_with_shared_secret(shared_secret, &self.ciphertext)?;
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
    pub fn encrypt(&self, shared_secret: &SharedSecret) -> EncryptedThresholdDecryptionResponse {
        EncryptedThresholdDecryptionResponse::new(self, shared_secret)
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
    #[serde(with = "serde_bytes::as_base64")]
    ciphertext: Box<[u8]>,
}

impl EncryptedThresholdDecryptionResponse {
    fn new(response: &ThresholdDecryptionResponse, shared_secret: &SharedSecret) -> Self {
        // TODO: using Umbral for encryption to avoid introducing more crypto primitives.
        let ciphertext = encrypt_with_shared_secret(shared_secret, &response.to_bytes())
            .expect("encryption failed - out of memory?");
        Self { ciphertext }
    }

    /// Decrypts the decryption request
    pub fn decrypt(
        &self,
        shared_secret: &SharedSecret,
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
    use x25519_dalek::{EphemeralSecret, PublicKey};
    use ferveo::api::{encrypt as ferveo_encrypt, DkgPublicKey, SecretBox};

    use crate::{
        Conditions, Context, EncryptedThresholdDecryptionRequest,
        EncryptedThresholdDecryptionResponse, FerveoVariant, ProtocolObject,
        ThresholdDecryptionRequest, ThresholdDecryptionResponse,
    };

    use generic_array::typenum::Unsigned;

    use crate::dkg::{decrypt_with_shared_secret, DecryptionError, NonceSize};
    use rand_core::OsRng;

    #[test]
    fn decryption_with_shared_secret() {
        let service_secret = EphemeralSecret::random_from_rng(OsRng);

        let requester_secret = EphemeralSecret::random_from_rng(OsRng);
        let requester_public_key = PublicKey::from(&requester_secret);

        let service_shared_secret = service_secret.diffie_hellman(&requester_public_key);

        let ciphertext = b"1".to_vec().into_boxed_slice(); // length less than nonce size
        let nonce_size = <NonceSize as Unsigned>::to_usize();
        assert!(ciphertext.len() < nonce_size);

        assert!(matches!(
            decrypt_with_shared_secret(&service_shared_secret, &ciphertext).unwrap_err(),
            DecryptionError::CiphertextTooShort
        ));
    }

    #[test]
    fn threshold_decryption_request() {
        let ritual_id = 0;

        let service_secret = EphemeralSecret::random_from_rng(OsRng);
        let service_public_key = PublicKey::from(&service_secret);

        let requester_secret = EphemeralSecret::random_from_rng(OsRng);
        let requester_public_key = PublicKey::from(&requester_secret);

        let service_shared_secret = service_secret.diffie_hellman(&requester_public_key);
        let requester_shared_secret = requester_secret.diffie_hellman(&service_public_key);

        let dkg_pk = DkgPublicKey::random();
        let message = "The Tyranny of Merit".as_bytes().to_vec();
        let aad = "my-add".as_bytes();
        let ciphertext = ferveo_encrypt(SecretBox::new(message), aad, &dkg_pk).unwrap();

        let request = ThresholdDecryptionRequest::new(
            ritual_id,
            &ciphertext,
            Some(&Conditions::new("abcd")),
            Some(&Context::new("efgh")),
            FerveoVariant::SIMPLE,
        );

        // requester encrypts request to send to service
        let encrypted_request = request.encrypt(&requester_shared_secret, &requester_public_key);

        // mimic serialization/deserialization over the wire
        let encrypted_request_bytes = encrypted_request.to_bytes();
        let encrypted_request_from_bytes =
            EncryptedThresholdDecryptionRequest::from_bytes(&encrypted_request_bytes).unwrap();

        assert_eq!(encrypted_request_from_bytes.ritual_id, ritual_id);
        assert_eq!(
            encrypted_request_from_bytes.requester_public_key,
            requester_public_key.as_bytes().to_vec().into_boxed_slice()
        );

        // service decrypts request
        let decrypted_request = encrypted_request_from_bytes
            .decrypt(&service_shared_secret)
            .unwrap();
        assert_eq!(decrypted_request, request);

        // wrong shared key used
        let random_secret_key = EphemeralSecret::random_from_rng(OsRng);
        let random_shared_secret = random_secret_key.diffie_hellman(&requester_public_key);
        assert!(encrypted_request_from_bytes
            .decrypt(&random_shared_secret)
            .is_err());
    }

    #[test]
    fn threshold_decryption_response() {
        let service_secret = EphemeralSecret::random_from_rng(OsRng);
        let service_public_key = PublicKey::from(&service_secret);

        let requester_secret = EphemeralSecret::random_from_rng(OsRng);
        let requester_public_key = PublicKey::from(&requester_secret);

        let service_shared_secret = service_secret.diffie_hellman(&requester_public_key);
        let requester_shared_secret = requester_secret.diffie_hellman(&service_public_key);

        let decryption_share = b"The Tyranny of Merit";

        let response = ThresholdDecryptionResponse::new(decryption_share);

        // service encrypts response to send back
        let encrypted_response = response.encrypt(&service_shared_secret);

        // mimic serialization/deserialization over the wire
        let encrypted_response_bytes = encrypted_response.to_bytes();
        let encrypted_response_from_bytes =
            EncryptedThresholdDecryptionResponse::from_bytes(&encrypted_response_bytes).unwrap();

        // requester decrypts response
        let decrypted_response = encrypted_response_from_bytes
            .decrypt(&requester_shared_secret)
            .unwrap();
        assert_eq!(response, decrypted_response);
        assert_eq!(
            response.decryption_share,
            decrypted_response.decryption_share
        );

        // wrong shared key used
        let random_secret_key = EphemeralSecret::random_from_rng(OsRng);
        let random_shared_secret = random_secret_key.diffie_hellman(&requester_public_key);
        assert!(encrypted_response_from_bytes
            .decrypt(&random_shared_secret)
            .is_err());
    }
}
