use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ferveo::api::{CiphertextHeader, FerveoVariant};
use generic_array::typenum::Unsigned;
use rand_core::{CryptoRng, RngCore};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json;
use umbral_pre::serde_bytes; // TODO should this be in umbral?

use crate::access_control::AccessControlPolicy;
use crate::conditions::Context;
use crate::dkg::session::{SessionSecretFactory, SessionSharedSecret, SessionStaticKey};
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, DeserializationError, ProtocolObject,
    ProtocolObjectInner,
};

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

/// Encrypts data using a shared secret with the default OS RNG.
#[cfg(not(all(test, feature = "deterministic_encryption")))]
fn encrypt_with_shared_secret(
    shared_secret: &SessionSharedSecret,
    plaintext: &[u8],
) -> Result<Box<[u8]>, EncryptionError> {
    use chacha20poly1305::aead::OsRng;
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    encrypt_with_shared_secret_and_nonce(shared_secret, &nonce, plaintext)
}

#[cfg(all(test, feature = "deterministic_encryption"))]
fn encrypt_with_shared_secret(
    shared_secret: &SessionSharedSecret,
    plaintext: &[u8],
) -> Result<Box<[u8]>, EncryptionError> {
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    let rng = <StdRng as SeedableRng>::from_seed([0u8; 32]); // TODO: Note that this seed is currently fixed for all tests
    let nonce = ChaCha20Poly1305::generate_nonce(rng);
    encrypt_with_shared_secret_and_nonce(shared_secret, &nonce, plaintext)
}

/// Encrypts data using a shared secret with a custom nonce.
fn encrypt_with_shared_secret_and_nonce(
    shared_secret: &SessionSharedSecret,
    nonce: &Nonce,
    plaintext: &[u8],
) -> Result<Box<[u8]>, EncryptionError> {
    let key = Key::from_slice(shared_secret.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    let mut result = nonce.to_vec();
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .map_err(|_err| EncryptionError::PlaintextTooLarge)?;
    result.extend(ciphertext);
    Ok(result.into_boxed_slice())
}

fn decrypt_with_shared_secret(
    shared_secret: &SessionSharedSecret,
    ciphertext: &[u8],
) -> Result<Box<[u8]>, DecryptionError> {
    let nonce_size = <NonceSize as Unsigned>::to_usize();
    let buf_size = ciphertext.len();
    if buf_size < nonce_size {
        return Err(DecryptionError::CiphertextTooShort);
    }
    let nonce = Nonce::from_slice(&ciphertext[..nonce_size]);
    let encrypted_data = &ciphertext[nonce_size..];

    let key = Key::from_slice(shared_secret.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    let plaintext = cipher
        .decrypt(nonce, encrypted_data)
        .map_err(|_err| DecryptionError::AuthenticationFailed)?;
    Ok(plaintext.into_boxed_slice())
}

/// Module for session key objects.
pub mod session {
    use alloc::boxed::Box;
    use alloc::string::String;
    use core::fmt;

    use generic_array::{
        typenum::{Unsigned, U32},
        GenericArray,
    };
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{CryptoRng, OsRng, RngCore};
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use umbral_pre::serde_bytes;
    use x25519_dalek::{PublicKey, SharedSecret, StaticSecret};
    use zeroize::ZeroizeOnDrop;

    use crate::secret_box::{kdf, SecretBox};
    use crate::versioning::{
        messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
    };

    /// A Diffie-Hellman shared secret
    #[derive(ZeroizeOnDrop)]
    pub struct SessionSharedSecret {
        derived_bytes: [u8; 32],
    }

    /// Implementation of Diffie-Hellman shared secret
    impl SessionSharedSecret {
        /// Create new shared secret from underlying library.
        pub fn new(shared_secret: SharedSecret) -> Self {
            let info = b"SESSION_SHARED_SECRET_DERIVATION/";
            let derived_key = kdf::<U32>(shared_secret.as_bytes(), Some(info));
            let derived_bytes = <[u8; 32]>::try_from(derived_key.as_secret().as_slice()).unwrap();
            Self { derived_bytes }
        }

        /// View this shared secret as a byte array.
        pub fn as_bytes(&self) -> &[u8; 32] {
            &self.derived_bytes
        }
    }

    impl AsRef<[u8]> for SessionSharedSecret {
        /// View this shared secret as a byte array.
        fn as_ref(&self) -> &[u8] {
            self.as_bytes()
        }
    }

    impl fmt::Display for SessionSharedSecret {
        /// Format shared secret information.
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "SessionSharedSecret...")
        }
    }

    /// A session public key.
    #[derive(PartialEq, Eq, Hash, Copy, Clone, Debug)]
    pub struct SessionStaticKey(PublicKey);

    /// Implementation of session static key
    impl SessionStaticKey {
        /// Convert this public key to a byte array.
        pub fn to_bytes(&self) -> [u8; 32] {
            self.0.to_bytes()
        }
    }

    impl AsRef<[u8]> for SessionStaticKey {
        /// View this public key as a byte array.
        fn as_ref(&self) -> &[u8] {
            self.0.as_bytes()
        }
    }

    impl fmt::Display for SessionStaticKey {
        /// Format public key information.
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "SessionStaticKey: {}", hex::encode(&self.as_ref()[..8]))
        }
    }

    impl Serialize for SessionStaticKey {
        fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: Serializer,
        {
            serde_bytes::as_hex::serialize(self.0.as_bytes(), serializer)
        }
    }

    impl serde_bytes::TryFromBytes for SessionStaticKey {
        type Error = core::array::TryFromSliceError;
        fn try_from_bytes(bytes: &[u8]) -> Result<Self, Self::Error> {
            let array: [u8; 32] = bytes.try_into()?;
            Ok(SessionStaticKey(PublicKey::from(array)))
        }
    }

    impl<'a> Deserialize<'a> for SessionStaticKey {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: Deserializer<'a>,
        {
            serde_bytes::as_hex::deserialize(deserializer)
        }
    }

    impl ProtocolObjectInner<'_> for SessionStaticKey {
        fn version() -> (u16, u16) {
            (2, 0)
        }

        fn brand() -> [u8; 4] {
            *b"TSSk"
        }

        fn unversioned_to_bytes(&self) -> Box<[u8]> {
            messagepack_serialize(&self)
        }

        fn unversioned_from_bytes(
            minor_version: u16,
            bytes: &[u8],
        ) -> Option<Result<Self, String>> {
            if minor_version == 0 {
                Some(messagepack_deserialize(bytes))
            } else {
                None
            }
        }
    }

    impl ProtocolObject<'_> for SessionStaticKey {}

    /// A session secret key.
    #[derive(ZeroizeOnDrop)]
    pub struct SessionStaticSecret(pub(crate) StaticSecret);

    impl SessionStaticSecret {
        /// Perform diffie-hellman
        pub fn derive_shared_secret(
            &self,
            their_public_key: &SessionStaticKey,
        ) -> SessionSharedSecret {
            let shared_secret = self.0.diffie_hellman(&their_public_key.0);
            SessionSharedSecret::new(shared_secret)
        }

        /// Create secret key from RNG.
        pub fn random_from_rng(csprng: &mut (impl RngCore + CryptoRng)) -> Self {
            let secret_key = StaticSecret::random_from_rng(csprng);
            Self(secret_key)
        }

        /// Create random secret key.
        pub fn random() -> Self {
            Self::random_from_rng(&mut OsRng)
        }

        /// Returns a public key corresponding to this secret key.
        pub fn public_key(&self) -> SessionStaticKey {
            let public_key = PublicKey::from(&self.0);
            SessionStaticKey(public_key)
        }
    }

    impl fmt::Display for SessionStaticSecret {
        /// Format information above secret key.
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "SessionStaticSecret:...")
        }
    }

    // the size of the seed material for key derivation
    type SessionSecretFactorySeedSize = U32;
    // the size of the derived key
    type SessionSecretFactoryDerivedKeySize = U32;
    type SessionSecretFactorySeed = GenericArray<u8, SessionSecretFactorySeedSize>;

    /// Error thrown when invalid random seed provided for creating key factory.
    #[derive(Debug)]
    pub struct InvalidSessionSecretFactorySeedLength;

    impl fmt::Display for InvalidSessionSecretFactorySeedLength {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Invalid seed length")
        }
    }

    /// This class handles keyring material for session keys, by allowing deterministic
    /// derivation of `SessionStaticSecret` objects based on labels.
    #[derive(Clone, ZeroizeOnDrop, PartialEq)]
    pub struct SessionSecretFactory(SecretBox<SessionSecretFactorySeed>);

    impl SessionSecretFactory {
        /// Creates a session secret factory using the given RNG.
        pub fn random_with_rng(rng: &mut (impl CryptoRng + RngCore)) -> Self {
            let mut bytes = SecretBox::new(SessionSecretFactorySeed::default());
            rng.fill_bytes(bytes.as_mut_secret());
            Self(bytes)
        }

        /// Creates a session secret factory using the default RNG.
        pub fn random() -> Self {
            Self::random_with_rng(&mut OsRng)
        }

        /// Returns the seed size required by
        pub fn seed_size() -> usize {
            SessionSecretFactorySeedSize::to_usize()
        }

        /// Creates a `SessionSecretFactory` using the given random bytes.
        ///
        /// **Warning:** make sure the given seed has been obtained
        /// from a cryptographically secure source of randomness!
        pub fn from_secure_randomness(
            seed: &[u8],
        ) -> Result<Self, InvalidSessionSecretFactorySeedLength> {
            if seed.len() != Self::seed_size() {
                return Err(InvalidSessionSecretFactorySeedLength);
            }
            Ok(Self(SecretBox::new(*SessionSecretFactorySeed::from_slice(
                seed,
            ))))
        }

        /// Creates a `SessionStaticSecret` deterministically from the given label.
        pub fn make_key(&self, label: &[u8]) -> SessionStaticSecret {
            let prefix = b"SESSION_KEY_DERIVATION/";
            let info = [prefix, label].concat();
            let seed = kdf::<SessionSecretFactoryDerivedKeySize>(self.0.as_secret(), Some(&info));
            let mut rng =
                ChaCha20Rng::from_seed(<[u8; 32]>::try_from(seed.as_secret().as_slice()).unwrap());
            SessionStaticSecret::random_from_rng(&mut rng)
        }
    }

    impl fmt::Display for SessionSecretFactory {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "SessionSecretFactory:...")
        }
    }
}

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

impl ProtocolObjectInner<'_> for ThresholdDecryptionRequest {
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

impl ProtocolObject<'_> for ThresholdDecryptionRequest {}

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

impl ProtocolObjectInner<'_> for EncryptedThresholdDecryptionRequest {
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

impl ProtocolObject<'_> for EncryptedThresholdDecryptionRequest {}

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

impl ProtocolObjectInner<'_> for ThresholdDecryptionResponse {
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

impl ProtocolObject<'_> for ThresholdDecryptionResponse {}

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

impl ProtocolObjectInner<'_> for EncryptedThresholdDecryptionResponse {
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

impl ProtocolObject<'_> for EncryptedThresholdDecryptionResponse {}

#[cfg(test)]
mod tests {
    use crate::dkg::session::{
        SessionSecretFactory, SessionSharedSecret, SessionStaticKey, SessionStaticSecret,
    };
    use crate::dkg::{
        decrypt_with_shared_secret, encrypt_with_shared_secret, DecryptionError,
        EncryptedThresholdDecryptionRequest, EncryptedThresholdDecryptionResponse, NonceSize,
        ThresholdDecryptionRequest, ThresholdDecryptionResponse,
    };
    use crate::{AuthenticatedData, Conditions};
    use alloc::boxed::Box;
    #[cfg(feature = "deterministic_encryption")]
    use alloc::format;
    #[cfg(feature = "deterministic_encryption")]
    use alloc::string::String;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::clone::Clone;
    use ferveo::api::{encrypt as ferveo_encrypt, DkgPublicKey, FerveoVariant, SecretBox};
    use generic_array::typenum::Unsigned;
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use rand_core::RngCore;
    use serde::{Deserialize, Serialize};
    use serde_json;
    use x25519_dalek::{PublicKey, StaticSecret};

    use crate::access_control::AccessControlPolicy;
    use crate::conditions::Context;
    use crate::versioning::{
        messagepack_deserialize, messagepack_serialize, DeserializationError, ProtocolObject,
        ProtocolObjectInner,
    };

    #[cfg(feature = "deterministic_encryption")]
    #[derive(Serialize, Deserialize)]
    pub struct TestVector {
        pub seed: u8,
        pub plaintext: Vec<u8>,
        pub nonce: [u8; 12],
        pub ciphertext: Box<[u8]>,
    }

    #[test]
    fn decryption_with_shared_secret() {
        let service_secret = SessionStaticSecret::random();

        let requester_secret = SessionStaticSecret::random();
        let requester_public_key = requester_secret.public_key();

        let service_shared_secret = service_secret.derive_shared_secret(&requester_public_key);

        let ciphertext = b"1".to_vec().into_boxed_slice(); // length less than nonce size
        let nonce_size = <NonceSize as Unsigned>::to_usize();
        assert!(ciphertext.len() < nonce_size);

        assert!(matches!(
            decrypt_with_shared_secret(&service_shared_secret, &ciphertext).unwrap_err(),
            DecryptionError::CiphertextTooShort
        ));
    }

    #[test]
    fn request_key_factory() {
        let secret_factory = SessionSecretFactory::random();

        // ensure that shared secret derived from factory can be used correctly
        let label_1 = b"label_1".to_vec().into_boxed_slice();
        let service_secret_key = secret_factory.make_key(label_1.as_ref());
        let service_public_key = service_secret_key.public_key();

        let label_2 = b"label_2".to_vec().into_boxed_slice();
        let requester_secret_key = secret_factory.make_key(label_2.as_ref());
        let requester_public_key = requester_secret_key.public_key();

        let service_shared_secret = service_secret_key.derive_shared_secret(&requester_public_key);
        let requester_shared_secret =
            requester_secret_key.derive_shared_secret(&service_public_key);

        let data_to_encrypt = b"The Tyranny of Merit".to_vec().into_boxed_slice();
        let ciphertext =
            encrypt_with_shared_secret(&requester_shared_secret, data_to_encrypt.as_ref()).unwrap();
        let decrypted_data =
            decrypt_with_shared_secret(&service_shared_secret, &ciphertext).unwrap();
        assert_eq!(decrypted_data, data_to_encrypt);

        // ensure same key can be generated by the same factory using the same seed
        let same_requester_secret_key = secret_factory.make_key(label_2.as_ref());
        let same_requester_public_key = same_requester_secret_key.public_key();
        assert_eq!(requester_public_key, same_requester_public_key);

        // ensure different key generated using same seed but using different factory
        let other_secret_factory = SessionSecretFactory::random();
        let not_same_requester_secret_key = other_secret_factory.make_key(label_2.as_ref());
        let not_same_requester_public_key = not_same_requester_secret_key.public_key();
        assert_ne!(requester_public_key, not_same_requester_public_key);

        // ensure that two secret factories with the same seed generate the same keys
        let mut secret_factory_seed = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut secret_factory_seed);
        let seeded_secret_factory_1 =
            SessionSecretFactory::from_secure_randomness(&secret_factory_seed).unwrap();
        let seeded_secret_factory_2 =
            SessionSecretFactory::from_secure_randomness(&secret_factory_seed).unwrap();

        let key_label = b"seeded_factory_key_label".to_vec().into_boxed_slice();
        let sk_1 = seeded_secret_factory_1.make_key(&key_label);
        let pk_1 = sk_1.public_key();

        let sk_2 = seeded_secret_factory_2.make_key(&key_label);
        let pk_2 = sk_2.public_key();

        assert_eq!(pk_1, pk_2);

        // test secure randomness
        let bytes = [0u8; 32];
        let factory = SessionSecretFactory::from_secure_randomness(&bytes);
        assert!(factory.is_ok());

        let bytes = [0u8; 31];
        let factory = SessionSecretFactory::from_secure_randomness(&bytes);
        assert!(factory.is_err());
    }

    #[test]
    fn session_static_key() {
        let public_key_1: SessionStaticKey = SessionStaticSecret::random().public_key();
        let public_key_2: SessionStaticKey = SessionStaticSecret::random().public_key();

        let public_key_1_bytes = public_key_1.unversioned_to_bytes();
        let public_key_2_bytes = public_key_2.unversioned_to_bytes();

        // serialized public keys should always have the same length
        assert_eq!(public_key_1_bytes.len(), public_key_2_bytes.len());

        let deserialized_public_key_1 =
            SessionStaticKey::unversioned_from_bytes(0, &public_key_1_bytes)
                .unwrap()
                .unwrap();
        let deserialized_public_key_2 =
            SessionStaticKey::unversioned_from_bytes(0, &public_key_2_bytes)
                .unwrap()
                .unwrap();

        assert_eq!(public_key_1, deserialized_public_key_1);
        assert_eq!(public_key_2, deserialized_public_key_2);
    }

    #[test]
    fn threshold_decryption_request() {
        for variant in [FerveoVariant::Simple, FerveoVariant::Precomputed] {
            let ritual_id = 0;

            let service_secret = SessionStaticSecret::random();

            let requester_secret = SessionStaticSecret::random();
            let requester_public_key = requester_secret.public_key();

            let dkg_pk = DkgPublicKey::random();
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

    #[cfg(feature = "deterministic_encryption")]
    pub fn generate_test_vectors() -> Vec<TestVector> {
        use chacha20poly1305::{AeadCore, ChaCha20Poly1305};

        let mut test_vectors = Vec::new();

        // Generate test vectors with different seeds
        for seed in 0..3 {
            // Generate test plaintexts
            let plaintexts = vec![
                b"test data".to_vec(),
                b"another test".to_vec(),
                b"".to_vec(), // empty string test
            ];

            // Generate ciphertexts for each plaintext
            for plaintext in plaintexts {
                let session_shared_secret = create_session_shared_secret_from_seed(seed);

                let ciphertext = encrypt_with_shared_secret(&session_shared_secret, &plaintext)
                    .expect("Encryption failed");

                // TODO: Note that this seed is currently fixed for all tests, and hence the nonce is also fixed
                let rng = <StdRng as SeedableRng>::from_seed([0u8; 32]);
                let nonce = ChaCha20Poly1305::generate_nonce(rng);

                test_vectors.push(TestVector {
                    seed,
                    plaintext,
                    nonce: nonce.as_slice().try_into().unwrap(),
                    ciphertext,
                });
            }
        }

        test_vectors
    }

    #[cfg(feature = "deterministic_encryption")]
    pub fn serialize_test_vector_to_json(vector: &TestVector) -> String {
        serde_json::to_string(vector).expect("Failed to serialize test vector to JSON")
    }

    #[cfg(feature = "deterministic_encryption")]
    pub fn deserialize_test_vector_from_json(json: &str) -> TestVector {
        serde_json::from_str(json).expect("Failed to deserialize test vector from JSON")
    }

    #[test]
    #[cfg(feature = "deterministic_encryption")]
    fn test_encryption_deterministic() {
        use crate::dkg::session::SessionSharedSecret;
        use rand::rngs::StdRng;
        use rand_core::SeedableRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        // Create a test session_shared_secret and test plaintext
        let mut rng0 = <StdRng as SeedableRng>::from_seed([0u8; 32]);
        let static_secret_a = StaticSecret::random_from_rng(&mut rng0);
        let static_secret_b = StaticSecret::random_from_rng(&mut rng0);
        let public_key_b = PublicKey::from(&static_secret_b);
        let shared_secret = static_secret_a.diffie_hellman(&public_key_b);
        let session_shared_secret = SessionSharedSecret::new(shared_secret);

        let plaintext = b"test data";

        // Use a seeded RNG for deterministic testing on encryption
        let ciphertext1 = encrypt_with_shared_secret(&session_shared_secret, plaintext).unwrap();

        // Reset the RNG with the same seed
        let ciphertext2 = encrypt_with_shared_secret(&session_shared_secret, plaintext).unwrap();

        // The ciphertexts will be identical because we used the same seed
        assert_eq!(ciphertext1, ciphertext2);
    }

    #[cfg(feature = "deterministic_encryption")]
    fn create_session_shared_secret_from_seed(seed: u8) -> SessionSharedSecret {
        use rand::rngs::StdRng;
        use rand_core::SeedableRng;
        use x25519_dalek::{PublicKey, StaticSecret};

        let mut rng = <StdRng as SeedableRng>::from_seed([seed; 32]);
        let static_secret_a = StaticSecret::random_from_rng(&mut rng);
        let static_secret_b = StaticSecret::random_from_rng(&mut rng);
        let public_key_b = PublicKey::from(&static_secret_b);
        let shared_secret = static_secret_a.diffie_hellman(&public_key_b);
        SessionSharedSecret::new(shared_secret)
    }

    #[test]
    #[cfg(feature = "deterministic_encryption")]
    fn test_encryption_vectors() {
        let test_vectors = generate_test_vectors();

        // Verify each test vector
        for vector in test_vectors {
            let session_shared_secret = create_session_shared_secret_from_seed(vector.seed);

            // Verify decryption works
            let decrypted = decrypt_with_shared_secret(&session_shared_secret, &vector.ciphertext)
                .expect("Decryption failed");
            assert_eq!(decrypted.as_ref(), vector.plaintext.as_slice());

            // Verify encryption is deterministic
            let new_ciphertext =
                encrypt_with_shared_secret(&session_shared_secret, &vector.plaintext)
                    .expect("Encryption failed");
            assert_eq!(new_ciphertext, vector.ciphertext);
        }
    }
}
