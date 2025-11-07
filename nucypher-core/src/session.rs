use alloc::boxed::Box;
use core::fmt;

use chacha20poly1305::aead::{Aead, AeadCore, KeyInit, OsRng};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use generic_array::typenum::Unsigned;

use crate::session::key::SessionSharedSecret;
use crate::versioning::DeserializationError;

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

#[derive(Debug)]
/// Errors during decryption.
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
            Self::DeserializationFailed(err) => write!(f, "deserialization failed: {err}"),
        }
    }
}

type NonceSize = <ChaCha20Poly1305 as AeadCore>::NonceSize;

pub fn encrypt_with_shared_secret(
    shared_secret: &SessionSharedSecret,
    plaintext: &[u8],
) -> Result<Box<[u8]>, EncryptionError> {
    let key = Key::from_slice(shared_secret.as_ref());
    let cipher = ChaCha20Poly1305::new(key);
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);
    let mut result = nonce.to_vec();
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_ref())
        .map_err(|_err| EncryptionError::PlaintextTooLarge)?;
    result.extend(ciphertext);
    Ok(result.into_boxed_slice())
}

pub fn decrypt_with_shared_secret(
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
pub mod key {
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

    impl<'a> ProtocolObjectInner<'a> for SessionStaticKey {
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

    impl<'a> ProtocolObject<'a> for SessionStaticKey {}

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

#[cfg(test)]
mod tests {
    use generic_array::typenum::Unsigned;
    use rand_core::RngCore;

    use crate::session::key::SessionStaticSecret;
    use crate::session::{
        decrypt_with_shared_secret, encrypt_with_shared_secret, DecryptionError, NonceSize,
    };
    use crate::versioning::ProtocolObjectInner;
    use crate::{SessionSecretFactory, SessionStaticKey};

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
}
