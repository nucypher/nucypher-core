//! Module for generating and handling test vectors for encryption/decryption testing.

use alloc::vec::Vec;
use alloc::string::String;
use serde::{Deserialize, Serialize};

use crate::dkg::session::SessionSharedSecret;

/// A test vector containing all necessary data for encryption/decryption testing.
#[derive(Serialize, Deserialize)]
pub struct TestVector {
    /// The seed used to generate the session shared secret
    pub seed: u8,
    /// The plaintext to be encrypted
    pub plaintext: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: [u8; 12],
    /// The resulting ciphertext
    pub ciphertext: alloc::boxed::Box<[u8]>,
}

/// Creates a session shared secret from a seed value.
/// 
/// This is a helper function used by `generate_test_vectors` to create
/// deterministic session shared secrets for testing.
#[cfg(feature = "test_vectors")]
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

/// Generates a set of test vectors for encryption/decryption testing.
/// 
/// This function creates test vectors with different seeds and plaintexts,
/// encrypting them to produce ciphertexts that can be used for testing.
#[cfg(feature = "test_vectors")]
pub fn generate_test_vectors() -> Vec<TestVector> {
    use chacha20poly1305::{AeadCore, ChaCha20Poly1305};
    use rand::rngs::StdRng;
    use rand::SeedableRng;
    use alloc::vec;

    let mut test_vectors = Vec::new();
    
    // Generate test vectors with different seeds
    for seed in 0..3 {
        // Generate test plaintexts
        let plaintexts: Vec<Vec<u8>> = vec![
            b"test data".to_vec(),
            b"another test".to_vec(),
            b"".to_vec(), // empty string test
        ];
        
        // Generate ciphertexts for each plaintext
        for plaintext in plaintexts {
            let session_shared_secret = create_session_shared_secret_from_seed(seed);
            
            let ciphertext = crate::dkg::encrypt_with_shared_secret(&session_shared_secret, &plaintext)
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

#[cfg(feature = "test_vectors")]
pub fn serialize_test_vector_to_json(vector: &TestVector) -> String {
    serde_json::to_string(vector).expect("Failed to serialize test vector to JSON")
}

#[cfg(feature = "test_vectors")]
pub fn deserialize_test_vector_from_json(json: &str) -> TestVector {
    serde_json::from_str(json).expect("Failed to deserialize test vector from JSON")
}
