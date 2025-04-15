// Include the test_utils module at the crate root level
mod test_utils {
    pub mod cross_impl_test_vectors;
}

#[cfg(test)]
mod tests {
    // Import the test utilities for TypeScript project paths
    use crate::test_utils::cross_impl_test_vectors;

    // json file name
    const JSON_FILE_NAME: &str = "session-key-vectors.json";
    use nucypher_core::{SessionSharedSecret, SessionStaticKey, SessionStaticSecret};
    use serde::{Deserialize, Serialize};
    use std::fs;
    use std::path::Path;
    use std::time::{SystemTime, UNIX_EPOCH};
    use umbral_pre::serde_bytes;

    // Structures to represent the test vectors
    #[derive(Serialize, Deserialize, Debug)]
    struct KeyPair {
        public_key: Vec<u8>, // Public key bytes
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct SharedSecretResult {
        initiator_public_key: Vec<u8>, // First party's public key
        responder_public_key: Vec<u8>, // Second party's public key
        shared_secret: Vec<u8>,        // Resulting shared secret
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestVector {
        id: String,
        description: String,
        vector_type: String,

        // For random key pair generation tests
        random_key_pairs: Option<Vec<KeyPair>>,

        // For key exchange tests
        key_exchange_scenarios: Option<Vec<SharedSecretResult>>,

        // For compatibility verification
        interoperability_check: Option<bool>,
    }

    #[derive(Serialize, Deserialize, Debug)]
    struct TestVectors {
        schema_version: String,
        timestamp: String,
        curve: String,
        algorithm: String,
        test_vectors: Vec<TestVector>,
    }

    // Helper function to generate a random key pair
    fn generate_random_key_pair() -> (SessionStaticSecret, SessionStaticKey) {
        // Use the built-in random generator
        let secret = SessionStaticSecret::random();
        let public = secret.public_key();

        (secret, public)
    }

    // Helper to create a key exchange scenario between two parties
    fn create_key_exchange(
        initiator_secret: &SessionStaticSecret,
        responder_secret: &SessionStaticSecret,
    ) -> SharedSecretResult {
        // Generate public keys
        let initiator_public = initiator_secret.public_key();
        let responder_public = responder_secret.public_key();

        // Exchange keys
        let shared_secret_initiator = initiator_secret.derive_shared_secret(&responder_public);
        let shared_secret_responder = responder_secret.derive_shared_secret(&initiator_public);

        // Verify they match (DH property)
        assert_eq!(
            shared_secret_initiator.as_bytes(),
            shared_secret_responder.as_bytes()
        );

        SharedSecretResult {
            initiator_public_key: initiator_public.to_bytes().to_vec(),
            responder_public_key: responder_public.to_bytes().to_vec(),
            shared_secret: shared_secret_initiator.as_bytes().to_vec(),
        }
    }

    #[test]
    fn generate_test_vectors() {
        println!(
            "Generating SessionStaticSecret test vectors for cross-implementation compatibility..."
        );

        // Create timestamp for the test vectors
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs();

        // Create test vectors container
        let mut test_vectors = Vec::new();

        // === Vector 1: Random Key Generation Test ===
        {
            println!("Generating Vector 1: Random Key Pair Generation");
            let mut random_pairs = Vec::new();

            // Generate multiple random key pairs
            for i in 0..10 {
                let (_, public) = generate_random_key_pair();

                println!("  - Generated random key pair {}", i + 1);

                // Store the public key bytes
                random_pairs.push(KeyPair {
                    public_key: public.to_bytes().to_vec(),
                });
            }

            test_vectors.push(TestVector {
                id: "vector1".to_string(),
                description: "Random key pair generation examples".to_string(),
                vector_type: "random_generation".to_string(),
                random_key_pairs: Some(random_pairs),
                key_exchange_scenarios: None,
                interoperability_check: Some(true),
            });
        }

        // === Vector 2: Key Exchange Test ===
        {
            println!("Generating Vector 2: Key Exchange Scenarios");
            let mut exchange_scenarios = Vec::new();

            // Generate multiple random key exchange scenarios
            for i in 0..5 {
                let (initiator_secret, _) = generate_random_key_pair();
                let (responder_secret, _) = generate_random_key_pair();

                println!("  - Generated key exchange scenario {}", i + 1);
                let scenario = create_key_exchange(&initiator_secret, &responder_secret);
                exchange_scenarios.push(scenario);
            }

            test_vectors.push(TestVector {
                id: "vector2".to_string(),
                description: "Key exchange scenarios (Diffie-Hellman)".to_string(),
                vector_type: "key_exchange".to_string(),
                random_key_pairs: None,
                key_exchange_scenarios: Some(exchange_scenarios),
                interoperability_check: Some(true),
            });
        }

        // Create the complete test vectors structure
        let test_vectors_output = TestVectors {
            schema_version: "1.0".to_string(),
            timestamp: timestamp.to_string(),
            curve: "X25519".to_string(),
            algorithm: "Diffie-Hellman Key Exchange".to_string(),
            test_vectors,
        };

        // Format the JSON with pretty-printing
        let formatted_json = serde_json::to_string_pretty(&test_vectors_output)
            .expect("Failed to serialize test vectors to JSON");

        // Ensure the fixtures directory exists
        let fixtures_dir = Path::new("tests/fixtures");
        if !fixtures_dir.exists() {
            fs::create_dir_all(fixtures_dir).expect("Failed to create fixtures directory");
        }

        // Write the test vectors to the fixtures file in the Rust project
        let fixture_path = fixtures_dir.join("session-key-vectors.json");
        fs::write(&fixture_path, &formatted_json).expect("Failed to write test vectors to file");
        println!("✓ Test vectors saved to {:?}", fixture_path);

        // Write test vectors to TypeScript project using the shared utility
        cross_impl_test_vectors::write_to_ts_project_path(
            JSON_FILE_NAME,
            &formatted_json,
            &fixture_path,
        );

        // Verify the test vectors are valid
        verify_test_vectors(&test_vectors_output, &fixture_path);

        println!("\nInstructions for manual copying test vectors (if needed):");
        println!(
            "  cp {} {}",
            fixture_path.display(),
            cross_impl_test_vectors::DEFAULT_TS_PROJECT_TEST_VECTORS_PATH
        );
    }

    // Verify the test vectors to ensure they're properly formatted and usable
    fn verify_test_vectors(vectors: &TestVectors, _path: &Path) {
        println!("\nVerifying generated test vectors...");

        // Verify each test vector category
        for vector in &vectors.test_vectors {
            match vector.vector_type.as_str() {
                "random_generation" => {
                    if let Some(key_pairs) = &vector.random_key_pairs {
                        for (i, key_pair) in key_pairs.iter().enumerate() {
                            // Check the public key has correct X25519 length (32 bytes)
                            assert_eq!(
                                key_pair.public_key.len(),
                                32,
                                "Key pair {} has invalid public key length",
                                i
                            );

                            // Create SessionStaticKey to verify format using serde_bytes::TryFromBytes trait
                            let _pub_key =
                                <SessionStaticKey as serde_bytes::TryFromBytes>::try_from_bytes(
                                    &key_pair.public_key,
                                )
                                .expect("Failed to convert bytes to SessionStaticKey");
                        }
                        println!("  ✓ Validated {} random key pairs", key_pairs.len());
                    }
                }
                "key_exchange" => {
                    if let Some(scenarios) = &vector.key_exchange_scenarios {
                        for (i, scenario) in scenarios.iter().enumerate() {
                            // Check key lengths
                            assert_eq!(
                                scenario.initiator_public_key.len(),
                                32,
                                "Scenario {} has invalid initiator public key length",
                                i
                            );
                            assert_eq!(
                                scenario.responder_public_key.len(),
                                32,
                                "Scenario {} has invalid responder public key length",
                                i
                            );
                            assert_eq!(
                                scenario.shared_secret.len(),
                                32,
                                "Scenario {} has invalid shared secret length",
                                i
                            );

                            // Verify we can reconstruct the public keys using serde_bytes::TryFromBytes trait
                            let _initiator_key =
                                <SessionStaticKey as serde_bytes::TryFromBytes>::try_from_bytes(
                                    &scenario.initiator_public_key,
                                )
                                .expect("Failed to convert bytes to initiator SessionStaticKey");
                            let _responder_key =
                                <SessionStaticKey as serde_bytes::TryFromBytes>::try_from_bytes(
                                    &scenario.responder_public_key,
                                )
                                .expect("Failed to convert bytes to responder SessionStaticKey");

                            // Create a shared secret for validation
                            let _shared_secret =
                                SessionSharedSecret::from_test_vector(&scenario.shared_secret);
                        }
                        println!("  ✓ Validated {} key exchange scenarios", scenarios.len());
                    }
                }
                _ => panic!("Unknown vector type: {}", vector.vector_type),
            }
        }

        println!(
            "\n✓ Test vectors successfully validated! Ready for cross-implementation testing."
        );
    }
}
