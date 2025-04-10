#[cfg(test)]
mod tests {
    use chacha20poly1305::aead::Aead;
    use chacha20poly1305::{ChaCha20Poly1305, Key, KeyInit, Nonce};
    use rand::rngs::OsRng;
    use rand::RngCore; // Add this import for the fill_bytes method
    use serde::{Deserialize, Serialize};
    use serde_json::{json, Value};
    use std::fs;
    use std::path::Path;

    // Since the dkg module is private, we reimplement the encryption/decryption functions here
    // based on the implementation in src/dkg.rs

    // Structure that matches the JSON test vector format
    #[derive(Serialize, Deserialize)]
    struct TestVector {
        id: String,
        description: String,
        shared_secret: Vec<u8>,
        plaintext: Option<String>,
        fixed_nonce: Option<Vec<u8>>,
        expected_ciphertext: Option<String>,
        rust_generated_ciphertext: Option<Vec<u8>>,
        expected_plaintext: Option<String>,
    }

    #[derive(Serialize, Deserialize)]
    struct TestVectors {
        test_vectors: Vec<TestVector>,
    }

    // Implementation of encrypt_with_shared_secret as found in dkg.rs
    fn encrypt_with_shared_secret(
        shared_secret: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = Key::from_slice(shared_secret);
        let cipher = ChaCha20Poly1305::new(key);

        // Generate random nonce
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        // Create result with nonce
        let mut result = nonce_bytes.to_vec();

        // Encrypt plaintext
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| "Encryption failed: plaintext too large")?;

        // Append ciphertext to nonce
        result.extend(ciphertext);

        Ok(result)
    }

    // Implementation of decrypt_with_shared_secret as found in dkg.rs
    fn decrypt_with_shared_secret(
        shared_secret: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        if ciphertext.len() <= 12 {
            return Err("The ciphertext must include the nonce".into());
        }

        let key = Key::from_slice(shared_secret);
        let cipher = ChaCha20Poly1305::new(key);

        let nonce = Nonce::from_slice(&ciphertext[..12]);
        let decrypt_result = cipher
            .decrypt(nonce, &ciphertext[12..])
            .map_err(|_| "Decryption of ciphertext failed")?;

        Ok(decrypt_result)
    }

    // Function to encrypt with fixed nonce for test vector generation
    fn encrypt_with_fixed_nonce(
        shared_secret: &[u8],
        plaintext: &[u8],
        fixed_nonce: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let key = Key::from_slice(shared_secret);
        let cipher = ChaCha20Poly1305::new(key);

        // Use the provided fixed nonce
        let nonce = Nonce::from_slice(fixed_nonce);

        // Create the result starting with the nonce
        let mut result = fixed_nonce.to_vec();

        // Encrypt the plaintext with the fixed nonce
        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|_| "Encryption failed: plaintext too large")?;

        // Append the ciphertext to the nonce
        result.extend(ciphertext);

        Ok(result)
    }

    #[test]
    fn generate_test_vectors() {
        println!("Generating encryption test vectors for TypeScript compatibility...");

        // Define test vectors
        let vectors = vec![
            // Vector 1: Basic encryption/decryption with fixed nonce
            json!({
                "id": "vector1",
                "description": "Basic encryption/decryption compatibility",
                "shared_secret": (0..32).collect::<Vec<u8>>(),
                "plaintext": "This is a fixed test message",
                "fixed_nonce": vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12],
            }),
            // Vector 2: Empty plaintext with fixed nonce
            json!({
                "id": "vector2",
                "description": "Empty plaintext compatibility",
                "shared_secret": (32..64).collect::<Vec<u8>>(),
                "plaintext": "",
                "fixed_nonce": vec![16, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192],
            }),
            // Vector 3: For Rust-generated ciphertext compatibility using normal encryption
            json!({
                "id": "vector3",
                "description": "Rust-generated ciphertext for TypeScript compatibility check",
                "shared_secret": (0..32).collect::<Vec<u8>>(),
                "expected_plaintext": "This is a message encrypted by the Rust implementation",
            }),
        ];

        // Process each vector to add encryption outputs
        let mut processed_vectors = Vec::new();

        for vector in vectors {
            let mut processed = vector.clone();

            // Extract shared secret
            let shared_secret = vector["shared_secret"].as_array().unwrap();
            let shared_secret_bytes: Vec<u8> = shared_secret
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();

            // Handle vector3 - generate ciphertext with standard Rust implementation
            if vector["id"].as_str().unwrap() == "vector3" {
                let plaintext = vector["expected_plaintext"].as_str().unwrap().as_bytes();

                println!("Creating vector3 with Rust-generated ciphertext");
                // Standard encryption with random nonce
                let ciphertext =
                    encrypt_with_shared_secret(&shared_secret_bytes, plaintext).unwrap();
                let ciphertext_vec = ciphertext.to_vec();

                // Add the Rust-generated ciphertext to the vector
                processed["rust_generated_ciphertext"] = json!(ciphertext_vec);
                processed_vectors.push(processed);
                continue;
            }

            // For vectors 1 & 2, use fixed nonces
            if let (Some(plaintext_str), Some(fixed_nonce)) = (
                vector["plaintext"].as_str(),
                vector["fixed_nonce"].as_array(),
            ) {
                let plaintext = plaintext_str.as_bytes();
                let fixed_nonce_bytes: Vec<u8> = fixed_nonce
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect();

                println!("Processing vector {} with fixed nonce", vector["id"]);

                // Generate ciphertext with fixed nonce
                match encrypt_with_fixed_nonce(&shared_secret_bytes, plaintext, &fixed_nonce_bytes)
                {
                    Ok(ciphertext) => {
                        // Convert ciphertext to hex string for expected_ciphertext
                        let ciphertext_hex = hex::encode(&ciphertext);
                        processed["expected_ciphertext"] = json!(ciphertext_hex);
                        println!("  ✓ Successfully generated ciphertext with fixed nonce");
                    }
                    Err(e) => {
                        eprintln!("Error encrypting vector {}: {}", vector["id"], e);
                    }
                }
            }

            processed_vectors.push(processed);
        }

        // Create the final JSON structure with camelCase keys for TypeScript
        let final_json = json!({
            "testVectors": processed_vectors
        });

        // Format the JSON with pretty-printing
        let formatted_json = serde_json::to_string_pretty(&final_json).unwrap();

        // Path for the output file
        let output_dir = Path::new("tests/fixtures");
        let output_file = output_dir.join("shared-secret-vectors.json");

        // Create directory if it doesn't exist
        fs::create_dir_all(output_dir).expect("Failed to create output directory");

        // Save to file in the Rust project first
        fs::write(&output_file, &formatted_json).expect("Unable to write test vectors file");
        println!("Test vectors saved to {:?}", output_file);

        // Also save to TypeScript project if path exists
        let ts_path =
            Path::new("../taco-web/packages/shared/test/fixtures/shared-secret-vectors.json");
        if let Ok(()) = fs::write(ts_path, &formatted_json) {
            println!(
                "Test vectors also copied to TypeScript project: {:?}",
                ts_path
            );
        } else {
            println!(
                "Note: Couldn't copy to TypeScript project. You'll need to manually copy the file."
            );
        }

        // Verify vectors by decrypting
        verify_test_vectors(&final_json);

        println!("\nInstructions for manually copying test vectors:");
        println!("1. The file has been saved to: {:?}", output_file);
        println!(
            "2. Copy it to: ../taco-web/packages/shared/test/fixtures/shared-secret-vectors.json"
        );
        println!("3. Run the TypeScript tests to verify compatibility");
    }

    fn verify_test_vectors(test_vectors_json: &Value) {
        println!("\nVerifying test vectors...");
        let vectors = test_vectors_json["testVectors"].as_array().unwrap();

        for vector in vectors {
            let id = vector["id"].as_str().unwrap();
            let shared_secret = vector["shared_secret"].as_array().unwrap();
            let shared_secret_bytes: Vec<u8> = shared_secret
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();

            println!("Verifying vector: {}", id);

            // Verify vector3 with rust-generated ciphertext
            if id == "vector3" && vector["rust_generated_ciphertext"].is_array() {
                let ciphertext_json = vector["rust_generated_ciphertext"].as_array().unwrap();
                let ciphertext: Vec<u8> = ciphertext_json
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect();

                let expected_plaintext = vector["expected_plaintext"].as_str().unwrap();

                match decrypt_with_shared_secret(&shared_secret_bytes, &ciphertext) {
                    Ok(decrypted) => {
                        let decrypted_str = String::from_utf8_lossy(&decrypted);
                        assert_eq!(
                            decrypted_str, expected_plaintext,
                            "Decryption mismatch for vector {}",
                            id
                        );
                        println!("  ✓ Successfully verified rust-generated ciphertext");
                    }
                    Err(e) => {
                        panic!("Failed to decrypt rust-generated ciphertext: {:?}", e);
                    }
                }
                continue;
            }

            // Verify vectors with expected_ciphertext
            if let Some(ciphertext_hex) = vector["expected_ciphertext"].as_str() {
                let ciphertext = hex::decode(ciphertext_hex).unwrap();
                let plaintext = vector["plaintext"].as_str().unwrap().as_bytes();

                match decrypt_with_shared_secret(&shared_secret_bytes, &ciphertext) {
                    Ok(decrypted) => {
                        assert_eq!(
                            &decrypted, plaintext,
                            "Decryption mismatch for vector {}",
                            id
                        );
                        println!("  ✓ Successfully verified expected_ciphertext");
                    }
                    Err(e) => {
                        panic!("Failed to decrypt expected_ciphertext: {:?}", e);
                    }
                }
            }
        }

        println!("All test vectors verified successfully!");
    }
}
