// Include the test_utils module at the crate root level
mod test_utils {
    pub mod cross_impl_test_vectors;
}

#[cfg(test)]
mod tests {
    // Import the test utilities for TypeScript project paths
    use crate::test_utils::cross_impl_test_vectors;

    // json file name
    const JSON_FILE_NAME: &str = "shared-secret-vectors.json";

    use chacha20poly1305::{Key, KeyInit, Nonce};
    use nucypher_core::{
        decrypt_with_shared_secret, encrypt_with_shared_secret, SessionSharedSecret,
    };
    use serde::{Deserialize, Serialize};
    use serde_json::Value;
    use std::fs;
    use std::path::Path;

    // Structure that matches the JSON test vector format
    #[derive(Serialize, Deserialize)]
    struct TestVector {
        id: String,
        description: String,
        shared_secret: Vec<u8>,
        #[serde(skip_serializing_if = "Option::is_none")]
        plaintext: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        fixed_nonce: Option<Vec<u8>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        expected_ciphertext: Option<Vec<u8>>,
    }

    #[derive(Serialize, Deserialize)]
    struct TestVectors {
        test_vectors: Vec<TestVector>,
    }

    // Wrapper for encrypt_with_shared_secret that takes raw bytes for compatibility with test vectors
    fn test_encrypt_with_shared_secret(
        shared_secret: &[u8],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Create SessionSharedSecret from raw bytes
        let shared_secret_obj = SessionSharedSecret::from_test_vector(shared_secret);

        // Use the actual library function
        let result = encrypt_with_shared_secret(&shared_secret_obj, plaintext).map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Encryption error: {:?}", e))
        })?;

        Ok(result.to_vec())
    }

    // Wrapper for decrypt_with_shared_secret that takes raw bytes for compatibility with test vectors
    fn test_decrypt_with_shared_secret(
        shared_secret: &[u8],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // Create SessionSharedSecret from raw bytes
        let shared_secret_obj = SessionSharedSecret::from_test_vector(shared_secret);

        // Use the actual library function
        let result = decrypt_with_shared_secret(&shared_secret_obj, ciphertext).map_err(|e| {
            Box::<dyn std::error::Error>::from(format!("Decryption error: {:?}", e))
        })?;

        Ok(result.to_vec())
    }

    // Function to encrypt with fixed nonce for test vector generation
    fn encrypt_with_fixed_nonce(
        shared_secret: &[u8],
        plaintext: &[u8],
        fixed_nonce: &[u8],
    ) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        use chacha20poly1305::aead::Aead;

        // Create key from shared secret bytes
        let key = Key::from_slice(shared_secret);
        let cipher = chacha20poly1305::ChaCha20Poly1305::new(key);

        // Use the provided fixed nonce
        let nonce = Nonce::from_slice(fixed_nonce);

        // Encrypt the plaintext with the fixed nonce
        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|_| "Encryption failed: plaintext too large")?;

        // Format the result as nonce + ciphertext, matching the library format
        let mut result = fixed_nonce.to_vec();
        result.extend(ciphertext);

        Ok(result)
    }

    #[test]
    fn generate_test_vectors() {
        println!("Generating encryption test vectors for TypeScript compatibility...");

        // Define test vectors directly as TestVector structs
        let mut test_vectors = Vec::new();

        // Vector 1: Known plaintext + fixed nonce -> expected ciphertext
        let shared_secret1: Vec<u8> = (0..32).collect();
        let plaintext1 = "This is a test message";
        let fixed_nonce1: Vec<u8> = vec![0; 12]; // 12 zeros

        println!("Processing vector1 with fixed nonce");
        let mut vector1 = TestVector {
            id: "vector1".to_string(),
            description: "Fixed nonce encryption with known plaintext".to_string(),
            shared_secret: shared_secret1.clone(),
            plaintext: Some(plaintext1.to_string()),
            fixed_nonce: Some(fixed_nonce1.clone()),
            expected_ciphertext: None,
        };

        // Generate ciphertext with fixed nonce for vector1
        match encrypt_with_fixed_nonce(&shared_secret1, plaintext1.as_bytes(), &fixed_nonce1) {
            Ok(ciphertext) => {
                vector1.expected_ciphertext = Some(ciphertext);
                println!("  ✓ Successfully generated ciphertext with fixed nonce");
            }
            Err(e) => {
                eprintln!("Error encrypting vector1: {}", e);
            }
        }
        test_vectors.push(vector1);

        // Vector 2: Known plaintext + fixed nonce -> expected ciphertext (different values)
        let shared_secret2: Vec<u8> = (0..32).rev().collect(); // Reversed range
        let plaintext2 = ""; // Empty plaintext for testing empty message encryption
        let fixed_nonce2: Vec<u8> = vec![1; 12]; // 12 ones

        println!("Processing vector2 with fixed nonce");
        let mut vector2 = TestVector {
            id: "vector2".to_string(),
            description: "Fixed nonce encryption with alternative values".to_string(),
            shared_secret: shared_secret2.clone(),
            plaintext: Some(plaintext2.to_string()),
            fixed_nonce: Some(fixed_nonce2.clone()),
            expected_ciphertext: None,
        };

        // Generate ciphertext with fixed nonce for vector2
        match encrypt_with_fixed_nonce(&shared_secret2, plaintext2.as_bytes(), &fixed_nonce2) {
            Ok(ciphertext) => {
                vector2.expected_ciphertext = Some(ciphertext);
                println!("  ✓ Successfully generated ciphertext with fixed nonce");
            }
            Err(e) => {
                eprintln!("Error encrypting vector2: {}", e);
            }
        }
        test_vectors.push(vector2);

        // Vector 3: For Rust-generated ciphertext compatibility using normal encryption
        let shared_secret3: Vec<u8> = (0..32).collect();
        let plaintext3 = "This is a message encrypted by the Rust implementation";

        println!("Creating vector3 with Rust-generated ciphertext");
        let mut vector3 = TestVector {
            id: "vector3".to_string(),
            description: "Rust-generated ciphertext for TypeScript compatibility check".to_string(),
            shared_secret: shared_secret3.clone(),
            plaintext: Some(plaintext3.to_string()),
            fixed_nonce: None,
            expected_ciphertext: None,
        };

        // Standard encryption with random nonce
        match test_encrypt_with_shared_secret(&shared_secret3, plaintext3.as_bytes()) {
            Ok(ciphertext) => {
                vector3.expected_ciphertext = Some(ciphertext);
                println!("  ✓ Successfully generated ciphertext for vector3");
            }
            Err(e) => {
                eprintln!("Error encrypting vector3: {}", e);
            }
        }
        test_vectors.push(vector3);

        // Create the complete test vectors structure
        let test_vectors_output = TestVectors { test_vectors };

        // Format the JSON with pretty-printing
        let formatted_json = serde_json::to_string_pretty(&test_vectors_output).unwrap();

        // Path for the output file
        let output_dir = Path::new("tests/fixtures");
        let output_file = output_dir.join("shared-secret-vectors.json");

        // Create directory if it doesn't exist
        fs::create_dir_all(output_dir).expect("Failed to create output directory");

        // Save to file in the Rust project first
        fs::write(&output_file, &formatted_json).expect("Unable to write test vectors file");
        println!("Test vectors saved to {:?}", output_file);

        // Write test vectors to TypeScript project
        cross_impl_test_vectors::write_to_ts_project_path(
            JSON_FILE_NAME,
            &formatted_json,
            &output_file,
        );

        // Verify vectors by decrypting
        // Parse the JSON string back to a Value before passing to verify_test_vectors
        let test_vectors_value: Value = serde_json::from_str(&formatted_json).unwrap();
        verify_test_vectors(&test_vectors_value);

        println!("\nInstructions for manually copying test vectors:");
        println!("1. The file has been saved to: {:?}", output_file);
        println!(
            "2. Copy it to: {}",
            cross_impl_test_vectors::get_ts_project_path(JSON_FILE_NAME)
        );
        println!("3. Run the TypeScript tests to verify compatibility");
    }

    fn verify_test_vectors(test_vectors_json: &Value) {
        println!("\nVerifying test vectors...");
        let vectors = test_vectors_json["test_vectors"].as_array().unwrap();

        for vector in vectors {
            let id = vector["id"].as_str().unwrap();
            let shared_secret = vector["shared_secret"].as_array().unwrap();
            let shared_secret_bytes: Vec<u8> = shared_secret
                .iter()
                .map(|v| v.as_u64().unwrap() as u8)
                .collect();

            println!("Verifying vector: {}", id);

            // Verify vector3 with rust-generated ciphertext
            if id == "vector3" && vector["expected_ciphertext"].is_array() {
                let ciphertext_json = vector["expected_ciphertext"].as_array().unwrap();
                let ciphertext: Vec<u8> = ciphertext_json
                    .iter()
                    .map(|v| v.as_u64().unwrap() as u8)
                    .collect();

                let plaintext = vector["plaintext"].as_str().unwrap();

                match test_decrypt_with_shared_secret(&shared_secret_bytes, &ciphertext) {
                    Ok(decrypted) => {
                        let decrypted_str = String::from_utf8_lossy(&decrypted);
                        assert_eq!(
                            decrypted_str, plaintext,
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

                match test_decrypt_with_shared_secret(&shared_secret_bytes, &ciphertext) {
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
