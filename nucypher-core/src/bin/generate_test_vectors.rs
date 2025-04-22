use std::fs;
use std::path::Path;
use nucypher_core::test_vectors::{TestVector, generate_test_vectors};

// Usage: cargo run --bin generate-test-vectors --features test_vectors deterministic_encryption
fn main() {
    // Generate test vectors
    let test_vectors: Vec<TestVector> = generate_test_vectors();
    
    // Create output directory if it doesn't exist
    let output_dir = Path::new("test_vectors");
    fs::create_dir_all(output_dir).expect("Failed to create output directory");
    
    // Save all test vectors to a single file
    let filename = "test_vectors/encrypt_with_shared_secret.json";
    let json = serde_json::to_string_pretty(&test_vectors).expect("Failed to serialize test vectors");
    fs::write(filename, json).expect("Failed to write test vectors to file");
    
    println!("Generated {} test vectors in '{}'", test_vectors.len(), filename);
} 