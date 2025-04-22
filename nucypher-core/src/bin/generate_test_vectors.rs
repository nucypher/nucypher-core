use nucypher_core::test_vectors::{TestVector, generate_test_vectors};
use std::fs;
use std::path::Path;

fn main() {
    // Generate test vectors
    let test_vectors: Vec<TestVector> = generate_test_vectors();
    
    // Create output directory if it doesn't exist
    let output_dir = Path::new("test_vectors");
    fs::create_dir_all(output_dir).expect("Failed to create output directory");
    
    // Save each test vector to a separate file
    for (i, vector) in test_vectors.iter().enumerate() {
        let filename = format!("test_vectors/vector_{}.json", i);
        let json = serde_json::to_string_pretty(vector).expect("Failed to serialize test vector");
        fs::write(filename, json).expect("Failed to write test vector to file");
    }
    
    println!("Generated {} test vectors in the 'test_vectors' directory", test_vectors.len());
} 