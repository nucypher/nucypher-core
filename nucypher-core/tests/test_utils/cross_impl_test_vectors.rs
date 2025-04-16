// Utility functions for handling TypeScript project paths in tests
use std::path::Path;

/// Default base path to TypeScript project test fixtures
pub const DEFAULT_TS_PROJECT_TEST_VECTORS_PATH: &str =
    "../../taco-web/packages/shared/test/fixtures/";

/// Environment variable name for TypeScript project path
pub const TS_PROJECT_TEST_VECTORS_PATH_ENV_VAR: &str = "TS_PROJECT_TEST_VECTORS_PATH";

/// Get the TypeScript project path combining the base directory with the specified file name
/// 
/// Checks for the environment variable `TS_PROJECT_TEST_VECTORS_PATH_ENV_VAR` first,
/// and falls back to the default path if not set.
pub fn get_ts_project_path(file_name: &str) -> String {
    // Check for environment variable
    match std::env::var(TS_PROJECT_TEST_VECTORS_PATH_ENV_VAR) {
        Ok(path) if !path.is_empty() => {
            println!(
                "Using custom path from {} environment variable",
                TS_PROJECT_TEST_VECTORS_PATH_ENV_VAR
            );
            format!("{}{}", path, file_name)
        }
        _ => {
            println!("Using default TypeScript project path");
            format!("{}{}", DEFAULT_TS_PROJECT_TEST_VECTORS_PATH, file_name)
        }
    }
}

/// Write test vectors to TypeScript project path
/// 
/// Returns true if successful, false otherwise
/// 
/// If writing fails, it will print manual copy instructions
/// using the provided source file path
pub fn write_to_ts_project_path(file_name: &str, content: &str, source_file_path: &Path) -> bool {
    let ts_project_path = get_ts_project_path(file_name);
    println!("TypeScript project path: {}", ts_project_path);
    
    let ts_path = Path::new(&ts_project_path);
    match std::fs::write(ts_path, content) {
        Ok(()) => {
            println!(
                "✓ Test vectors successfully copied to TypeScript project: {:?}",
                ts_path
            );
            true
        }
        Err(e) => {
            println!(
                "Note: Couldn't copy to TypeScript project ({:?}): {}",
                ts_path, e
            );
            // Add manual copy instructions
            println!(
                "You'll need to manually copy the file from {:?} to the TypeScript project.",
                source_file_path
            );
            false
        }
    }
}
