# NuCypher Core: Cryptographic Protocol Structures for the NuCypher Network

This repository contains the Rust implementation of cryptographic protocol structures that power the NuCypher network, providing secure data sharing, access control, and threshold cryptography. The core implementation is in Rust, with cross-language bindings for Python and JavaScript (via WebAssembly).

- [Rust](https://github.com/nucypher/nucypher-core/tree/main/nucypher-core) (primary) [![crate][rust-crate-image]][rust-crate-link] [![Docs][rust-docs-image]][rust-docs-link] ![License][rust-license-image] [![Build Status][rust-build-image]][rust-build-link] [![Coverage][rust-coverage-image]][rust-coverage-link]
- [JavaScript](https://github.com/nucypher/nucypher-core/tree/main/nucypher-core-wasm) (WASM-based) [![npm package][js-npm-image]][js-npm-link] ![License][js-license-image]
- [Python](https://github.com/nucypher/nucypher-core/tree/main/nucypher-core-python) [![pypi package][pypi-image]][pypi-link] [![Docs][rtd-image]][rtd-link] ![License][pypi-license-image]

## Overview

NuCypher Core provides the cryptographic foundation for the NuCypher network, implementing:

- **Proxy Re-Encryption (PRE)**: Using the Umbral algorithm to enable secure data sharing without revealing encryption keys
- **Distributed Key Generation (DKG)**: For threshold cryptography that distributes trust across multiple parties
- **Condition-based Access Control**: Fine-grained policies to determine access to encrypted data
- **Secure Message Encryption**: For confidential communications between nodes
- **Cross-Platform Compatibility**: Protocol objects that can be seamlessly shared across language boundaries

## Architecture

NuCypher Core follows a modular architecture designed for security, flexibility, and cross-language compatibility:

- **Core Cryptographic Layer**: Implemented in Rust for performance and safety
- **Protocol Object Framework**: Provides serialization/deserialization with versioning support
- **Binding Layers**: Native interfaces for Python, JavaScript (via WASM), and TypeScript
- **No-std Support**: Core functionality works without the Rust standard library

## Key Components

- **Access Control System**:

  - `AccessControlPolicy`: Combines authenticated data with authorization
  - `AuthenticatedData`: Links encryption data with specific access conditions
  - `Conditions`: Expressive string-based policy descriptions
  - `encrypt_for_dkg()`: Encrypts data using conditions and DKG public keys

- **DKG (Distributed Key Generation)**:

  - Threshold cryptography infrastructure
  - Session management for secure key exchange
  - Encrypted request/response patterns for secure communications

- **Cryptographic Primitives**:
  - `MessageKit`: Tools for encrypting, decrypting, and re-encrypting messages
  - `ThresholdMessageKit`: Allows decryption when a minimum threshold of key fragments are collected
  - `ReencryptionRequest/Response`: Handles proxy re-encryption operations
  - `Ferveo Integration`: Advanced cryptography for enhanced security

[rust-crate-image]: https://img.shields.io/crates/v/nucypher-core.svg
[rust-crate-link]: https://crates.io/crates/nucypher-core
[rust-docs-image]: https://docs.rs/nucypher-core/badge.svg

## Installation

### Rust

Add nucypher-core to your Cargo.toml:

```toml
[dependencies]
nucypher-core = "0.14.0"
```

### JavaScript (via WASM)

Install from npm:

```bash
npm install @nucypher/nucypher-core
```

### Python

Install from PyPI:

```bash
pip install nucypher-core
```

### TypeScript Port

The TypeScript port for client functions is available in the taco-web repository and can be imported from there. It maintains API compatibility with the original Rust implementation while leveraging TypeScript's type system.

## Compatibility Test Vectors

This repository contains a script to generate test vectors for ensuring compatibility between the Rust implementation and other language ports, such as TypeScript.

### Generating Shared Secret Encryption Test Vectors

To generate test vectors for shared secret encryption/decryption compatibility:

```bash
# From the nucypher-core directory
cd nucypher-core
cargo test --test test_encryption_vectors -- --nocapture
```

This will:

1. Generate deterministic test vectors using fixed nonces for encryption/decryption compatibility testing
2. Save them to `tests/fixtures/shared-secret-vectors.json`
3. Attempt to copy them to the TypeScript project (if available at `../taco-web/packages/shared/test/fixtures/`)
4. Verify that all test vectors can be properly decrypted

The test vectors include:

- Basic encryption/decryption with fixed shared secrets and nonces
- Empty plaintext handling
- Rust-generated ciphertexts for cross-implementation compatibility verification

## Usage Examples

### Encrypt Data with Access Control

```rust
use nucypher_core::{AccessControlPolicy, AuthenticatedData, encrypt_for_dkg, Conditions};
use ferveo::api::DkgPublicKey;

// Create conditions for access control
let conditions = Conditions::new("policy_id: abc123");

// Get a DKG public key
let dkg_pk = DkgPublicKey::random();

// Encrypt data with conditions
let data = b"Secret message";
let (ciphertext, auth_data) = encrypt_for_dkg(data, &dkg_pk, &conditions).unwrap();

// Create access control policy
let authorization = b"authorization_data";
let acp = AccessControlPolicy::new(&auth_data, authorization);
```

### Cross-Language Interoperability

NuCypher Core is designed to allow seamless protocol object exchange between different language implementations. The same cryptographic operations can be performed with identical results across all supported languages.

Note: for the ported TypeScript code, refer to taco-web.

### Advanced Usage: Threshold Decryption

NuCypher Core supports threshold cryptography, where data can only be decrypted when a minimum number of key fragments are collected.

## Building from Source

### Prerequisites

- For WebAssembly: wasm-pack
- For Python bindings: Python 3.7+ and maturin

### Building Rust Crate

```bash
# Clone the repository
git clone https://github.com/nucypher/nucypher-core.git
cd nucypher-core

# Build the Rust library
cargo build

# Run tests
cargo test

# Build in release mode
cargo build --release
```

### Building WASM Bindings

```bash
cd nucypher-core-wasm
wasm-pack build --target web
```

### Building Python Bindings

```bash
cd nucypher-core-python
maturin build
```

## Project Structure

- **nucypher-core/**: Core Rust implementation
  - **src/**: Source code for all cryptographic operations
    - **access_control.rs**: Access control policies and authentication
    - **conditions.rs**: Condition-based access mechanisms
    - **dkg.rs**: Distributed Key Generation implementation
    - **message_kit.rs**: Message encryption/decryption tools
    - **threshold_message_kit.rs**: Threshold encryption mechanisms
    - **reencryption.rs**: Proxy Re-Encryption (PRE) implementation
    - And more component-specific modules
- **nucypher-core-wasm/**: WebAssembly bindings for JavaScript
- **nucypher-core-python/**: Python bindings

## Security Considerations

- Implements secure cryptographic primitives with formal security properties
- Uses Umbral PRE algorithm for secure proxy re-encryption
- Integrates Ferveo for advanced cryptography
- Zero-knowledge proof validation in key operations
- Constant-time operations for timing attack resistance
- Cross-platform validation ensures cryptographic consistency

## More Resources

- [Rust API Documentation](https://docs.rs/nucypher-core/)
- [Umbral PRE Algorithm](https://github.com/nucypher/rust-umbral)
- [NuCypher Network](https://www.nucypher.com/)
- [Threshold Cryptography Primer](https://en.wikipedia.org/wiki/Threshold_cryptosystem)
- [TACO: Threshold Asset Control Offering](https://docs.threshold.network/applications/taco)

[rust-docs-link]: https://docs.rs/nucypher-core/
[rust-license-image]: https://img.shields.io/crates/l/nucypher-core
[rust-build-image]: https://github.com/nucypher/nucypher-core/workflows/nucypher-core/badge.svg?branch=main&event=push
[rust-build-link]: https://github.com/nucypher/nucypher-core/actions?query=workflow%3Anucypher-core
[rust-coverage-image]: https://codecov.io/gh/nucypher/nucypher-core/branch/main/graph/badge.svg
[rust-coverage-link]: https://codecov.io/gh/nucypher/nucypher-core
[js-npm-image]: https://img.shields.io/npm/v/@nucypher/nucypher-core
[js-npm-link]: https://www.npmjs.com/package/@nucypher/nucypher-core
[js-license-image]: https://img.shields.io/npm/l/@nucypher/nucypher-core
[pypi-image]: https://img.shields.io/pypi/v/nucypher-core
[pypi-link]: https://pypi.org/project/nucypher-core/
[pypi-license-image]: https://img.shields.io/pypi/l/nucypher-core
[rtd-image]: https://readthedocs.org/projects/nucypher-core/badge/?version=latest
[rtd-link]: https://nucypher-core.readthedocs.io/en/latest/
