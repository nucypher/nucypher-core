# Rust implementation of Umbral proxy reencryption algorithm

[![crate][crate-image]][crate-link]
[![Docs][docs-image]][docs-link]
![License][license-image]
[![Build Status][build-image]][build-link]
[![Coverage][coverage-image]][coverage-link]

`nucypher-core` is the Rust implementation of the protocol objects for Nucypher network.

[Documentation][docs-link]

## Bindings

Bindings for several languages are available:

- [JavaScript](https://github.com/nucypher/nucypher-core/tree/main/nucypher-core-wasm) (WASM-based)
- [Python](https://github.com/nucypher/nucypher-core/tree/main/nucypher-core-python)

## Cross-Implementation Testing

This library tests generate test vectors for ensuring compatibility between different implementations. The test vector generators automatically produce JSON files in both the Rust project and the TypeScript project.

### Setting Custom Path for TypeScript Test Vectors

By default, the test vector generators will look for the TypeScript project at a relative path. If your project structure is different, you can customize the TypeScript project path using an environment variable:

```bash
# Generate both session key and shared secret test vectors with a single command
TS_PROJECT_TEST_VECTORS_PATH=/path/to/taco-web/packages/shared/test/fixtures/ cargo test -p nucypher-core --test generate_session_key_vectors --test generate_shared_secret_vectors

# Or run individual generators if needed
# Generate shared secret test vectors with custom TypeScript project path
TS_PROJECT_TEST_VECTORS_PATH=/path/to/taco-web/packages/shared/test/fixtures/ cargo test -p nucypher-core --test generate_shared_secret_vectors
# Generate session key test vectors with custom TypeScript project path
TS_PROJECT_TEST_VECTORS_PATH=/path/to/taco-web/packages/shared/test/fixtures/ cargo test -p nucypher-core --test generate_session_key_vectors
```

[crate-image]: https://img.shields.io/crates/v/nucypher-core.svg
[crate-link]: https://crates.io/crates/nucypher-core
[docs-image]: https://docs.rs/nucypher-core/badge.svg
[docs-link]: https://docs.rs/nucypher-core/
[license-image]: https://img.shields.io/crates/l/nucypher-core
[build-image]: https://github.com/nucypher/nucypher-core/workflows/nucypher-core/badge.svg?branch=main&event=push
[build-link]: https://github.com/nucypher/nucypher-core/actions?query=workflow%3Anucypher-core
[coverage-image]: https://codecov.io/gh/nucypher/nucypher-core/branch/main/graph/badge.svg
[coverage-link]: https://codecov.io/gh/nucypher/nucypher-core
