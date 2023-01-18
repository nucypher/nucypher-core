# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [Unreleased]

Under construction.


## [0.5.1] - 2023-01-17

### Added

- Add `wasm-pack build -t web` to the `Makefile` for use in web pages without a wasm aware bundler. ([#42])
- Re-exported `umbral-pre` bumped to 0.8.1. ([#43])


[#42]: https://github.com/nucypher/nucypher-core/pull/42
[#43]: https://github.com/nucypher/nucypher-core/pull/43


## [0.5.0] - 2023-01-16

### Changed

- Bumped MSRV to 1.63. (#[41])
- Bumped `umbral-pre` to 0.8 (with consequent API changes to the re-exported `umbral_pre` crate), `rmp-serde` to 1.x, `pyo3` to 0.17. (#[41])
- Major protocol versions bumped to 2 - ABI has changed. (#[41])


[#41]: https://github.com/nucypher/nucypher-core/pull/41


## [0.4.1] - 2022-10-22

### Fixed

- Finish up introducing the `Address` type in the spots forgotten in #[34]. Namely, in Python bindings: in `TreasureMap.destinations()`, in `RetrievalKit.queried_addresses()`, and in `NodeMetadata.staking_provider_address()`. (#[38])


[#38]: https://github.com/nucypher/nucypher-core/pull/38


## [0.4.0] - 2022-10-02

### Changed

- Conditions and context are now strings instead of bytestrings. (#[33])
- Methods taking `VerifiedCapsuleFrag` objects use "vcfrag" instead of "cfrag" for their names and the names of the corresponding parameters. (#[33])
- Use a workaround with `wasm-bindgen-derive` to support `Option<&T>` and `Vec<&T>` arguments, and `Vec<T>` and tuple return values, with correct TypeScript annotations. Removed all the Builder pattern helper classes. (#[34])
- Use `Address` instead of plain bytes in arguments and return values (both in WASM and Python bindgins). Export the `Address` type. (#[34])
- `umbral-pre` dependency bumped to 0.7. (#[36])
- `ReencryptionResponse::new()` now takes an iterator of pairs `(Capsule, VerifiedCapsuleFrag)` instead of two separate iterators; bindings changed correspondingly. (#[37])
- Change `Iterable` to `Sequence` in Python binding type stubs: bindings cannot actually take just iterables. (#[37])
- `AuthorizedKeyFrag.verify()`, `ReencryptionResponse.verify()`, and `AuthorizedTreasureMap.verify()` now consume `self`. (#[37])


### Added

- `conditions` getters in `MessageKit` and `RetrievalKit` in WASM bindings. (#[32])
- Attributes `MessageKit.conditions`, `ReencryptionRequest.conditions`, and `ReencryptionRequest.context` in Python typing stubs. ([#32])
- `Conditions` and `Context` newtypes, to be used instead of raw objects. (#[33])
- `MessageKit`, `RetrievalKit`, and `ReencryptionRequest` protocol versions bumped to v1.1. (#[33])


### Fixed

- Removed `serde` dependency for WASM bindings. (#[34])


[#32]: https://github.com/nucypher/nucypher-core/pull/32
[#33]: https://github.com/nucypher/nucypher-core/pull/33
[#34]: https://github.com/nucypher/nucypher-core/pull/34
[#36]: https://github.com/nucypher/nucypher-core/pull/36
[#37]: https://github.com/nucypher/nucypher-core/pull/37


## [0.4.0-alpha.0] - 2022-09-07

### Fixed

- Fixed the type annotation for `signer` in `generate_kfrags()` in Python type stubs. ([#28])

### Added

- `conditions` and `context` to `ReencryptionRequest` with python/wasm bindings to expose them. ([#26])
- `conditions` to `MessageKit` and `RetrievalKit` with python/wasm bindings to expose them. ([#26])
- Rust-native tests for these new attributes and getters. ([#26])


[#26]: https://github.com/nucypher/nucypher-core/pull/26
[#28]: https://github.com/nucypher/nucypher-core/pull/28


## [0.3.0] - 2022-08-16

### Changed

- Bumped `umbral-pre` to 0.6, and the nested dependencies accordingly. ([#17])
- Following the changes in `umbral-pre` 0.6, the types that were `serde`-serialized in human readable formats as hex will now have a `"0x"` prefix. ([#17])


### Added

- `Eq` marker for `HRAC` and `FleetStateChecksum`. ([#17])
- Python typing stubs. ([#20])
- The Python module `nucypher_core.umbral` now exports `KeyFrag`. ([#20])
- `Display` impl for `HRAC` and `FleetStateChecksum`, and exposed it in the Python and WASM bindings. ([#22])


[#17]: https://github.com/nucypher/nucypher-core/pull/17
[#20]: https://github.com/nucypher/nucypher-core/pull/20
[#22]: https://github.com/nucypher/nucypher-core/pull/22


## [0.2.0] - 2022-04-24

### Changed

- Changed from `sha3_256` to `Keccak` when building `FleetState` and `HRAC`. ([#15])


[#15]: https://github.com/nucypher/nucypher-core/pull/15


## [0.1.1] - 2022-03-15

### Fixed

- `umbral-pre` bumped to 0.5.2 and `k256` bumped to 0.10.4 to make use of an important bugfix (see https://github.com/RustCrypto/elliptic-curves/issues/529). Previous 0.1.* versions (using `k256` 0.10.2 with the bug) are yanked.


## [0.1.0] - 2022-03-14

### Changed

- Renamed `staker_address` to `staking_provider_address` in `NodeMetadataPayload` fields and `RevocationOrder::new` parameters. ([#10])
- Renamed `NodeMetadataPayload.decentralized_identity_evidence` to `operator_signature`. ([#10])
- Declared `NodeMetadataPayload.operator_signature` as `recoverable::Signature` instead of just a byte array. This allows the user to detect an invalid signature on `NodeMetadata` creation. ([#11])
- Renamed `NodeMetadataPayload.certificate_bytes` to `certificate_der` (although it is not deserialized on the Rust side, so the DER format is not strictly enforced). ([#13])
- Changed some method and field names in WASM bindings to conform to JS style (camel case). New names are: `TreasureMap.publisherVerifyingKey`, `TreasureMap.bobVerifyingKey`, `TreasureMap.encryptedKfrag`, `RetrievalKit.queriedAddresses`, `RevocationOrder.verifySignature`, `NodeMetadataPayload.verifyingKey`, `NodeMetadataPayload.encryptingKey`, `NodeMetadataPayload.timestampEpoch`, `MetadataRequest.announceNodes`. ([#9])
- Moved `ADDRESS_SIZE` to `Address::SIZE`. ([#14])
- `MetadataResponse::verify()` and `ReencryptionResponse::verify()` return a `Result` instead of `Option`. ([#14])
- Renamed `RevocationOrder::verify_signature()` to `verify()` and made it return a `Result<(Address, EncryptedKeyFrag)>`. ([#14])


### Added

- `TreasureMap::make_revocation_orders()` (with the corresponding methods in Python and WASM bindings). ([#9])
- `HRAC.fromBytes()` in WASM bindings ([#9]), and in Python bindings ([#14]).
- `RevocationOrder.stakingProviderAddress` in WASM bindings. ([#9])
- `MetadataResponse.verify()` in WASM bindings. ([#9])
- `impl From<[u8; 16]>` for `HRAC`. ([#9])
- Made `RevocationOrder.staking_provider_address` public. ([#9]) Rolled back in ([#14]) in favor of the return value from `verify()`.
- `HRAC::SIZE` constant ([#14])
- `VerificationError` for use in various `verify()` methods. ([#14])


### Fixed

- Some methods in WASM bindings that were previously taking `self` are now taking `&self`, leading to a more idiomatic behavior in JS. ([#9])


[#9]: https://github.com/nucypher/nucypher-core/pull/9
[#10]: https://github.com/nucypher/nucypher-core/pull/10
[#11]: https://github.com/nucypher/nucypher-core/pull/11
[#13]: https://github.com/nucypher/nucypher-core/pull/13
[#14]: https://github.com/nucypher/nucypher-core/pull/14


## [0.0.4] - 2022-02-09

### Changed

- Changed "worker" to "operator" in the API, according to the new terminology. ([#5])


[#5]: https://github.com/nucypher/nucypher-core/pull/5


## [0.0.3] - 2022-02-03

### Fixed

- Added the manifest to the Python bindings package, fixing the source distribution build.


## [0.0.2] - 2022-01-25

### Changed

- `umbral-pre` dependency bumped to 0.5 (and to match it, MSRV to 1.56, and Rust edition to 2021). The API was updated accordingly (mainly due to the no-clone approach). Note that this changes the ABI as well. ([#4])
- `NodeMetadataPayload.decentralized_identity_evidence` is now a fixed-sized array in the serialized metadata. ([#2])
- `k256` dependency bumped to 0.10, and `umbral-pre` to 0.5. ([#2])
- `NodeMetadataPayload.canonical_address` and the parameter `ursula_address` of `RevocationOrder::new()` are renamed to `staker_address`. ([#2])


### Added

- WASM bindings. ([#1])
- `NodeMetadataPayload::derive_worker_address()` method. ([#2])


[#1]: https://github.com/nucypher/nucypher-core/pull/1
[#2]: https://github.com/nucypher/nucypher-core/pull/2
[#4]: https://github.com/nucypher/nucypher-core/pull/4


## [0.0.1] - 2021-12-25

Initial release.


[Unreleased]: https://github.com/nucypher/nucypher-core/compare/v0.5.1...HEAD
[0.0.1]: https://github.com/nucypher/nucypher-core/releases/tag/v0.0.1
[0.0.2]: https://github.com/nucypher/nucypher-core/releases/tag/v0.0.2
[0.0.3]: https://github.com/nucypher/nucypher-core/releases/tag/v0.0.3
[0.0.4]: https://github.com/nucypher/nucypher-core/releases/tag/v0.0.4
[0.1.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.1.0
[0.1.1]: https://github.com/nucypher/nucypher-core/releases/tag/v0.1.1
[0.2.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.2.0
[0.3.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.3.0
[0.4.0-alpha.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.4.0-alpha.0
[0.4.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.4.0
[0.4.1]: https://github.com/nucypher/nucypher-core/releases/tag/v0.4.1
[0.5.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.5.0
[0.5.1]: https://github.com/nucypher/nucypher-core/releases/tag/v0.5.1
