# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).


## [0.12.0] - Unreleased

### Changed

- Modified `ThresholdDecryptionResponse`  to use `CiphertextHeader` and `AccessControlPolicy` to utilize encapsulation now provided by `ferveo`. ([#74])

### Added

- Added `ThresholdMessageKit` which is the representation of data encrypted via `ferveo` that utilizes data encapsulation and ephemeral symmetric key. ([#74])
- Added `AccessControlPolicy` which contains access metadata (conditions, public key, authorization etc.) which forms part of the `ThresholdMessageKit`. ([#74])
- Added `AuthenticatedData` which forms part of the `AccessControlPolicy` and is needed to ensure that the aad is consistent during encryption process and during decryption process. ([#74])
- Added `encrypt_for_dkg` method for generation of `ferveo` `Ciphertext` and `AuthenticatedData`. ([#74])


[#74]: https://github.com/nucypher/nucypher-core/pull/74


## [0.11.0] - 2023-08-01

### Changed

- Bumped `umbral-pre` version to 0.11.0 and `ferveo-pre-release` version to 0.2.1 ([#72])
- Bumped MSRV to 1.67. ([#72])

### Added

- Expose `FerveoVariant` from `ferveo-pre-release` in Python bindings. ([#72])

[#72]: https://github.com/nucypher/nucypher-core/pull/72

## [0.10.0] - 2023-06-23

### Changed

- Custom (de)serialization of `SessionStaticKey` to bytestring instead of vector of integers. ([#63])
- Replaced raw tuples with `ValidatorMessage` in Python bindings. ([#65])
- Removed `DkgPublicParams` from bindings. ([#66])


### Added

- Added `equals` method to protocol objects in WASM bindings ([#56])


### Fixed

- Fixed a typo in the Python type stubs for `ferveo.Keypair.secure_randomness_size()`. ([#61])


[#56]: https://github.com/nucypher/nucypher-core/pull/56
[#61]: https://github.com/nucypher/nucypher-core/pull/61
[#63]: https://github.com/nucypher/nucypher-core/pull/63
[#65]: https://github.com/nucypher/nucypher-core/pull/65
[#66]: https://github.com/nucypher/nucypher-core/pull/66


## [0.9.0] - 2023-06-07

### Added

- Re-exported `ferveo` Python and WASM bindings. ([#58])
- Added `SessionSharedSecret`, `SessionStaticKey`, `SessionStaticSecret`, `SessionSecretFactory` as wrappers for underlying Curve 25519 key functionality. ([#54])
- Added Rust `pre-commit` hooks for repos. ([#54])
- Added `secret_box` functionality. ([#54])


### Changed

- Replaced opaque types with native `ferveo` types. ([#53])
- Removed `E2EThresholdDecryptionRequest` type and bindings. ([#54])
- Modified `EncryptedThresholdDecryptionRequest`/`EncryptedThresholdDecryptionResponse` to use Curve 25519 keys instead of Umbral keys for encryption/decryption. ([#54])
- Modified `ThresholdDecryptionResponse`/`EncryptedThresholdDecryptionResponse`  to include `ritual_id` member in struct. ([#54])
- Ritual ID for `ThresholdDecryption[Request/Response]` / `EncryptedThresholdDecryption[Request/Response]` is now u32 instead of u16. ([#54])


[#53]: https://github.com/nucypher/nucypher-core/pull/53
[#54]: https://github.com/nucypher/nucypher-core/pull/54
[#56]: https://github.com/nucypher/nucypher-core/pull/56
[#58]: https://github.com/nucypher/nucypher-core/pull/58


## [0.8.0] - 2023-05-23

### Added

- Add `EncryptedThresholdDecryptionRequest`/`EncryptedThresholdDecryptionResponse` types and bindings. ([#52])


### Changed

- Bumped MSRV to 1.65. ([#52])


[#52]: https://github.com/nucypher/nucypher-core/pull/52


## [0.7.0] - 2023-05-01

### Added

- Add `ThresholdDecryptionRequest`/`ThresholdDecryptionResponse` types and bindings. ([#48])
- Add `ferveo_public_key` field to `NodeMetadataPayload`. ([#48])


### Changed

- Bumped MSRV to 1.64. ([#48])


[#48]: https://github.com/nucypher/nucypher-core/pull/48


## [0.6.1] - 2023-02-18

### Fixed

- Fixed the type signature for `RecoverableSignature.from_be_bytes()` in Python bindings. ([#45])


[#45]: https://github.com/nucypher/rust-umbral/pull/45


## [0.6.0] - 2023-02-17

### Changed

- Bumped `umbral-pre` version to 0.9.1 and `PyO3` to 0.18. ([#44])
- `NodeMetadataPayload::operator_signature` now has the type `umbral_pre::RecoverableSignature`. ([#44])
- Major protocol versions bumped to 3 - ABI has changed (because of the changes in how `Signature` is serialized). ([#44])
- `FleetStateChecksum` argument order changed (because `PyO3` wants the optional argument to be the last). ([#44])
- `RECOVERABLE_SIGNATURE_SIZE` and `k256` removed from the exports. ([#44])


[#44]: https://github.com/nucypher/nucypher-core/pull/44


## [0.5.1] - 2023-01-17

### Added

- Add `wasm-pack build -t web` to the `Makefile` for use in web pages without a wasm aware bundler. ([#42])
- Re-exported `umbral-pre` bumped to 0.8.1. ([#43])


[#42]: https://github.com/nucypher/nucypher-core/pull/42
[#43]: https://github.com/nucypher/nucypher-core/pull/43


## [0.5.0] - 2023-01-16

### Changed

- Bumped MSRV to 1.63. ([#41])
- Bumped `umbral-pre` to 0.8 (with consequent API changes to the re-exported `umbral_pre` crate), `rmp-serde` to 1.x, `pyo3` to 0.17. ([#41])
- Major protocol versions bumped to 2 - ABI has changed. ([#41])


[#41]: https://github.com/nucypher/nucypher-core/pull/41


## [0.4.1] - 2022-10-22

### Fixed

- Finish up introducing the `Address` type in the spots forgotten in [#34]. Namely, in Python bindings: in `TreasureMap.destinations()`, in `RetrievalKit.queried_addresses()`, and in `NodeMetadata.staking_provider_address()`. ([#38])


[#38]: https://github.com/nucypher/nucypher-core/pull/38


## [0.4.0] - 2022-10-02

### Changed

- Conditions and context are now strings instead of bytestrings. ([#33])
- Methods taking `VerifiedCapsuleFrag` objects use "vcfrag" instead of "cfrag" for their names and the names of the corresponding parameters. ([#33])
- Use a workaround with `wasm-bindgen-derive` to support `Option<&T>` and `Vec<&T>` arguments, and `Vec<T>` and tuple return values, with correct TypeScript annotations. Removed all the Builder pattern helper classes. ([#34])
- Use `Address` instead of plain bytes in arguments and return values (both in WASM and Python bindgins). Export the `Address` type. ([#34])
- `umbral-pre` dependency bumped to 0.7. ([#36])
- `ReencryptionResponse::new()` now takes an iterator of pairs `(Capsule, VerifiedCapsuleFrag)` instead of two separate iterators; bindings changed correspondingly. ([#37])
- Change `Iterable` to `Sequence` in Python binding type stubs: bindings cannot actually take just iterables. ([#37])
- `AuthorizedKeyFrag.verify()`, `ReencryptionResponse.verify()`, and `AuthorizedTreasureMap.verify()` now consume `self`. ([#37])


### Added

- `conditions` getters in `MessageKit` and `RetrievalKit` in WASM bindings. ([#32])
- Attributes `MessageKit.conditions`, `ReencryptionRequest.conditions`, and `ReencryptionRequest.context` in Python typing stubs. ([#32])
- `Conditions` and `Context` newtypes, to be used instead of raw objects. ([#33])
- `MessageKit`, `RetrievalKit`, and `ReencryptionRequest` protocol versions bumped to v1.1. ([#33])


### Fixed

- Removed `serde` dependency for WASM bindings. ([#34])


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


[Unreleased]: https://github.com/nucypher/nucypher-core/compare/v0.11.0...HEAD
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
[0.6.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.6.0
[0.6.1]: https://github.com/nucypher/nucypher-core/releases/tag/v0.6.1
[0.7.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.7.0
[0.8.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.8.0
[0.9.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.9.0
[0.10.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.10.0
[0.11.0]: https://github.com/nucypher/nucypher-core/releases/tag/v0.11.0
