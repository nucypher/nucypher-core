#![no_std]

// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern crate alloc;
use serde::{Deserialize, Serialize};

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use js_sys::Error;
use nucypher_core::{DeserializableFromBytes, SerializableToBytes};
use umbral_pre::bindings_wasm::{
    Capsule, PublicKey, SecretKey, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

fn map_js_err<T: fmt::Display>(err: T) -> JsValue {
    Error::new(&format!("{}", err)).into()
}

trait AsBackend<T> {
    fn as_backend(&self) -> &T;
}

trait FromBackend<T> {
    fn from_backend(backend: T) -> Self;
}

fn to_bytes<T, U>(obj: &T) -> Box<[u8]>
where
    T: AsBackend<U>,
    U: SerializableToBytes,
{
    obj.as_backend().to_bytes()
}

fn from_bytes<'a, T, U>(data: &'a [u8]) -> Result<T, JsValue>
where
    T: FromBackend<U>,
    U: DeserializableFromBytes<'a>,
{
    U::from_bytes(data).map(T::from_backend).map_err(map_js_err)
}

//
// MessageKit
//

#[wasm_bindgen]
#[derive(PartialEq, Debug)]
pub struct MessageKit {
    backend: nucypher_core::MessageKit,
}

impl AsBackend<nucypher_core::MessageKit> for MessageKit {
    fn as_backend(&self) -> &nucypher_core::MessageKit {
        &self.backend
    }
}

impl FromBackend<nucypher_core::MessageKit> for MessageKit {
    fn from_backend(backend: nucypher_core::MessageKit) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl MessageKit {
    #[wasm_bindgen(constructor)]
    pub fn new(policy_encrypting_key: &PublicKey, plaintext: &[u8]) -> Result<MessageKit, JsValue> {
        nucypher_core::MessageKit::new(policy_encrypting_key.inner(), plaintext)
            .map(|mk| MessageKit { backend: mk })
            .map_err(map_js_err)
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Result<Box<[u8]>, JsValue> {
        self.backend.decrypt(sk.inner()).map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = decryptReencrypted)]
    pub fn decrypt_reencrypted(
        &self,
        sk: &SecretKey,
        policy_encrypting_key: &PublicKey,
        cfrags: &JsValue,
    ) -> Result<Box<[u8]>, JsValue> {
        let cfrags: Vec<VerifiedCapsuleFrag> = cfrags
            .into_serde()
            .unwrap_or_else(|_| panic!("cfrags must be an array of VerifiedCapsuleFrag"));
        let backend_cfrags: Vec<umbral_pre::VerifiedCapsuleFrag> =
            cfrags.iter().map(|vcfrag| vcfrag.inner().clone()).collect();

        self.backend
            .decrypt_reencrypted(sk.inner(), policy_encrypting_key.inner(), &backend_cfrags)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(method, getter)]
    pub fn capsule(&self) -> Capsule {
        Capsule::new(self.backend.capsule)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<MessageKit, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// HRAC
//

#[wasm_bindgen]
#[derive(PartialEq)]
pub struct HRAC {
    backend: nucypher_core::HRAC,
}

impl AsBackend<nucypher_core::HRAC> for HRAC {
    fn as_backend(&self) -> &nucypher_core::HRAC {
        &self.backend
    }
}

impl FromBackend<nucypher_core::HRAC> for HRAC {
    fn from_backend(backend: nucypher_core::HRAC) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl HRAC {
    #[wasm_bindgen(constructor)]
    pub fn new(
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        label: &[u8],
    ) -> HRAC {
        Self {
            backend: nucypher_core::HRAC::new(
                publisher_verifying_key.inner(),
                bob_verifying_key.inner(),
                label,
            ),
        }
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<HRAC, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

impl HRAC {
    pub fn inner(&self) -> nucypher_core::HRAC {
        self.backend
    }
}

//
// EncryptedKeyFrag
//

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct EncryptedKeyFrag {
    backend: nucypher_core::EncryptedKeyFrag,
}

impl AsBackend<nucypher_core::EncryptedKeyFrag> for EncryptedKeyFrag {
    fn as_backend(&self) -> &nucypher_core::EncryptedKeyFrag {
        &self.backend
    }
}

impl FromBackend<nucypher_core::EncryptedKeyFrag> for EncryptedKeyFrag {
    fn from_backend(backend: nucypher_core::EncryptedKeyFrag) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl EncryptedKeyFrag {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        recipient_key: &PublicKey,
        hrac: &HRAC,
        verified_kfrag: &VerifiedKeyFrag,
    ) -> Result<EncryptedKeyFrag, JsValue> {
        nucypher_core::EncryptedKeyFrag::new(
            signer.inner(),
            recipient_key.inner(),
            &hrac.backend,
            verified_kfrag.inner(),
        )
        .map_err(map_js_err)
        .map(|ekfrag| EncryptedKeyFrag { backend: ekfrag })
    }

    pub fn decrypt(
        &self,
        sk: &SecretKey,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> Result<VerifiedKeyFrag, JsValue> {
        self.backend
            .decrypt(sk.inner(), &hrac.inner(), publisher_verifying_key.inner())
            .ok_or("Decryption failed")
            .map_err(map_js_err)
            .map(VerifiedKeyFrag::new)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<EncryptedKeyFrag, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

impl EncryptedKeyFrag {
    pub fn inner(&self) -> nucypher_core::EncryptedKeyFrag {
        self.backend.clone()
    }
}

//
// Address
//

#[wasm_bindgen]
#[derive(Clone)]
pub struct Address(ethereum_types::Address);

#[wasm_bindgen]
impl Address {
    #[wasm_bindgen(js_name = fromChecksumAddress)]
    pub fn from_checksum_address(checksum_address: &str) -> Self {
        // TODO: Check length of checksum_address
        Address(nucypher_core::to_canonical_address(checksum_address).unwrap())
    }
}

impl Address {
    pub fn as_string(&self) -> String {
        self.0.to_string()
    }
}

//
// TreasureMap
//

#[wasm_bindgen]
#[derive(Clone, PartialEq, Debug)]
pub struct TreasureMap {
    backend: nucypher_core::TreasureMap,
}

impl AsBackend<nucypher_core::TreasureMap> for TreasureMap {
    fn as_backend(&self) -> &nucypher_core::TreasureMap {
        &self.backend
    }
}

impl FromBackend<nucypher_core::TreasureMap> for TreasureMap {
    fn from_backend(backend: nucypher_core::TreasureMap) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl TreasureMap {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        hrac: &HRAC,
        policy_encrypting_key: &PublicKey,
        assigned_kfrags: JsValue,
        threshold: usize,
    ) -> Result<TreasureMap, JsValue> {
        // Using String here to avoid issue where Deserialize is not implemented
        // for every possible lifetime.
        let assigned_kfrags: BTreeMap<String, (PublicKey, VerifiedKeyFrag)> =
            serde_wasm_bindgen::from_value(assigned_kfrags)?;
        let assigned_kfrags_backend = assigned_kfrags
            .iter()
            // TODO: check `address` size
            .map(|(address, (key, vkfrag))| {
                (
                    ethereum_types::Address::from_slice(address.as_bytes()),
                    key.inner().clone(),
                    vkfrag.inner().clone(),
                )
            })
            .collect::<Vec<_>>();
        Ok(Self {
            backend: nucypher_core::TreasureMap::new(
                signer.inner(),
                &hrac.backend,
                policy_encrypting_key.inner(),
                &assigned_kfrags_backend,
                threshold,
            )
            .ok()
            .ok_or("TreasureMap creation failed")?,
        })
    }

    pub fn encrypt(&self, signer: &Signer, recipient_key: &PublicKey) -> EncryptedTreasureMap {
        EncryptedTreasureMap {
            backend: self.backend.encrypt(signer.inner(), recipient_key.inner()),
        }
    }

    #[wasm_bindgen(method, getter)]
    pub fn destinations(&self) -> Result<JsValue, JsValue> {
        let mut result = Vec::new();
        for (address, ekfrag) in &self.backend.destinations {
            // Using String here to avoid issue where Deserialize is not implemented
            // for every possible lifetime.
            let address = String::from(from_canonical(address));
            result.push((
                address,
                EncryptedKeyFrag {
                    backend: ekfrag.clone(),
                },
            ));
        }
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    #[wasm_bindgen(method, getter)]
    pub fn hrac(&self) -> HRAC {
        HRAC {
            backend: self.backend.hrac,
        }
    }

    #[wasm_bindgen(method, getter)]
    pub fn threshold(&self) -> usize {
        self.backend.threshold
    }

    #[wasm_bindgen(method, getter, js_name = policyEncryptingKey)]
    pub fn policy_encrypting_key(&self) -> PublicKey {
        PublicKey::new(self.backend.policy_encrypting_key)
    }

    #[wasm_bindgen(method, getter, js_name = publisherVerifyingKey)]
    pub fn publisher_verifying_key(&self) -> PublicKey {
        PublicKey::new(self.backend.publisher_verifying_key)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<TreasureMap, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

#[wasm_bindgen]
#[derive(PartialEq, Debug)]
pub struct EncryptedTreasureMap {
    backend: nucypher_core::EncryptedTreasureMap,
}

impl AsBackend<nucypher_core::EncryptedTreasureMap> for EncryptedTreasureMap {
    fn as_backend(&self) -> &nucypher_core::EncryptedTreasureMap {
        &self.backend
    }
}

impl FromBackend<nucypher_core::EncryptedTreasureMap> for EncryptedTreasureMap {
    fn from_backend(backend: nucypher_core::EncryptedTreasureMap) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl EncryptedTreasureMap {
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        publisher_verifying_key: &PublicKey,
    ) -> Result<TreasureMap, JsValue> {
        self.backend
            .decrypt(sk.inner(), publisher_verifying_key.inner())
            .ok_or("Invalid secret key")
            .map_err(map_js_err)
            .map(|treasure_map| TreasureMap {
                backend: treasure_map,
            })
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<EncryptedTreasureMap, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// ReencryptionRequest
//

#[wasm_bindgen]
#[derive(PartialEq, Debug)]
pub struct ReencryptionRequest {
    backend: nucypher_core::ReencryptionRequest,
}

impl AsBackend<nucypher_core::ReencryptionRequest> for ReencryptionRequest {
    fn as_backend(&self) -> &nucypher_core::ReencryptionRequest {
        &self.backend
    }
}

impl FromBackend<nucypher_core::ReencryptionRequest> for ReencryptionRequest {
    fn from_backend(backend: nucypher_core::ReencryptionRequest) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl ReencryptionRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ursula_address: &[u8],
        capsules: JsValue,
        treasure_map: &TreasureMap,
        bob_verifying_key: &PublicKey,
    ) -> Result<ReencryptionRequest, JsValue> {
        let capsules: Vec<Capsule> =
            serde_wasm_bindgen::from_value(capsules).map_err(map_js_err)?;
        // TODO: check length
        let address = ethereum_types::Address::from_slice(ursula_address);
        let capsules_backend = capsules
            .iter()
            .map(|capsule| *capsule.inner())
            .collect::<Vec<_>>();
        Ok(Self {
            backend: nucypher_core::ReencryptionRequest::new(
                &address,
                &capsules_backend,
                &treasure_map.backend,
                bob_verifying_key.inner(),
            ),
        })
    }

    #[wasm_bindgen(method, getter)]
    pub fn hrac(&self) -> HRAC {
        HRAC {
            backend: self.backend.hrac,
        }
    }

    #[wasm_bindgen(method, getter)]
    pub fn publisher_verifying_key(&self) -> PublicKey {
        PublicKey::new(self.backend.publisher_verifying_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn bob_verifying_key(&self) -> PublicKey {
        PublicKey::new(self.backend.bob_verifying_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn encrypted_kfrag(&self) -> EncryptedKeyFrag {
        EncryptedKeyFrag {
            backend: self.backend.encrypted_kfrag.clone(),
        }
    }

    #[wasm_bindgen(method, getter)]
    pub fn capsules(&self) -> Vec<JsValue> {
        self.backend
            .capsules
            .iter()
            .map(|capsule| Capsule::new(*capsule))
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<ReencryptionRequest, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

impl ReencryptionRequest {
    pub fn inner(&self) -> nucypher_core::ReencryptionRequest {
        self.backend.clone()
    }
}

//
// ReencryptionResponse
//

#[wasm_bindgen]
pub struct ReencryptionResponse {
    backend: nucypher_core::ReencryptionResponse,
}

impl AsBackend<nucypher_core::ReencryptionResponse> for ReencryptionResponse {
    fn as_backend(&self) -> &nucypher_core::ReencryptionResponse {
        &self.backend
    }
}

impl FromBackend<nucypher_core::ReencryptionResponse> for ReencryptionResponse {
    fn from_backend(backend: nucypher_core::ReencryptionResponse) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl ReencryptionResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        capsules: &JsValue,
        verified_capsule_frags: &JsValue,
    ) -> Result<ReencryptionResponse, JsValue> {
        let capsules: Vec<Capsule> =
            serde_wasm_bindgen::from_value(capsules.clone()).map_err(map_js_err)?;
        let vcfrags: Vec<VerifiedCapsuleFrag> =
            serde_wasm_bindgen::from_value(verified_capsule_frags.clone()).map_err(map_js_err)?;

        let capsules_backend = capsules
            .iter()
            .map(|capsule| *capsule.inner())
            .collect::<Vec<_>>();
        let vcfrags_backend = vcfrags
            .iter()
            .map(|vcfrag| vcfrag.inner().clone())
            .collect::<Vec<_>>();
        Ok(ReencryptionResponse {
            backend: nucypher_core::ReencryptionResponse::new(
                signer.inner(),
                &capsules_backend,
                &vcfrags_backend,
            ),
        })
    }

    pub fn verify(
        &self,
        capsules: &JsValue,
        alice_verifying_key: &PublicKey,
        ursula_verifying_key: &PublicKey,
        policy_encrypting_key: &PublicKey,
        bob_encrypting_key: &PublicKey,
    ) -> Result<JsValue, JsValue> {
        let capsules: Vec<Capsule> =
            serde_wasm_bindgen::from_value(capsules.clone()).map_err(map_js_err)?;
        let capsules_backend = capsules
            .iter()
            .map(|capsule| *capsule.inner())
            .collect::<Vec<_>>();
        let vcfrags_backend = self
            .backend
            .verify(
                &capsules_backend,
                alice_verifying_key.inner(),
                ursula_verifying_key.inner(),
                policy_encrypting_key.inner(),
                bob_encrypting_key.inner(),
            )
            .unwrap();
        serde_wasm_bindgen::to_value(
            &vcfrags_backend
                .iter()
                .map(|vcfrag| VerifiedCapsuleFrag::new(vcfrag.clone()))
                .collect::<Vec<_>>(),
        )
        .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<ReencryptionResponse, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// RetrievalKit
//

#[wasm_bindgen]
pub struct RetrievalKit {
    backend: nucypher_core::RetrievalKit,
}

impl AsBackend<nucypher_core::RetrievalKit> for RetrievalKit {
    fn as_backend(&self) -> &nucypher_core::RetrievalKit {
        &self.backend
    }
}

impl FromBackend<nucypher_core::RetrievalKit> for RetrievalKit {
    fn from_backend(backend: nucypher_core::RetrievalKit) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl RetrievalKit {
    #[wasm_bindgen(js_name = fromMessageKit)]
    pub fn from_message_kit(message_kit: &MessageKit) -> Self {
        Self {
            backend: nucypher_core::RetrievalKit::from_message_kit(&message_kit.backend),
        }
    }

    #[wasm_bindgen(constructor)]
    pub fn new(capsule: &Capsule, queried_addresses: JsValue) -> Result<RetrievalKit, JsValue> {
        // Using String here to avoid issue where Deserialize is not implemented
        // for every possible lifetime.
        let queried_addresses: Vec<String> = serde_wasm_bindgen::from_value(queried_addresses)?;
        let addresses_backend = queried_addresses
            .iter()
            // TODO: check slice length first
            .map(|address| ethereum_types::Address::from_slice(address.as_bytes()))
            .collect::<Vec<_>>();
        Ok(Self {
            backend: nucypher_core::RetrievalKit::new(capsule.inner(), addresses_backend.iter()),
        })
    }

    #[wasm_bindgen(method, getter)]
    pub fn capsule(&self) -> Capsule {
        Capsule::new(self.backend.capsule)
    }

    #[wasm_bindgen(method, getter)]
    pub fn queried_addresses(&self) -> Vec<JsValue> {
        self.backend
            .queried_addresses
            .iter()
            .map(|address| JsValue::from_serde(&address).unwrap())
            .collect::<Vec<_>>()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<RetrievalKit, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// RevocationOrder
//

#[wasm_bindgen]
pub struct RevocationOrder {
    backend: nucypher_core::RevocationOrder,
}

impl AsBackend<nucypher_core::RevocationOrder> for RevocationOrder {
    fn as_backend(&self) -> &nucypher_core::RevocationOrder {
        &self.backend
    }
}

impl FromBackend<nucypher_core::RevocationOrder> for RevocationOrder {
    fn from_backend(backend: nucypher_core::RevocationOrder) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl RevocationOrder {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, ursula_address: &[u8], encrypted_kfrag: &EncryptedKeyFrag) -> Self {
        // TODO: check length
        let address = ethereum_types::Address::from_slice(ursula_address);
        Self {
            backend: nucypher_core::RevocationOrder::new(
                signer.inner(),
                &address,
                &encrypted_kfrag.backend,
            ),
        }
    }

    #[wasm_bindgen]
    pub fn verify_signature(&self, alice_verifying_key: &PublicKey) -> bool {
        self.backend.verify_signature(alice_verifying_key.inner())
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<RevocationOrder, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// NodeMetadataPayload
//

// TODO: Find a way to avoid this conversion?
pub fn from_canonical(data: &ethereum_types::H160) -> &str {
    core::str::from_utf8(&data[..]).unwrap()
}

#[wasm_bindgen]
pub struct NodeMetadataPayload {
    backend: nucypher_core::NodeMetadataPayload,
}

#[wasm_bindgen]
impl NodeMetadataPayload {
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(constructor)]
    pub fn new(
        canonical_address: &[u8],
        domain: &str,
        timestamp_epoch: u32,
        verifying_key: &PublicKey,
        encrypting_key: &PublicKey,
        certificate_bytes: &[u8],
        host: &str,
        port: u16,
        decentralized_identity_evidence: Option<Vec<u8>>,
    ) -> Self {
        // TODO: check slice length first
        let address = ethereum_types::Address::from_slice(canonical_address);
        Self {
            backend: nucypher_core::NodeMetadataPayload {
                canonical_address: address,
                domain: domain.to_string(),
                timestamp_epoch,
                verifying_key: *verifying_key.inner(),
                encrypting_key: *encrypting_key.inner(),
                certificate_bytes: certificate_bytes.into(),
                host: host.to_string(),
                port,
                decentralized_identity_evidence: decentralized_identity_evidence
                    .map(|v| v.into_boxed_slice()),
            },
        }
    }

    #[wasm_bindgen(method, getter)]
    pub fn canonical_address(&self) -> Address {
        Address::from_checksum_address(from_canonical(&self.backend.canonical_address))
    }

    #[wasm_bindgen(method, getter)]
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::new(self.backend.verifying_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn encrypting_key(&self) -> PublicKey {
        PublicKey::new(self.backend.encrypting_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn decentralized_identity_evidence(&self) -> Option<Box<[u8]>> {
        self.backend.decentralized_identity_evidence.clone()
    }

    #[wasm_bindgen(method, getter)]
    pub fn domain(&self) -> String {
        self.backend.domain.clone()
    }

    #[wasm_bindgen(method, getter)]
    pub fn host(&self) -> String {
        self.backend.host.clone()
    }

    #[wasm_bindgen(method, getter)]
    pub fn port(&self) -> u16 {
        self.backend.port
    }

    #[wasm_bindgen(method, getter)]
    pub fn timestamp_epoch(&self) -> u32 {
        self.backend.timestamp_epoch
    }

    #[wasm_bindgen(method, getter)]
    pub fn certificate_bytes(&self) -> Box<[u8]> {
        self.backend.certificate_bytes.clone()
    }
}

//
// NodeMetadata
//

#[wasm_bindgen(method, getter)]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct NodeMetadata {
    backend: nucypher_core::NodeMetadata,
}

impl AsBackend<nucypher_core::NodeMetadata> for NodeMetadata {
    fn as_backend(&self) -> &nucypher_core::NodeMetadata {
        &self.backend
    }
}

impl FromBackend<nucypher_core::NodeMetadata> for NodeMetadata {
    fn from_backend(backend: nucypher_core::NodeMetadata) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl NodeMetadata {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        Self {
            backend: nucypher_core::NodeMetadata::new(signer.inner(), &payload.backend),
        }
    }

    pub fn verify(&self) -> bool {
        self.backend.verify()
    }

    #[wasm_bindgen(method, getter)]
    pub fn payload(&self) -> NodeMetadataPayload {
        NodeMetadataPayload {
            backend: self.backend.payload.clone(),
        }
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<NodeMetadata, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// FleetStateChecksum
//

#[wasm_bindgen]
pub struct FleetStateChecksum {
    backend: nucypher_core::FleetStateChecksum,
}

impl AsBackend<nucypher_core::FleetStateChecksum> for FleetStateChecksum {
    fn as_backend(&self) -> &nucypher_core::FleetStateChecksum {
        &self.backend
    }
}

impl FromBackend<nucypher_core::FleetStateChecksum> for FleetStateChecksum {
    fn from_backend(backend: nucypher_core::FleetStateChecksum) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl FleetStateChecksum {
    #[wasm_bindgen(constructor)]
    pub fn new(
        // TODO: Fix lack of reference leading to accidental freeing of memory
        //       https://github.com/rustwasm/wasm-bindgen/issues/2370
        // this_node: Option<&NodeMetadata>,
        this_node: Option<NodeMetadata>,
        other_nodes: JsValue,
    ) -> Result<FleetStateChecksum, JsValue> {
        let other_nodes: Vec<NodeMetadata> = serde_wasm_bindgen::from_value(other_nodes)?;
        let other_nodes_backend = other_nodes
            .iter()
            .map(|node| node.backend.clone())
            .collect::<Vec<_>>();
        Ok(Self {
            backend: nucypher_core::FleetStateChecksum::from_nodes(
                this_node.map(|node| node.backend).as_ref(),
                &other_nodes_backend,
            ),
        })
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<FleetStateChecksum, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// MetadataRequest
//

#[wasm_bindgen]
pub struct MetadataRequest {
    backend: nucypher_core::MetadataRequest,
}

impl AsBackend<nucypher_core::MetadataRequest> for MetadataRequest {
    fn as_backend(&self) -> &nucypher_core::MetadataRequest {
        &self.backend
    }
}

impl FromBackend<nucypher_core::MetadataRequest> for MetadataRequest {
    fn from_backend(backend: nucypher_core::MetadataRequest) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl MetadataRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        fleet_state_checksum: &FleetStateChecksum,
        announce_nodes: JsValue,
    ) -> Result<MetadataRequest, JsValue> {
        let announce_nodes: Vec<NodeMetadata> = serde_wasm_bindgen::from_value(announce_nodes)?;
        let nodes_backend = announce_nodes
            .iter()
            .map(|node| node.backend.clone())
            .collect::<Vec<_>>();
        Ok(Self {
            backend: nucypher_core::MetadataRequest::new(
                &fleet_state_checksum.backend,
                &nodes_backend,
            ),
        })
    }

    #[wasm_bindgen(method, getter, js_name = fleetStateChecksum)]
    pub fn fleet_state_checksum(&self) -> FleetStateChecksum {
        FleetStateChecksum {
            backend: self.backend.fleet_state_checksum,
        }
    }

    #[wasm_bindgen(method, getter, js_name = announceNodes)]
    pub fn announce_nodes(&self) -> Vec<JsValue> {
        self.backend
            .announce_nodes
            .iter()
            .map(|node| NodeMetadata {
                backend: node.clone(),
            })
            .map(JsValue::from)
            .collect()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<MetadataRequest, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// VerifiedMetadataResponse
//

#[wasm_bindgen]
pub struct VerifiedMetadataResponse {
    backend: nucypher_core::VerifiedMetadataResponse,
}

#[wasm_bindgen]
impl VerifiedMetadataResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(timestamp_epoch: u32, announce_nodes: JsValue) -> Self {
        let announce_nodes: Vec<NodeMetadata> =
            serde_wasm_bindgen::from_value(announce_nodes).unwrap();
        let nodes_backend = announce_nodes
            .iter()
            .map(|node| node.backend.clone())
            .collect::<Vec<_>>();
        VerifiedMetadataResponse {
            backend: nucypher_core::VerifiedMetadataResponse::new(timestamp_epoch, &nodes_backend),
        }
    }

    #[wasm_bindgen(method, getter)]
    pub fn timestamp_epoch(&self) -> u32 {
        self.backend.timestamp_epoch
    }

    #[wasm_bindgen(method, getter)]
    pub fn announce_nodes(&self) -> Vec<JsValue> {
        self.backend
            .announce_nodes
            .iter()
            .map(|node| NodeMetadata {
                backend: node.clone(),
            })
            .map(JsValue::from)
            .collect()
    }
}

//
// MetadataResponse
//

#[wasm_bindgen]
pub struct MetadataResponse {
    backend: nucypher_core::MetadataResponse,
}

impl AsBackend<nucypher_core::MetadataResponse> for MetadataResponse {
    fn as_backend(&self) -> &nucypher_core::MetadataResponse {
        &self.backend
    }
}

impl FromBackend<nucypher_core::MetadataResponse> for MetadataResponse {
    fn from_backend(backend: nucypher_core::MetadataResponse) -> Self {
        Self { backend }
    }
}

#[wasm_bindgen]
impl MetadataResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, response: &VerifiedMetadataResponse) -> Self {
        Self {
            backend: nucypher_core::MetadataResponse::new(signer.inner(), &response.backend),
        }
    }

    pub fn verify(&self, verifying_pk: &PublicKey) -> Result<VerifiedMetadataResponse, JsValue> {
        self.backend
            .verify(verifying_pk.inner())
            .ok_or("Invalid signature")
            .map_err(map_js_err)
            .map(|backend| VerifiedMetadataResponse { backend })
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<MetadataResponse, JsValue> {
        from_bytes(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}
