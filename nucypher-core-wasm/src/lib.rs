#![no_std]

// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern crate alloc;
use nucypher_core::ProtocolObject;
use serde::{Deserialize, Serialize};

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;
use js_sys::{Error, Uint8Array};
use umbral_pre::bindings_wasm::{
    Capsule, PublicKey, SecretKey, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
};
use wasm_bindgen::{
    prelude::{wasm_bindgen, JsValue},
    JsCast,
};

fn map_js_err<T: fmt::Display>(err: T) -> JsValue {
    Error::new(&format!("{}", err)).into()
}

trait AsBackend<T> {
    fn as_backend(&self) -> &T;
}

trait FromBackend<T> {
    fn from_backend(backend: T) -> Self;
}

fn to_bytes<'a, T, U>(obj: &T) -> Box<[u8]>
where
    T: AsBackend<U>,
    U: ProtocolObject<'a>,
{
    obj.as_backend().to_bytes()
}

fn from_bytes<'a, T, U>(data: &'a [u8]) -> Result<T, JsValue>
where
    T: FromBackend<U>,
    U: ProtocolObject<'a>,
{
    U::from_bytes(data).map(T::from_backend).map_err(map_js_err)
}

fn try_make_address(address_bytes: &[u8]) -> Result<nucypher_core::Address, JsValue> {
    let addr = nucypher_core::Address::from_slice(address_bytes)
        .ok_or_else(|| Error::new(&format!("Invalid address: {:?}", address_bytes)))?;
    Ok(addr)
}

fn js_value_to_u8_vec(array_of_uint8_arrays: &[JsValue]) -> Result<Vec<Vec<u8>>, JsValue> {
    let vec_vec_u8 = array_of_uint8_arrays
        .iter()
        .filter_map(|u8_array| {
            u8_array
                .dyn_ref::<Uint8Array>()
                .map(|u8_array| u8_array.to_vec())
        })
        .collect::<Vec<_>>();

    if vec_vec_u8.len() != array_of_uint8_arrays.len() {
        Err("Invalid Array of Uint8Arrays.".to_string().into())
    } else {
        Ok(vec_vec_u8)
    }
}

//
// MessageKit
//

#[wasm_bindgen]
#[derive(PartialEq, Debug)]
pub struct MessageKit(nucypher_core::MessageKit);

impl AsBackend<nucypher_core::MessageKit> for MessageKit {
    fn as_backend(&self) -> &nucypher_core::MessageKit {
        &self.0
    }
}

impl FromBackend<nucypher_core::MessageKit> for MessageKit {
    fn from_backend(backend: nucypher_core::MessageKit) -> Self {
        MessageKit(backend)
    }
}

#[wasm_bindgen]
impl MessageKit {
    #[wasm_bindgen(constructor)]
    pub fn new(policy_encrypting_key: &PublicKey, plaintext: &[u8]) -> MessageKit {
        MessageKit(nucypher_core::MessageKit::new(
            policy_encrypting_key.inner(),
            plaintext,
        ))
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Result<Box<[u8]>, JsValue> {
        self.0.decrypt(sk.inner()).map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = decryptReencrypted)]
    pub fn decrypt_reencrypted(
        &self,
        sk: &SecretKey,
        policy_encrypting_key: &PublicKey,
        cfrags: Box<[JsValue]>,
    ) -> Result<Box<[u8]>, JsValue> {
        let backend_cfrags = js_value_to_u8_vec(&cfrags)?
            .iter()
            .map(|bytes| {
                VerifiedCapsuleFrag::from_verified_bytes(&bytes)
                    .and_then(|vcfrag| Ok(vcfrag.inner()))
            })
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        self.0
            .decrypt_reencrypted(sk.inner(), policy_encrypting_key.inner(), &backend_cfrags)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(method, getter)]
    pub fn capsule(&self) -> Capsule {
        Capsule::new(self.0.capsule)
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
pub struct HRAC(nucypher_core::HRAC);

impl AsBackend<nucypher_core::HRAC> for HRAC {
    fn as_backend(&self) -> &nucypher_core::HRAC {
        &self.0
    }
}

impl FromBackend<nucypher_core::HRAC> for HRAC {
    fn from_backend(backend: nucypher_core::HRAC) -> Self {
        HRAC(backend)
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
        HRAC(nucypher_core::HRAC::new(
            publisher_verifying_key.inner(),
            bob_verifying_key.inner(),
            label,
        ))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.as_ref().to_vec().into_boxed_slice()
    }
}

//
// EncryptedKeyFrag
//

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug)]
pub struct EncryptedKeyFrag(nucypher_core::EncryptedKeyFrag);

impl AsBackend<nucypher_core::EncryptedKeyFrag> for EncryptedKeyFrag {
    fn as_backend(&self) -> &nucypher_core::EncryptedKeyFrag {
        &self.0
    }
}

impl FromBackend<nucypher_core::EncryptedKeyFrag> for EncryptedKeyFrag {
    fn from_backend(backend: nucypher_core::EncryptedKeyFrag) -> Self {
        EncryptedKeyFrag(backend)
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
    ) -> EncryptedKeyFrag {
        EncryptedKeyFrag(nucypher_core::EncryptedKeyFrag::new(
            signer.inner(),
            recipient_key.inner(),
            &hrac.0,
            verified_kfrag.inner(),
        ))
    }

    pub fn decrypt(
        &self,
        sk: &SecretKey,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> Result<VerifiedKeyFrag, JsValue> {
        self.0
            .decrypt(sk.inner(), &hrac.0, publisher_verifying_key.inner())
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

//
// TreasureMap
//

#[wasm_bindgen]
#[derive(Clone, PartialEq, Debug)]
pub struct TreasureMap(nucypher_core::TreasureMap);

impl AsBackend<nucypher_core::TreasureMap> for TreasureMap {
    fn as_backend(&self) -> &nucypher_core::TreasureMap {
        &self.0
    }
}

impl FromBackend<nucypher_core::TreasureMap> for TreasureMap {
    fn from_backend(backend: nucypher_core::TreasureMap) -> Self {
        TreasureMap(backend)
    }
}

#[wasm_bindgen]
pub struct TreasureMapBuilder {
    signer: umbral_pre::Signer,
    hrac: nucypher_core::HRAC,
    policy_encrypting_key: umbral_pre::PublicKey,
    assigned_kfrags: Vec<(
        nucypher_core::Address,
        (umbral_pre::PublicKey, umbral_pre::VerifiedKeyFrag),
    )>,
    threshold: u8,
}

#[wasm_bindgen]
impl TreasureMapBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        hrac: &HRAC,
        policy_encrypting_key: &PublicKey,
        threshold: u8,
    ) -> Result<TreasureMapBuilder, JsValue> {
        Ok(Self {
            signer: signer.inner().clone(),
            hrac: hrac.0.clone(),
            policy_encrypting_key: policy_encrypting_key.inner().clone(),
            assigned_kfrags: Vec::new(),
            threshold,
        })
    }

    #[wasm_bindgen(js_name = withKFrag)]
    pub fn with_kfrag(
        mut self,
        address: String,
        public_key: PublicKey,
        vkfrag: VerifiedKeyFrag,
    ) -> Result<TreasureMapBuilder, JsValue> {
        let address = try_make_address(address.as_bytes())?;
        self.assigned_kfrags.push((
            address,
            (public_key.inner().clone(), vkfrag.inner().clone()),
        ));
        Ok(self)
    }

    #[wasm_bindgen]
    pub fn build(self) -> TreasureMap {
        TreasureMap(nucypher_core::TreasureMap::new(
            &self.signer,
            &self.hrac,
            &self.policy_encrypting_key,
            self.assigned_kfrags,
            self.threshold,
        ))
    }
}

#[wasm_bindgen]
impl TreasureMap {
    pub fn encrypt(&self, signer: &Signer, recipient_key: &PublicKey) -> EncryptedTreasureMap {
        EncryptedTreasureMap(self.0.encrypt(signer.inner(), recipient_key.inner()))
    }

    #[wasm_bindgen(method, getter)]
    pub fn destinations(&self) -> Result<JsValue, JsValue> {
        let mut result = Vec::new();
        for (address, ekfrag) in &self.0.destinations {
            result.push((address, EncryptedKeyFrag(ekfrag.clone())));
        }
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    #[wasm_bindgen(method, getter)]
    pub fn hrac(&self) -> HRAC {
        HRAC(self.0.hrac)
    }

    #[wasm_bindgen(method, getter)]
    pub fn threshold(&self) -> u8 {
        self.0.threshold
    }

    #[wasm_bindgen(method, getter, js_name = policyEncryptingKey)]
    pub fn policy_encrypting_key(&self) -> PublicKey {
        PublicKey::new(self.0.policy_encrypting_key)
    }

    #[wasm_bindgen(method, getter, js_name = publisherVerifyingKey)]
    pub fn publisher_verifying_key(&self) -> PublicKey {
        PublicKey::new(self.0.publisher_verifying_key)
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

//
// EncryptedTreasureMap
//

#[wasm_bindgen]
#[derive(PartialEq, Debug)]
pub struct EncryptedTreasureMap(nucypher_core::EncryptedTreasureMap);

impl AsBackend<nucypher_core::EncryptedTreasureMap> for EncryptedTreasureMap {
    fn as_backend(&self) -> &nucypher_core::EncryptedTreasureMap {
        &self.0
    }
}

impl FromBackend<nucypher_core::EncryptedTreasureMap> for EncryptedTreasureMap {
    fn from_backend(backend: nucypher_core::EncryptedTreasureMap) -> Self {
        EncryptedTreasureMap(backend)
    }
}

#[wasm_bindgen]
impl EncryptedTreasureMap {
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        publisher_verifying_key: &PublicKey,
    ) -> Result<TreasureMap, JsValue> {
        self.0
            .decrypt(sk.inner(), publisher_verifying_key.inner())
            .map_err(map_js_err)
            .map(|treasure_map| TreasureMap(treasure_map))
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
pub struct ReencryptionRequest(nucypher_core::ReencryptionRequest);

impl AsBackend<nucypher_core::ReencryptionRequest> for ReencryptionRequest {
    fn as_backend(&self) -> &nucypher_core::ReencryptionRequest {
        &self.0
    }
}

impl FromBackend<nucypher_core::ReencryptionRequest> for ReencryptionRequest {
    fn from_backend(backend: nucypher_core::ReencryptionRequest) -> Self {
        ReencryptionRequest(backend)
    }
}

#[wasm_bindgen]
impl ReencryptionRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        capsules: Box<[JsValue]>,
        hrac: &HRAC,
        encrypted_kfrag: &EncryptedKeyFrag,
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
    ) -> Result<ReencryptionRequest, JsValue> {
        let capsules_backend: Vec<umbral_pre::Capsule> = js_value_to_u8_vec(&capsules)?
            .iter()
            .map(|capsule| Capsule::from_bytes(capsule).and_then(|capsule| Ok(*capsule.inner())))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok(ReencryptionRequest(
            nucypher_core::ReencryptionRequest::new(
                &capsules_backend,
                &hrac.0,
                &encrypted_kfrag.0,
                publisher_verifying_key.inner(),
                bob_verifying_key.inner(),
            ),
        ))
    }

    #[wasm_bindgen(method, getter)]
    pub fn hrac(&self) -> HRAC {
        HRAC(self.0.hrac)
    }

    #[wasm_bindgen(method, getter)]
    pub fn publisher_verifying_key(&self) -> PublicKey {
        PublicKey::new(self.0.publisher_verifying_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn bob_verifying_key(&self) -> PublicKey {
        PublicKey::new(self.0.bob_verifying_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn encrypted_kfrag(&self) -> EncryptedKeyFrag {
        EncryptedKeyFrag(self.0.encrypted_kfrag.clone())
    }

    #[wasm_bindgen(method, getter)]
    pub fn capsules(&self) -> Vec<JsValue> {
        self.0
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

//
// ReencryptionResponse
//

#[wasm_bindgen]
pub struct ReencryptionResponse(nucypher_core::ReencryptionResponse);

impl AsBackend<nucypher_core::ReencryptionResponse> for ReencryptionResponse {
    fn as_backend(&self) -> &nucypher_core::ReencryptionResponse {
        &self.0
    }
}

impl FromBackend<nucypher_core::ReencryptionResponse> for ReencryptionResponse {
    fn from_backend(backend: nucypher_core::ReencryptionResponse) -> Self {
        ReencryptionResponse(backend)
    }
}

#[wasm_bindgen]
impl ReencryptionResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        capsules: Box<[JsValue]>,
        verified_capsule_frags: Box<[JsValue]>,
    ) -> Result<ReencryptionResponse, JsValue> {
        let capsules_backend: Vec<umbral_pre::Capsule> = js_value_to_u8_vec(&capsules)?
            .iter()
            .map(|capsule| Capsule::from_bytes(capsule).and_then(|capsule| Ok(*capsule.inner())))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        let verified_capsule_frags: Vec<umbral_pre::VerifiedCapsuleFrag> =
            js_value_to_u8_vec(&verified_capsule_frags)?
                .iter()
                .map(|vcfrag| {
                    VerifiedCapsuleFrag::from_verified_bytes(vcfrag)
                        .and_then(|vcfrag| Ok(vcfrag.inner()))
                })
                .into_iter()
                .collect::<Result<Vec<_>, _>>()?;

        Ok(ReencryptionResponse(
            nucypher_core::ReencryptionResponse::new(
                signer.inner(),
                &capsules_backend,
                &verified_capsule_frags,
            ),
        ))
    }

    pub fn verify(
        &self,
        capsules: Box<[JsValue]>,
        alice_verifying_key: &PublicKey,
        ursula_verifying_key: &PublicKey,
        policy_encrypting_key: &PublicKey,
        bob_encrypting_key: &PublicKey,
    ) -> Result<Box<[JsValue]>, JsValue> {
        let capsules_backend: Vec<umbral_pre::Capsule> = js_value_to_u8_vec(&capsules)?
            .iter()
            .map(|capsule| Capsule::from_bytes(capsule).and_then(|capsule| Ok(*capsule.inner())))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        let vcfrags_backend = self
            .0
            .verify(
                &capsules_backend,
                alice_verifying_key.inner(),
                ursula_verifying_key.inner(),
                policy_encrypting_key.inner(),
                bob_encrypting_key.inner(),
            )
            // TODO: Should we throw an error here or return an empty result, i.e. JS `null`?
            .ok_or_else(|| JsValue::from_str("ReencryptionResponse verification failed"))?;

        let vcfrags_backend_js = vcfrags_backend
            .iter()
            .map(|vcfrag| VerifiedCapsuleFrag::new(vcfrag.clone()))
            .map(|vcfrag| JsValue::from_serde(&vcfrag))
            .into_iter()
            .collect::<Result<Box<_>, _>>()
            .map_err(map_js_err)?;
        Ok(vcfrags_backend_js)
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
pub struct RetrievalKit(nucypher_core::RetrievalKit);

impl AsBackend<nucypher_core::RetrievalKit> for RetrievalKit {
    fn as_backend(&self) -> &nucypher_core::RetrievalKit {
        &self.0
    }
}

impl FromBackend<nucypher_core::RetrievalKit> for RetrievalKit {
    fn from_backend(backend: nucypher_core::RetrievalKit) -> Self {
        RetrievalKit(backend)
    }
}

#[wasm_bindgen]
impl RetrievalKit {
    #[wasm_bindgen(js_name = fromMessageKit)]
    pub fn from_message_kit(message_kit: &MessageKit) -> Self {
        RetrievalKit(nucypher_core::RetrievalKit::from_message_kit(
            &message_kit.0,
        ))
    }

    #[wasm_bindgen(constructor)]
    pub fn new(capsule: &Capsule, queried_addresses: JsValue) -> Result<RetrievalKit, JsValue> {
        // Using String here to avoid issue where Deserialize is not implemented
        // for every possible lifetime.
        let queried_addresses: Vec<String> = serde_wasm_bindgen::from_value(queried_addresses)?;
        let addresses_backend = queried_addresses
            .iter()
            .map(|address| try_make_address(address.as_bytes()))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;
        Ok(RetrievalKit(nucypher_core::RetrievalKit::new(
            capsule.inner(),
            addresses_backend,
        )))
    }

    #[wasm_bindgen(method, getter)]
    pub fn capsule(&self) -> Capsule {
        Capsule::new(self.0.capsule)
    }

    #[wasm_bindgen(method, getter)]
    pub fn queried_addresses(&self) -> Result<Vec<JsValue>, JsValue> {
        self.0
            .queried_addresses
            .iter()
            .map(|address| JsValue::from_serde(&address))
            .into_iter()
            .collect::<Result<Vec<_>, _>>()
            .map_err(map_js_err)
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
pub struct RevocationOrder(nucypher_core::RevocationOrder);

impl AsBackend<nucypher_core::RevocationOrder> for RevocationOrder {
    fn as_backend(&self) -> &nucypher_core::RevocationOrder {
        &self.0
    }
}

impl FromBackend<nucypher_core::RevocationOrder> for RevocationOrder {
    fn from_backend(backend: nucypher_core::RevocationOrder) -> Self {
        RevocationOrder(backend)
    }
}

#[wasm_bindgen]
impl RevocationOrder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        ursula_address: &[u8],
        encrypted_kfrag: &EncryptedKeyFrag,
    ) -> Result<RevocationOrder, JsValue> {
        let address = try_make_address(ursula_address)?;
        Ok(RevocationOrder(nucypher_core::RevocationOrder::new(
            signer.inner(),
            &address,
            &encrypted_kfrag.0,
        )))
    }

    #[wasm_bindgen]
    pub fn verify_signature(&self, alice_verifying_key: &PublicKey) -> bool {
        self.0.verify_signature(alice_verifying_key.inner())
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
pub struct NodeMetadataPayload(nucypher_core::NodeMetadataPayload);

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
    ) -> Result<NodeMetadataPayload, JsValue> {
        let address = try_make_address(canonical_address)?;
        Ok(NodeMetadataPayload(nucypher_core::NodeMetadataPayload {
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
        }))
    }

    #[wasm_bindgen(method, getter)]
    pub fn canonical_address(&self) -> Vec<u8> {
        self.0.canonical_address.as_ref().to_vec()
    }

    #[wasm_bindgen(method, getter)]
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::new(self.0.verifying_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn encrypting_key(&self) -> PublicKey {
        PublicKey::new(self.0.encrypting_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn decentralized_identity_evidence(&self) -> Option<Box<[u8]>> {
        self.0.decentralized_identity_evidence.clone()
    }

    #[wasm_bindgen(method, getter)]
    pub fn domain(&self) -> String {
        self.0.domain.clone()
    }

    #[wasm_bindgen(method, getter)]
    pub fn host(&self) -> String {
        self.0.host.clone()
    }

    #[wasm_bindgen(method, getter)]
    pub fn port(&self) -> u16 {
        self.0.port
    }

    #[wasm_bindgen(method, getter)]
    pub fn timestamp_epoch(&self) -> u32 {
        self.0.timestamp_epoch
    }

    #[wasm_bindgen(method, getter)]
    pub fn certificate_bytes(&self) -> Box<[u8]> {
        self.0.certificate_bytes.clone()
    }
}

//
// NodeMetadata
//

#[wasm_bindgen(method, getter)]
#[derive(Clone, Serialize, Deserialize, PartialEq, Debug)]
pub struct NodeMetadata(nucypher_core::NodeMetadata);

impl AsBackend<nucypher_core::NodeMetadata> for NodeMetadata {
    fn as_backend(&self) -> &nucypher_core::NodeMetadata {
        &self.0
    }
}

impl FromBackend<nucypher_core::NodeMetadata> for NodeMetadata {
    fn from_backend(backend: nucypher_core::NodeMetadata) -> Self {
        NodeMetadata(backend)
    }
}

#[wasm_bindgen]
impl NodeMetadata {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        NodeMetadata(nucypher_core::NodeMetadata::new(signer.inner(), &payload.0))
    }

    pub fn verify(&self) -> bool {
        self.0.verify()
    }

    #[wasm_bindgen(method, getter)]
    pub fn payload(&self) -> NodeMetadataPayload {
        NodeMetadataPayload(self.0.payload.clone())
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
pub struct FleetStateChecksum(nucypher_core::FleetStateChecksum);

impl AsBackend<nucypher_core::FleetStateChecksum> for FleetStateChecksum {
    fn as_backend(&self) -> &nucypher_core::FleetStateChecksum {
        &self.0
    }
}

impl FromBackend<nucypher_core::FleetStateChecksum> for FleetStateChecksum {
    fn from_backend(backend: nucypher_core::FleetStateChecksum) -> Self {
        FleetStateChecksum(backend)
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
            .map(|node| node.0.clone())
            .collect::<Vec<_>>();
        Ok(FleetStateChecksum(
            nucypher_core::FleetStateChecksum::from_nodes(
                this_node.map(|node| node.0).as_ref(),
                &other_nodes_backend,
            ),
        ))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.as_ref().to_vec().into_boxed_slice()
    }
}

//
// MetadataRequest
//

#[wasm_bindgen]
pub struct MetadataRequest(nucypher_core::MetadataRequest);

impl AsBackend<nucypher_core::MetadataRequest> for MetadataRequest {
    fn as_backend(&self) -> &nucypher_core::MetadataRequest {
        &self.0
    }
}

impl FromBackend<nucypher_core::MetadataRequest> for MetadataRequest {
    fn from_backend(backend: nucypher_core::MetadataRequest) -> Self {
        MetadataRequest(backend)
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
            .map(|node| node.0.clone())
            .collect::<Vec<_>>();
        Ok(MetadataRequest(nucypher_core::MetadataRequest::new(
            &fleet_state_checksum.0,
            &nodes_backend,
        )))
    }

    #[wasm_bindgen(method, getter, js_name = fleetStateChecksum)]
    pub fn fleet_state_checksum(&self) -> FleetStateChecksum {
        FleetStateChecksum(self.0.fleet_state_checksum)
    }

    #[wasm_bindgen(method, getter, js_name = announceNodes)]
    pub fn announce_nodes(&self) -> Vec<JsValue> {
        self.0
            .announce_nodes
            .iter()
            .map(|node| NodeMetadata(node.clone()))
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
// MetadataResponsePayload
//

#[wasm_bindgen]
pub struct MetadataResponsePayload(nucypher_core::MetadataResponsePayload);

#[wasm_bindgen]
impl MetadataResponsePayload {
    #[wasm_bindgen(constructor)]
    pub fn new(
        timestamp_epoch: u32,
        announce_nodes: JsValue,
    ) -> Result<MetadataResponsePayload, JsValue> {
        let announce_nodes: Vec<NodeMetadata> =
            serde_wasm_bindgen::from_value(announce_nodes).map_err(map_js_err)?;
        let nodes_backend = announce_nodes
            .iter()
            .map(|node| node.0.clone())
            .collect::<Vec<_>>();
        Ok(MetadataResponsePayload(
            nucypher_core::MetadataResponsePayload::new(timestamp_epoch, &nodes_backend),
        ))
    }

    #[wasm_bindgen(method, getter)]
    pub fn timestamp_epoch(&self) -> u32 {
        self.0.timestamp_epoch
    }

    #[wasm_bindgen(method, getter)]
    pub fn announce_nodes(&self) -> Vec<JsValue> {
        self.0
            .announce_nodes
            .iter()
            .map(|node| NodeMetadata(node.clone()))
            .map(JsValue::from)
            .collect()
    }
}

//
// MetadataResponse
//

#[wasm_bindgen]
pub struct MetadataResponse(nucypher_core::MetadataResponse);

impl AsBackend<nucypher_core::MetadataResponse> for MetadataResponse {
    fn as_backend(&self) -> &nucypher_core::MetadataResponse {
        &self.0
    }
}

impl FromBackend<nucypher_core::MetadataResponse> for MetadataResponse {
    fn from_backend(backend: nucypher_core::MetadataResponse) -> Self {
        MetadataResponse(backend)
    }
}

#[wasm_bindgen]
impl MetadataResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, response: &MetadataResponsePayload) -> Self {
        MetadataResponse(nucypher_core::MetadataResponse::new(
            signer.inner(),
            &response.0,
        ))
    }

    pub fn verify(&self, verifying_pk: &PublicKey) -> Result<MetadataResponsePayload, JsValue> {
        self.0
            .verify(verifying_pk.inner())
            .ok_or("Invalid signature")
            .map_err(map_js_err)
            .map(|backend| MetadataResponsePayload(backend))
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
