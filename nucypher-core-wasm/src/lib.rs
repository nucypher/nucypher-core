#![no_std]
// Disable false-positive warnings caused by `#[wasm-bindgen]` on struct impls
#![allow(clippy::unused_unit)]

#[macro_use]
extern crate alloc;
// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use js_sys::Error;
use serde::{Deserialize, Serialize};
use umbral_pre::bindings_wasm::{
    Capsule, PublicKey, SecretKey, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

use nucypher_core::k256::ecdsa::recoverable;
use nucypher_core::k256::ecdsa::signature::Signature as SignatureTrait;
use nucypher_core::ProtocolObject;

#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

fn map_js_err<T: fmt::Display>(err: T) -> JsValue {
    Error::new(&format!("{}", err)).into()
}

fn to_bytes<'a, T, U>(obj: &T) -> Box<[u8]>
where
    T: AsRef<U>,
    U: ProtocolObject<'a>,
{
    obj.as_ref().to_bytes()
}

// Since `From` already has a blanket `impl From<T> for T`,
// we will have to specify `U` explicitly when calling this function.
// This could be avoided if a more specific "newtype" trait could be derived instead of `From`.
// See https://github.com/JelteF/derive_more/issues/201
fn from_bytes<'a, T, U>(data: &'a [u8]) -> Result<T, JsValue>
where
    T: From<U>,
    U: ProtocolObject<'a>,
{
    U::from_bytes(data).map(T::from).map_err(map_js_err)
}

fn try_make_address(address_bytes: &[u8]) -> Result<nucypher_core::Address, JsValue> {
    address_bytes
        .try_into()
        .map(nucypher_core::Address::new)
        .map_err(|_err| {
            JsValue::from(Error::new(&format!(
                "Incorrect address size: {}, expected {}",
                address_bytes.len(),
                nucypher_core::Address::SIZE
            )))
        })
}

/// A simple adapter that unboxes a bytestring inside an `Option`.
fn box_ref(source: &Option<Box<[u8]>>) -> Option<&[u8]> {
    source.as_ref().map(|bytes| bytes.as_ref())
}

//
// MessageKit
//

#[wasm_bindgen]
#[derive(PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct MessageKit(nucypher_core::MessageKit);

#[wasm_bindgen]
impl MessageKit {
    #[wasm_bindgen(constructor)]
    pub fn new(
        policy_encrypting_key: &PublicKey,
        plaintext: &[u8],
        conditions: Option<Box<[u8]>>,
    ) -> MessageKit {
        MessageKit(nucypher_core::MessageKit::new(
            policy_encrypting_key.inner(),
            plaintext,
            box_ref(&conditions),
        ))
    }

    #[wasm_bindgen(js_name = withVCFrag)]
    pub fn with_vcfrag(&self, vcfrag: &VerifiedCapsuleFrag) -> MessageKitWithFrags {
        MessageKitWithFrags {
            message_kit: self.0.clone(),
            vcfrags: vec![vcfrag.inner()],
        }
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Result<Box<[u8]>, JsValue> {
        self.0.decrypt(sk.inner()).map_err(map_js_err)
    }

    #[wasm_bindgen(method, getter)]
    pub fn capsule(&self) -> Capsule {
        Capsule::new(self.0.capsule)
    }

    #[wasm_bindgen(method, getter)]
    pub fn conditions(&self) -> Option<Box<[u8]>> {
        self.0.conditions.clone()
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<MessageKit, JsValue> {
        from_bytes::<_, nucypher_core::MessageKit>(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

#[wasm_bindgen]
#[derive(Clone)]
pub struct MessageKitWithFrags {
    message_kit: nucypher_core::MessageKit,
    vcfrags: Vec<umbral_pre::VerifiedCapsuleFrag>,
}

#[wasm_bindgen]
impl MessageKitWithFrags {
    #[wasm_bindgen(js_name = withVCFrag)]
    pub fn with_vcfrag(&mut self, vcfrag: &VerifiedCapsuleFrag) -> MessageKitWithFrags {
        self.vcfrags.push(vcfrag.inner());
        self.clone()
    }

    #[wasm_bindgen(js_name = decryptReencrypted)]
    pub fn decrypt_reencrypted(
        &self,
        sk: &SecretKey,
        policy_encrypting_key: &PublicKey,
    ) -> Result<Box<[u8]>, JsValue> {
        self.message_kit
            .decrypt_reencrypted(
                sk.inner(),
                policy_encrypting_key.inner(),
                self.vcfrags.clone(),
            )
            .map_err(map_js_err)
    }
}

//
// HRAC
//

#[wasm_bindgen]
#[derive(PartialEq, Eq)]
pub struct HRAC(nucypher_core::HRAC);

#[wasm_bindgen]
impl HRAC {
    #[wasm_bindgen(constructor)]
    pub fn new(
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        label: &[u8],
    ) -> Self {
        Self(nucypher_core::HRAC::new(
            publisher_verifying_key.inner(),
            bob_verifying_key.inner(),
            label,
        ))
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<HRAC, JsValue> {
        let bytes: [u8; nucypher_core::HRAC::SIZE] = bytes.try_into().map_err(map_js_err)?;
        Ok(Self(bytes.into()))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.as_ref().to_vec().into_boxed_slice()
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }
}

//
// EncryptedKeyFrag
//

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct EncryptedKeyFrag(nucypher_core::EncryptedKeyFrag);

#[wasm_bindgen]
impl EncryptedKeyFrag {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        recipient_key: &PublicKey,
        hrac: &HRAC,
        verified_kfrag: &VerifiedKeyFrag,
    ) -> Self {
        Self(nucypher_core::EncryptedKeyFrag::new(
            signer.inner(),
            recipient_key.inner(),
            &hrac.0,
            verified_kfrag.inner().clone(),
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
        from_bytes::<_, nucypher_core::EncryptedKeyFrag>(data)
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
            hrac: hrac.0,
            policy_encrypting_key: *policy_encrypting_key.inner(),
            assigned_kfrags: Vec::new(),
            threshold,
        })
    }

    #[wasm_bindgen(js_name = addKfrag)]
    pub fn add_kfrag(
        &mut self,
        address: &[u8],
        public_key: &PublicKey,
        vkfrag: &VerifiedKeyFrag,
    ) -> Result<TreasureMapBuilder, JsValue> {
        let address = try_make_address(address)?;
        self.assigned_kfrags
            .push((address, (*public_key.inner(), vkfrag.inner().clone())));
        Ok(self.clone())
    }

    #[wasm_bindgen]
    pub fn build(&self) -> TreasureMap {
        TreasureMap(nucypher_core::TreasureMap::new(
            &self.signer,
            &self.hrac,
            &self.policy_encrypting_key,
            self.assigned_kfrags.clone(),
            self.threshold,
        ))
    }
}

#[wasm_bindgen]
#[derive(Clone, PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct TreasureMap(nucypher_core::TreasureMap);

#[wasm_bindgen]
#[derive(Clone)]
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

    #[wasm_bindgen(js_name = makeRevocationOrders)]
    pub fn make_revocation_orders(&self, signer: &Signer) -> Vec<JsValue> {
        self.0
            .make_revocation_orders(signer.inner())
            .iter()
            .map(|order| JsValue::from_serde(&order).unwrap())
            .collect()
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
        from_bytes::<_, nucypher_core::TreasureMap>(data)
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
#[derive(PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct EncryptedTreasureMap(nucypher_core::EncryptedTreasureMap);

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
            .map(TreasureMap)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<EncryptedTreasureMap, JsValue> {
        from_bytes::<_, nucypher_core::EncryptedTreasureMap>(data)
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
#[derive(PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct ReencryptionRequest(nucypher_core::ReencryptionRequest);

#[wasm_bindgen]
#[derive(Clone)]
pub struct ReencryptionRequestBuilder {
    capsules: Vec<umbral_pre::Capsule>,
    hrac: nucypher_core::HRAC,
    encrypted_kfrag: nucypher_core::EncryptedKeyFrag,
    publisher_verifying_key: umbral_pre::PublicKey,
    bob_verifying_key: umbral_pre::PublicKey,
    conditions: Option<Box<[u8]>>,
    context: Option<Box<[u8]>>,
}

#[wasm_bindgen]
impl ReencryptionRequestBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        hrac: &HRAC,
        encrypted_kfrag: &EncryptedKeyFrag,
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        conditions: Option<Box<[u8]>>,
        context: Option<Box<[u8]>>,
    ) -> Result<ReencryptionRequestBuilder, JsValue> {
        Ok(Self {
            capsules: Vec::new(),
            hrac: hrac.0,
            encrypted_kfrag: encrypted_kfrag.0.clone(),
            publisher_verifying_key: *publisher_verifying_key.inner(),
            bob_verifying_key: *bob_verifying_key.inner(),
            conditions,
            context,
        })
    }

    #[wasm_bindgen(js_name = addCapsule)]
    pub fn add_capsule(&mut self, capsule: &Capsule) -> Self {
        self.capsules.push(*capsule.inner());
        self.clone()
    }

    #[wasm_bindgen]
    pub fn build(&self) -> ReencryptionRequest {
        ReencryptionRequest(nucypher_core::ReencryptionRequest::new(
            &self.capsules,
            &self.hrac,
            &self.encrypted_kfrag,
            &self.publisher_verifying_key,
            &self.bob_verifying_key,
            box_ref(&self.conditions),
            box_ref(&self.context),
        ))
    }
}

#[wasm_bindgen]
impl ReencryptionRequest {
    #[wasm_bindgen(method, getter)]
    pub fn hrac(&self) -> HRAC {
        HRAC(self.0.hrac)
    }

    #[wasm_bindgen(method, getter, js_name = publisherVerifyingKey)]
    pub fn publisher_verifying_key(&self) -> PublicKey {
        PublicKey::new(self.0.publisher_verifying_key)
    }

    #[wasm_bindgen(method, getter, js_name = bobVerifyingKey)]
    pub fn bob_verifying_key(&self) -> PublicKey {
        PublicKey::new(self.0.bob_verifying_key)
    }

    #[wasm_bindgen(method, getter, js_name = encryptedKfrag)]
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
        from_bytes::<_, nucypher_core::ReencryptionRequest>(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }

    #[wasm_bindgen(method, getter)]
    pub fn conditions(&self) -> Option<Box<[u8]>> {
        self.0.conditions.clone()
    }

    #[wasm_bindgen(method, getter)]
    pub fn context(&self) -> Option<Box<[u8]>> {
        self.0.context.clone()
    }
}

//
// ReencryptionResponse
//

#[wasm_bindgen]
#[derive(Clone)]
pub struct ReencryptionResponseBuilder {
    signer: umbral_pre::Signer,
    capsules: Vec<umbral_pre::Capsule>,
    vcfrags: Vec<umbral_pre::VerifiedCapsuleFrag>,
}

#[wasm_bindgen]
impl ReencryptionResponseBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer) -> Self {
        Self {
            signer: signer.inner().clone(),
            capsules: Vec::new(),
            vcfrags: Vec::new(),
        }
    }

    #[wasm_bindgen(js_name = addCapsule)]
    pub fn add_capsule(&mut self, capsule: &Capsule) -> ReencryptionResponseBuilder {
        self.capsules.push(*capsule.inner());
        self.clone()
    }

    #[wasm_bindgen(js_name = addCfrag)]
    pub fn add_cfrag(&mut self, cfrag: &VerifiedCapsuleFrag) -> ReencryptionResponseBuilder {
        self.vcfrags.push(cfrag.inner());
        self.clone()
    }

    #[wasm_bindgen]
    pub fn build(&self) -> ReencryptionResponse {
        ReencryptionResponse(nucypher_core::ReencryptionResponse::new(
            &self.signer,
            &self.capsules,
            self.vcfrags.clone(),
        ))
    }
}

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct ReencryptionResponse(nucypher_core::ReencryptionResponse);

#[wasm_bindgen]
impl ReencryptionResponse {
    #[wasm_bindgen(js_name = withCapsule)]
    pub fn with_capsule(&self, capsule: &Capsule) -> ReencryptionResponseWithCapsules {
        ReencryptionResponseWithCapsules {
            reencryption_response: self.0.clone(),
            capsules: vec![*capsule.inner()],
        }
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<ReencryptionResponse, JsValue> {
        from_bytes::<_, nucypher_core::ReencryptionResponse>(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

impl ReencryptionResponse {
    pub fn inner(&self) -> &nucypher_core::ReencryptionResponse {
        &self.0
    }
}

#[wasm_bindgen]
pub struct ReencryptionResponseWithCapsules {
    reencryption_response: nucypher_core::ReencryptionResponse,
    capsules: Vec<umbral_pre::Capsule>,
}

#[wasm_bindgen]
impl ReencryptionResponseWithCapsules {
    #[wasm_bindgen(js_name = withCapsule)]
    pub fn with_capsule(&self, capsule: &Capsule) -> ReencryptionResponseWithCapsules {
        let mut capsules = self.capsules.clone();
        capsules.push(*capsule.inner());
        ReencryptionResponseWithCapsules {
            reencryption_response: self.reencryption_response.clone(),
            capsules,
        }
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        alice_verifying_key: &PublicKey,
        ursula_verifying_key: &PublicKey,
        policy_encrypting_key: &PublicKey,
        bob_encrypting_key: &PublicKey,
    ) -> Result<Box<[JsValue]>, JsValue> {
        let vcfrags_backend = self
            .reencryption_response
            .verify(
                &self.capsules,
                alice_verifying_key.inner(),
                ursula_verifying_key.inner(),
                policy_encrypting_key.inner(),
                bob_encrypting_key.inner(),
            )
            .map_err(|_err| {
                JsValue::from(Error::new("ReencryptionResponse verification failed"))
            })?;

        let vcfrags_backend_js = vcfrags_backend
            .iter()
            .map(|vcfrag| VerifiedCapsuleFrag::new(vcfrag.clone()))
            .map(|vcfrag| JsValue::from_serde(&vcfrag))
            .into_iter()
            .collect::<Result<Box<_>, _>>()
            .map_err(map_js_err)?;
        Ok(vcfrags_backend_js)
    }
}

//
// RetrievalKit
//

#[wasm_bindgen]
#[derive(Clone)]
pub struct RetrievalKitBuilder {
    capsule: umbral_pre::Capsule,
    queried_addresses: Vec<nucypher_core::Address>,
    conditions: Option<Box<[u8]>>,
}

#[wasm_bindgen]
impl RetrievalKitBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(capsule: &Capsule, conditions: Option<Box<[u8]>>) -> Self {
        Self {
            capsule: *capsule.inner(),
            queried_addresses: Vec::new(),
            conditions,
        }
    }

    #[wasm_bindgen(js_name = addQueriedAddress)]
    pub fn add_queried_address(&mut self, address: &[u8]) -> Result<RetrievalKitBuilder, JsValue> {
        let address = try_make_address(address)?;
        self.queried_addresses.push(address);
        Ok(self.clone())
    }

    #[wasm_bindgen]
    pub fn build(&self) -> RetrievalKit {
        RetrievalKit(nucypher_core::RetrievalKit::new(
            &self.capsule,
            self.queried_addresses.clone(),
            box_ref(&self.conditions),
        ))
    }
}

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct RetrievalKit(nucypher_core::RetrievalKit);

#[wasm_bindgen]
impl RetrievalKit {
    #[wasm_bindgen(js_name = fromMessageKit)]
    pub fn from_message_kit(message_kit: &MessageKit) -> Self {
        RetrievalKit(nucypher_core::RetrievalKit::from_message_kit(
            &message_kit.0,
        ))
    }

    #[wasm_bindgen(method, getter)]
    pub fn capsule(&self) -> Capsule {
        Capsule::new(self.0.capsule)
    }

    #[wasm_bindgen(method, getter, js_name = queriedAddresses)]
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
        from_bytes::<_, nucypher_core::RetrievalKit>(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }

    #[wasm_bindgen(method, getter)]
    pub fn conditions(&self) -> Option<Box<[u8]>> {
        self.0.conditions.clone()
    }
}

//
// RevocationOrder
//

#[wasm_bindgen]
#[derive(Serialize, Deserialize, PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct RevocationOrder(nucypher_core::RevocationOrder);

#[wasm_bindgen]
impl RevocationOrder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        staking_provider_address: &[u8],
        encrypted_kfrag: &EncryptedKeyFrag,
    ) -> Result<RevocationOrder, JsValue> {
        let address = try_make_address(staking_provider_address)?;
        Ok(Self(nucypher_core::RevocationOrder::new(
            signer.inner(),
            &address,
            &encrypted_kfrag.0,
        )))
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        alice_verifying_key: &PublicKey,
    ) -> Result<VerifiedRevocationOrder, JsValue> {
        self.0
            .clone()
            .verify(alice_verifying_key.inner())
            .map(|(address, ekfrag)| VerifiedRevocationOrder {
                address: address.as_ref().to_vec().into_boxed_slice(),
                encrypted_kfrag: ekfrag,
            })
            .map_err(|_err| Error::new("Failed to verify RevocationOrder").into())
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<RevocationOrder, JsValue> {
        from_bytes::<_, nucypher_core::RevocationOrder>(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

// wasm-bindgen does not support returning tuples, so have to use a struct.
#[wasm_bindgen]
pub struct VerifiedRevocationOrder {
    address: Box<[u8]>,
    encrypted_kfrag: nucypher_core::EncryptedKeyFrag,
}

#[wasm_bindgen]
impl VerifiedRevocationOrder {
    #[wasm_bindgen(getter)]
    pub fn address(&self) -> Box<[u8]> {
        self.address.clone()
    }

    #[wasm_bindgen(getter, js_name = encryptedKFrag)]
    pub fn encrypted_kfrag(&self) -> EncryptedKeyFrag {
        EncryptedKeyFrag(self.encrypted_kfrag.clone())
    }
}

//
// NodeMetadataPayload
//

#[wasm_bindgen]
pub struct NodeMetadataPayload(nucypher_core::NodeMetadataPayload);

#[wasm_bindgen]
impl NodeMetadataPayload {
    #[allow(clippy::too_many_arguments)]
    #[wasm_bindgen(constructor)]
    pub fn new(
        staking_provider_address: &[u8],
        domain: &str,
        timestamp_epoch: u32,
        verifying_key: &PublicKey,
        encrypting_key: &PublicKey,
        certificate_der: &[u8],
        host: &str,
        port: u16,
        operator_signature: Option<Vec<u8>>,
    ) -> Result<NodeMetadataPayload, JsValue> {
        let address = try_make_address(staking_provider_address)?;

        let signature = operator_signature
            .map(|signature_bytes| {
                recoverable::Signature::from_bytes(&signature_bytes).map_err(|err| {
                    JsValue::from(Error::new(&format!(
                        "Incorrect operator signature format: {}",
                        err
                    )))
                })
            })
            .transpose()?;

        Ok(Self(nucypher_core::NodeMetadataPayload {
            staking_provider_address: address,
            domain: domain.to_string(),
            timestamp_epoch,
            verifying_key: *verifying_key.inner(),
            encrypting_key: *encrypting_key.inner(),
            certificate_der: certificate_der.into(),
            host: host.to_string(),
            port,
            operator_signature: signature,
        }))
    }

    #[wasm_bindgen(method, getter)]
    pub fn staking_provider_address(&self) -> Vec<u8> {
        self.0.staking_provider_address.as_ref().to_vec()
    }

    #[wasm_bindgen(method, getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::new(self.0.verifying_key)
    }

    #[wasm_bindgen(method, getter, js_name = encryptingKey)]
    pub fn encrypting_key(&self) -> PublicKey {
        PublicKey::new(self.0.encrypting_key)
    }

    #[wasm_bindgen(method, getter)]
    pub fn operator_signature(&self) -> Option<Box<[u8]>> {
        self.0
            .operator_signature
            .map(|signature| signature.as_ref().into())
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

    #[wasm_bindgen(method, getter, js_name = timestampEpoch)]
    pub fn timestamp_epoch(&self) -> u32 {
        self.0.timestamp_epoch
    }

    #[wasm_bindgen(method, getter)]
    pub fn certificate_der(&self) -> Box<[u8]> {
        self.0.certificate_der.clone()
    }

    #[wasm_bindgen(js_name = deriveOperatorAddress)]
    pub fn derive_operator_address(&self) -> Result<Vec<u8>, JsValue> {
        self.0
            .derive_operator_address()
            .map(|address| address.as_ref().to_vec())
            .map_err(map_js_err)
    }
}

//
// NodeMetadata
//

#[wasm_bindgen]
#[derive(
    Clone, Serialize, Deserialize, PartialEq, Debug, derive_more::From, derive_more::AsRef,
)]
pub struct NodeMetadata(nucypher_core::NodeMetadata);

#[wasm_bindgen]
impl NodeMetadata {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        Self(nucypher_core::NodeMetadata::new(signer.inner(), &payload.0))
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
        from_bytes::<_, nucypher_core::NodeMetadata>(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

// TODO: Replace inner() with From<>?
impl NodeMetadata {
    pub fn inner(&self) -> &nucypher_core::NodeMetadata {
        &self.0
    }
}

//
// FleetStateChecksum
//

#[wasm_bindgen]
#[derive(Clone)]
pub struct FleetStateChecksumBuilder {
    this_node: Option<nucypher_core::NodeMetadata>,
    other_nodes: Vec<nucypher_core::NodeMetadata>,
}

#[wasm_bindgen]
impl FleetStateChecksumBuilder {
    // TODO: Fix lack of reference leading to accidental freeing of memory
    //       https://github.com/rustwasm/wasm-bindgen/issues/2370
    // this_node: Option<&NodeMetadata>,
    #[wasm_bindgen(constructor)]
    pub fn new(this_node: Option<NodeMetadata>) -> Self {
        Self {
            this_node: this_node.map(|n| n.0),
            other_nodes: Vec::new(),
        }
    }

    #[wasm_bindgen(js_name = addOtherNode)]
    pub fn add_other_node(&mut self, other_node: &NodeMetadata) -> Self {
        self.other_nodes.push(other_node.inner().clone());
        self.clone()
    }

    #[wasm_bindgen]
    pub fn build(&self) -> FleetStateChecksum {
        FleetStateChecksum(nucypher_core::FleetStateChecksum::from_nodes(
            self.this_node.as_ref(),
            &self.other_nodes,
        ))
    }
}

#[wasm_bindgen]
#[derive(Clone, derive_more::AsRef)]
pub struct FleetStateChecksum(nucypher_core::FleetStateChecksum);

#[wasm_bindgen]
impl FleetStateChecksum {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.as_ref().to_vec().into_boxed_slice()
    }

    #[allow(clippy::inherent_to_string)]
    #[wasm_bindgen(js_name = toString)]
    pub fn to_string(&self) -> String {
        format!("{}", self.0)
    }
}

impl FleetStateChecksum {
    pub fn new(this_node: Option<NodeMetadata>, other_nodes: Vec<NodeMetadata>) -> Self {
        let this_node = this_node.map(|n| n.0);
        let other_nodes: Vec<nucypher_core::NodeMetadata> =
            other_nodes.iter().cloned().map(|n| n.0).collect();
        FleetStateChecksum(nucypher_core::FleetStateChecksum::from_nodes(
            this_node.as_ref(),
            &other_nodes,
        ))
    }
}

//
// MetadataRequest
//

#[wasm_bindgen]
#[derive(Clone)]
pub struct MetadataRequestBuilder {
    fleet_state_checksum: nucypher_core::FleetStateChecksum,
    announce_nodes: Vec<nucypher_core::NodeMetadata>,
}

#[wasm_bindgen]
impl MetadataRequestBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(fleet_state_checksum: &FleetStateChecksum) -> Self {
        Self {
            fleet_state_checksum: fleet_state_checksum.0,
            announce_nodes: Vec::new(),
        }
    }

    #[wasm_bindgen(js_name = addAnnounceNode)]
    pub fn add_announce_node(&mut self, announce_node: &NodeMetadata) -> Self {
        self.announce_nodes.push(announce_node.inner().clone());
        self.clone()
    }

    #[wasm_bindgen]
    pub fn build(&self) -> MetadataRequest {
        MetadataRequest(nucypher_core::MetadataRequest::new(
            &self.fleet_state_checksum,
            &self.announce_nodes,
        ))
    }
}

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct MetadataRequest(nucypher_core::MetadataRequest);

#[wasm_bindgen]
impl MetadataRequest {
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
        from_bytes::<_, nucypher_core::MetadataRequest>(data)
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
#[derive(Clone)]
pub struct MetadataResponsePayloadBuilder {
    timestamp_epoch: u32,
    announce_nodes: Vec<nucypher_core::NodeMetadata>,
}

#[wasm_bindgen]
impl MetadataResponsePayloadBuilder {
    #[wasm_bindgen(constructor)]
    pub fn new(timestamp_epoch: u32) -> Self {
        Self {
            timestamp_epoch,
            announce_nodes: Vec::new(),
        }
    }

    #[wasm_bindgen(js_name = addAnnounceNode)]
    pub fn add_announce_node(&mut self, announce_node: &NodeMetadata) -> Self {
        self.announce_nodes.push(announce_node.inner().clone());
        self.clone()
    }

    #[wasm_bindgen]
    pub fn build(&self) -> MetadataResponsePayload {
        MetadataResponsePayload(nucypher_core::MetadataResponsePayload::new(
            self.timestamp_epoch,
            &self.announce_nodes,
        ))
    }
}

#[wasm_bindgen]
pub struct MetadataResponsePayload(nucypher_core::MetadataResponsePayload);

#[wasm_bindgen]
impl MetadataResponsePayload {
    #[wasm_bindgen(method, getter)]
    pub fn timestamp_epoch(&self) -> u32 {
        self.0.timestamp_epoch
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
}

//
// MetadataResponse
//

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct MetadataResponse(nucypher_core::MetadataResponse);

#[wasm_bindgen]
impl MetadataResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, response: &MetadataResponsePayload) -> Self {
        MetadataResponse(nucypher_core::MetadataResponse::new(
            signer.inner(),
            &response.0,
        ))
    }

    #[wasm_bindgen]
    pub fn verify(&self, verifying_pk: &PublicKey) -> Result<MetadataResponsePayload, JsValue> {
        self.0
            .clone()
            .verify(verifying_pk.inner())
            .map_err(|_err| Error::new("Failed to verify MetadataResponse").into())
            .map(MetadataResponsePayload)
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &[u8]) -> Result<MetadataResponse, JsValue> {
        from_bytes::<_, nucypher_core::MetadataResponse>(data)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}
