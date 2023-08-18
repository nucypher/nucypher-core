#![no_std]
// Disable false-positive warnings caused by `#[wasm-bindgen]` on struct impls
#![allow(clippy::unused_unit)]

extern crate alloc;

use alloc::{
    boxed::Box,
    format,
    string::{String, ToString},
    vec::Vec,
};
use core::fmt;

use ferveo::bindings_wasm::{Ciphertext, CiphertextHeader, DkgPublicKey, FerveoVariant};
use js_sys::Error;
use umbral_pre::bindings_wasm::{
    Capsule, PublicKey, RecoverableSignature, SecretKey, Signer, VerifiedCapsuleFrag,
    VerifiedKeyFrag,
};
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};
use wasm_bindgen::JsCast;
use wasm_bindgen_derive::TryFromJsValue;

use nucypher_core::ProtocolObject;

// Re-export certain types so they can be used from `nucypher-core` WASM bindings directly.
pub use ferveo::bindings_wasm::{FerveoPublicKey, Keypair};

fn map_js_err<T: fmt::Display>(err: T) -> Error {
    Error::new(&format!("{}", err))
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
fn from_bytes<'a, T, U>(data: &'a [u8]) -> Result<T, Error>
where
    T: From<U>,
    U: ProtocolObject<'a>,
{
    U::from_bytes(data).map(T::from).map_err(map_js_err)
}

/// Tries to convert an optional value (either `null` or a `#[wasm_bindgen]` marked structure)
/// from `JsValue` to the Rust type.
// TODO (rust-umbral#25): This is necessary since wasm-bindgen does not support
// having a parameter of `Option<&T>`, and using `Option<T>` consumes the argument
// (see https://github.com/rustwasm/wasm-bindgen/issues/2370).
fn try_from_js_option<T>(value: impl AsRef<JsValue>) -> Result<Option<T>, Error>
where
    for<'a> T: TryFrom<&'a JsValue> + 'static,
    for<'a> <T as TryFrom<&'a JsValue>>::Error: core::fmt::Display,
{
    let js_value = value.as_ref();

    let typed_value = if js_value.is_null() {
        None
    } else {
        Some(T::try_from(js_value).map_err(map_js_err)?)
    };
    Ok(typed_value)
}

/// Tries to convert a JS array from `JsValue` to a vector of Rust type elements.
// TODO (rust-umbral#23): This is necessary since wasm-bindgen does not support
// having a parameter of `Vec<&T>`
// (see https://github.com/rustwasm/wasm-bindgen/issues/111).
fn try_from_js_array<T>(value: impl AsRef<JsValue>) -> Result<Vec<T>, Error>
where
    for<'a> T: TryFrom<&'a JsValue>,
    for<'a> <T as TryFrom<&'a JsValue>>::Error: core::fmt::Display,
{
    let array: &js_sys::Array = value
        .as_ref()
        .dyn_ref()
        .ok_or_else(|| Error::new("Got a non-array argument where an array was expected"))?;
    let length: usize = array.length().try_into().map_err(map_js_err)?;
    let mut result = Vec::<T>::with_capacity(length);
    for js in array.iter() {
        let typed_elem = T::try_from(&js).map_err(map_js_err)?;
        result.push(typed_elem);
    }
    Ok(result)
}

fn into_js_array<T, U>(value: impl IntoIterator<Item = U>) -> T
where
    JsValue: From<U>,
    T: JsCast,
{
    value
        .into_iter()
        .map(JsValue::from)
        .collect::<js_sys::Array>()
        .unchecked_into::<T>()
}

macro_rules! generate_from_bytes {
    ($struct_name:ident) => {
        #[wasm_bindgen]
        impl $struct_name {
            #[wasm_bindgen(js_name = "fromBytes")]
            pub fn from_bytes(bytes: &[u8]) -> Result<$struct_name, Error> {
                from_bytes(bytes).map(Self)
            }
        }
    };
}

macro_rules! generate_to_bytes {
    ($struct_name:ident) => {
        #[wasm_bindgen]
        impl $struct_name {
            #[wasm_bindgen(js_name = "toBytes")]
            pub fn to_bytes(&self) -> Box<[u8]> {
                to_bytes(self)
            }
        }
    };
}

macro_rules! generate_equals {
    ($struct_name:ident) => {
        #[wasm_bindgen]
        impl $struct_name {
            #[wasm_bindgen]
            pub fn equals(&self, other: &$struct_name) -> bool {
                self.0 == other.0
            }
        }
    };
}

macro_rules! generate_to_string {
    ($struct_name:ident) => {
        #[wasm_bindgen]
        impl $struct_name {
            #[allow(clippy::inherent_to_string)]
            #[wasm_bindgen(js_name = toString)]
            pub fn to_string(&self) -> String {
                format!("{}", self.0)
            }
        }
    };
}

#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(typescript_type = "VerifiedCapsuleFrag[]")]
    pub type VerifiedCapsuleFragArray;

    #[wasm_bindgen(typescript_type = "[Capsule, VerifiedCapsuleFrag][]")]
    pub type CapsuleAndVerifiedCapsuleFragArray;

    #[wasm_bindgen(typescript_type = "Conditions | null")]
    pub type OptionConditions;

    #[wasm_bindgen(typescript_type = "Context | null")]
    pub type OptionContext;

    #[wasm_bindgen(typescript_type = "[Address, [PublicKey, VerifiedKeyFrag]][]")]
    pub type AssignedKeyFragsArray;

    #[wasm_bindgen(typescript_type = "[Address, EncryptedKeyFrag][]")]
    pub type DestinationsArray;

    #[wasm_bindgen(typescript_type = "Capsule[]")]
    pub type CapsuleArray;

    #[wasm_bindgen(typescript_type = "Address[]")]
    pub type AddressArray;

    #[wasm_bindgen(typescript_type = "NodeMetadata[]")]
    pub type NodeMetadataArray;

    #[wasm_bindgen(typescript_type = "NodeMetadata | null")]
    pub type OptionNodeMetadata;

    #[wasm_bindgen(typescript_type = "RevocationOrder | null")]
    pub type RevocationOrderArray;

    #[wasm_bindgen(typescript_type = "Uint8Array | null")]
    pub type OptionUint8Array;

    #[wasm_bindgen(typescript_type = "[Address, EncryptedKeyFrag]")]
    pub type VerifiedRevocationOrder;
}

//
// Conditions
//

#[derive(Clone, TryFromJsValue)]
#[wasm_bindgen]
pub struct Conditions(nucypher_core::Conditions);

generate_to_string!(Conditions);
generate_equals!(Conditions);

#[wasm_bindgen]
impl Conditions {
    #[wasm_bindgen(constructor)]
    pub fn new(conditions: &str) -> Self {
        Self(nucypher_core::Conditions::new(conditions))
    }

    // TODO: Why is this called `from_bytes` and not `from_string`?
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &str) -> Self {
        let data_owned: String = data.into();
        Self(nucypher_core::Conditions::from(data_owned))
    }
}

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone)]
pub struct Context(nucypher_core::Context);

generate_to_string!(Context);
generate_equals!(Context);

#[wasm_bindgen]
impl Context {
    #[wasm_bindgen(constructor)]
    pub fn new(context: &str) -> Self {
        Self(nucypher_core::Context::new(context))
    }

    // TODO: Why is this called `from_bytes` and not `from_string`?
    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(data: &str) -> Self {
        let data_owned: String = data.into();
        Self(nucypher_core::Context::from(data_owned))
    }
}

//
// Address
//

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, derive_more::AsRef, derive_more::From)]
pub struct Address(nucypher_core::Address);

generate_equals!(Address);

#[wasm_bindgen]
impl Address {
    #[wasm_bindgen(constructor)]
    pub fn new(address_bytes: &[u8]) -> Result<Address, Error> {
        address_bytes
            .try_into()
            .map(nucypher_core::Address::new)
            .map(Self)
            .map_err(|_err| {
                Error::new(&format!(
                    "Incorrect address size: {}, expected {}",
                    address_bytes.len(),
                    nucypher_core::Address::SIZE
                ))
            })
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.as_ref().to_vec().into_boxed_slice()
    }
}

//
// MessageKit
//

#[wasm_bindgen]
#[derive(PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct MessageKit(nucypher_core::MessageKit);

generate_equals!(MessageKit);
generate_from_bytes!(MessageKit);
generate_to_bytes!(MessageKit);

#[wasm_bindgen]
impl MessageKit {
    #[wasm_bindgen(constructor)]
    pub fn new(
        policy_encrypting_key: &PublicKey,
        plaintext: &[u8],
        conditions: &OptionConditions,
    ) -> Result<MessageKit, Error> {
        let typed_conditions = try_from_js_option::<Conditions>(conditions)?;

        Ok(MessageKit(nucypher_core::MessageKit::new(
            policy_encrypting_key.as_ref(),
            plaintext,
            typed_conditions.as_ref().map(|c| &c.0),
        )))
    }

    pub fn decrypt(&self, sk: &SecretKey) -> Result<Box<[u8]>, Error> {
        self.0.decrypt(sk.as_ref()).map_err(map_js_err)
    }

    #[wasm_bindgen(getter)]
    pub fn capsule(&self) -> Capsule {
        Capsule::from(self.0.capsule.clone())
    }

    #[wasm_bindgen(getter)]
    pub fn conditions(&self) -> Option<Conditions> {
        self.0.conditions.clone().map(Conditions)
    }

    #[wasm_bindgen(js_name = decryptReencrypted)]
    pub fn decrypt_reencrypted(
        &self,
        sk: &SecretKey,
        policy_encrypting_key: &PublicKey,
        vcfrags: &VerifiedCapsuleFragArray,
    ) -> Result<Box<[u8]>, Error> {
        let typed_vcfrags = try_from_js_array::<VerifiedCapsuleFrag>(vcfrags)?;
        self.0
            .decrypt_reencrypted(
                sk.as_ref(),
                policy_encrypting_key.as_ref(),
                typed_vcfrags
                    .into_iter()
                    .map(umbral_pre::VerifiedCapsuleFrag::from),
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

generate_to_string!(HRAC);
generate_equals!(HRAC);

#[wasm_bindgen]
impl HRAC {
    #[wasm_bindgen(constructor)]
    pub fn new(
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        label: &[u8],
    ) -> Self {
        Self(nucypher_core::HRAC::new(
            publisher_verifying_key.as_ref(),
            bob_verifying_key.as_ref(),
            label,
        ))
    }

    #[wasm_bindgen(js_name = fromBytes)]
    pub fn from_bytes(bytes: &[u8]) -> Result<HRAC, Error> {
        let bytes: [u8; nucypher_core::HRAC::SIZE] = bytes.try_into().map_err(map_js_err)?;
        Ok(Self(bytes.into()))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        self.0.as_ref().to_vec().into_boxed_slice()
    }
}

//
// EncryptedKeyFrag
//

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct EncryptedKeyFrag(nucypher_core::EncryptedKeyFrag);

generate_from_bytes!(EncryptedKeyFrag);

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
            signer.as_ref(),
            recipient_key.as_ref(),
            &hrac.0,
            verified_kfrag.as_ref().clone(),
        ))
    }

    pub fn decrypt(
        &self,
        sk: &SecretKey,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> Result<VerifiedKeyFrag, Error> {
        self.0
            .decrypt(sk.as_ref(), &hrac.0, publisher_verifying_key.as_ref())
            .map_err(map_js_err)
            .map(VerifiedKeyFrag::from)
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
#[derive(Clone, PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct TreasureMap(nucypher_core::TreasureMap);

generate_equals!(TreasureMap);
generate_from_bytes!(TreasureMap);

#[wasm_bindgen]
impl TreasureMap {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        hrac: &HRAC,
        policy_encrypting_key: &PublicKey,
        assigned_kfrags: &AssignedKeyFragsArray,
        threshold: u8,
    ) -> Result<TreasureMap, Error> {
        let js_kfrags: &JsValue = assigned_kfrags.as_ref();
        let kfrags_array: &js_sys::Array = js_kfrags
            .dyn_ref()
            .ok_or_else(|| Error::new("`assigned_kfrags` must be an array"))?;

        let mut typed_assigned_kfrags = Vec::new();

        for entry in kfrags_array.iter() {
            let key_value: js_sys::Array = entry.dyn_into()?;
            if key_value.length() != 2 {
                return Err(Error::new(
                    "A tuple of an incorrect size received when iterating through map's entries",
                ));
            }
            let key = key_value.get(0);
            let value = key_value.get(1);

            let value_tuple: js_sys::Array = value.dyn_into()?;
            if value_tuple.length() != 2 {
                return Err(Error::new(
                    "A tuple of an incorrect size received when iterating through map's entries",
                ));
            }

            let address = Address::try_from(&key).map_err(map_js_err)?;
            let pk = PublicKey::try_from(&value_tuple.get(0)).map_err(map_js_err)?;
            let kfrag = VerifiedKeyFrag::try_from(&value_tuple.get(1)).map_err(map_js_err)?;

            typed_assigned_kfrags.push((address.0, (pk.into(), kfrag.into())));
        }

        Ok(Self(nucypher_core::TreasureMap::new(
            signer.as_ref(),
            &hrac.0,
            policy_encrypting_key.as_ref(),
            typed_assigned_kfrags,
            threshold,
        )))
    }

    pub fn encrypt(&self, signer: &Signer, recipient_key: &PublicKey) -> EncryptedTreasureMap {
        EncryptedTreasureMap(self.0.encrypt(signer.as_ref(), recipient_key.as_ref()))
    }

    #[wasm_bindgen(getter)]
    pub fn destinations(&self) -> DestinationsArray {
        into_js_array(self.0.destinations.iter().map(|(address, ekfrag)| {
            [
                JsValue::from(Address(*address)),
                JsValue::from(EncryptedKeyFrag(ekfrag.clone())),
            ]
            .iter()
            .collect::<js_sys::Array>()
        }))
    }

    #[wasm_bindgen(js_name = makeRevocationOrders)]
    pub fn make_revocation_orders(&self, signer: &Signer) -> RevocationOrderArray {
        into_js_array(
            self.0
                .make_revocation_orders(signer.as_ref())
                .into_iter()
                .map(RevocationOrder),
        )
    }

    #[wasm_bindgen(getter)]
    pub fn hrac(&self) -> HRAC {
        HRAC(self.0.hrac)
    }

    #[wasm_bindgen(getter)]
    pub fn threshold(&self) -> u8 {
        self.0.threshold
    }

    #[wasm_bindgen(getter, js_name = policyEncryptingKey)]
    pub fn policy_encrypting_key(&self) -> PublicKey {
        PublicKey::from(self.0.policy_encrypting_key)
    }

    #[wasm_bindgen(getter, js_name = publisherVerifyingKey)]
    pub fn publisher_verifying_key(&self) -> PublicKey {
        PublicKey::from(self.0.publisher_verifying_key)
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

generate_equals!(EncryptedTreasureMap);
generate_from_bytes!(EncryptedTreasureMap);

#[wasm_bindgen]
impl EncryptedTreasureMap {
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        publisher_verifying_key: &PublicKey,
    ) -> Result<TreasureMap, Error> {
        self.0
            .decrypt(sk.as_ref(), publisher_verifying_key.as_ref())
            .map_err(map_js_err)
            .map(TreasureMap)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// Session Keys
//

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct SessionSharedSecret(nucypher_core::SessionSharedSecret);

#[wasm_bindgen]
#[derive(PartialEq, Eq, Debug, derive_more::From, derive_more::AsRef)]
pub struct SessionStaticKey(nucypher_core::SessionStaticKey);

generate_equals!(SessionStaticKey);
generate_from_bytes!(SessionStaticKey);
generate_to_string!(SessionStaticKey);

#[wasm_bindgen]
impl SessionStaticKey {
    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct SessionStaticSecret(nucypher_core::SessionStaticSecret);

generate_to_string!(SessionStaticSecret);

#[wasm_bindgen]
impl SessionStaticSecret {
    /// Generates a secret key using the default RNG and returns it.
    pub fn random() -> Self {
        Self(nucypher_core::SessionStaticSecret::random())
    }

    /// Generates a secret key using the default RNG and returns it.
    #[wasm_bindgen(js_name = publicKey)]
    pub fn public_key(&self) -> SessionStaticKey {
        SessionStaticKey(self.0.public_key())
    }

    #[wasm_bindgen(js_name = deriveSharedSecret)]
    pub fn derive_shared_secret(&self, their_public_key: &SessionStaticKey) -> SessionSharedSecret {
        SessionSharedSecret(self.0.derive_shared_secret(their_public_key.as_ref()))
    }
}

#[wasm_bindgen]
pub struct SessionSecretFactory(nucypher_core::SessionSecretFactory);

generate_to_string!(SessionSecretFactory);

#[wasm_bindgen]
impl SessionSecretFactory {
    /// Generates a secret key factory using the default RNG and returns it.
    pub fn random() -> Self {
        Self(nucypher_core::SessionSecretFactory::random())
    }

    #[wasm_bindgen(js_name = seedSize)]
    pub fn seed_size() -> usize {
        nucypher_core::SessionSecretFactory::seed_size()
    }

    #[wasm_bindgen(js_name = fromSecureRandomness)]
    pub fn from_secure_randomness(seed: &[u8]) -> Result<SessionSecretFactory, Error> {
        nucypher_core::SessionSecretFactory::from_secure_randomness(seed)
            .map(Self)
            .map_err(map_js_err)
    }

    #[wasm_bindgen(js_name = makeKey)]
    pub fn make_key(&self, label: &[u8]) -> SessionStaticSecret {
        SessionStaticSecret(self.0.make_key(label))
    }
}

//
// AccessControlPolicy
//

#[wasm_bindgen]
#[derive(PartialEq, Eq, Debug, derive_more::From, derive_more::AsRef)]
pub struct AccessControlPolicy(nucypher_core::AccessControlPolicy);

generate_from_bytes!(AccessControlPolicy);
generate_equals!(AccessControlPolicy);

#[wasm_bindgen]
impl AccessControlPolicy {
    #[wasm_bindgen(constructor)]
    pub fn new(
        public_key: &DkgPublicKey,
        authorization: &[u8],
        conditions: &OptionConditions,
    ) -> Result<AccessControlPolicy, Error> {
        let typed_conditions = try_from_js_option::<Conditions>(conditions)?;

        Ok(Self(nucypher_core::AccessControlPolicy::new(
            public_key.as_ref(),
            authorization,
            typed_conditions.as_ref().map(|conditions| &conditions.0),
        )))
    }

    pub fn aad(&self) -> Box<[u8]> {
        self.0.aad()
    }

    #[wasm_bindgen(getter, js_name = publicKey)]
    pub fn public_key(&self) -> DkgPublicKey {
        DkgPublicKey::from(self.0.public_key)
    }

    #[wasm_bindgen(getter)]
    pub fn authorization(&self) -> Box<[u8]> {
        self.0.authorization.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn conditions(&self) -> Option<Conditions> {
        self.0.conditions.clone().map(Conditions)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// ThresholdMessageKit
//
#[wasm_bindgen]
#[derive(PartialEq, Eq, Debug, derive_more::From, derive_more::AsRef)]
pub struct ThresholdMessageKit(nucypher_core::ThresholdMessageKit);

generate_from_bytes!(ThresholdMessageKit);
generate_equals!(ThresholdMessageKit);

#[wasm_bindgen]
impl ThresholdMessageKit {
    #[wasm_bindgen(constructor)]
    pub fn new(ciphertext: &Ciphertext, acp: &AccessControlPolicy) -> Self {
        Self(nucypher_core::ThresholdMessageKit::new(
            ciphertext.as_ref(),
            acp.as_ref(),
        ))
    }

    #[wasm_bindgen(getter)]
    pub fn ciphertext(&self) -> Ciphertext {
        self.0.ciphertext.clone().into()
    }

    #[wasm_bindgen(getter)]
    pub fn acp(&self) -> AccessControlPolicy {
        self.0.acp.clone().into()
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// Threshold Decryption Request
//

#[wasm_bindgen]
#[derive(PartialEq, Eq, Debug, derive_more::From, derive_more::AsRef)]
pub struct ThresholdDecryptionRequest(nucypher_core::ThresholdDecryptionRequest);

generate_from_bytes!(ThresholdDecryptionRequest);
generate_equals!(ThresholdDecryptionRequest);

#[wasm_bindgen]
impl ThresholdDecryptionRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ritual_id: u32,
        variant: &FerveoVariant,
        ciphertext_header: &CiphertextHeader,
        acp: &AccessControlPolicy,
        context: &OptionContext,
    ) -> Result<ThresholdDecryptionRequest, Error> {
        let typed_context = try_from_js_option::<Context>(context)?;

        Ok(Self(nucypher_core::ThresholdDecryptionRequest::new(
            ritual_id,
            ciphertext_header.as_ref(),
            acp.as_ref(),
            typed_context.as_ref().map(|context| &context.0),
            variant.clone().into(),
        )))
    }

    #[wasm_bindgen(getter, js_name = ritualId)]
    pub fn ritual_id(&self) -> u32 {
        self.0.ritual_id
    }

    #[wasm_bindgen(getter)]
    pub fn variant(&self) -> FerveoVariant {
        self.0.variant.into()
    }

    #[wasm_bindgen(getter, js_name = ciphertextHeader)]
    pub fn ciphertext_header(&self) -> CiphertextHeader {
        self.0.ciphertext_header.clone().into()
    }

    #[wasm_bindgen(getter)]
    pub fn acp(&self) -> AccessControlPolicy {
        self.0.acp.clone().into()
    }

    pub fn encrypt(
        &self,
        shared_secret: &SessionSharedSecret,
        requester_public_key: &SessionStaticKey,
    ) -> EncryptedThresholdDecryptionRequest {
        EncryptedThresholdDecryptionRequest(
            self.0
                .encrypt(shared_secret.as_ref(), requester_public_key.as_ref()),
        )
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// EncryptedThresholdDecryptionRequest
//

#[wasm_bindgen]
#[derive(PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct EncryptedThresholdDecryptionRequest(nucypher_core::EncryptedThresholdDecryptionRequest);

generate_from_bytes!(EncryptedThresholdDecryptionRequest);

#[wasm_bindgen]
impl EncryptedThresholdDecryptionRequest {
    #[wasm_bindgen(getter, js_name = ritualId)]
    pub fn ritual_id(&self) -> u32 {
        self.0.ritual_id
    }

    #[wasm_bindgen(getter, js_name = requesterPublicKey)]
    pub fn requester_public_key(&self) -> SessionStaticKey {
        SessionStaticKey::from(self.0.requester_public_key)
    }

    pub fn decrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> Result<ThresholdDecryptionRequest, Error> {
        self.0
            .decrypt(shared_secret.as_ref())
            .map_err(map_js_err)
            .map(ThresholdDecryptionRequest)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// Threshold Decryption Response
//

#[wasm_bindgen]
#[derive(PartialEq, Eq, Debug, derive_more::From, derive_more::AsRef)]
pub struct ThresholdDecryptionResponse(nucypher_core::ThresholdDecryptionResponse);

generate_from_bytes!(ThresholdDecryptionResponse);

#[wasm_bindgen]
impl ThresholdDecryptionResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(
        ritual_id: u32,
        decryption_share: &[u8],
    ) -> Result<ThresholdDecryptionResponse, Error> {
        Ok(Self(nucypher_core::ThresholdDecryptionResponse::new(
            ritual_id,
            decryption_share,
        )))
    }

    #[wasm_bindgen(getter, js_name = ritualId)]
    pub fn ritual_id(&self) -> u32 {
        self.0.ritual_id
    }

    #[wasm_bindgen(getter, js_name = decryptionShare)]
    pub fn decryption_share(&self) -> Box<[u8]> {
        self.0.decryption_share.clone()
    }

    pub fn encrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> EncryptedThresholdDecryptionResponse {
        EncryptedThresholdDecryptionResponse(self.0.encrypt(shared_secret.as_ref()))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}

//
// EncryptedThresholdDecryptionResponse
//

#[wasm_bindgen]
#[derive(PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct EncryptedThresholdDecryptionResponse(
    nucypher_core::EncryptedThresholdDecryptionResponse,
);

generate_from_bytes!(EncryptedThresholdDecryptionResponse);

#[wasm_bindgen]
impl EncryptedThresholdDecryptionResponse {
    #[wasm_bindgen(getter, js_name = ritualId)]
    pub fn ritual_id(&self) -> u32 {
        self.0.ritual_id
    }

    pub fn decrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> Result<ThresholdDecryptionResponse, Error> {
        self.0
            .decrypt(shared_secret.as_ref())
            .map_err(map_js_err)
            .map(ThresholdDecryptionResponse)
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

generate_from_bytes!(ReencryptionRequest);

#[wasm_bindgen]
impl ReencryptionRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        capsules: &CapsuleArray,
        hrac: &HRAC,
        encrypted_kfrag: &EncryptedKeyFrag,
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        conditions: &OptionConditions,
        context: &OptionContext,
    ) -> Result<ReencryptionRequest, Error> {
        let typed_conditions = try_from_js_option::<Conditions>(conditions)?;
        let typed_context = try_from_js_option::<Context>(context)?;
        let typed_capsules = try_from_js_array::<Capsule>(capsules)?;
        let backend_capules = typed_capsules
            .into_iter()
            .map(umbral_pre::Capsule::from)
            .collect::<Vec<_>>();
        Ok(Self(nucypher_core::ReencryptionRequest::new(
            &backend_capules,
            &hrac.0,
            &encrypted_kfrag.0,
            publisher_verifying_key.as_ref(),
            bob_verifying_key.as_ref(),
            typed_conditions.as_ref().map(|conditions| &conditions.0),
            typed_context.as_ref().map(|context| &context.0),
        )))
    }

    #[wasm_bindgen(getter)]
    pub fn hrac(&self) -> HRAC {
        HRAC(self.0.hrac)
    }

    #[wasm_bindgen(getter, js_name = publisherVerifyingKey)]
    pub fn publisher_verifying_key(&self) -> PublicKey {
        PublicKey::from(self.0.publisher_verifying_key)
    }

    #[wasm_bindgen(getter, js_name = bobVerifyingKey)]
    pub fn bob_verifying_key(&self) -> PublicKey {
        PublicKey::from(self.0.bob_verifying_key)
    }

    #[wasm_bindgen(getter, js_name = encryptedKfrag)]
    pub fn encrypted_kfrag(&self) -> EncryptedKeyFrag {
        EncryptedKeyFrag(self.0.encrypted_kfrag.clone())
    }

    #[wasm_bindgen(getter)]
    pub fn capsules(&self) -> CapsuleArray {
        into_js_array(self.0.capsules.iter().cloned().map(Capsule::from))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }

    #[wasm_bindgen(getter)]
    pub fn conditions(&self) -> Option<Conditions> {
        self.0.conditions.clone().map(Conditions)
    }

    #[wasm_bindgen(getter)]
    pub fn context(&self) -> Option<Context> {
        self.0.context.clone().map(Context)
    }
}

//
// ReencryptionResponse
//

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct ReencryptionResponse(nucypher_core::ReencryptionResponse);

generate_from_bytes!(ReencryptionResponse);

#[wasm_bindgen]
impl ReencryptionResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        capsules_and_vcfrags: &CapsuleAndVerifiedCapsuleFragArray,
    ) -> Result<ReencryptionResponse, Error> {
        let js_capsules_and_vcfrags: &JsValue = capsules_and_vcfrags.as_ref();
        let capsules_and_vcfrags_array: &js_sys::Array = js_capsules_and_vcfrags
            .dyn_ref()
            .ok_or_else(|| Error::new("`capsules_and_vcfrags` must be an array"))?;

        let mut backend_capsules = Vec::new();
        let mut backend_vcfrags = Vec::new();

        for entry in capsules_and_vcfrags_array.iter() {
            let entry_tuple: js_sys::Array = entry.dyn_into()?;
            if entry_tuple.length() != 2 {
                return Err(Error::new(
                    "A tuple of an incorrect size received when iterating through list's entries",
                ));
            }

            let capsule = umbral_pre::Capsule::from(
                Capsule::try_from(&entry_tuple.get(0)).map_err(map_js_err)?,
            );
            let vcfrag = umbral_pre::VerifiedCapsuleFrag::from(
                VerifiedCapsuleFrag::try_from(&entry_tuple.get(1)).map_err(map_js_err)?,
            );

            backend_capsules.push(capsule);
            backend_vcfrags.push(vcfrag);
        }

        Ok(Self(nucypher_core::ReencryptionResponse::new(
            signer.as_ref(),
            backend_capsules.iter().zip(backend_vcfrags.into_iter()),
        )))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        capsules: &CapsuleArray,
        alice_verifying_key: &PublicKey,
        ursula_verifying_key: &PublicKey,
        policy_encrypting_key: &PublicKey,
        bob_encrypting_key: &PublicKey,
    ) -> Result<VerifiedCapsuleFragArray, Error> {
        let typed_capsules = try_from_js_array::<Capsule>(capsules)?;
        let backend_capsules = typed_capsules
            .into_iter()
            .map(|capsule| capsule.as_ref().clone())
            .collect::<Vec<_>>();
        let backend_vcfrags = self
            .0
            .clone()
            .verify(
                &backend_capsules,
                alice_verifying_key.as_ref(),
                ursula_verifying_key.as_ref(),
                policy_encrypting_key.as_ref(),
                bob_encrypting_key.as_ref(),
            )
            .map_err(|_err| {
                JsValue::from(Error::new("ReencryptionResponse verification failed"))
            })?;

        Ok(into_js_array(
            backend_vcfrags
                .into_vec()
                .into_iter()
                .map(VerifiedCapsuleFrag::from),
        ))
    }
}

//
// RetrievalKit
//

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct RetrievalKit(nucypher_core::RetrievalKit);

generate_from_bytes!(RetrievalKit);

#[wasm_bindgen]
impl RetrievalKit {
    #[wasm_bindgen(constructor)]
    pub fn new(
        capsule: &Capsule,
        queried_addresses: &AddressArray,
        conditions: &OptionConditions,
    ) -> Result<RetrievalKit, Error> {
        let typed_conditions = try_from_js_option::<Conditions>(conditions)?;
        let typed_addresses = try_from_js_array::<Address>(queried_addresses)?;
        let backend_addresses = typed_addresses
            .into_iter()
            .map(|address| address.0)
            .collect::<Vec<_>>();
        Ok(Self(nucypher_core::RetrievalKit::new(
            capsule.as_ref(),
            backend_addresses,
            typed_conditions.as_ref().map(|conditions| &conditions.0),
        )))
    }

    #[wasm_bindgen(js_name = fromMessageKit)]
    pub fn from_message_kit(message_kit: &MessageKit) -> Self {
        RetrievalKit(nucypher_core::RetrievalKit::from_message_kit(
            &message_kit.0,
        ))
    }

    #[wasm_bindgen(getter)]
    pub fn capsule(&self) -> Capsule {
        Capsule::from(self.0.capsule.clone())
    }

    #[wasm_bindgen(getter, js_name = queriedAddresses)]
    pub fn queried_addresses(&self) -> AddressArray {
        into_js_array(self.0.queried_addresses.iter().cloned().map(Address::from))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }

    #[wasm_bindgen(getter)]
    pub fn conditions(&self) -> Option<Conditions> {
        self.0.conditions.clone().map(Conditions)
    }
}

//
// RevocationOrder
//

#[wasm_bindgen]
#[derive(PartialEq, Debug, derive_more::From, derive_more::AsRef)]
pub struct RevocationOrder(nucypher_core::RevocationOrder);

generate_from_bytes!(RevocationOrder);

#[wasm_bindgen]
impl RevocationOrder {
    #[wasm_bindgen(constructor)]
    pub fn new(
        signer: &Signer,
        staking_provider_address: &Address,
        encrypted_kfrag: &EncryptedKeyFrag,
    ) -> Result<RevocationOrder, Error> {
        Ok(Self(nucypher_core::RevocationOrder::new(
            signer.as_ref(),
            &staking_provider_address.0,
            &encrypted_kfrag.0,
        )))
    }

    #[wasm_bindgen]
    pub fn verify(
        &self,
        alice_verifying_key: &PublicKey,
    ) -> Result<VerifiedRevocationOrder, Error> {
        let (address, ekfrag) = self
            .0
            .clone()
            .verify(alice_verifying_key.as_ref())
            .map_err(|_err| Error::new("Failed to verify RevocationOrder"))?;
        Ok(into_js_array([
            JsValue::from(Address(address)),
            JsValue::from(EncryptedKeyFrag(ekfrag)),
        ]))
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
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
        staking_provider_address: &Address,
        domain: &str,
        timestamp_epoch: u32,
        verifying_key: &PublicKey,
        encrypting_key: &PublicKey,
        ferveo_public_key: &FerveoPublicKey,
        certificate_der: &[u8],
        host: &str,
        port: u16,
        operator_signature: &RecoverableSignature,
    ) -> Result<NodeMetadataPayload, Error> {
        Ok(Self(nucypher_core::NodeMetadataPayload {
            staking_provider_address: staking_provider_address.0,
            domain: domain.to_string(),
            timestamp_epoch,
            verifying_key: *verifying_key.as_ref(),
            encrypting_key: *encrypting_key.as_ref(),
            ferveo_public_key: *ferveo_public_key.as_ref(),
            certificate_der: certificate_der.into(),
            host: host.to_string(),
            port,
            operator_signature: operator_signature.as_ref().clone(),
        }))
    }

    #[wasm_bindgen(getter)]
    pub fn staking_provider_address(&self) -> Address {
        Address(self.0.staking_provider_address)
    }

    #[wasm_bindgen(getter, js_name = verifyingKey)]
    pub fn verifying_key(&self) -> PublicKey {
        PublicKey::from(self.0.verifying_key)
    }

    #[wasm_bindgen(getter, js_name = encryptingKey)]
    pub fn encrypting_key(&self) -> PublicKey {
        PublicKey::from(self.0.encrypting_key)
    }

    #[wasm_bindgen(getter)]
    pub fn operator_signature(&self) -> RecoverableSignature {
        self.0.operator_signature.clone().into()
    }

    #[wasm_bindgen(getter)]
    pub fn domain(&self) -> String {
        self.0.domain.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn host(&self) -> String {
        self.0.host.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn port(&self) -> u16 {
        self.0.port
    }

    #[wasm_bindgen(getter, js_name = timestampEpoch)]
    pub fn timestamp_epoch(&self) -> u32 {
        self.0.timestamp_epoch
    }

    #[wasm_bindgen(getter)]
    pub fn certificate_der(&self) -> Box<[u8]> {
        self.0.certificate_der.clone()
    }

    #[wasm_bindgen(js_name = deriveOperatorAddress)]
    pub fn derive_operator_address(&self) -> Result<Address, Error> {
        self.0
            .derive_operator_address()
            .map(Address)
            .map_err(map_js_err)
    }
}

//
// NodeMetadata
//

#[derive(TryFromJsValue)]
#[wasm_bindgen]
#[derive(Clone, PartialEq, Eq, Debug, derive_more::From, derive_more::AsRef)]
pub struct NodeMetadata(nucypher_core::NodeMetadata);

generate_from_bytes!(NodeMetadata);

#[wasm_bindgen]
impl NodeMetadata {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        Self(nucypher_core::NodeMetadata::new(
            signer.as_ref(),
            &payload.0,
        ))
    }

    pub fn verify(&self) -> bool {
        self.0.verify()
    }

    #[wasm_bindgen(getter)]
    pub fn payload(&self) -> NodeMetadataPayload {
        NodeMetadataPayload(self.0.payload.clone())
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
#[derive(Clone, derive_more::AsRef)]
pub struct FleetStateChecksum(nucypher_core::FleetStateChecksum);

generate_to_string!(FleetStateChecksum);

#[wasm_bindgen]
impl FleetStateChecksum {
    #[wasm_bindgen(constructor)]
    pub fn new(
        other_nodes: &NodeMetadataArray,
        this_node: &OptionNodeMetadata,
    ) -> Result<FleetStateChecksum, Error> {
        let typed_this_node = try_from_js_option::<NodeMetadata>(this_node)?;
        let typed_nodes = try_from_js_array::<NodeMetadata>(other_nodes)?;
        let backend_nodes = typed_nodes
            .into_iter()
            .map(|node| node.0)
            .collect::<Vec<_>>();
        Ok(Self(nucypher_core::FleetStateChecksum::from_nodes(
            &backend_nodes,
            typed_this_node.as_ref().map(|node| &node.0),
        )))
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
#[derive(derive_more::From, derive_more::AsRef)]
pub struct MetadataRequest(nucypher_core::MetadataRequest);

generate_from_bytes!(MetadataRequest);

#[wasm_bindgen]
impl MetadataRequest {
    #[wasm_bindgen(constructor)]
    pub fn new(
        fleet_state_checksum: &FleetStateChecksum,
        announce_nodes: &NodeMetadataArray,
    ) -> Result<MetadataRequest, Error> {
        let typed_nodes = try_from_js_array::<NodeMetadata>(announce_nodes)?;
        let backend_nodes = typed_nodes
            .into_iter()
            .map(|node| node.0)
            .collect::<Vec<_>>();
        Ok(Self(nucypher_core::MetadataRequest::new(
            &fleet_state_checksum.0,
            &backend_nodes,
        )))
    }

    #[wasm_bindgen(getter, js_name = fleetStateChecksum)]
    pub fn fleet_state_checksum(&self) -> FleetStateChecksum {
        FleetStateChecksum(self.0.fleet_state_checksum)
    }

    #[wasm_bindgen(getter, js_name = announceNodes)]
    pub fn announce_nodes(&self) -> NodeMetadataArray {
        into_js_array(self.0.announce_nodes.iter().cloned().map(NodeMetadata))
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
        announce_nodes: &NodeMetadataArray,
    ) -> Result<MetadataResponsePayload, Error> {
        let typed_nodes = try_from_js_array::<NodeMetadata>(announce_nodes)?;
        let backend_nodes = typed_nodes
            .into_iter()
            .map(|node| node.0)
            .collect::<Vec<_>>();
        Ok(Self(nucypher_core::MetadataResponsePayload::new(
            timestamp_epoch,
            &backend_nodes,
        )))
    }

    #[wasm_bindgen(getter)]
    pub fn timestamp_epoch(&self) -> u32 {
        self.0.timestamp_epoch
    }

    #[wasm_bindgen(getter, js_name = announceNodes)]
    pub fn announce_nodes(&self) -> NodeMetadataArray {
        into_js_array(self.0.announce_nodes.iter().cloned().map(NodeMetadata))
    }
}

//
// MetadataResponse
//

#[wasm_bindgen]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct MetadataResponse(nucypher_core::MetadataResponse);

generate_from_bytes!(MetadataResponse);

#[wasm_bindgen]
impl MetadataResponse {
    #[wasm_bindgen(constructor)]
    pub fn new(signer: &Signer, response: &MetadataResponsePayload) -> Self {
        MetadataResponse(nucypher_core::MetadataResponse::new(
            signer.as_ref(),
            &response.0,
        ))
    }

    #[wasm_bindgen]
    pub fn verify(&self, verifying_pk: &PublicKey) -> Result<MetadataResponsePayload, Error> {
        self.0
            .clone()
            .verify(verifying_pk.as_ref())
            .map_err(|_err| Error::new("Failed to verify MetadataResponse"))
            .map(MetadataResponsePayload)
    }

    #[wasm_bindgen(js_name = toBytes)]
    pub fn to_bytes(&self) -> Box<[u8]> {
        to_bytes(self)
    }
}
