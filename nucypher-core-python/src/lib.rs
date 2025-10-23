// Clippy shows false positives in PyO3 methods.
// See https://github.com/rust-lang/rust-clippy/issues/8971
// Will probably be fixed by Rust 1.65
#![allow(clippy::borrow_deref_ref)]

extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};
use core::str::FromStr;
use ferveo::bindings_python::{
    Ciphertext, CiphertextHeader, DkgPublicKey, FerveoPublicKey, FerveoPythonError, FerveoVariant,
    SharedSecret,
};
use pyo3::class::basic::CompareOp;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pyclass::PyClass;
use pyo3::types::{PyBytes, PyUnicode};
use umbral_pre::bindings_python::{
    Capsule, PublicKey, RecoverableSignature, SecretKey, Signer, VerificationError,
    VerifiedCapsuleFrag, VerifiedKeyFrag,
};

use nucypher_core as rust_nucypher_core;
use rust_nucypher_core::{
    PackedUserOperation as SignatureRequestPackedUserOperation, SignatureRequestType,
    SignedPackedUserOperation as SignatureRequestSignedPackedUserOperation,
    UserOperation as SignatureRequestUserOperation,
};

use nucypher_core::ProtocolObject;

fn to_bytes<'a, T, U>(obj: &T) -> PyObject
where
    T: AsRef<U>,
    U: ProtocolObject<'a>,
{
    let serialized = obj.as_ref().to_bytes();
    Python::with_gil(|py| -> PyObject { PyBytes::new(py, &serialized).into() })
}

// Since `From` already has a blanket `impl From<T> for T`,
// we will have to specify `U` explicitly when calling this function.
// This could be avoided if a more specific "newtype" trait could be derived instead of `From`.
// See https://github.com/JelteF/derive_more/issues/201
fn from_bytes<'a, T, U>(data: &'a [u8]) -> PyResult<T>
where
    T: From<U>,
    U: ProtocolObject<'a>,
{
    U::from_bytes(data)
        .map(T::from)
        .map_err(|err| PyValueError::new_err(format!("Failed to deserialize: {err}")))
}

fn richcmp<T>(obj: &T, other: &T, op: CompareOp) -> PyResult<bool>
where
    T: PyClass + PartialEq,
{
    match op {
        CompareOp::Eq => Ok(obj == other),
        CompareOp::Ne => Ok(obj != other),
        _ => Err(PyTypeError::new_err("Objects are not ordered")),
    }
}

fn hash<T, U>(type_name: &str, obj: &T) -> PyResult<isize>
where
    T: AsRef<U>,
    U: AsRef<[u8]>,
{
    let serialized = obj.as_ref().as_ref();

    // call `hash((class_name, bytes(obj)))`
    Python::with_gil(|py| {
        let builtins = PyModule::import(py, "builtins")?;
        let arg1 = PyUnicode::new(py, type_name);
        let arg2: PyObject = PyBytes::new(py, serialized).into();
        builtins.getattr("hash")?.call1(((arg1, arg2),))?.extract()
    })
}

#[pyclass(module = "nucypher_core")]
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, derive_more::AsRef)]
pub struct Address {
    backend: nucypher_core::Address,
}

#[pymethods]
impl Address {
    #[new]
    pub fn new(address_bytes: [u8; nucypher_core::Address::SIZE]) -> Self {
        Self {
            backend: nucypher_core::Address::new(&address_bytes),
        }
    }

    fn __bytes__(&self) -> &[u8] {
        self.backend.as_ref()
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash("Address", self)
    }
}

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct Conditions {
    backend: nucypher_core::Conditions,
}

#[pymethods]
impl Conditions {
    #[new]
    pub fn new(conditions: &str) -> Self {
        Self {
            backend: nucypher_core::Conditions::new(conditions),
        }
    }

    #[staticmethod]
    pub fn from_string(conditions: String) -> Self {
        Self {
            backend: conditions.into(),
        }
    }

    fn __str__(&self) -> &str {
        self.backend.as_ref()
    }
}

#[pyclass(module = "nucypher_core")]
pub struct Context {
    backend: nucypher_core::Context,
}

#[pymethods]
impl Context {
    #[new]
    pub fn new(context: &str) -> Self {
        Self {
            backend: nucypher_core::Context::new(context),
        }
    }

    fn __str__(&self) -> &str {
        self.backend.as_ref()
    }
}

//
// MessageKit
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct MessageKit {
    backend: nucypher_core::MessageKit,
}

#[pymethods]
impl MessageKit {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::MessageKit>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }

    #[new]
    pub fn new(
        policy_encrypting_key: &PublicKey,
        plaintext: &[u8],
        conditions: Option<&Conditions>,
    ) -> Self {
        Self {
            backend: nucypher_core::MessageKit::new(
                policy_encrypting_key.as_ref(),
                plaintext,
                conditions.map(|conditions| &conditions.backend),
            ),
        }
    }

    pub fn decrypt(&self, py: Python, sk: &SecretKey) -> PyResult<PyObject> {
        let plaintext = self
            .backend
            .decrypt(sk.as_ref())
            .map_err(|err| PyValueError::new_err(format!("{err}")))?;
        Ok(PyBytes::new(py, &plaintext).into())
    }

    pub fn decrypt_reencrypted(
        &self,
        py: Python,
        sk: &SecretKey,
        policy_encrypting_key: &PublicKey,
        vcfrags: Vec<VerifiedCapsuleFrag>,
    ) -> PyResult<PyObject> {
        let backend_vcfrags: Vec<umbral_pre::VerifiedCapsuleFrag> =
            vcfrags.into_iter().map(|vcfrag| vcfrag.into()).collect();
        let plaintext = self
            .backend
            .decrypt_reencrypted(sk.as_ref(), policy_encrypting_key.as_ref(), backend_vcfrags)
            .map_err(|err| PyValueError::new_err(format!("{err}")))?;
        Ok(PyBytes::new(py, &plaintext).into())
    }

    #[getter]
    fn capsule(&self) -> Capsule {
        self.backend.capsule.clone().into()
    }

    #[getter]
    fn conditions(&self) -> Option<Conditions> {
        self.backend
            .conditions
            .clone()
            .map(|conditions| Conditions {
                backend: conditions,
            })
    }
}

//
// HRAC
//

#[allow(clippy::upper_case_acronyms)]
#[pyclass(module = "nucypher_core")]
#[derive(PartialEq, Eq, derive_more::AsRef)]
pub struct HRAC {
    backend: nucypher_core::HRAC,
}

#[pymethods]
impl HRAC {
    #[new]
    pub fn new(
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        label: &[u8],
    ) -> Self {
        Self {
            backend: nucypher_core::HRAC::new(
                publisher_verifying_key.as_ref(),
                bob_verifying_key.as_ref(),
                label,
            ),
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: [u8; nucypher_core::HRAC::SIZE]) -> Self {
        Self {
            backend: data.into(),
        }
    }

    fn __bytes__(&self) -> &[u8] {
        self.backend.as_ref()
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash("HRAC", self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

//
// EncryptedKeyFrag
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct EncryptedKeyFrag {
    backend: nucypher_core::EncryptedKeyFrag,
}

#[pymethods]
impl EncryptedKeyFrag {
    #[new]
    pub fn new(
        signer: &Signer,
        recipient_key: &PublicKey,
        hrac: &HRAC,
        verified_kfrag: &VerifiedKeyFrag,
    ) -> Self {
        Self {
            backend: nucypher_core::EncryptedKeyFrag::new(
                signer.as_ref(),
                recipient_key.as_ref(),
                &hrac.backend,
                verified_kfrag.as_ref().clone(),
            ),
        }
    }

    pub fn decrypt(
        &self,
        sk: &SecretKey,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> PyResult<VerifiedKeyFrag> {
        self.backend
            .decrypt(sk.as_ref(), &hrac.backend, publisher_verifying_key.as_ref())
            .map(VerifiedKeyFrag::from)
            .map_err(|err| PyValueError::new_err(format!("{err}")))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::EncryptedKeyFrag>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// TreasureMap
//

#[pyclass(module = "nucypher_core")]
#[derive(PartialEq, derive_more::From, derive_more::AsRef)]
pub struct TreasureMap {
    backend: nucypher_core::TreasureMap,
}

#[pymethods]
impl TreasureMap {
    #[new]
    pub fn new(
        signer: &Signer,
        hrac: &HRAC,
        policy_encrypting_key: &PublicKey,
        assigned_kfrags: BTreeMap<Address, (PublicKey, VerifiedKeyFrag)>,
        threshold: u8,
    ) -> Self {
        let assigned_kfrags_backend = assigned_kfrags
            .into_iter()
            .map(|(address, (key, vkfrag))| (address.backend, (key.into(), vkfrag.into())))
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::TreasureMap::new(
                signer.as_ref(),
                &hrac.backend,
                policy_encrypting_key.as_ref(),
                assigned_kfrags_backend,
                threshold,
            ),
        }
    }

    pub fn encrypt(&self, signer: &Signer, recipient_key: &PublicKey) -> EncryptedTreasureMap {
        EncryptedTreasureMap {
            backend: self
                .backend
                .encrypt(signer.as_ref(), recipient_key.as_ref()),
        }
    }

    pub fn make_revocation_orders(&self, signer: &Signer) -> Vec<RevocationOrder> {
        self.backend
            .make_revocation_orders(signer.as_ref())
            .into_iter()
            .map(|backend| RevocationOrder { backend })
            .collect()
    }

    #[getter]
    fn destinations(&self) -> BTreeMap<Address, EncryptedKeyFrag> {
        let mut result = BTreeMap::new();
        for (address, ekfrag) in &self.backend.destinations {
            result.insert(
                Address { backend: *address },
                EncryptedKeyFrag {
                    backend: ekfrag.clone(),
                },
            );
        }
        result
    }

    #[getter]
    fn hrac(&self) -> HRAC {
        HRAC {
            backend: self.backend.hrac,
        }
    }

    #[getter]
    fn threshold(&self) -> u8 {
        self.backend.threshold
    }

    #[getter]
    fn policy_encrypting_key(&self) -> PublicKey {
        self.backend.policy_encrypting_key.into()
    }

    #[getter]
    fn publisher_verifying_key(&self) -> PublicKey {
        self.backend.publisher_verifying_key.into()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::TreasureMap>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// EncryptedTreasureMap
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct EncryptedTreasureMap {
    backend: nucypher_core::EncryptedTreasureMap,
}

#[pymethods]
impl EncryptedTreasureMap {
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        publisher_verifying_key: &PublicKey,
    ) -> PyResult<TreasureMap> {
        self.backend
            .decrypt(sk.as_ref(), publisher_verifying_key.as_ref())
            .map(TreasureMap::from)
            .map_err(|err| PyValueError::new_err(format!("{err}")))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::EncryptedTreasureMap>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// ReencryptionRequest
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct ReencryptionRequest {
    backend: nucypher_core::ReencryptionRequest,
}

#[pymethods]
impl ReencryptionRequest {
    #[new]
    pub fn new(
        capsules: Vec<Capsule>,
        hrac: &HRAC,
        encrypted_kfrag: &EncryptedKeyFrag,
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
        conditions: Option<&Conditions>,
        context: Option<&Context>,
    ) -> Self {
        let capsules_backend = capsules
            .into_iter()
            .map(umbral_pre::Capsule::from)
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::ReencryptionRequest::new(
                &capsules_backend,
                &hrac.backend,
                &encrypted_kfrag.backend,
                publisher_verifying_key.as_ref(),
                bob_verifying_key.as_ref(),
                conditions.map(|conditions| &conditions.backend),
                context.map(|context| &context.backend),
            ),
        }
    }

    #[getter]
    fn hrac(&self) -> HRAC {
        HRAC {
            backend: self.backend.hrac,
        }
    }

    #[getter]
    fn publisher_verifying_key(&self) -> PublicKey {
        self.backend.publisher_verifying_key.into()
    }

    #[getter]
    fn bob_verifying_key(&self) -> PublicKey {
        self.backend.bob_verifying_key.into()
    }

    #[getter]
    fn encrypted_kfrag(&self) -> EncryptedKeyFrag {
        EncryptedKeyFrag {
            backend: self.backend.encrypted_kfrag.clone(),
        }
    }

    #[getter]
    fn capsules(&self) -> Vec<Capsule> {
        self.backend
            .capsules
            .iter()
            .cloned()
            .map(Capsule::from)
            .collect::<Vec<_>>()
    }

    #[getter]
    fn conditions(&self) -> Option<Conditions> {
        self.backend
            .conditions
            .clone()
            .map(|conditions| Conditions {
                backend: conditions,
            })
    }

    #[getter]
    fn context(&self) -> Option<Context> {
        self.backend
            .context
            .clone()
            .map(|context| Context { backend: context })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::ReencryptionRequest>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// ReencryptionResponse
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct ReencryptionResponse {
    backend: nucypher_core::ReencryptionResponse,
}

#[pymethods]
impl ReencryptionResponse {
    #[new]
    pub fn new(signer: &Signer, capsules_and_vcfrags: Vec<(Capsule, VerifiedCapsuleFrag)>) -> Self {
        let (capsules_backend, vcfrags_backend): (Vec<_>, Vec<_>) = capsules_and_vcfrags
            .into_iter()
            .map(|(capsule, vcfrag)| {
                (
                    umbral_pre::Capsule::from(capsule),
                    umbral_pre::VerifiedCapsuleFrag::from(vcfrag),
                )
            })
            .unzip();
        ReencryptionResponse {
            backend: nucypher_core::ReencryptionResponse::new(
                signer.as_ref(),
                capsules_backend.iter().zip(vcfrags_backend),
            ),
        }
    }

    pub fn verify(
        &self,
        capsules: Vec<Capsule>,
        alice_verifying_key: &PublicKey,
        ursula_verifying_key: &PublicKey,
        policy_encrypting_key: &PublicKey,
        bob_encrypting_key: &PublicKey,
    ) -> PyResult<Vec<VerifiedCapsuleFrag>> {
        let capsules_backend = capsules
            .into_iter()
            .map(umbral_pre::Capsule::from)
            .collect::<Vec<_>>();
        let vcfrags_backend = self
            .backend
            .clone()
            .verify(
                &capsules_backend,
                alice_verifying_key.as_ref(),
                ursula_verifying_key.as_ref(),
                policy_encrypting_key.as_ref(),
                bob_encrypting_key.as_ref(),
            )
            .map_err(|_err| PyValueError::new_err("ReencryptionResponse verification failed"))?;
        Ok(vcfrags_backend
            .iter()
            .cloned()
            .map(VerifiedCapsuleFrag::from)
            .collect::<Vec<_>>())
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::ReencryptionResponse>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// Session Keys
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct SessionSharedSecret {
    backend: nucypher_core::SessionSharedSecret,
}

#[pyclass(module = "nucypher_core")]
#[derive(Clone, PartialEq, Eq, derive_more::From, derive_more::AsRef)]
pub struct SessionStaticKey {
    backend: nucypher_core::SessionStaticKey,
}

#[pymethods]
impl SessionStaticKey {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::SessionStaticKey>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash("SessionStaticKey", self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct SessionStaticSecret {
    backend: nucypher_core::SessionStaticSecret,
}

#[pymethods]
impl SessionStaticSecret {
    #[staticmethod]
    pub fn random() -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::SessionStaticSecret::random(),
        })
    }

    pub fn public_key(&self) -> SessionStaticKey {
        SessionStaticKey {
            backend: self.backend.public_key(),
        }
    }

    pub fn derive_shared_secret(&self, their_public_key: &SessionStaticKey) -> SessionSharedSecret {
        SessionSharedSecret {
            backend: self.backend.derive_shared_secret(their_public_key.as_ref()),
        }
    }

    fn __str__(&self) -> String {
        self.backend.to_string()
    }
}

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct SessionSecretFactory {
    backend: nucypher_core::SessionSecretFactory,
}

#[pymethods]
impl SessionSecretFactory {
    #[staticmethod]
    pub fn random() -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::SessionSecretFactory::random(),
        })
    }

    #[staticmethod]
    pub fn seed_size() -> usize {
        nucypher_core::SessionSecretFactory::seed_size()
    }

    #[staticmethod]
    pub fn from_secure_randomness(seed: &[u8]) -> PyResult<Self> {
        let factory = nucypher_core::SessionSecretFactory::from_secure_randomness(seed)
            .map_err(|err| PyValueError::new_err(format!("{err}")))?;
        Ok(Self { backend: factory })
    }

    pub fn make_key(&self, label: &[u8]) -> SessionStaticSecret {
        SessionStaticSecret {
            backend: self.backend.make_key(label),
        }
    }

    fn __str__(&self) -> String {
        self.backend.to_string()
    }
}

//
// Authenticated data.
//
#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct AuthenticatedData {
    backend: nucypher_core::AuthenticatedData,
}

#[pymethods]
impl AuthenticatedData {
    #[new]
    pub fn new(public_key: &DkgPublicKey, conditions: &Conditions) -> Self {
        Self {
            backend: nucypher_core::AuthenticatedData::new(
                public_key.as_ref(),
                conditions.as_ref(),
            ),
        }
    }

    pub fn aad(&self, py: Python) -> PyResult<PyObject> {
        let result = self
            .backend
            .aad()
            .map_err(|err| PyValueError::new_err(format!("{err}")))?;
        Ok(PyBytes::new(py, &result).into())
    }

    #[getter]
    pub fn public_key(&self) -> DkgPublicKey {
        self.backend.public_key.into()
    }

    #[getter]
    pub fn conditions(&self) -> Conditions {
        self.backend.conditions.clone().into()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::AuthenticatedData>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// Encrypt for DKG.
//
#[pyfunction]
#[pyo3(signature = (data, public_key, conditions))]
pub fn encrypt_for_dkg(
    data: &[u8],
    public_key: &DkgPublicKey,
    conditions: &Conditions,
) -> PyResult<(Ciphertext, AuthenticatedData)> {
    let (ciphertext, auth_data) =
        nucypher_core::encrypt_for_dkg(data, public_key.as_ref(), conditions.as_ref())
            .map_err(FerveoPythonError::FerveoError)?;
    Ok((ciphertext.into(), auth_data.into()))
}

//
// Access control metadata for encrypted data.
//
#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct AccessControlPolicy {
    backend: nucypher_core::AccessControlPolicy,
}

#[pymethods]
impl AccessControlPolicy {
    #[new]
    pub fn new(auth_data: &AuthenticatedData, authorization: &[u8]) -> Self {
        Self {
            backend: nucypher_core::AccessControlPolicy::new(&auth_data.backend, authorization),
        }
    }

    pub fn aad(&self, py: Python) -> PyResult<PyObject> {
        let result = self
            .backend
            .aad()
            .map_err(|err| PyValueError::new_err(format!("{err}")))?;
        Ok(PyBytes::new(py, &result).into())
    }

    #[getter]
    pub fn public_key(&self) -> DkgPublicKey {
        self.backend.public_key().into()
    }

    #[getter]
    pub fn conditions(&self) -> Conditions {
        Conditions {
            backend: self.backend.conditions(),
        }
    }

    #[getter]
    pub fn authorization(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.authorization).into()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::AccessControlPolicy>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// ThresholdMessageKit
//
#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct ThresholdMessageKit {
    backend: nucypher_core::ThresholdMessageKit,
}

#[pymethods]
impl ThresholdMessageKit {
    #[new]
    pub fn new(ciphertext: &Ciphertext, acp: &AccessControlPolicy) -> Self {
        Self {
            backend: nucypher_core::ThresholdMessageKit::new(ciphertext.as_ref(), &acp.backend),
        }
    }

    #[getter]
    pub fn ciphertext_header(&self) -> PyResult<CiphertextHeader> {
        let header = self
            .backend
            .ciphertext_header()
            .map_err(FerveoPythonError::from)?;
        Ok(CiphertextHeader::from(header))
    }

    #[getter]
    pub fn acp(&self) -> AccessControlPolicy {
        self.backend.acp.clone().into()
    }

    pub fn decrypt_with_shared_secret(&self, shared_secret: &SharedSecret) -> PyResult<Vec<u8>> {
        self.backend
            .decrypt_with_shared_secret(shared_secret.as_ref())
            .map_err(|err| FerveoPythonError::FerveoError(err).into())
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::ThresholdMessageKit>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// Threshold Decryption Request
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct ThresholdDecryptionRequest {
    backend: nucypher_core::ThresholdDecryptionRequest,
}

#[pymethods]
impl ThresholdDecryptionRequest {
    #[new]
    pub fn new(
        ritual_id: u32,
        variant: FerveoVariant,
        ciphertext_header: &CiphertextHeader,
        acp: &AccessControlPolicy,
        context: Option<&Context>,
    ) -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::ThresholdDecryptionRequest::new(
                ritual_id,
                ciphertext_header.as_ref(),
                acp.as_ref(),
                context.map(|context| &context.backend),
                variant.into(),
            ),
        })
    }

    #[getter]
    pub fn ritual_id(&self) -> u32 {
        self.backend.ritual_id
    }

    #[getter]
    pub fn acp(&self) -> AccessControlPolicy {
        self.backend.acp.clone().into()
    }

    #[getter]
    pub fn context(&self) -> Option<Context> {
        self.backend
            .context
            .clone()
            .map(|context| Context { backend: context })
    }

    #[getter]
    pub fn ciphertext_header(&self) -> CiphertextHeader {
        self.backend.ciphertext_header.clone().into()
    }

    #[getter]
    pub fn variant(&self) -> FerveoVariant {
        self.backend.variant.into()
    }

    pub fn encrypt(
        &self,
        shared_secret: &SessionSharedSecret,
        requester_public_key: &SessionStaticKey,
    ) -> EncryptedThresholdDecryptionRequest {
        let encrypted_request = self
            .backend
            .encrypt(shared_secret.as_ref(), requester_public_key.as_ref());
        EncryptedThresholdDecryptionRequest {
            backend: encrypted_request,
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::ThresholdDecryptionRequest>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// EncryptedThresholdDecryptionRequest
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct EncryptedThresholdDecryptionRequest {
    backend: nucypher_core::EncryptedThresholdDecryptionRequest,
}

#[pymethods]
impl EncryptedThresholdDecryptionRequest {
    #[getter]
    pub fn ritual_id(&self) -> u32 {
        self.backend.ritual_id
    }

    #[getter]
    pub fn requester_public_key(&self) -> SessionStaticKey {
        self.backend.requester_public_key.into()
    }

    pub fn decrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> PyResult<ThresholdDecryptionRequest> {
        self.backend
            .decrypt(shared_secret.as_ref())
            .map(ThresholdDecryptionRequest::from)
            .map_err(|err| PyValueError::new_err(format!("{err}")))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::EncryptedThresholdDecryptionRequest>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// Threshold Decryption Response
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct ThresholdDecryptionResponse {
    backend: nucypher_core::ThresholdDecryptionResponse,
}

#[pymethods]
impl ThresholdDecryptionResponse {
    #[new]
    pub fn new(ritual_id: u32, decryption_share: &[u8]) -> Self {
        ThresholdDecryptionResponse {
            backend: nucypher_core::ThresholdDecryptionResponse::new(ritual_id, decryption_share),
        }
    }

    #[getter]
    pub fn ritual_id(&self) -> u32 {
        self.backend.ritual_id
    }

    #[getter]
    pub fn decryption_share(&self) -> &[u8] {
        self.backend.decryption_share.as_ref()
    }

    pub fn encrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> EncryptedThresholdDecryptionResponse {
        EncryptedThresholdDecryptionResponse {
            backend: self.backend.encrypt(shared_secret.as_ref()),
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::ThresholdDecryptionResponse>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// EncryptedThresholdDecryptionResponse
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct EncryptedThresholdDecryptionResponse {
    backend: nucypher_core::EncryptedThresholdDecryptionResponse,
}

#[pymethods]
impl EncryptedThresholdDecryptionResponse {
    #[getter]
    pub fn ritual_id(&self) -> u32 {
        self.backend.ritual_id
    }

    pub fn decrypt(
        &self,
        shared_secret: &SessionSharedSecret,
    ) -> PyResult<ThresholdDecryptionResponse> {
        self.backend
            .decrypt(shared_secret.as_ref())
            .map(ThresholdDecryptionResponse::from)
            .map_err(|err| PyValueError::new_err(format!("{err}")))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::EncryptedThresholdDecryptionResponse>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// RetrievalKit
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct RetrievalKit {
    backend: nucypher_core::RetrievalKit,
}

#[pymethods]
impl RetrievalKit {
    #[staticmethod]
    pub fn from_message_kit(message_kit: &MessageKit) -> Self {
        Self {
            backend: nucypher_core::RetrievalKit::from_message_kit(&message_kit.backend),
        }
    }

    #[new]
    pub fn new(
        capsule: &Capsule,
        queried_addresses: BTreeSet<Address>,
        conditions: Option<&Conditions>,
    ) -> Self {
        let addresses_backend = queried_addresses
            .iter()
            .map(|address| address.backend)
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::RetrievalKit::new(
                capsule.as_ref(),
                addresses_backend,
                conditions.map(|conditions| &conditions.backend),
            ),
        }
    }

    #[getter]
    fn capsule(&self) -> Capsule {
        self.backend.capsule.clone().into()
    }

    #[getter]
    fn queried_addresses(&self) -> BTreeSet<Address> {
        self.backend
            .queried_addresses
            .iter()
            .map(|address| Address { backend: *address })
            .collect::<BTreeSet<_>>()
    }

    #[getter]
    fn conditions(&self) -> Option<Conditions> {
        self.backend
            .conditions
            .clone()
            .map(|conditions| Conditions {
                backend: conditions,
            })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::RetrievalKit>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// RevocationOrder
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct RevocationOrder {
    backend: nucypher_core::RevocationOrder,
}

#[pymethods]
impl RevocationOrder {
    #[new]
    pub fn new(
        signer: &Signer,
        staking_provider_address: &Address,
        encrypted_kfrag: &EncryptedKeyFrag,
    ) -> Self {
        Self {
            backend: nucypher_core::RevocationOrder::new(
                signer.as_ref(),
                &staking_provider_address.backend,
                &encrypted_kfrag.backend,
            ),
        }
    }

    pub fn verify(&self, alice_verifying_key: &PublicKey) -> PyResult<(Address, EncryptedKeyFrag)> {
        self.backend
            .clone()
            .verify(alice_verifying_key.as_ref())
            .map(|(address, ekfrag)| {
                (
                    Address { backend: address },
                    EncryptedKeyFrag { backend: ekfrag },
                )
            })
            .map_err(|_err| VerificationError::new_err("RevocationOrder verification failed"))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::RevocationOrder>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// NodeMetadataPayload
//

#[pyclass(module = "nucypher_core")]
pub struct NodeMetadataPayload {
    backend: nucypher_core::NodeMetadataPayload,
}

#[pymethods]
impl NodeMetadataPayload {
    #[allow(clippy::too_many_arguments)]
    #[new]
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
    ) -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::NodeMetadataPayload {
                staking_provider_address: staking_provider_address.backend,
                domain: domain.to_string(),
                timestamp_epoch,
                verifying_key: *verifying_key.as_ref(),
                encrypting_key: *encrypting_key.as_ref(),
                ferveo_public_key: *ferveo_public_key.as_ref(),
                certificate_der: certificate_der.into(),
                host: host.to_string(),
                port,
                operator_signature: operator_signature.as_ref().clone(),
            },
        })
    }

    #[getter]
    fn staking_provider_address(&self) -> Address {
        Address {
            backend: self.backend.staking_provider_address,
        }
    }

    #[getter]
    fn verifying_key(&self) -> PublicKey {
        self.backend.verifying_key.into()
    }

    #[getter]
    fn encrypting_key(&self) -> PublicKey {
        self.backend.encrypting_key.into()
    }

    #[getter]
    fn ferveo_public_key(&self) -> FerveoPublicKey {
        self.backend.ferveo_public_key.into()
    }

    #[getter]
    fn operator_signature(&self) -> RecoverableSignature {
        self.backend.operator_signature.clone().into()
    }

    #[getter]
    fn domain(&self) -> &str {
        &self.backend.domain
    }

    #[getter]
    fn host(&self) -> &str {
        &self.backend.host
    }

    #[getter]
    fn port(&self) -> u16 {
        self.backend.port
    }

    #[getter]
    fn timestamp_epoch(&self) -> u32 {
        self.backend.timestamp_epoch
    }

    #[getter]
    fn certificate_der(&self) -> &[u8] {
        self.backend.certificate_der.as_ref()
    }

    fn derive_operator_address(&self) -> PyResult<PyObject> {
        let address = self
            .backend
            .derive_operator_address()
            .map_err(|err| PyValueError::new_err(format!("{err}")))?;
        Ok(Python::with_gil(|py| -> PyObject {
            PyBytes::new(py, address.as_ref()).into()
        }))
    }
}

//
// NodeMetadata
//

#[pyclass(module = "nucypher_core")]
#[derive(Clone, derive_more::From, derive_more::AsRef)]
pub struct NodeMetadata {
    backend: nucypher_core::NodeMetadata,
}

#[pymethods]
impl NodeMetadata {
    #[new]
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        Self {
            backend: nucypher_core::NodeMetadata::new(signer.as_ref(), &payload.backend),
        }
    }

    pub fn verify(&self) -> bool {
        self.backend.verify()
    }

    #[getter]
    pub fn payload(&self) -> NodeMetadataPayload {
        NodeMetadataPayload {
            backend: self.backend.payload.clone(),
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::NodeMetadata>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// FleetStateChecksum
//

#[pyclass(module = "nucypher_core")]
#[derive(PartialEq, Eq, derive_more::AsRef)]
pub struct FleetStateChecksum {
    backend: nucypher_core::FleetStateChecksum,
}

#[pymethods]
impl FleetStateChecksum {
    #[new]
    pub fn new(other_nodes: Vec<NodeMetadata>, this_node: Option<&NodeMetadata>) -> Self {
        let other_nodes_backend = other_nodes
            .iter()
            .map(|node| node.backend.clone())
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::FleetStateChecksum::from_nodes(
                &other_nodes_backend,
                this_node.map(|node| node.backend.clone()).as_ref(),
            ),
        }
    }

    fn __bytes__(&self) -> &[u8] {
        self.backend.as_ref()
    }

    fn __richcmp__(&self, other: &Self, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash("FleetStateChecksum", self)
    }

    fn __str__(&self) -> PyResult<String> {
        Ok(format!("{}", self.backend))
    }
}

//
// MetadataRequest
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct MetadataRequest {
    backend: nucypher_core::MetadataRequest,
}

#[pymethods]
impl MetadataRequest {
    #[new]
    pub fn new(
        fleet_state_checksum: &FleetStateChecksum,
        announce_nodes: Vec<NodeMetadata>,
    ) -> Self {
        let nodes_backend = announce_nodes
            .iter()
            .map(|node| node.backend.clone())
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::MetadataRequest::new(
                &fleet_state_checksum.backend,
                &nodes_backend,
            ),
        }
    }

    #[getter]
    fn fleet_state_checksum(&self) -> FleetStateChecksum {
        FleetStateChecksum {
            backend: self.backend.fleet_state_checksum,
        }
    }

    #[getter]
    fn announce_nodes(&self) -> Vec<NodeMetadata> {
        self.backend
            .announce_nodes
            .iter()
            .map(|node| NodeMetadata {
                backend: node.clone(),
            })
            .collect::<Vec<_>>()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::MetadataRequest>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// MetadataResponsePayload
//

#[pyclass(module = "nucypher_core")]
pub struct MetadataResponsePayload {
    backend: nucypher_core::MetadataResponsePayload,
}

#[pymethods]
impl MetadataResponsePayload {
    #[new]
    fn new(timestamp_epoch: u32, announce_nodes: Vec<NodeMetadata>) -> Self {
        let nodes_backend = announce_nodes
            .iter()
            .map(|node| node.backend.clone())
            .collect::<Vec<_>>();
        MetadataResponsePayload {
            backend: nucypher_core::MetadataResponsePayload::new(timestamp_epoch, &nodes_backend),
        }
    }

    #[getter]
    fn timestamp_epoch(&self) -> u32 {
        self.backend.timestamp_epoch
    }

    #[getter]
    fn announce_nodes(&self) -> Vec<NodeMetadata> {
        self.backend
            .announce_nodes
            .iter()
            .map(|node| NodeMetadata {
                backend: node.clone(),
            })
            .collect::<Vec<_>>()
    }
}

//
// MetadataResponse
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct MetadataResponse {
    backend: nucypher_core::MetadataResponse,
}

#[pymethods]
impl MetadataResponse {
    #[new]
    pub fn new(signer: &Signer, payload: &MetadataResponsePayload) -> Self {
        Self {
            backend: nucypher_core::MetadataResponse::new(signer.as_ref(), &payload.backend),
        }
    }

    pub fn verify(&self, verifying_pk: &PublicKey) -> PyResult<MetadataResponsePayload> {
        self.backend
            .clone()
            .verify(verifying_pk.as_ref())
            .map(|backend_payload| MetadataResponsePayload {
                backend: backend_payload,
            })
            .map_err(|_err| VerificationError::new_err("MetadataResponse verification failed"))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::MetadataResponse>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// UserOperation
//

/// Python bindings for UserOperation
#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct UserOperation {
    backend: SignatureRequestUserOperation,
}

#[pymethods]
impl UserOperation {
    #[new]
    #[pyo3(signature = (sender, nonce, call_data, call_gas_limit, verification_gas_limit, pre_verification_gas, max_fee_per_gas, max_priority_fee_per_gas, factory=None, factory_data=None, paymaster=None, paymaster_verification_gas_limit=None, paymaster_post_op_gas_limit=None, paymaster_data=None))]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender: String,
        nonce: u64,
        call_data: &[u8],
        call_gas_limit: u128,
        verification_gas_limit: u128,
        pre_verification_gas: u128,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
        factory: Option<String>,
        factory_data: Option<&[u8]>,
        paymaster: Option<String>,
        paymaster_verification_gas_limit: Option<u128>,
        paymaster_post_op_gas_limit: Option<u128>,
        paymaster_data: Option<&[u8]>,
    ) -> PyResult<Self> {
        // Convert hex string to Address
        let sender_address = nucypher_core::Address::from_str(&sender)
            .map_err(|e| PyValueError::new_err(format!("Invalid sender address: {}", e)))?;
        let paymaster_address = paymaster
            .as_ref()
            .map(|p| nucypher_core::Address::from_str(p))
            .transpose()
            .map_err(|e| PyValueError::new_err(format!("Invalid paymaster address: {}", e)))?;
        let factory_address = factory
            .as_ref()
            .map(|f| nucypher_core::Address::from_str(f))
            .transpose()
            .map_err(|e| PyValueError::new_err(format!("Invalid factory address: {}", e)))?;

        Ok(Self {
            backend: SignatureRequestUserOperation::new(
                sender_address,
                nonce,
                call_data,
                call_gas_limit,
                verification_gas_limit,
                pre_verification_gas,
                max_fee_per_gas,
                max_priority_fee_per_gas,
                factory_address,
                factory_data,
                paymaster_address,
                paymaster_verification_gas_limit,
                paymaster_post_op_gas_limit,
                paymaster_data,
            ),
        })
    }

    #[getter]
    pub fn sender(&self) -> String {
        self.backend.sender.to_checksum_address()
    }

    #[getter]
    pub fn nonce(&self) -> u64 {
        self.backend.nonce
    }

    #[getter]
    pub fn call_data(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.call_data).into()
    }

    #[getter]
    pub fn call_gas_limit(&self) -> u128 {
        self.backend.call_gas_limit
    }

    #[getter]
    pub fn verification_gas_limit(&self) -> u128 {
        self.backend.verification_gas_limit
    }

    #[getter]
    pub fn pre_verification_gas(&self) -> u128 {
        self.backend.pre_verification_gas
    }

    #[getter]
    pub fn max_fee_per_gas(&self) -> u128 {
        self.backend.max_fee_per_gas
    }

    #[getter]
    pub fn max_priority_fee_per_gas(&self) -> u128 {
        self.backend.max_priority_fee_per_gas
    }

    #[getter]
    pub fn factory(&self) -> Option<String> {
        self.backend.factory.map(|f| f.to_checksum_address())
    }

    #[getter]
    pub fn factory_data(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.factory_data).into()
    }

    #[getter]
    pub fn paymaster(&self) -> Option<String> {
        self.backend.paymaster.map(|p| p.to_checksum_address())
    }

    #[getter]
    pub fn paymaster_verification_gas_limit(&self) -> u128 {
        self.backend.paymaster_verification_gas_limit
    }

    #[getter]
    pub fn paymaster_post_op_gas_limit(&self) -> u128 {
        self.backend.paymaster_post_op_gas_limit
    }

    #[getter]
    pub fn paymaster_data(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.paymaster_data).into()
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, SignatureRequestUserOperation>(data)
    }
}

//
// UserOperationSignatureRequest
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct UserOperationSignatureRequest {
    backend: nucypher_core::UserOperationSignatureRequest,
}

#[pymethods]
impl UserOperationSignatureRequest {
    #[new]
    pub fn new(
        user_op: &UserOperation,
        cohort_id: u32,
        chain_id: u64,
        aa_version: &str,
        context: Option<&Context>,
    ) -> PyResult<Self> {
        let core_aa_version = nucypher_core::AAVersion::from_str(aa_version)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        Ok(Self {
            backend: nucypher_core::UserOperationSignatureRequest::new(
                user_op.backend.clone(),
                cohort_id,
                chain_id,
                core_aa_version,
                context.map(|c| &c.backend),
            ),
        })
    }

    #[getter]
    fn user_op(&self) -> UserOperation {
        UserOperation::from(self.backend.user_op.clone())
    }

    #[getter]
    fn cohort_id(&self) -> u32 {
        self.backend.cohort_id
    }

    #[getter]
    fn chain_id(&self) -> u64 {
        self.backend.chain_id
    }

    #[getter]
    fn aa_version(&self) -> &str {
        self.backend.aa_version.as_str()
    }

    #[getter]
    fn context(&self) -> Option<Context> {
        self.backend
            .context
            .clone()
            .map(|context| Context { backend: context })
    }

    #[getter]
    fn signature_type(&self) -> u8 {
        self.backend.signature_type.as_u8()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::UserOperationSignatureRequest>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// PackedUserOperation
//

/// Python bindings for PackedUserOperation
#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct PackedUserOperation {
    backend: SignatureRequestPackedUserOperation,
}

#[pymethods]
impl PackedUserOperation {
    #[new]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sender: String,
        nonce: u64,
        init_code: &[u8],
        call_data: &[u8],
        account_gas_limits: &[u8],
        pre_verification_gas: u128,
        gas_fees: &[u8],
        paymaster_and_data: &[u8],
    ) -> PyResult<Self> {
        // Convert hex string to Address
        let sender_address = nucypher_core::Address::from_str(&sender)
            .map_err(|e| PyValueError::new_err(format!("Invalid sender address: {}", e)))?;

        Ok(Self {
            backend: SignatureRequestPackedUserOperation::new(
                sender_address,
                nonce,
                init_code,
                call_data,
                account_gas_limits,
                pre_verification_gas,
                gas_fees,
                paymaster_and_data,
            ),
        })
    }

    #[staticmethod]
    pub fn from_user_operation(user_op: &UserOperation) -> Self {
        Self {
            backend: SignatureRequestPackedUserOperation::from_user_operation(&user_op.backend),
        }
    }

    #[staticmethod]
    #[pyo3(name = "_pack_account_gas_limits")]
    pub fn pack_account_gas_limits(
        py: Python,
        call_gas_limit: u128,
        verification_gas_limit: u128,
    ) -> PyObject {
        let mut result = [0u8; 32];
        // Pack as: verification_gas_limit << 128 | call_gas_limit
        // Each value is u128, so verification goes in upper 16 bytes, call in lower 16 bytes
        result[0..16].copy_from_slice(&verification_gas_limit.to_be_bytes());
        result[16..32].copy_from_slice(&call_gas_limit.to_be_bytes());
        PyBytes::new(py, &result).into()
    }

    #[staticmethod]
    #[pyo3(name = "_pack_gas_fees")]
    pub fn pack_gas_fees(
        py: Python,
        max_fee_per_gas: u128,
        max_priority_fee_per_gas: u128,
    ) -> PyObject {
        let mut result = [0u8; 32];
        // Pack as: max_priority_fee_per_gas << 128 | max_fee_per_gas
        // Each value is u128, so priority goes in upper 16 bytes, max_fee in lower 16 bytes
        result[0..16].copy_from_slice(&max_priority_fee_per_gas.to_be_bytes());
        result[16..32].copy_from_slice(&max_fee_per_gas.to_be_bytes());
        PyBytes::new(py, &result).into()
    }

    #[staticmethod]
    #[pyo3(name = "_pack_paymaster_and_data", signature = (paymaster, paymaster_verification_gas_limit, paymaster_post_op_gas_limit, paymaster_data))]
    pub fn pack_paymaster_and_data(
        py: Python,
        paymaster: Option<String>,
        paymaster_verification_gas_limit: u128,
        paymaster_post_op_gas_limit: u128,
        paymaster_data: &[u8],
    ) -> PyResult<PyObject> {
        match paymaster {
            None => Ok(PyBytes::new(py, &[]).into()),
            Some(addr_str) => {
                let addr = nucypher_core::Address::from_str(&addr_str).map_err(|e| {
                    PyValueError::new_err(format!("Invalid paymaster address: {}", e))
                })?;
                let mut result = Vec::with_capacity(20 + 16 + 16 + paymaster_data.len());
                result.extend_from_slice(addr.as_ref());

                // Verification gas limit as 16 bytes big-endian (full u128)
                result.extend_from_slice(&paymaster_verification_gas_limit.to_be_bytes());

                // Post-op gas limit as 16 bytes big-endian (full u128)
                result.extend_from_slice(&paymaster_post_op_gas_limit.to_be_bytes());

                result.extend_from_slice(paymaster_data);
                Ok(PyBytes::new(py, &result).into())
            }
        }
    }

    #[getter]
    pub fn sender(&self) -> String {
        self.backend.sender.to_checksum_address()
    }

    #[getter]
    pub fn nonce(&self) -> u64 {
        self.backend.nonce
    }

    #[getter]
    pub fn init_code(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.init_code).into()
    }

    #[getter]
    pub fn call_data(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.call_data).into()
    }

    #[getter]
    pub fn account_gas_limits(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.account_gas_limits).into()
    }

    #[getter]
    pub fn pre_verification_gas(&self) -> u128 {
        self.backend.pre_verification_gas
    }

    #[getter]
    pub fn gas_fees(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.gas_fees).into()
    }

    #[getter]
    pub fn paymaster_and_data(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.paymaster_and_data).into()
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, SignatureRequestPackedUserOperation>(data)
    }

    pub fn to_eip712_struct(&self, aa_version: &str, chain_id: u64) -> PyResult<PyObject> {
        let core_aa_version = nucypher_core::AAVersion::from_str(aa_version)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let eip712_struct = self.backend.to_eip712_struct(&core_aa_version, chain_id);

        Python::with_gil(|py| json_to_pyobject(py, &serde_json::Value::Object(eip712_struct)))
    }

    #[pyo3(name = "_to_eip712_message")]
    pub fn to_eip712_message(&self, aa_version: &str) -> PyResult<PyObject> {
        let core_aa_version = nucypher_core::AAVersion::from_str(aa_version)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let message = self.backend.to_eip712_message(&core_aa_version);

        Python::with_gil(|py| json_to_pyobject(py, &serde_json::Value::Object(message)))
    }

    #[pyo3(name = "_get_domain")]
    pub fn get_domain(&self, aa_version: &str, chain_id: u64) -> PyResult<PyObject> {
        let core_aa_version = nucypher_core::AAVersion::from_str(aa_version)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let domain = self.backend.get_domain(&core_aa_version, chain_id);

        Python::with_gil(|py| json_to_pyobject(py, &serde_json::Value::Object(domain)))
    }
}

//
// SignedPackedUserOperation
//

/// Python bindings for SignedPackedUserOperation
#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct SignedPackedUserOperation {
    backend: SignatureRequestSignedPackedUserOperation,
}

#[pymethods]
impl SignedPackedUserOperation {
    #[new]
    pub fn new(operation: &PackedUserOperation, signature: &[u8]) -> Self {
        Self {
            backend: SignatureRequestSignedPackedUserOperation::new(
                operation.backend.clone(),
                signature,
            ),
        }
    }

    #[getter]
    pub fn operation(&self) -> PackedUserOperation {
        PackedUserOperation::from(self.backend.operation().clone())
    }

    #[getter]
    pub fn signature(&self, py: Python) -> PyObject {
        PyBytes::new(py, self.backend.signature()).into()
    }

    pub fn into_parts(&self) -> (PackedUserOperation, PyObject) {
        let (operation, signature) = (self.backend.operation().clone(), self.backend.signature());
        Python::with_gil(|py| {
            (
                PackedUserOperation::from(operation),
                PyBytes::new(py, signature).into(),
            )
        })
    }

    pub fn to_eip712_struct(&self, aa_version: &str, chain_id: u64) -> PyResult<PyObject> {
        let core_aa_version = nucypher_core::AAVersion::from_str(aa_version)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let eip712_struct = self.backend.to_eip712_struct(&core_aa_version, chain_id);

        Python::with_gil(|py| json_to_pyobject(py, &serde_json::Value::Object(eip712_struct)))
    }

    #[pyo3(name = "_to_eip712_message")]
    pub fn to_eip712_message(&self, aa_version: &str) -> PyResult<PyObject> {
        let core_aa_version = nucypher_core::AAVersion::from_str(aa_version)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let message = self.backend.to_eip712_message(&core_aa_version);

        Python::with_gil(|py| json_to_pyobject(py, &serde_json::Value::Object(message)))
    }

    #[pyo3(name = "_get_domain")]
    pub fn get_domain(&self, aa_version: &str, chain_id: u64) -> PyResult<PyObject> {
        let core_aa_version = nucypher_core::AAVersion::from_str(aa_version)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        let domain = self.backend.get_domain(&core_aa_version, chain_id);

        Python::with_gil(|py| json_to_pyobject(py, &serde_json::Value::Object(domain)))
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, SignatureRequestSignedPackedUserOperation>(data)
    }
}

//
// PackedUserOperationSignatureRequest
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct PackedUserOperationSignatureRequest {
    backend: nucypher_core::PackedUserOperationSignatureRequest,
}

#[pymethods]
impl PackedUserOperationSignatureRequest {
    #[new]
    pub fn new(
        packed_user_op: &PackedUserOperation,
        cohort_id: u32,
        chain_id: u64,
        aa_version: &str,
        context: Option<&Context>,
    ) -> PyResult<Self> {
        let core_aa_version = nucypher_core::AAVersion::from_str(aa_version)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        Ok(Self {
            backend: nucypher_core::PackedUserOperationSignatureRequest::new(
                packed_user_op.backend.clone(),
                cohort_id,
                chain_id,
                core_aa_version,
                context.map(|c| &c.backend),
            ),
        })
    }

    #[getter]
    fn packed_user_op(&self) -> PackedUserOperation {
        PackedUserOperation::from(self.backend.packed_user_op.clone())
    }

    #[getter]
    fn cohort_id(&self) -> u32 {
        self.backend.cohort_id
    }

    #[getter]
    fn chain_id(&self) -> u64 {
        self.backend.chain_id
    }

    #[getter]
    fn aa_version(&self) -> &str {
        self.backend.aa_version.as_str()
    }

    #[getter]
    fn context(&self) -> Option<Context> {
        self.backend
            .context
            .clone()
            .map(|context| Context { backend: context })
    }

    #[getter]
    fn signature_type(&self) -> u8 {
        self.backend.signature_type as u8
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::PackedUserOperationSignatureRequest>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// SignatureResponse
//

#[pyclass(module = "nucypher_core")]
#[derive(derive_more::From, derive_more::AsRef)]
pub struct SignatureResponse {
    backend: nucypher_core::SignatureResponse,
}

#[pymethods]
impl SignatureResponse {
    #[new]
    pub fn new(hash: &[u8], signature: &[u8], signature_type: u8) -> PyResult<Self> {
        let core_signature_type = SignatureRequestType::from_u8(signature_type)
            .map_err(|err| PyValueError::new_err(err.to_string()))?;
        Ok(Self {
            backend: nucypher_core::SignatureResponse::new(hash, signature, core_signature_type),
        })
    }

    #[getter]
    fn hash(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.hash).into()
    }

    #[getter]
    fn signature(&self, py: Python) -> PyObject {
        PyBytes::new(py, &self.backend.signature).into()
    }

    #[getter]
    fn signature_type(&self) -> u8 {
        self.backend.signature_type.as_u8()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes::<_, nucypher_core::SignatureResponse>(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _nucypher_core(py: Python, core_module: &PyModule) -> PyResult<()> {
    core_module.add_class::<Address>()?;
    core_module.add_class::<Conditions>()?;
    core_module.add_class::<Context>()?;
    core_module.add_class::<MessageKit>()?;
    core_module.add_class::<HRAC>()?;
    core_module.add_class::<EncryptedKeyFrag>()?;
    core_module.add_class::<TreasureMap>()?;
    core_module.add_class::<EncryptedTreasureMap>()?;
    core_module.add_class::<ReencryptionRequest>()?;
    core_module.add_class::<ReencryptionResponse>()?;
    core_module.add_class::<RetrievalKit>()?;
    core_module.add_class::<RevocationOrder>()?;
    core_module.add_class::<NodeMetadata>()?;
    core_module.add_class::<NodeMetadataPayload>()?;
    core_module.add_class::<FleetStateChecksum>()?;
    core_module.add_class::<MetadataRequest>()?;
    core_module.add_class::<MetadataResponsePayload>()?;
    core_module.add_class::<MetadataResponse>()?;
    core_module.add_class::<ThresholdDecryptionRequest>()?;
    core_module.add_class::<ThresholdDecryptionResponse>()?;
    core_module.add_class::<EncryptedThresholdDecryptionRequest>()?;
    core_module.add_class::<EncryptedThresholdDecryptionResponse>()?;
    core_module.add_class::<SessionSharedSecret>()?;
    core_module.add_class::<SessionStaticKey>()?;
    core_module.add_class::<SessionStaticSecret>()?;
    core_module.add_class::<SessionSecretFactory>()?;
    core_module.add_class::<AuthenticatedData>()?;
    core_module.add_class::<AccessControlPolicy>()?;
    core_module.add_class::<ThresholdMessageKit>()?;
    core_module.add_function(wrap_pyfunction!(encrypt_for_dkg, core_module)?)?;

    // Add signature request/response classes
    core_module.add_class::<UserOperation>()?;
    core_module.add_class::<UserOperationSignatureRequest>()?;
    core_module.add_class::<PackedUserOperation>()?;
    core_module.add_class::<SignedPackedUserOperation>()?;
    core_module.add_class::<PackedUserOperationSignatureRequest>()?;
    core_module.add_class::<SignatureResponse>()?;
    core_module.add_function(wrap_pyfunction!(
        deserialize_signature_request,
        core_module
    )?)?;

    // Build the umbral module
    let umbral_module = PyModule::new(py, "umbral")?;

    umbral_module.add_class::<umbral_pre::bindings_python::SecretKey>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::SecretKeyFactory>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::PublicKey>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::Capsule>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::VerifiedKeyFrag>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::VerifiedCapsuleFrag>()?;
    umbral_pre::bindings_python::register_reencrypt(umbral_module)?;
    umbral_pre::bindings_python::register_generate_kfrags(umbral_module)?;

    umbral_module.add_class::<umbral_pre::bindings_python::Signer>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::Signature>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::RecoverableSignature>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::KeyFrag>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::CapsuleFrag>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::ReencryptionEvidence>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::CurvePoint>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::Parameters>()?;
    umbral_module.add(
        "VerificationError",
        py.get_type::<umbral_pre::bindings_python::VerificationError>(),
    )?; // depends on what `reencryption_response.verify()` returns
    core_module.add_submodule(umbral_module)?;

    // Build the ferveo module
    let ferveo_module = PyModule::new(py, "ferveo")?;
    ferveo::bindings_python::make_ferveo_py_module(py, ferveo_module)?;
    core_module.add_submodule(ferveo_module)?;

    Ok(())
}

// Helper function to convert JSON value to Python object
fn json_to_pyobject(py: Python, value: &serde_json::Value) -> PyResult<PyObject> {
    use pyo3::types::{PyDict, PyList};
    use serde_json::Value;

    match value {
        Value::Null => Ok(py.None()),
        Value::Bool(b) => Ok(b.to_object(py)),
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Ok(i.to_object(py))
            } else if let Some(u) = n.as_u64() {
                Ok(u.to_object(py))
            } else if let Some(f) = n.as_f64() {
                Ok(f.to_object(py))
            } else {
                Err(PyValueError::new_err("Invalid number"))
            }
        }
        Value::String(s) => Ok(s.to_object(py)),
        Value::Array(arr) => {
            let list = PyList::empty(py);
            for item in arr {
                list.append(json_to_pyobject(py, item)?)?;
            }
            Ok(list.to_object(py))
        }
        Value::Object(map) => {
            let dict = PyDict::new(py);
            for (k, v) in map {
                dict.set_item(k, json_to_pyobject(py, v)?)?;
            }
            Ok(dict.to_object(py))
        }
    }
}

//
// Signature Request Deserializer
//

/// Utility function to deserialize any signature request from bytes - returns specific type directly
#[pyfunction]
pub fn deserialize_signature_request(data: &[u8]) -> PyResult<PyObject> {
    let direct_request = nucypher_core::deserialize_signature_request(data).map_err(|err| {
        PyValueError::new_err(format!("Failed to deserialize signature request: {}", err))
    })?;

    // Convert to the specific Python type
    match direct_request {
        nucypher_core::DirectSignatureRequest::UserOp(req) => Python::with_gil(|py| {
            let python_req = UserOperationSignatureRequest { backend: req };
            Ok(python_req.into_py(py))
        }),
        nucypher_core::DirectSignatureRequest::PackedUserOp(req) => Python::with_gil(|py| {
            let python_req = PackedUserOperationSignatureRequest { backend: req };
            Ok(python_req.into_py(py))
        }),
    }
}
