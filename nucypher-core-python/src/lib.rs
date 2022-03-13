extern crate alloc;

use alloc::collections::{BTreeMap, BTreeSet};

use pyo3::class::basic::CompareOp;
use pyo3::exceptions::{PyTypeError, PyValueError};
use pyo3::prelude::*;
use pyo3::pyclass::PyClass;
use pyo3::types::{PyBytes, PyUnicode};
use pyo3::PyObjectProtocol;

use nucypher_core::k256::ecdsa::recoverable;
use nucypher_core::k256::ecdsa::signature::Signature as SignatureTrait;
use nucypher_core::{ProtocolObject, RECOVERABLE_SIGNATURE_SIZE};
use umbral_pre::bindings_python::{
    Capsule, PublicKey, SecretKey, Signer, VerificationError, VerifiedCapsuleFrag, VerifiedKeyFrag,
};

//
// Helper traits to generalize implementing various Python protocol functions for our types.
//

trait AsBackend<T> {
    fn as_backend(&self) -> &T;
}

trait FromBackend<T> {
    fn from_backend(backend: T) -> Self;
}

fn to_bytes<'a, T, U>(obj: &T) -> PyObject
where
    T: AsBackend<U>,
    U: ProtocolObject<'a>,
{
    let serialized = obj.as_backend().to_bytes();
    Python::with_gil(|py| -> PyObject { PyBytes::new(py, &serialized).into() })
}

fn from_bytes<'a, T, U>(data: &'a [u8]) -> PyResult<T>
where
    T: FromBackend<U>,
    U: ProtocolObject<'a>,
{
    U::from_bytes(data)
        .map(T::from_backend)
        .map_err(|err| PyValueError::new_err(format!("Failed to deserialize: {}", err)))
}

fn richcmp<T>(obj: &T, other: PyRef<'_, T>, op: CompareOp) -> PyResult<bool>
where
    T: PyClass + PartialEq,
{
    match op {
        CompareOp::Eq => Ok(obj == &*other),
        CompareOp::Ne => Ok(obj != &*other),
        _ => Err(PyTypeError::new_err("Objects are not ordered")),
    }
}

fn hash<T, U>(type_name: &str, obj: &T) -> PyResult<isize>
where
    T: AsBackend<U>,
    U: AsRef<[u8]>,
{
    let serialized = obj.as_backend().as_ref();

    // call `hash((class_name, bytes(obj)))`
    Python::with_gil(|py| {
        let builtins = PyModule::import(py, "builtins")?;
        let arg1 = PyUnicode::new(py, type_name);
        let arg2: PyObject = PyBytes::new(py, serialized).into();
        builtins.getattr("hash")?.call1(((arg1, arg2),))?.extract()
    })
}

//
// MessageKit
//

#[pyclass(module = "nucypher_core")]
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

#[pymethods]
impl MessageKit {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }

    #[new]
    pub fn new(policy_encrypting_key: &PublicKey, plaintext: &[u8]) -> Self {
        Self {
            backend: nucypher_core::MessageKit::new(&policy_encrypting_key.backend, plaintext),
        }
    }

    pub fn decrypt(&self, py: Python, sk: &SecretKey) -> PyResult<PyObject> {
        let plaintext = self
            .backend
            .decrypt(&sk.backend)
            .map_err(|err| PyValueError::new_err(format!("{}", err)))?;
        Ok(PyBytes::new(py, &plaintext).into())
    }

    pub fn decrypt_reencrypted(
        &self,
        py: Python,
        sk: &SecretKey,
        policy_encrypting_key: &PublicKey,
        cfrags: Vec<VerifiedCapsuleFrag>,
    ) -> PyResult<PyObject> {
        let backend_cfrags: Vec<umbral_pre::VerifiedCapsuleFrag> =
            cfrags.into_iter().map(|vcfrag| vcfrag.backend).collect();
        let plaintext = self
            .backend
            .decrypt_reencrypted(&sk.backend, &policy_encrypting_key.backend, backend_cfrags)
            .map_err(|err| PyValueError::new_err(format!("{}", err)))?;
        Ok(PyBytes::new(py, &plaintext).into())
    }

    #[getter]
    fn capsule(&self) -> Capsule {
        Capsule {
            backend: self.backend.capsule,
        }
    }
}

//
// HRAC
//

#[allow(clippy::upper_case_acronyms)]
#[pyclass(module = "nucypher_core")]
#[derive(PartialEq)]
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
                &publisher_verifying_key.backend,
                &bob_verifying_key.backend,
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
}

impl AsBackend<nucypher_core::HRAC> for HRAC {
    fn as_backend(&self) -> &nucypher_core::HRAC {
        &self.backend
    }
}

#[pyproto]
impl PyObjectProtocol for HRAC {
    fn __richcmp__(&self, other: PyRef<HRAC>, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash("HRAC", self)
    }
}

//
// EncryptedKeyFrag
//

#[pyclass(module = "nucypher_core")]
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

#[pymethods]
impl EncryptedKeyFrag {
    #[new]
    pub fn new(
        signer: &Signer,
        recipient_key: &PublicKey,
        hrac: &HRAC,
        verified_kfrag: VerifiedKeyFrag,
    ) -> Self {
        Self {
            backend: nucypher_core::EncryptedKeyFrag::new(
                &signer.backend,
                &recipient_key.backend,
                &hrac.backend,
                verified_kfrag.backend,
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
            .decrypt(&sk.backend, &hrac.backend, &publisher_verifying_key.backend)
            .map(|backend| VerifiedKeyFrag { backend })
            .map_err(|err| PyValueError::new_err(format!("{}", err)))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// TreasureMap
//

#[pyclass(module = "nucypher_core")]
#[derive(Clone, PartialEq)]
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

#[pymethods]
impl TreasureMap {
    #[new]
    pub fn new(
        signer: &Signer,
        hrac: &HRAC,
        policy_encrypting_key: &PublicKey,
        assigned_kfrags: BTreeMap<[u8; nucypher_core::Address::SIZE], (PublicKey, VerifiedKeyFrag)>,
        threshold: u8,
    ) -> Self {
        let assigned_kfrags_backend = assigned_kfrags
            .into_iter()
            .map(|(address_bytes, (key, vkfrag))| {
                (
                    nucypher_core::Address::new(&address_bytes),
                    (key.backend, vkfrag.backend),
                )
            })
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::TreasureMap::new(
                &signer.backend,
                &hrac.backend,
                &policy_encrypting_key.backend,
                assigned_kfrags_backend,
                threshold,
            ),
        }
    }

    pub fn encrypt(&self, signer: &Signer, recipient_key: &PublicKey) -> EncryptedTreasureMap {
        EncryptedTreasureMap {
            backend: self
                .backend
                .encrypt(&signer.backend, &recipient_key.backend),
        }
    }

    pub fn make_revocation_orders(&self, signer: &Signer) -> Vec<RevocationOrder> {
        self.backend
            .make_revocation_orders(&signer.backend)
            .into_iter()
            .map(|backend| RevocationOrder { backend })
            .collect()
    }

    #[getter]
    fn destinations(&self) -> BTreeMap<&[u8], EncryptedKeyFrag> {
        let mut result = BTreeMap::new();
        for (address, ekfrag) in &self.backend.destinations {
            result.insert(
                address.as_ref(),
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
        PublicKey {
            backend: self.backend.policy_encrypting_key,
        }
    }

    #[getter]
    fn publisher_verifying_key(&self) -> PublicKey {
        PublicKey {
            backend: self.backend.publisher_verifying_key,
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// EncryptedTreasureMap
//

#[pyclass(module = "nucypher_core")]
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

#[pymethods]
impl EncryptedTreasureMap {
    pub fn decrypt(
        &self,
        sk: &SecretKey,
        publisher_verifying_key: &PublicKey,
    ) -> PyResult<TreasureMap> {
        self.backend
            .decrypt(&sk.backend, &publisher_verifying_key.backend)
            .map(TreasureMap::from_backend)
            .map_err(|err| PyValueError::new_err(format!("{}", err)))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// ReencryptionRequest
//

#[pyclass(module = "nucypher_core")]
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

#[pymethods]
impl ReencryptionRequest {
    #[new]
    pub fn new(
        capsules: Vec<Capsule>,
        hrac: &HRAC,
        encrypted_kfrag: &EncryptedKeyFrag,
        publisher_verifying_key: &PublicKey,
        bob_verifying_key: &PublicKey,
    ) -> Self {
        let capsules_backend = capsules
            .iter()
            .map(|capsule| capsule.backend)
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::ReencryptionRequest::new(
                &capsules_backend,
                &hrac.backend,
                &encrypted_kfrag.backend,
                &publisher_verifying_key.backend,
                &bob_verifying_key.backend,
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
        PublicKey {
            backend: self.backend.publisher_verifying_key,
        }
    }

    #[getter]
    fn bob_verifying_key(&self) -> PublicKey {
        PublicKey {
            backend: self.backend.bob_verifying_key,
        }
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
            .map(|capsule| Capsule { backend: *capsule })
            .collect::<Vec<_>>()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// ReencryptionResponse
//

#[pyclass(module = "nucypher_core")]
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

#[pymethods]
impl ReencryptionResponse {
    #[new]
    pub fn new(signer: &Signer, capsules: Vec<Capsule>, vcfrags: Vec<VerifiedCapsuleFrag>) -> Self {
        let capsules_backend = capsules
            .into_iter()
            .map(|capsule| capsule.backend)
            .collect::<Vec<_>>();
        let vcfrags_backend = vcfrags
            .into_iter()
            .map(|vcfrag| vcfrag.backend)
            .collect::<Vec<_>>();
        ReencryptionResponse {
            backend: nucypher_core::ReencryptionResponse::new(
                &signer.backend,
                &capsules_backend,
                vcfrags_backend,
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
            .iter()
            .map(|capsule| capsule.backend)
            .collect::<Vec<_>>();
        let vcfrags_backend = self
            .backend
            .verify(
                &capsules_backend,
                &alice_verifying_key.backend,
                &ursula_verifying_key.backend,
                &policy_encrypting_key.backend,
                &bob_encrypting_key.backend,
            )
            .map_err(|_err| PyValueError::new_err("ReencryptionResponse verification failed"))?;
        Ok(vcfrags_backend
            .iter()
            .map(|vcfrag| VerifiedCapsuleFrag {
                backend: vcfrag.clone(),
            })
            .collect::<Vec<_>>())
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// RetrievalKit
//

#[pyclass(module = "nucypher_core")]
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
        queried_addresses: BTreeSet<[u8; nucypher_core::Address::SIZE]>,
    ) -> Self {
        let addresses_backend = queried_addresses
            .iter()
            .map(nucypher_core::Address::new)
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::RetrievalKit::new(&capsule.backend, addresses_backend),
        }
    }

    #[getter]
    fn capsule(&self) -> Capsule {
        Capsule {
            backend: self.backend.capsule,
        }
    }

    #[getter]
    fn queried_addresses(&self) -> BTreeSet<&[u8]> {
        self.backend
            .queried_addresses
            .iter()
            .map(|address| address.as_ref())
            .collect::<BTreeSet<_>>()
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// RevocationOrder
//

#[pyclass(module = "nucypher_core")]
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

#[pymethods]
impl RevocationOrder {
    #[new]
    pub fn new(
        signer: &Signer,
        staking_provider_address: [u8; nucypher_core::Address::SIZE],
        encrypted_kfrag: &EncryptedKeyFrag,
    ) -> Self {
        let address = nucypher_core::Address::new(&staking_provider_address);
        Self {
            backend: nucypher_core::RevocationOrder::new(
                &signer.backend,
                &address,
                &encrypted_kfrag.backend,
            ),
        }
    }

    pub fn verify(
        &self,
        alice_verifying_key: &PublicKey,
    ) -> PyResult<([u8; nucypher_core::Address::SIZE], EncryptedKeyFrag)> {
        self.backend
            .clone()
            .verify(&alice_verifying_key.backend)
            .map(|(address, ekfrag)| (address.into(), EncryptedKeyFrag { backend: ekfrag }))
            .map_err(|_err| VerificationError::new_err("RevocationOrder verification failed"))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
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
        staking_provider_address: [u8; nucypher_core::Address::SIZE],
        domain: &str,
        timestamp_epoch: u32,
        verifying_key: &PublicKey,
        encrypting_key: &PublicKey,
        certificate_der: &[u8],
        host: &str,
        port: u16,
        operator_signature: Option<[u8; RECOVERABLE_SIGNATURE_SIZE]>,
    ) -> PyResult<Self> {
        let signature = operator_signature
            .map(|signature_bytes| {
                recoverable::Signature::from_bytes(&signature_bytes).map_err(|err| {
                    PyValueError::new_err(format!("Invalid operator signature format: {}", err))
                })
            })
            .transpose()?;
        Ok(Self {
            backend: nucypher_core::NodeMetadataPayload {
                staking_provider_address: nucypher_core::Address::new(&staking_provider_address),
                domain: domain.to_string(),
                timestamp_epoch,
                verifying_key: verifying_key.backend,
                encrypting_key: encrypting_key.backend,
                certificate_der: certificate_der.into(),
                host: host.to_string(),
                port,
                operator_signature: signature,
            },
        })
    }

    #[getter]
    fn staking_provider_address(&self) -> &[u8] {
        self.backend.staking_provider_address.as_ref()
    }

    #[getter]
    fn verifying_key(&self) -> PublicKey {
        PublicKey {
            backend: self.backend.verifying_key,
        }
    }

    #[getter]
    fn encrypting_key(&self) -> PublicKey {
        PublicKey {
            backend: self.backend.encrypting_key,
        }
    }

    #[getter]
    fn operator_signature(&self) -> Option<&[u8]> {
        self.backend
            .operator_signature
            .as_ref()
            .map(|boxed_signature| boxed_signature.as_ref())
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
            .map_err(|err| PyValueError::new_err(format!("{}", err)))?;
        Ok(Python::with_gil(|py| -> PyObject {
            PyBytes::new(py, address.as_ref()).into()
        }))
    }
}

//
// NodeMetadata
//

#[pyclass(module = "nucypher_core")]
#[derive(Clone)]
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

#[pymethods]
impl NodeMetadata {
    #[new]
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> Self {
        Self {
            backend: nucypher_core::NodeMetadata::new(&signer.backend, &payload.backend),
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
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

//
// FleetStateChecksum
//

#[pyclass(module = "nucypher_core")]
#[derive(PartialEq)]
pub struct FleetStateChecksum {
    backend: nucypher_core::FleetStateChecksum,
}

impl AsBackend<nucypher_core::FleetStateChecksum> for FleetStateChecksum {
    fn as_backend(&self) -> &nucypher_core::FleetStateChecksum {
        &self.backend
    }
}

#[pymethods]
impl FleetStateChecksum {
    #[new]
    pub fn new(this_node: Option<&NodeMetadata>, other_nodes: Vec<NodeMetadata>) -> Self {
        let other_nodes_backend = other_nodes
            .iter()
            .map(|node| node.backend.clone())
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::FleetStateChecksum::from_nodes(
                this_node.map(|node| node.backend.clone()).as_ref(),
                &other_nodes_backend,
            ),
        }
    }

    fn __bytes__(&self) -> &[u8] {
        self.backend.as_ref()
    }
}

#[pyproto]
impl PyObjectProtocol for FleetStateChecksum {
    fn __richcmp__(&self, other: PyRef<FleetStateChecksum>, op: CompareOp) -> PyResult<bool> {
        richcmp(self, other, op)
    }

    fn __hash__(&self) -> PyResult<isize> {
        hash("FleetStateChecksum", self)
    }
}

//
// MetadataRequest
//

#[pyclass(module = "nucypher_core")]
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
        from_bytes(data)
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

#[pymethods]
impl MetadataResponse {
    #[new]
    pub fn new(signer: &Signer, payload: &MetadataResponsePayload) -> Self {
        Self {
            backend: nucypher_core::MetadataResponse::new(&signer.backend, &payload.backend),
        }
    }

    pub fn verify(&self, verifying_pk: &PublicKey) -> PyResult<MetadataResponsePayload> {
        self.backend
            .clone()
            .verify(&verifying_pk.backend)
            .map(|backend_payload| MetadataResponsePayload {
                backend: backend_payload,
            })
            .map_err(|_err| VerificationError::new_err("MetadataResponse verification failed"))
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyObject {
        to_bytes(self)
    }
}

/// A Python module implemented in Rust.
#[pymodule]
fn _nucypher_core(py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<MessageKit>()?;
    m.add_class::<HRAC>()?;
    m.add_class::<EncryptedKeyFrag>()?;
    m.add_class::<TreasureMap>()?;
    m.add_class::<EncryptedTreasureMap>()?;
    m.add_class::<ReencryptionRequest>()?;
    m.add_class::<ReencryptionResponse>()?;
    m.add_class::<RetrievalKit>()?;
    m.add_class::<RevocationOrder>()?;
    m.add_class::<NodeMetadata>()?;
    m.add_class::<NodeMetadataPayload>()?;
    m.add_class::<FleetStateChecksum>()?;
    m.add_class::<MetadataRequest>()?;
    m.add_class::<MetadataResponsePayload>()?;
    m.add_class::<MetadataResponse>()?;

    let umbral_module = PyModule::new(py, "umbral")?;

    umbral_module.add_class::<umbral_pre::bindings_python::SecretKey>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::SecretKeyFactory>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::PublicKey>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::Capsule>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::VerifiedKeyFrag>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::VerifiedCapsuleFrag>()?;
    umbral_pre::bindings_python::register_reencrypt(umbral_module)?;
    umbral_pre::bindings_python::register_generate_kfrags(umbral_module)?;

    umbral_module.add_class::<umbral_pre::bindings_python::Signer>()?; // Don't need it if we accept secret keys instead
    umbral_module.add_class::<umbral_pre::bindings_python::Signature>()?; // probably not?
    umbral_module.add_class::<umbral_pre::bindings_python::CapsuleFrag>()?; // probably not? Porter needs it
    umbral_module.add(
        "VerificationError",
        py.get_type::<umbral_pre::bindings_python::VerificationError>(),
    )?; // depends on what `reencryption_response.verify()` returns
    m.add_submodule(umbral_module)?;

    Ok(())
}
