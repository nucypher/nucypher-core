use pyo3::exceptions::{PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes};

use nucypher_core::{DeserializableFromBytes, SerializableToBytes};
use umbral_pre::bindings_python::{
    Capsule, PublicKey, SecretKey, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
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

fn to_bytes<T, U>(obj: &T) -> PyResult<PyObject>
where
    T: AsBackend<U>,
    U: SerializableToBytes,
{
    let serialized = obj.as_backend().to_bytes();
    Python::with_gil(|py| -> PyResult<PyObject> { Ok(PyBytes::new(py, &serialized).into()) })
}

fn from_bytes<'a, T, U>(data: &'a [u8]) -> PyResult<T>
where
    T: FromBackend<U>,
    U: DeserializableFromBytes<'a>,
{
    U::from_bytes(data)
        .map(T::from_backend)
        .map_err(|err| PyValueError::new_err(format!("{}", err)))
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

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }

    #[new]
    pub fn new(policy_encrypting_key: &PublicKey, plaintext: &[u8]) -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::MessageKit::new(&policy_encrypting_key.backend, plaintext)
                .unwrap(),
        })
    }

    pub fn decrypt_original(&self, py: Python, sk: &SecretKey) -> PyResult<PyObject> {
        let plaintext = self.backend.decrypt_original(&sk.backend).unwrap();
        Ok(PyBytes::new(py, &plaintext).into())
    }

    pub fn decrypt_reencrypted(
        &self,
        py: Python,
        sk: &SecretKey,
        policy_encrypting_key: &PublicKey,
        cfrags: Vec<VerifiedCapsuleFrag>,
    ) -> PyResult<PyObject> {
        let backend_cfrags: Vec<umbral_pre::VerifiedCapsuleFrag> = cfrags
            .iter()
            .cloned()
            .map(|vcfrag| vcfrag.backend)
            .collect();
        let plaintext = self
            .backend
            .decrypt_reencrypted(&sk.backend, &policy_encrypting_key.backend, &backend_cfrags)
            .unwrap();
        Ok(PyBytes::new(py, &plaintext).into())
    }
}

//
// HRAC
//

#[pyclass(module = "nucypher_core")]
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
    ) -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::HRAC::new(
                &publisher_verifying_key.backend,
                &bob_verifying_key.backend,
                label,
            ),
        })
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
        verified_kfrag: &VerifiedKeyFrag,
    ) -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::EncryptedKeyFrag::new(
                &signer.backend,
                &recipient_key.backend,
                &hrac.backend,
                &verified_kfrag.backend,
            )
            .unwrap(),
        })
    }

    pub fn decrypt(
        &self,
        sk: &SecretKey,
        hrac: &HRAC,
        publisher_verifying_key: &PublicKey,
    ) -> PyResult<VerifiedKeyFrag> {
        Ok(VerifiedKeyFrag {
            backend: self
                .backend
                .decrypt(&sk.backend, &hrac.backend, &publisher_verifying_key.backend)
                .unwrap(),
        })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

//
// Address
//

#[pyclass(module = "nucypher_core")]
#[derive(Clone)]
pub struct Address {
    backend: ethereum_types::Address,
}

#[pymethods]
impl Address {
    #[new]
    fn from_checksum_address(checksum_address: &str) -> Self {
        Address {
            backend: nucypher_core::to_canonical_address(checksum_address).unwrap(),
        }
    }
}

//
// TreasureMap
//

#[pyclass(module = "nucypher_core")]
#[derive(Clone)]
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
        assigned_kfrags: Vec<(Address, PublicKey, VerifiedKeyFrag)>,
        threshold: usize,
    ) -> PyResult<Self> {
        let assigned_kfrags_backend = assigned_kfrags
            .iter()
            .map(|(address, key, vkfrag)| (address.backend, key.backend, vkfrag.backend.clone()))
            .collect::<Vec<_>>();
        Ok(Self {
            backend: nucypher_core::TreasureMap::new(
                &signer.backend,
                &hrac.backend,
                &policy_encrypting_key.backend,
                &assigned_kfrags_backend,
                threshold,
            )
            .ok()
            .unwrap(),
        })
    }

    pub fn encrypt(
        &self,
        signer: &Signer,
        recipient_key: &PublicKey,
    ) -> PyResult<EncryptedTreasureMap> {
        Ok(EncryptedTreasureMap {
            backend: self
                .backend
                .encrypt(&signer.backend, &recipient_key.backend),
        })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
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
        Ok(TreasureMap {
            backend: self
                .backend
                .decrypt(&sk.backend, &publisher_verifying_key.backend)
                .unwrap(),
        })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
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
        ursula_address: &Address,
        capsules: Vec<Capsule>,
        treasure_map: &TreasureMap,
        bob_verifying_key: &PublicKey,
    ) -> Self {
        let capsules_backend = capsules
            .iter()
            .map(|capsule| capsule.backend)
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::ReencryptionRequest::new(
                &ursula_address.backend,
                &capsules_backend,
                &treasure_map.backend,
                &bob_verifying_key.backend,
            ),
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
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
            .iter()
            .map(|capsule| capsule.backend)
            .collect::<Vec<_>>();
        let vcfrags_backend = vcfrags
            .iter()
            .map(|vcfrag| vcfrag.backend.clone())
            .collect::<Vec<_>>();
        ReencryptionResponse {
            backend: nucypher_core::ReencryptionResponse::new(
                &signer.backend,
                &capsules_backend,
                &vcfrags_backend,
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
            .unwrap();
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

    fn __bytes__(&self) -> PyResult<PyObject> {
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
    pub fn new(capsule: &Capsule, queried_addresses: Vec<Address>) -> Self {
        let addresses_backend = queried_addresses
            .iter()
            .map(|address| address.backend)
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::RetrievalKit::new(&capsule.backend, &addresses_backend),
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
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
        ursula_address: &Address,
        encrypted_kfrag: &EncryptedKeyFrag,
    ) -> Self {
        Self {
            backend: nucypher_core::RevocationOrder::new(
                &signer.backend,
                &ursula_address.backend,
                &encrypted_kfrag.backend,
            ),
        }
    }

    pub fn verify_signature(&self, alice_verifying_key: &PublicKey) -> bool {
        self.backend.verify_signature(&alice_verifying_key.backend)
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
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
        public_address: Address,
        domain: &str,
        timestamp_epoch: u32,
        verifying_key: &PublicKey,
        encrypting_key: &PublicKey,
        certificate_bytes: &[u8],
        host: &str,
        port: u16,
        decentralized_identity_evidence: Option<Vec<u8>>,
    ) -> Self {
        Self {
            backend: nucypher_core::NodeMetadataPayload {
                public_address: public_address.backend,
                domain: domain.to_string(),
                timestamp_epoch,
                verifying_key: verifying_key.backend,
                encrypting_key: encrypting_key.backend,
                certificate_bytes: certificate_bytes.into(),
                host: host.to_string(),
                port,
                decentralized_identity_evidence: decentralized_identity_evidence
                    .map(|v| v.into_boxed_slice()),
            },
        }
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
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::NodeMetadata::new(&signer.backend, &payload.backend),
        })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

//
// FleetStateChecksum
//

#[pyclass(module = "nucypher_core")]
pub struct FleetStateChecksum {
    backend: nucypher_core::FleetStateChecksum,
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
        announce_nodes: Option<Vec<NodeMetadata>>,
    ) -> Self {
        let nodes_backend = announce_nodes.map(|nodes| {
            nodes
                .iter()
                .map(|node| node.backend.clone())
                .collect::<Vec<_>>()
        });
        Self {
            backend: nucypher_core::MetadataRequest::new(
                &fleet_state_checksum.backend,
                nodes_backend.as_deref(),
            ),
        }
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
        to_bytes(self)
    }
}

//
// VerifiedMetadataResponse
//

#[pyclass(module = "nucypher_core")]
pub struct VerifiedMetadataResponse {
    backend: nucypher_core::VerifiedMetadataResponse,
}

#[pymethods]
impl VerifiedMetadataResponse {
    #[new]
    fn new(this_node: Option<&NodeMetadata>, other_nodes: Option<Vec<NodeMetadata>>) -> Self {
        let nodes_backend = other_nodes.map(|nodes| {
            nodes
                .iter()
                .map(|node| node.backend.clone())
                .collect::<Vec<_>>()
        });
        VerifiedMetadataResponse {
            backend: nucypher_core::VerifiedMetadataResponse::new(
                this_node.map(|node| &node.backend),
                nodes_backend.as_deref(),
            ),
        }
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
    pub fn new(signer: &Signer, response: &VerifiedMetadataResponse) -> Self {
        Self {
            backend: nucypher_core::MetadataResponse::new(&signer.backend, &response.backend),
        }
    }

    pub fn verify(&self, verifying_pk: &PublicKey) -> PyResult<VerifiedMetadataResponse> {
        let backend_response = self.backend.verify(&verifying_pk.backend).unwrap();
        Ok(VerifiedMetadataResponse {
            backend: backend_response,
        })
    }

    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        from_bytes(data)
    }

    fn __bytes__(&self) -> PyResult<PyObject> {
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

    let umbral_module = PyModule::new(py, "umbral")?;

    umbral_module.add_class::<umbral_pre::bindings_python::SecretKey>()?; //
    umbral_module.add_class::<umbral_pre::bindings_python::SecretKeyFactory>()?; //
    umbral_module.add_class::<umbral_pre::bindings_python::PublicKey>()?; //
    umbral_module.add_class::<umbral_pre::bindings_python::Capsule>()?; //
    umbral_module.add_class::<umbral_pre::bindings_python::VerifiedKeyFrag>()?; //
    umbral_module.add_class::<umbral_pre::bindings_python::VerifiedCapsuleFrag>()?; //
    umbral_pre::bindings_python::register_reencrypt(umbral_module)?; //

    umbral_module.add_class::<umbral_pre::bindings_python::Signer>()?; // Don't need it if we accept secret keys instead
    umbral_module.add_class::<umbral_pre::bindings_python::Signature>()?; // probably not?
    umbral_module.add_class::<umbral_pre::bindings_python::KeyFrag>()?;
    umbral_module.add_class::<umbral_pre::bindings_python::CapsuleFrag>()?; // probably not? Porter needs it
    umbral_module.add(
        "VerificationError",
        py.get_type::<umbral_pre::bindings_python::VerificationError>(),
    )?; // depends on what `reencryption_response.verify()` returns
    umbral_pre::bindings_python::register_encrypt(umbral_module)?;
    umbral_pre::bindings_python::register_decrypt_original(umbral_module)?;
    umbral_pre::bindings_python::register_generate_kfrags(umbral_module)?; // can potentially be hidden in TreasureMap constructor
    umbral_pre::bindings_python::register_decrypt_reencrypted(umbral_module)?;
    m.add_submodule(umbral_module)?;

    Ok(())
}
