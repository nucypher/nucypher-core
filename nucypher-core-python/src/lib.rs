//use pyo3::class::basic::CompareOp;
//use pyo3::create_exception;
//use pyo3::exceptions::{PyException, PyTypeError, PyValueError};
use pyo3::prelude::*;
//use pyo3::pyclass::PyClass;
use pyo3::types::{PyBytes, PyUnicode};
//use pyo3::wrap_pyfunction;
//use pyo3::PyObjectProtocol;
use ethereum_types;

use nucypher_core;
use nucypher_core::{DeserializableFromBytes, SerializableToBytes};
use umbral_pre::bindings_python::{
    Capsule, PublicKey, SecretKey, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
};

#[pyclass(module = "nucypher_core")]
pub struct MessageKit {
    backend: nucypher_core::MessageKit,
}

#[pymethods]
impl MessageKit {
    #[staticmethod]
    pub fn from_bytes(data: &[u8]) -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::MessageKit::from_bytes(data),
        })
    }

    pub fn __bytes__(&self) -> PyResult<PyObject> {
        Python::with_gil(|py| -> PyResult<PyObject> {
            Ok(PyBytes::new(py, &self.backend.to_bytes()).into())
        })
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

#[pyclass(module = "nucypher_core")]
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
}

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
            backend: nucypher_core::address::to_canonical_address(checksum_address).unwrap(),
        }
    }
}

#[pyclass(module = "nucypher_core")]
#[derive(Clone)]
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
}

#[pyclass(module = "nucypher_core")]
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
        Ok(TreasureMap {
            backend: self
                .backend
                .decrypt(&sk.backend, &publisher_verifying_key.backend)
                .unwrap(),
        })
    }
}

#[pyclass(module = "nucypher_core")]
pub struct ReencryptionRequest {
    backend: nucypher_core::ReencryptionRequest,
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
}

#[pyclass(module = "nucypher_core")]
pub struct ReencryptionResponse {
    backend: nucypher_core::ReencryptionResponse,
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
}

#[pyclass(module = "nucypher_core")]
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
    pub fn new(capsule: &Capsule, queried_addresses: Vec<Address>) -> Self {
        let addresses_backend = queried_addresses
            .iter()
            .map(|address| address.backend)
            .collect::<Vec<_>>();
        Self {
            backend: nucypher_core::RetrievalKit::new(&capsule.backend, &addresses_backend),
        }
    }
}

#[pyclass(module = "nucypher_core")]
pub struct RevocationOrder {
    backend: nucypher_core::RevocationOrder,
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
}

#[pyclass(module = "nucypher_core")]
pub struct NodeMetadataPayload {
    backend: nucypher_core::NodeMetadataPayload,
}

#[pymethods]
impl NodeMetadataPayload {
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
                port: port,
                decentralized_identity_evidence: decentralized_identity_evidence
                    .map(|v| v.into_boxed_slice()),
            },
        }
    }
}

#[pyclass(module = "nucypher_core")]
#[derive(Clone)]
pub struct NodeMetadata {
    backend: nucypher_core::NodeMetadata,
}

#[pymethods]
impl NodeMetadata {
    #[new]
    pub fn new(signer: &Signer, payload: &NodeMetadataPayload) -> PyResult<Self> {
        Ok(Self {
            backend: nucypher_core::NodeMetadata::new(&signer.backend, &payload.backend),
        })
    }
}

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

#[pyclass(module = "nucypher_core")]
pub struct MetadataRequest {
    backend: nucypher_core::MetadataRequest,
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
}

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

#[pyclass(module = "nucypher_core")]
pub struct MetadataResponse {
    backend: nucypher_core::MetadataResponse,
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
