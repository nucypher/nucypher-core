use alloc::boxed::Box;

use generic_array::GenericArray;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha3::{Digest, Sha3_256};
use typenum::U32;
use umbral_pre::serde::{serde_deserialize, serde_serialize, Representation};
use umbral_pre::{
    ConstructionError, DeserializableFromArray, HasTypeName, RepresentableAsArray,
    SerializableToArray,
};

use crate::node_metadata::NodeMetadata;
use crate::serde::{standard_serialize, SerializableToBytes};

/// An identifier of the fleet state.
#[derive(PartialEq, Debug, Clone, Copy)]
pub struct FleetStateChecksum([u8; 32]);

impl FleetStateChecksum {
    /// Creates a checksum from the given list of node metadata, and, possibly,
    /// also the metadata of the requesting node.
    pub fn from_nodes(this_node: Option<&NodeMetadata>, other_nodes: &[NodeMetadata]) -> Self {
        let mut nodes = other_nodes.to_vec();
        match this_node {
            None => {}
            Some(node) => nodes.push(node.clone()),
        }

        // We do not expect node metadata with equal checksum addresses,
        // so we use the unstable sort which is faster and has a lower memory profile.
        nodes.sort_unstable_by(|node1, node2| {
            node1
                .payload
                .canonical_address
                .cmp(&node2.payload.canonical_address)
        });

        let checksum = nodes
            .iter()
            .fold(Sha3_256::new(), |digest, node| {
                // Adding only the payload to the digest, since signatures are randomized.
                digest.chain(&standard_serialize(&node.payload))
            })
            .finalize();

        Self(checksum.into())
    }
}

impl HasTypeName for FleetStateChecksum {
    fn type_name() -> &'static str {
        "FleetStateChecksum"
    }
}

impl RepresentableAsArray for FleetStateChecksum {
    type Size = U32;
}

impl SerializableToArray for FleetStateChecksum {
    fn to_array(&self) -> GenericArray<u8, Self::Size> {
        self.0.into()
    }
}

impl DeserializableFromArray for FleetStateChecksum {
    fn from_array(arr: &GenericArray<u8, Self::Size>) -> Result<Self, ConstructionError> {
        Ok(FleetStateChecksum(*arr.as_ref()))
    }
}

impl Serialize for FleetStateChecksum {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serde_serialize(self, serializer, Representation::Hex)
    }
}

impl<'de> Deserialize<'de> for FleetStateChecksum {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        serde_deserialize(deserializer, Representation::Hex)
    }
}

impl SerializableToBytes for FleetStateChecksum {
    fn to_bytes(&self) -> Box<[u8]> {
        Box::<[u8]>::from(self.0.as_slice())
    }
}
