use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::arrays_as_bytes;
use crate::node_metadata::NodeMetadata;
use crate::versioning::ProtocolObject;

/// An identifier of the fleet state.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FleetStateChecksum(#[serde(with = "arrays_as_bytes")] [u8; 32]);

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
                .staking_provider_address
                .cmp(&node2.payload.staking_provider_address)
        });

        let checksum = nodes
            .iter()
            .fold(Sha3_256::new(), |digest, node| {
                // NodeMetadata has a payload signature, which is randomized,
                // so this may lead to unnecessary fleet state update.
                // But, unlike ProtocolObject::to_bytes(), payload serialization
                // is not standardized, so it is better not to rely on it.
                digest.chain(&node.to_bytes())
            })
            .finalize();

        Self(checksum.into())
    }
}

impl AsRef<[u8]> for FleetStateChecksum {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
