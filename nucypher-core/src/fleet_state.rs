use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::node_metadata::NodeMetadata;
use crate::serde::standard_serialize;
use crate::serde::{serde_deserialize_as_bytes, serde_serialize_as_bytes};

/// An identifier of the fleet state.
#[derive(PartialEq, Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FleetStateChecksum(
    #[serde(
        serialize_with = "serde_serialize_as_bytes",
        deserialize_with = "serde_deserialize_as_bytes"
    )]
    [u8; 32],
);

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

impl AsRef<[u8]> for FleetStateChecksum {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}
