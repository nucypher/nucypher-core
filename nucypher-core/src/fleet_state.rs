use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};

use crate::node_metadata::NodeMetadata;
use crate::serde::standard_serialize;

#[derive(PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct FleetStateChecksum([u8; 32]);

impl FleetStateChecksum {
    pub fn from_nodes(this_node: Option<NodeMetadata>, other_nodes: &[NodeMetadata]) -> Self {
        let mut nodes = other_nodes.to_vec();
        match this_node {
            None => {}
            Some(node) => nodes.push(node),
        }

        // We do not expect node metadata with equal checksum addresses,
        // so we use the unstable sort which is faster and has a lower memory profile.
        nodes.sort_unstable_by(|node1, node2| {
            node1
                .payload
                .public_address
                .cmp(&node2.payload.public_address)
        });

        let checksum = nodes
            .iter()
            .fold(Sha3_256::new(), |digest, node| {
                digest.chain(&standard_serialize(&node))
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
