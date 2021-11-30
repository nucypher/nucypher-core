use alloc::boxed::Box;

use ethereum_types::Address;
use serde::{Deserialize, Serialize};
use umbral_pre::Capsule;

use crate::message_kit::MessageKit;

/// An object encapsulating the information necessary for retrieval of cfrags from Ursulas.
/// Contains the capsule and the checksum addresses of Ursulas from which the requester
/// already received cfrags.
#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RetrievalKit {
    /// The ciphertext's capsule.
    pub capsule: Capsule,
    // TODO: change to a set, find one that works in no-std
    /// The addresses that have already been queried for reencryption.
    pub queried_addresses: Option<Box<[Address]>>,
}

impl RetrievalKit {
    /// Creates a new retrival kit from a message kit.
    pub fn from_message_kit(message_kit: &MessageKit) -> Self {
        Self {
            capsule: message_kit.capsule,
            queried_addresses: None,
        }
    }

    /// Creates a new retrieval kit recording the addresses already queried for reencryption.
    pub fn new(capsule: &Capsule, queried_addresses: &[Address]) -> Self {
        // Can store cfrags too, if we're worried about Ursulas supplying duplicate ones.
        Self {
            capsule: *capsule,
            queried_addresses: Some(queried_addresses.into()),
        }
    }
}
