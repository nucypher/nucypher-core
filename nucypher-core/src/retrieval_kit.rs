use alloc::boxed::Box;

use serde::{Deserialize, Serialize};
use umbral_pre::Capsule;
use ethereum_types::Address;

use crate::message_kit::MessageKit;


#[derive(PartialEq, Debug, Serialize, Deserialize)]
pub struct RetrievalKit {
    capsule: Capsule,
    // TODO: change to a set, find one that works in no-std
    queried_addresses: Option<Box<[Address]>>,
}

impl RetrievalKit {
    pub fn from_message_kit(message_kit: &MessageKit) -> Self {
        Self {
            capsule: message_kit.capsule,
            queried_addresses: None,
        }
    }

    pub fn new(capsule: &Capsule, queried_addresses: &[Address]) -> Self {
        // Can store cfrags too, if we're worried about Ursulas supplying duplicate ones.
        Self {
            capsule: *capsule,
            queried_addresses: Some(queried_addresses.into()),
        }
    }
}
