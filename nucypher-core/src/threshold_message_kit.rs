use alloc::boxed::Box;
use alloc::string::String;

use ferveo::api::Ciphertext;
use serde::{Deserialize, Serialize};

use crate::access_control::AccessControlPolicy;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

// TODO should this be in umbral?

/// Access control metadata for encrypted data.
#[derive(PartialEq, Eq, Debug, Serialize, Deserialize, Clone)]
pub struct ThresholdMessageKit {
    /// The key encapsulation ciphertext
    pub ciphertext: Ciphertext,

    /// The associated access control metadata.
    pub acp: AccessControlPolicy,
}

impl ThresholdMessageKit {
    /// Creates a new threshold message kit.
    pub fn new(ciphertext: &Ciphertext, acp: &AccessControlPolicy) -> Self {
        ThresholdMessageKit {
            ciphertext: ciphertext.clone(),
            acp: acp.clone(),
        }
    }
}

impl<'a> ProtocolObjectInner<'a> for ThresholdMessageKit {
    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn brand() -> [u8; 4] {
        *b"TMKi"
    }

    fn unversioned_to_bytes(&self) -> Box<[u8]> {
        messagepack_serialize(&self)
    }

    fn unversioned_from_bytes(minor_version: u16, bytes: &[u8]) -> Option<Result<Self, String>> {
        if minor_version == 0 {
            Some(messagepack_deserialize(bytes))
        } else {
            None
        }
    }
}

impl<'a> ProtocolObject<'a> for ThresholdMessageKit {}

#[cfg(test)]
mod tests {
    use ferveo::api::{encrypt as ferveo_encrypt, DkgPublicKey, SecretBox};

    use crate::access_control::AccessControlPolicy;
    use crate::conditions::Conditions;
    use crate::threshold_message_kit::ThresholdMessageKit;
    use crate::versioning::ProtocolObject;

    #[test]
    fn threshold_message_kit() {
        let dkg_pk = DkgPublicKey::random();
        let data = "The Tyranny of Merit".as_bytes().to_vec();

        let authorization = b"we_dont_need_no_stinking_badges";
        let acp = AccessControlPolicy::new(&dkg_pk, authorization, Some(&Conditions::new("abcd")));

        let ciphertext = ferveo_encrypt(SecretBox::new(data), &acp.aad(), &dkg_pk).unwrap();
        let tmk = ThresholdMessageKit::new(&ciphertext, &acp);

        // mimic serialization/deserialization over the wire
        let serialized_tmk = tmk.to_bytes();
        let deserialized_tmk = ThresholdMessageKit::from_bytes(&serialized_tmk).unwrap();
        assert_eq!(ciphertext, deserialized_tmk.ciphertext);
        assert_eq!(acp, deserialized_tmk.acp);
    }
}
