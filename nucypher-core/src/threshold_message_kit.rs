use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use ferveo::api::{Ciphertext, CiphertextHeader, SharedSecret};
use ferveo::Error;
use serde::{Deserialize, Serialize};

use crate::access_control::AccessControlPolicy;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

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

    /// Returns ciphertext header.
    pub fn ciphertext_header(&self) -> Result<CiphertextHeader, Error> {
        self.ciphertext.header()
    }

    /// Decrypts encrypted data.
    pub fn decrypt_with_shared_secret(
        &self,
        shared_secret: &SharedSecret,
    ) -> Result<Vec<u8>, Error> {
        ferveo::api::decrypt_with_shared_secret(
            &self.ciphertext,
            self.acp.aad().as_ref(),
            shared_secret,
        )
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

    use crate::access_control::{AccessControlPolicy, AuthenticatedData};
    use crate::conditions::Conditions;
    use crate::threshold_message_kit::ThresholdMessageKit;
    use crate::versioning::ProtocolObject;

    #[test]
    fn threshold_message_kit() {
        let dkg_pk = DkgPublicKey::random();
        let data = "The Tyranny of Merit".as_bytes().to_vec();

        let authorization = b"we_dont_need_no_stinking_badges";
        let acp = AccessControlPolicy::new(
            &AuthenticatedData::new(&dkg_pk, Some(&Conditions::new("abcd"))),
            authorization,
        );

        let ciphertext = ferveo_encrypt(SecretBox::new(data), &acp.aad(), &dkg_pk).unwrap();
        let tmk = ThresholdMessageKit::new(&ciphertext, &acp);

        // mimic serialization/deserialization over the wire
        let serialized_tmk = tmk.to_bytes();
        let deserialized_tmk = ThresholdMessageKit::from_bytes(&serialized_tmk).unwrap();
        assert_eq!(
            ciphertext.header().unwrap(),
            deserialized_tmk.ciphertext_header().unwrap()
        );
        assert_eq!(acp, deserialized_tmk.acp);
    }
}
