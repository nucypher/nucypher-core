use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use ferveo::api::DkgPublicKey;
use serde::{Deserialize, Serialize};
use umbral_pre::serde_bytes;

use crate::conditions::Conditions;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

// TODO should this be in umbral?

/// Access control metadata for encrypted data.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct AccessControlPolicy {
    /// The public key for the encrypted data
    pub public_key: DkgPublicKey,

    /// The authorization data for the encrypter of the data
    #[serde(with = "serde_bytes::as_base64")]
    pub authorization: Box<[u8]>,

    /// The conditions associated with the encrypted data
    pub conditions: Option<Conditions>,
}

impl AccessControlPolicy {
    /// Creates a new access control policy.
    pub fn new(
        public_key: &DkgPublicKey,
        authorization: &[u8],
        conditions: Option<&Conditions>,
    ) -> Self {
        AccessControlPolicy {
            public_key: *public_key,
            authorization: authorization.to_vec().into(),
            conditions: conditions.cloned(),
        }
    }

    /// Return the aad.
    pub fn aad(&self) -> Box<[u8]> {
        let public_key_bytes = self.public_key.to_bytes().unwrap();
        let condition_bytes = self.conditions.as_ref().unwrap().as_ref().as_bytes();
        let mut result = Vec::with_capacity(public_key_bytes.len() + condition_bytes.len());
        result.extend(public_key_bytes);
        result.extend(condition_bytes);
        result.into_boxed_slice()
    }
}

impl PartialEq for AccessControlPolicy {
    fn eq(&self, other: &Self) -> bool {
        self.public_key.to_bytes().unwrap() == other.public_key.to_bytes().unwrap()
            && self.authorization == other.authorization
            && self.conditions == other.conditions
    }
}

impl Eq for AccessControlPolicy {}

impl<'a> ProtocolObjectInner<'a> for AccessControlPolicy {
    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn brand() -> [u8; 4] {
        *b"ACPo"
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

impl<'a> ProtocolObject<'a> for AccessControlPolicy {}

#[cfg(test)]
mod tests {
    use ferveo::api::DkgPublicKey;

    use crate::access_control::AccessControlPolicy;
    use crate::conditions::Conditions;
    use crate::versioning::ProtocolObject;

    #[test]
    fn access_control_policy() {
        let dkg_pk = DkgPublicKey::random();

        let conditions = Conditions::new("abcd");
        let authorization = b"we_dont_need_no_stinking_badges";
        let acp = AccessControlPolicy::new(&dkg_pk, authorization, Some(&conditions));

        // mimic serialization/deserialization over the wire
        let serialized_acp = acp.to_bytes();
        let deserialized_acp = AccessControlPolicy::from_bytes(&serialized_acp).unwrap();
        assert_eq!(dkg_pk, deserialized_acp.public_key);
        assert_eq!(conditions, deserialized_acp.conditions.unwrap());
        assert_eq!(
            authorization.to_vec().into_boxed_slice(),
            deserialized_acp.authorization
        );

        // check aad; expected to be dkg public key + conditions
        let aad = acp.aad();

        let mut expected_aad = dkg_pk.to_bytes().unwrap().to_vec();
        expected_aad.extend(conditions.as_ref().as_bytes());

        assert_eq!(expected_aad.into_boxed_slice(), aad);
    }
}
