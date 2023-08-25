use alloc::boxed::Box;
use alloc::string::String;

use ferveo::api::{encrypt, Ciphertext, DkgPublicKey, SecretBox};
use ferveo::Error;
use serde::{Deserialize, Serialize};
use umbral_pre::serde_bytes;

use crate::conditions::Conditions;
use crate::versioning::{
    messagepack_deserialize, messagepack_serialize, ProtocolObject, ProtocolObjectInner,
};

/// Authenticated data for encrypted data.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct AuthenticatedData {
    /// The public key for the encrypted data
    pub public_key: DkgPublicKey,

    /// The conditions associated with the encrypted data
    pub conditions: Option<Conditions>,
}

impl Eq for AuthenticatedData {}

impl AuthenticatedData {
    /// Creates a new access control policy.
    pub fn new(public_key: &DkgPublicKey, conditions: Option<&Conditions>) -> Self {
        AuthenticatedData {
            public_key: *public_key,
            conditions: conditions.cloned(),
        }
    }

    /// Return the aad.
    pub fn aad(&self) -> Result<Box<[u8]>, Error> {
        Ok([
            self.public_key.to_bytes()?.to_vec(),
            self.conditions
                .as_ref()
                .map(|c| c.as_ref().as_bytes())
                .unwrap_or_default()
                .to_vec(),
        ]
        .concat()
        .into_boxed_slice())
    }
}

impl<'a> ProtocolObjectInner<'a> for AuthenticatedData {
    fn version() -> (u16, u16) {
        (1, 0)
    }

    fn brand() -> [u8; 4] {
        *b"AuDa"
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

impl<'a> ProtocolObject<'a> for AuthenticatedData {}

/// Encrypt data based on conditions and dkg public key.
pub fn encrypt_for_dkg(
    data: &[u8],
    public_key: &DkgPublicKey,
    conditions: Option<&Conditions>,
) -> Result<(Ciphertext, AuthenticatedData), Error> {
    let auth_data = AuthenticatedData::new(public_key, conditions);
    let ciphertext = encrypt(
        SecretBox::new(data.to_vec()),
        auth_data.aad()?.as_ref(),
        public_key,
    )?;
    Ok((ciphertext, auth_data))
}

/// Access control policy data for encrypted data.
#[derive(Eq, PartialEq, Debug, Serialize, Deserialize, Clone)]
pub struct AccessControlPolicy {
    /// The authenticated data for the access control policy
    pub auth_data: AuthenticatedData,

    /// The authorization data for the authenticated data
    #[serde(with = "serde_bytes::as_base64")]
    pub authorization: Box<[u8]>,
}

impl AccessControlPolicy {
    /// Creates a new access control policy.
    pub fn new(auth_data: &AuthenticatedData, authorization: &[u8]) -> Self {
        AccessControlPolicy {
            auth_data: auth_data.clone(),
            authorization: authorization.to_vec().into(),
        }
    }

    /// Return the aad.
    pub fn aad(&self) -> Result<Box<[u8]>, Error> {
        self.auth_data.aad()
    }

    /// Return the DKG public key
    pub fn public_key(&self) -> DkgPublicKey {
        self.auth_data.public_key
    }

    /// Return the conditions
    pub fn conditions(&self) -> Option<Conditions> {
        self.auth_data.conditions.clone()
    }
}

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

    use crate::access_control::{AccessControlPolicy, AuthenticatedData};
    use crate::conditions::Conditions;
    use crate::versioning::ProtocolObject;

    #[test]
    fn authenticated_data() {
        let dkg_pk = DkgPublicKey::random();
        let conditions = Conditions::new("abcd");

        let auth_data = AuthenticatedData::new(&dkg_pk, Some(&conditions));

        // check aad for auth data; expected to be dkg public key + conditions
        let mut expected_aad = dkg_pk.to_bytes().unwrap().to_vec();
        expected_aad.extend(conditions.as_ref().as_bytes());
        let auth_data_aad = auth_data.aad().unwrap();
        assert_eq!(expected_aad.into_boxed_slice(), auth_data_aad);

        assert_eq!(auth_data.public_key, dkg_pk);
        assert_eq!(auth_data.conditions, Some(conditions));

        let auth_data_2 = AuthenticatedData::new(&dkg_pk, Some(&Conditions::new("abcd")));
        assert_eq!(auth_data, auth_data_2);

        // mimic serialization/deserialization over the wire
        let serialized_auth_data = auth_data.to_bytes();
        let deserialized_auth_data = AuthenticatedData::from_bytes(&serialized_auth_data).unwrap();
        assert_eq!(auth_data.public_key, deserialized_auth_data.public_key);
        assert_eq!(auth_data.conditions, deserialized_auth_data.conditions);
    }

    #[test]
    fn access_control_policy() {
        let dkg_pk = DkgPublicKey::random();
        let conditions = Conditions::new("abcd");

        let auth_data = AuthenticatedData::new(&dkg_pk, Some(&conditions));
        let authorization = b"we_dont_need_no_stinking_badges";
        let acp = AccessControlPolicy::new(&auth_data, authorization);

        // check that aad for auth_data and acp are the same
        assert_eq!(auth_data.aad().unwrap(), acp.aad().unwrap());

        // mimic serialization/deserialization over the wire
        let serialized_acp = acp.to_bytes();
        let deserialized_acp = AccessControlPolicy::from_bytes(&serialized_acp).unwrap();
        assert_eq!(auth_data.public_key, deserialized_acp.public_key());
        assert_eq!(auth_data.conditions, deserialized_acp.conditions());
        assert_eq!(
            authorization.to_vec().into_boxed_slice(),
            deserialized_acp.authorization
        );
    }
}
