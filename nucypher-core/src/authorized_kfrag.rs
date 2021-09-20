use serde::{Deserialize, Serialize};
use umbral_pre::{
    DeserializableFromArray, KeyFrag, SerializableToArray, Signature, Signer, VerifiedKeyFrag,
};

use crate::hrac::HRAC;

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedKeyFrag {
    hrac: HRAC,
    kfrag: KeyFrag,
    signature: Signature,
}

impl AuthorizedKeyFrag {
    pub fn new(hrac: &HRAC, verified_kfrag: &VerifiedKeyFrag, publisher_stamp: &Signer) -> Self {
        // Alice makes plain to Ursula that, upon decrypting this message,
        // this particular KFrag is authorized for use in the policy identified by this HRAC.

        // TODO: add VerifiedKeyFrag::unverify()?
        let kfrag = KeyFrag::from_array(&verified_kfrag.to_array()).unwrap();

        let signature = publisher_stamp.sign(&[hrac.as_ref(), &kfrag.to_array()].concat());

        Self {
            hrac: *hrac,
            kfrag,
            signature,
        }
    }
}
