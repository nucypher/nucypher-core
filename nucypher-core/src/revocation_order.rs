use serde::{Deserialize, Serialize};
use umbral_pre::{PublicKey, Signature, Signer};
use ethereum_types::Address;

use crate::key_frag::EncryptedKeyFrag;
use crate::serde::standard_serialize;


#[derive(PartialEq, Debug, Serialize, Deserialize)]
struct RevocationOrder {
    ursula_address: Address,
    encrypted_kfrag: EncryptedKeyFrag,
    signature: Signature,
}

impl RevocationOrder {
    pub fn new(
        signer: &Signer,
        ursula_address: &Address,
        encrypted_kfrag: &EncryptedKeyFrag,
    ) -> Self {
        Self {
            ursula_address: *ursula_address,
            encrypted_kfrag: encrypted_kfrag.clone(),
            signature: signer.sign(
                &[
                    ursula_address.as_ref(),
                    &standard_serialize(&encrypted_kfrag),
                ]
                .concat(),
            ),
        }
    }

    pub fn verify_signature(self, alice_verifying_key: &PublicKey) -> bool {
        // TODO: return an Option of something instead of returning `bool`?
        let message = [
            self.ursula_address.as_ref(),
            &standard_serialize(&self.encrypted_kfrag),
        ]
        .concat();
        self.signature.verify(alice_verifying_key, &message)
    }
}
