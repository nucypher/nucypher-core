use alloc::boxed::Box;

use serde::{Deserialize, Serialize};
use umbral_pre::{
    encrypt, Capsule, EncryptionError, PublicKey, SerializableToArray, Signature, Signer,
};

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct MessageKit {
    capsule: Capsule,
    ciphertext: Box<[u8]>,
    sender_verifying_key: PublicKey,
    signature: Option<Signature>,
}

impl MessageKit {
    pub fn new(
        recipient_key: &PublicKey,
        plaintext: &[u8],
        signer: &Signer,
        sign_plaintext: bool,
    ) -> Result<Self, EncryptionError> {
        let (capsule, ciphertext, signature) = if sign_plaintext {
            // Sign first, encrypt second.
            let signature = signer.sign(plaintext);
            let signature_arr = signature.to_array();
            let (capsule, ciphertext) =
                encrypt(recipient_key, &[&signature_arr, plaintext].concat())?;
            (capsule, ciphertext, None)
        } else {
            // Encrypt first, sign second.
            let (capsule, ciphertext) = encrypt(recipient_key, plaintext)?;
            let signature = signer.sign(&ciphertext);
            (capsule, ciphertext, Some(signature))
        };
        Ok(Self {
            capsule,
            ciphertext,
            sender_verifying_key: signer.verifying_key(),
            signature,
        })
    }
}
