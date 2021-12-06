#![no_std]

// Use `wee_alloc` as the global allocator.
extern crate wee_alloc;
#[global_allocator]
static ALLOC: wee_alloc::WeeAlloc = wee_alloc::WeeAlloc::INIT;

extern crate alloc;

use alloc::format;
use umbral_pre_bindings_wasm::PublicKey;

use core::fmt;

use js_sys::Error;
use wasm_bindgen::prelude::{wasm_bindgen, JsValue};

fn map_js_err<T: fmt::Display>(err: T) -> JsValue {
    Error::new(&format!("{}", err)).into()
}

#[wasm_bindgen]
pub struct MessageKit(nucypher_core::MessageKit);

#[wasm_bindgen]
impl MessageKit {
    #[wasm_bindgen(constructor)]
    pub fn new(policy_encrypting_key: &PublicKey, plaintext: &[u8]) -> Result<MessageKit, JsValue> {
        nucypher_core::MessageKit::new(&policy_encrypting_key.inner(), plaintext)
            .map(Self)
            .map_err(map_js_err)
    }
}
