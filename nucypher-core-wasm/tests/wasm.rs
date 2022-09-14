use nucypher_core::Address;
use nucypher_core_wasm::*;

use umbral_pre::bindings_wasm::{
    generate_kfrags, reencrypt, Capsule, SecretKey, Signer, VerifiedCapsuleFrag, VerifiedKeyFrag,
};
use wasm_bindgen::convert::FromWasmAbi;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

//
// Test utilities
//

// Downcast a WASM type to a Rust type
// Reference: https://github.com/rustwasm/wasm-bindgen/issues/2231
fn of_js_value_generic<T: FromWasmAbi<Abi = u32>>(
    js: JsValue,
    classname: &str,
) -> Result<T, JsValue> {
    use js_sys::{Object, Reflect};
    let ctor_name = Object::get_prototype_of(&js).constructor().name();
    if ctor_name == classname {
        let ptr = Reflect::get(&js, &JsValue::from_str("ptr"))?;
        let ptr_u32: u32 = ptr.as_f64().ok_or(JsValue::NULL)? as u32;
        let value_of_type = unsafe { T::from_abi(ptr_u32) };
        Ok(value_of_type)
    } else {
        Err(JsValue::NULL)
    }
}

pub fn verified_key_farg_of_js_value(js_value: JsValue) -> Option<VerifiedKeyFrag> {
    of_js_value_generic(js_value, "VerifiedKeyFrag").unwrap_or(None)
}

pub fn node_metadata_of_js_value(js_value: JsValue) -> Option<NodeMetadata> {
    of_js_value_generic(js_value, "NodeMetadata").unwrap_or(None)
}

fn make_message_kit(
    sk: &SecretKey,
    plaintext: &[u8],
    conditions: Option<impl AsRef<str>>,
) -> MessageKit {
    let policy_encrypting_key = sk.public_key();
    MessageKit::new(
        &policy_encrypting_key,
        plaintext,
        conditions.map(|s| Conditions::new(s.as_ref())),
    )
}

fn make_hrac() -> HRAC {
    let publisher_verifying_key = SecretKey::random().public_key();
    let bob_verifying_key = SecretKey::random().public_key();
    let label = b"Hello, world!";
    HRAC::new(&publisher_verifying_key, &bob_verifying_key, label)
}

fn make_kfrags(delegating_sk: &SecretKey, receiving_sk: &SecretKey) -> Vec<VerifiedKeyFrag> {
    let receiving_pk = receiving_sk.public_key();
    let signer = Signer::new(delegating_sk);
    let verified_kfrags: Vec<VerifiedKeyFrag> =
        generate_kfrags(delegating_sk, &receiving_pk, &signer, 2, 3, false, false)
            .iter()
            .map(|kfrag| verified_key_farg_of_js_value(kfrag.clone()).unwrap())
            .collect();
    verified_kfrags
}

fn make_fleet_state_checksum() -> FleetStateChecksum {
    let this_node = Some(make_node_metadata());
    let other_nodes = vec![make_node_metadata(), make_node_metadata()];
    let mut builder = FleetStateChecksumBuilder::new(this_node);
    for node in &other_nodes {
        builder.add_other_node(node);
    }
    builder.build()
}

fn make_node_metadata() -> NodeMetadata {
    // Just a random valid key.
    // Need to fix it to check the operator address derivation.
    let signing_key = SecretKey::from_bytes(b"01234567890123456789012345678901").unwrap();

    let staking_provider_address = b"00000000000000000001";
    let domain = "localhost";
    let timestamp_epoch = 1546300800;
    let verifying_key = signing_key.public_key();
    let encrypting_key = SecretKey::random().public_key();
    let certificate_der = b"certificate_der";
    let host = "https://localhost.com";
    let port = 443;
    let operator_signature =
        Some(b"0000000000000000000000000000000100000000000000000000000000000001\x00".to_vec());

    let node_metadata_payload = NodeMetadataPayload::new(
        staking_provider_address,
        domain,
        timestamp_epoch,
        &verifying_key,
        &encrypting_key,
        certificate_der,
        host,
        port,
        operator_signature,
    )
    .unwrap();

    let signer = Signer::new(&signing_key);
    NodeMetadata::new(&signer, &node_metadata_payload)
}

fn make_metadata_response_payload() -> (MetadataResponsePayload, Vec<NodeMetadata>) {
    let announce_nodes = vec![make_node_metadata(), make_node_metadata()];
    let timestamp_epoch = 1546300800;
    let mut payload_builder = MetadataResponsePayloadBuilder::new(timestamp_epoch);
    for node in &announce_nodes {
        payload_builder.add_announce_node(node);
    }
    (payload_builder.build(), announce_nodes)
}

//
// MessageKit
//

#[wasm_bindgen_test]
fn message_kit_decrypts() {
    let sk = SecretKey::random();
    let plaintext = "Hello, world!".as_bytes();
    let conditions = Some("{'llamas': 'yes'}");
    let message_kit = make_message_kit(&sk, plaintext, conditions);

    let decrypted = message_kit.decrypt(&sk).unwrap().to_vec();
    assert_eq!(
        decrypted, plaintext,
        "Decrypted message does not match plaintext"
    );
}

#[wasm_bindgen_test]
fn message_kit_decrypt_reencrypted() {
    // Create a message kit
    let delegating_sk = SecretKey::random();
    let delegating_pk = delegating_sk.public_key();
    let plaintext = b"Hello, world!";
    let conditions = Some(&"{'hello': 'world'}");
    let message_kit = make_message_kit(&delegating_sk, plaintext, conditions);

    // Create key fragments for reencryption
    let receiving_sk = SecretKey::random();
    let receiving_pk = receiving_sk.public_key();
    let verified_kfrags = generate_kfrags(
        &delegating_sk,
        &receiving_pk,
        &Signer::new(&delegating_sk),
        2,
        3,
        false,
        false,
    );

    // Simulate reencryption on the JS side
    let vcfrags: Vec<VerifiedCapsuleFrag> = verified_kfrags
        .iter()
        .map(|kfrag| {
            let kfrag = verified_key_farg_of_js_value(kfrag.clone()).unwrap();
            reencrypt(&message_kit.capsule(), &kfrag)
        })
        .collect();
    assert_eq!(vcfrags.len(), verified_kfrags.len());

    let mut mk_with_vcfrags = message_kit.with_vcfrag(&vcfrags[0]);
    for vcfrag in vcfrags.iter().skip(1) {
        mk_with_vcfrags.with_vcfrag(vcfrag);
    }

    // Decrypt on the Rust side
    let decrypted = mk_with_vcfrags
        .decrypt_reencrypted(&receiving_sk, &delegating_pk)
        .unwrap();

    assert_eq!(
        &decrypted[..],
        plaintext,
        "Decrypted message does not match plaintext"
    );
}

#[wasm_bindgen_test]
fn message_kit_to_bytes_from_bytes() {
    let sk = SecretKey::random();
    let plaintext = b"Hello, world!";

    let conditions = Some(&"{'hello': 'world'}");
    let message_kit = make_message_kit(&sk, plaintext, conditions);

    assert_eq!(
        message_kit,
        MessageKit::from_bytes(&message_kit.to_bytes()).unwrap(),
        "MessageKit does not roundtrip"
    );
}

//
// HRAC
//

#[wasm_bindgen_test]
fn hrac_serializes() {
    let hrac = make_hrac();
    let as_bytes = hrac.to_bytes();

    assert_eq!(
        as_bytes,
        HRAC::from_bytes(&as_bytes).unwrap().to_bytes(),
        "HRAC does not roundtrip"
    );
}

//
// EncryptedKeyFrag
//

#[wasm_bindgen_test]
fn encrypted_kfrag_decrypt() {
    let hrac = make_hrac();
    let delegating_sk = SecretKey::random();
    let delegating_pk = delegating_sk.public_key();
    let receiving_sk = SecretKey::random();
    let receiving_pk = receiving_sk.public_key();
    let signer = Signer::new(&delegating_sk);

    let verified_kfrags = make_kfrags(&delegating_sk, &receiving_sk);

    let encrypted_kfrag = EncryptedKeyFrag::new(&signer, &receiving_pk, &hrac, &verified_kfrags[0]);

    let decrypted = encrypted_kfrag
        .decrypt(&receiving_sk, &hrac, &delegating_pk)
        .unwrap();
    assert_eq!(
        decrypted.to_bytes(),
        verified_kfrags[0].to_bytes(),
        "Decrypted KFrag does not match"
    );
}

#[wasm_bindgen_test]
fn encrypted_to_bytes_from_bytes() {
    let hrac = make_hrac();
    let delegating_sk = SecretKey::random();
    let receiving_sk = SecretKey::random();
    let receiving_pk = receiving_sk.public_key();
    let signer = Signer::new(&delegating_sk);

    let verified_kfrags = make_kfrags(&delegating_sk, &receiving_sk);
    let encrypted_kfrag = EncryptedKeyFrag::new(&signer, &receiving_pk, &hrac, &verified_kfrags[0]);

    assert_eq!(
        encrypted_kfrag,
        EncryptedKeyFrag::from_bytes(&encrypted_kfrag.to_bytes()).unwrap(),
        "EncryptedKeyFrag does not roundtrip"
    );
}

//
// TreasureMap
//

fn make_treasure_map(publisher_sk: &SecretKey, receiving_sk: &SecretKey) -> TreasureMap {
    let hrac = make_hrac();
    let vkfrags = make_kfrags(publisher_sk, receiving_sk);

    // Try the non-consuming variant of builder
    let mut builder = TreasureMapBuilder::new(
        &Signer::new(publisher_sk),
        &hrac,
        &SecretKey::random().public_key(),
        2,
    )
    .unwrap()
    .add_kfrag(
        b"00000000000000000001",
        &SecretKey::random().public_key(),
        &vkfrags[0].clone(),
    )
    .unwrap();

    // Also try using the consuming variant of builder:
    builder
        .add_kfrag(
            b"00000000000000000002",
            &SecretKey::random().public_key(),
            &vkfrags[1].clone(),
        )
        .unwrap()
        .add_kfrag(
            b"00000000000000000003",
            &SecretKey::random().public_key(),
            &vkfrags[2].clone(),
        )
        .unwrap()
        .build()
}

#[wasm_bindgen_test]
fn treasure_map_encrypt_decrypt() {
    let publisher_sk = SecretKey::random();
    let receiving_sk = SecretKey::random();

    let treasure_map = make_treasure_map(&publisher_sk, &receiving_sk);

    let publisher_pk = publisher_sk.public_key();
    let recipient_pk = receiving_sk.public_key();
    let signer = Signer::new(&publisher_sk);
    let encrypted = treasure_map.encrypt(&signer, &recipient_pk);

    let decrypted = encrypted.decrypt(&receiving_sk, &publisher_pk).unwrap();

    assert_eq!(
        decrypted, treasure_map,
        "Decrypted TreasureMap does not match"
    );
}

#[wasm_bindgen_test]
fn treasure_map_destinations() {
    let publisher_sk = SecretKey::random();
    let receiving_sk = SecretKey::random();

    let treasure_map = make_treasure_map(&publisher_sk, &receiving_sk);
    let destinations = treasure_map.destinations().unwrap();
    let destinations: Vec<(Address, EncryptedKeyFrag)> =
        serde_wasm_bindgen::from_value(destinations).unwrap();

    assert!(destinations.len() == 3, "Destinations does not match");
    (0..destinations.len()).for_each(|i| {
        assert_eq!(
            destinations[i].0.as_ref(),
            format!("0000000000000000000{}", i + 1).as_bytes(),
            "Destination does not match"
        );
    });
}

#[wasm_bindgen_test]
fn encrypted_treasure_map_from_bytes_to_bytes() {
    let publisher_sk = SecretKey::random();
    let receiving_sk = SecretKey::random();
    let treasure_map = make_treasure_map(&publisher_sk, &receiving_sk);

    let encrypted = treasure_map.encrypt(&Signer::new(&publisher_sk), &receiving_sk.public_key());

    assert_eq!(
        encrypted,
        EncryptedTreasureMap::from_bytes(&encrypted.to_bytes()).unwrap(),
        "EncryptedTreasureMap does not roundtrip"
    );
}

//
// ReencryptionRequest
//

#[wasm_bindgen_test]
fn reencryption_request_from_bytes_to_bytes() {
    // Make capsules
    let publisher_sk = SecretKey::random();
    let plaintext = b"Hello, world!";
    let conditions = Some(&"{'hello': 'world'}");
    let message_kit = make_message_kit(&publisher_sk, plaintext, conditions);
    let capsules = vec![message_kit.capsule()];

    let hrac = make_hrac();

    // Make encrypted key frag
    let receiving_sk = SecretKey::random();
    let receiving_pk = receiving_sk.public_key();
    let signer = Signer::new(&publisher_sk);
    let verified_kfrags = make_kfrags(&publisher_sk, &receiving_sk);
    let encrypted_kfrag = EncryptedKeyFrag::new(&signer, &receiving_pk, &hrac, &verified_kfrags[0]);
    let conditions = Some(Conditions::new("{'some': 'condition'}"));
    let context = Some(Context::new("{'user': 'context'}"));

    // Make reencryption request
    let reencryption_request = ReencryptionRequestBuilder::new(
        &hrac,
        &encrypted_kfrag,
        &publisher_sk.public_key(),
        &receiving_pk,
        conditions,
        context,
    )
    .unwrap()
    .add_capsule(&capsules[0])
    .build();

    assert_eq!(
        reencryption_request,
        ReencryptionRequest::from_bytes(&reencryption_request.to_bytes()).unwrap(),
        "ReencryptionRequest does not roundtrip"
    )
}

//
// ReencryptionResponse
//

#[wasm_bindgen_test]
fn reencryption_response_verify() {
    // First, we're going to create a reencryption response
    // This response is created by the network and received by the network client

    let alice_sk = SecretKey::random();
    let bob_sk = SecretKey::random();

    // Make verified key fragments
    let kfrags = make_kfrags(&alice_sk, &bob_sk);

    // Make capsules
    let policy_encrypting_key = alice_sk.public_key();
    let plaintext = b"Hello, world!";
    let conditions = Some("{'hello': 'world'}");

    let message_kit = make_message_kit(&alice_sk, plaintext, conditions);
    let capsules: Vec<Capsule> = kfrags.iter().map(|_| message_kit.capsule()).collect();

    assert_eq!(capsules.len(), kfrags.len());

    // Simulate the reencryption
    let cfrags: Vec<VerifiedCapsuleFrag> = kfrags
        .iter()
        .map(|kfrag| reencrypt(&capsules[0], kfrag))
        .collect();

    // Make the reencryption response
    let ursula_sk = SecretKey::random();
    let signer = Signer::new(&ursula_sk);
    let mut builder = ReencryptionResponseBuilder::new(&signer);
    for cfrag in &cfrags {
        builder.add_cfrag(cfrag);
    }
    for capsule in &capsules {
        builder.add_capsule(capsule);
    }
    let reencryption_response = builder.build();

    // Now that the response is created, we're going to "send it" to the client and verify it

    // Add capsule to reencryption response
    let mut resp_with_capsules = reencryption_response.with_capsule(&capsules[0]);
    for capsule in &capsules[1..] {
        resp_with_capsules = resp_with_capsules.with_capsule(capsule);
    }

    // Verify reencryption response
    let verified_js = resp_with_capsules
        .verify(
            &alice_sk.public_key(),
            &ursula_sk.public_key(),
            &policy_encrypting_key,
            &bob_sk.public_key(),
        )
        .unwrap();
    let verified: Vec<VerifiedCapsuleFrag> = verified_js
        .iter()
        .map(|vkfrag| vkfrag.into_serde().unwrap())
        .collect();

    assert_eq!(cfrags, verified, "Capsule fragments do not match");

    let as_bytes = reencryption_response.to_bytes();
    assert_eq!(
        as_bytes,
        ReencryptionResponse::from_bytes(&as_bytes)
            .unwrap()
            .to_bytes(),
        "ReencryptionResponse does not roundtrip"
    );
}

//
// RetrievalKit
//

#[wasm_bindgen_test]
fn retrieval_kit() {
    // Make a message kit
    let conditions_str = "{'hello': 'world'}";
    let conditions = Some(Conditions::new(conditions_str));
    let message_kit = make_message_kit(
        &SecretKey::random(),
        b"Hello, world!",
        Some(&conditions_str),
    );

    let retrieval_kit_from_mk = RetrievalKit::from_message_kit(&message_kit);
    assert_eq!(
        retrieval_kit_from_mk.queried_addresses().unwrap().len(),
        0,
        "Queried addresses length does not match"
    );

    let queried_addresses = [
        b"00000000000000000001",
        b"00000000000000000002",
        b"00000000000000000003",
    ];
    let mut builder = RetrievalKitBuilder::new(&message_kit.capsule(), conditions.clone());
    for address in queried_addresses {
        builder.add_queried_address(address).unwrap();
    }
    let retreival_kit = builder.build();
    assert_eq!(
        retreival_kit.queried_addresses().unwrap().len(),
        queried_addresses.len(),
        "Queried addresses length does not match"
    );

    let as_bytes = retreival_kit.to_bytes();
    assert_eq!(
        as_bytes,
        RetrievalKit::from_bytes(&as_bytes).unwrap().to_bytes(),
        "RetrievalKit does not roundtrip"
    );
}

//
// RevocationOrder
//

#[wasm_bindgen_test]
fn revocation_order() {
    let delegating_sk = SecretKey::random();
    let receiving_sk = SecretKey::random();
    let verified_kfrags = make_kfrags(&delegating_sk, &receiving_sk);

    let hrac = make_hrac();
    let receiving_pk = receiving_sk.public_key();
    let signer = Signer::new(&delegating_sk);
    let encrypted_kfrag = EncryptedKeyFrag::new(&signer, &receiving_pk, &hrac, &verified_kfrags[0]);

    let ursula_address = b"00000000000000000001";
    let revocation_order = RevocationOrder::new(&signer, ursula_address, &encrypted_kfrag).unwrap();

    assert!(revocation_order.verify(&delegating_sk.public_key()).is_ok());

    let as_bytes = revocation_order.to_bytes();
    assert_eq!(
        as_bytes,
        RevocationOrder::from_bytes(&as_bytes).unwrap().to_bytes(),
        "RevocationOrder does not roundtrip"
    );
}

//
// NodeMetadataPayload
//

// See below for the `NodeMetadata` struct.

//
// NodeMetadata
//

#[wasm_bindgen_test]
fn node_metadata() {
    let node_metadata = make_node_metadata();

    let as_bytes = node_metadata.to_bytes();
    assert_eq!(
        as_bytes,
        NodeMetadata::from_bytes(&as_bytes).unwrap().to_bytes(),
        "NodeMetadata does not roundtrip"
    );
}

#[wasm_bindgen_test]
fn node_metadata_derive_operator_address() {
    let node_metadata = make_node_metadata();
    let operator_address = node_metadata.payload().derive_operator_address();

    assert_eq!(
        operator_address.unwrap(),
        b"\x01l\xac\x82\x9fj\x06/\r8d\xb5bX\xdd\xc75\xa1\xf9;",
        "Operator address derivation failed"
    );
}

//
// FleetStateChecksum
//

#[wasm_bindgen_test]
fn fleet_state_checksum_to_bytes() {
    let fleet_state_checksum = make_fleet_state_checksum();

    assert!(
        fleet_state_checksum.to_bytes().len() > 0,
        "FleetStateChecksum does not serialize to bytes"
    );
}

//
// MetadataRequest
//

#[wasm_bindgen_test]
fn metadata_request() {
    let fleet_state_checksum = make_fleet_state_checksum();
    let announce_nodes = vec![make_node_metadata(), make_node_metadata()];

    let mut builder = MetadataRequestBuilder::new(&fleet_state_checksum);
    for node in &announce_nodes {
        builder.add_announce_node(node);
    }
    let metadata_request = builder.build();

    let nodes_js = metadata_request.announce_nodes();
    let nodes: Vec<NodeMetadata> = nodes_js
        .iter()
        .cloned()
        .map(|js_node| node_metadata_of_js_value(js_node).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(nodes, announce_nodes);

    let as_bytes = metadata_request.to_bytes();
    assert_eq!(
        as_bytes,
        MetadataRequest::from_bytes(&as_bytes).unwrap().to_bytes(),
        "MetadataRequest does not roundtrip"
    );
}

//
// MetadataResponse
//

#[wasm_bindgen_test]
fn metadata_response_payload() {
    let (metadata_response_payload, announce_nodes) = make_metadata_response_payload();

    let nodes_js = metadata_response_payload.announce_nodes();
    let nodes: Vec<NodeMetadata> = nodes_js
        .iter()
        .cloned()
        .map(|js_node| node_metadata_of_js_value(js_node).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(nodes, announce_nodes, "Announce nodes does not match");
}

#[wasm_bindgen_test]
fn metadata_response() {
    let (metadata_response_payload, _) = make_metadata_response_payload();

    let signer = Signer::new(&SecretKey::random());

    let metadata_response = MetadataResponse::new(&signer, &metadata_response_payload);

    let as_bytes = metadata_response.to_bytes();
    assert_eq!(
        as_bytes,
        MetadataResponse::from_bytes(&as_bytes).unwrap().to_bytes(),
        "MetadataResponse does not roundtrip"
    );
}
