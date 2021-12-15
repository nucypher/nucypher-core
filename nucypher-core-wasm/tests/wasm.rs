use std::collections::BTreeMap;

use nucypher_core_wasm::*;

use umbral_pre::bindings_wasm::*;
use wasm_bindgen::convert::FromWasmAbi;
use wasm_bindgen::prelude::*;
use wasm_bindgen_test::*;

//
// Test utilities
//

// Downcast a WASM type to a Rust type
// Reference: https://github.com/rustwasm/wasm-bindgen/issues/2231
fn generic_of_jsval<T: FromWasmAbi<Abi = u32>>(js: JsValue, classname: &str) -> Result<T, JsValue> {
    use js_sys::{Object, Reflect};
    let ctor_name = Object::get_prototype_of(&js).constructor().name();
    if ctor_name == classname {
        let ptr = Reflect::get(&js, &JsValue::from_str("ptr"))?;
        let ptr_u32: u32 = ptr.as_f64().ok_or(JsValue::NULL)? as u32;
        let foo = unsafe { T::from_abi(ptr_u32) };
        Ok(foo)
    } else {
        Err(JsValue::NULL)
    }
}

#[wasm_bindgen]
pub fn verified_key_frag_of_jsval(js: JsValue) -> Option<VerifiedKeyFrag> {
    generic_of_jsval(js, "VerifiedKeyFrag").unwrap_or(None)
}

#[wasm_bindgen]
pub fn node_metadata_of_jsval(js: JsValue) -> Option<NodeMetadata> {
    generic_of_jsval(js, "NodeMetadata").unwrap_or(None)
}

//
// MessageKit
//

#[wasm_bindgen_test]
fn message_kit_decrypts() {
    let sk = SecretKey::random();
    let policy_encrypting_key = sk.public_key();
    let plaintext = "Hello, world!".as_bytes();
    let message_kit = MessageKit::new(&policy_encrypting_key, plaintext).unwrap();

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
    let plaintext = "Hello, world!".as_bytes();
    let message_kit = MessageKit::new(&delegating_pk, plaintext).unwrap();

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
    let cfrags: Vec<VerifiedCapsuleFrag> = verified_kfrags
        .iter()
        .map(|kfrag| {
            let kfrag = verified_key_frag_of_jsval(kfrag.clone()).unwrap();
            let cfrag = umbral_pre::reencrypt(&message_kit.capsule().inner(), &kfrag.inner());
            VerifiedCapsuleFrag::new(cfrag)
        })
        .collect();
    let cfrags = serde_wasm_bindgen::to_value(&cfrags).unwrap();

    // Decrypt on the Rust side
    let decrypted = message_kit
        .decrypt_reencrypted(&receiving_sk, &delegating_pk, &cfrags)
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
    let policy_encrypting_key = sk.public_key();
    let plaintext = "Hello, world!".as_bytes();

    let message_kit = MessageKit::new(&policy_encrypting_key, plaintext).unwrap();

    assert_eq!(
        message_kit,
        MessageKit::from_bytes(&message_kit.to_bytes()).unwrap(),
        "MessageKit does not roundtrip"
    );
}

//
// HRAC
//

fn make_hrac() -> HRAC {
    let publisher_verifying_key = SecretKey::random().public_key();
    let bob_verifying_key = SecretKey::random().public_key();
    let label = "Hello, world!".as_bytes();
    let hrac = HRAC::new(&publisher_verifying_key, &bob_verifying_key, label);
    hrac
}

#[wasm_bindgen_test]
fn hrac_to_bytes_from_bytes() {
    let hrac = make_hrac();

    assert_eq!(
        hrac.to_bytes(),
        HRAC::from_bytes(&hrac.to_bytes()).unwrap().to_bytes(),
        "HRAC does not roundtrip"
    );
}

//
// EncryptedKeyFrag
//

fn make_kfrags(delegating_sk: &SecretKey, receiving_sk: &SecretKey) -> Vec<VerifiedKeyFrag> {
    let receiving_pk = receiving_sk.public_key();
    let signer = Signer::new(&delegating_sk);
    let verified_kfrags: Vec<VerifiedKeyFrag> =
        generate_kfrags(&delegating_sk, &receiving_pk, &signer, 2, 3, false, false)
            .iter()
            .map(|kfrag| verified_key_frag_of_jsval(kfrag.clone()).unwrap())
            .collect();
    verified_kfrags
}

#[wasm_bindgen_test]
fn encrypted_kfrag_decrypt() {
    let hrac = make_hrac();
    let delegating_sk = SecretKey::random();
    let delegating_pk = delegating_sk.public_key();
    let receiving_sk = SecretKey::random();
    let receiving_pk = receiving_sk.public_key();
    let signer = Signer::new(&delegating_sk);

    let verified_kfrags = make_kfrags(&delegating_sk, &receiving_sk);

    let encrypted_kfrag =
        EncryptedKeyFrag::new(&signer, &receiving_pk, &hrac, &verified_kfrags[0]).unwrap();

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
    let encrypted_kfrag =
        EncryptedKeyFrag::new(&signer, &receiving_pk, &hrac, &verified_kfrags[0]).unwrap();

    assert_eq!(
        encrypted_kfrag,
        EncryptedKeyFrag::from_bytes(&encrypted_kfrag.to_bytes()).unwrap(),
        "EncryptedKeyFrag does not roundtrip"
    );
}

//
// Address
//

#[wasm_bindgen_test]
fn address_from_checksum_address() {
    let address = Address::from_checksum_address("0x0000000000000000000000000000000000000001");
    assert_eq!(address.as_string(), "0x0000…0001", "Address does not match");
}

//
// TreasureMap
//

fn make_assigned_kfrags(
    verified_kfrags: Vec<VerifiedKeyFrag>,
) -> BTreeMap<String, (PublicKey, VerifiedKeyFrag)> {
    let mut assigned_kfrags: BTreeMap<String, (PublicKey, VerifiedKeyFrag)> = BTreeMap::new();
    assigned_kfrags.insert(
        "00000000000000000001".to_string(),
        (SecretKey::random().public_key(), verified_kfrags[0].clone()),
    );
    assigned_kfrags.insert(
        "00000000000000000002".to_string(),
        (SecretKey::random().public_key(), verified_kfrags[1].clone()),
    );
    assigned_kfrags.insert(
        "00000000000000000003".to_string(),
        (SecretKey::random().public_key(), verified_kfrags[2].clone()),
    );
    assigned_kfrags
}

fn make_treasure_map(publisher_sk: &SecretKey, receiving_sk: &SecretKey) -> TreasureMap {
    let hrac = make_hrac();
    let verified_kfrags = make_kfrags(&publisher_sk, &receiving_sk);

    let assigned_kfrags = make_assigned_kfrags(verified_kfrags);

    TreasureMap::new(
        &Signer::new(&publisher_sk),
        &hrac,
        &SecretKey::random().public_key(),
        serde_wasm_bindgen::to_value(&assigned_kfrags).unwrap(),
        2,
    )
    .unwrap()
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
    let destinations: Vec<(String, EncryptedKeyFrag)> =
        serde_wasm_bindgen::from_value(destinations).unwrap();

    assert!(destinations.len() == 3, "Destinations does not match");
    assert_eq!(
        destinations[0].0,
        "00000000000000000001".to_string(),
        "Destination does not match"
    );
    assert_eq!(
        destinations[1].0,
        "00000000000000000002".to_string(),
        "Destination does not match"
    );
    assert_eq!(
        destinations[2].0,
        "00000000000000000003".to_string(),
        "Destination does not match"
    );
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
fn reencruption_request_from_bytes_to_bytes() {
    let ursula_address = "00000000000000000001".as_bytes();

    let publisher_sk = SecretKey::random();
    let receiving_sk = SecretKey::random();
    let treasure_map = make_treasure_map(&publisher_sk, &receiving_sk);

    let policy_encrypting_key = publisher_sk.public_key();
    let plaintext = "Hello, world!".as_bytes();
    let message_kit = MessageKit::new(&policy_encrypting_key, plaintext).unwrap();
    let capsule = message_kit.capsule();
    let capsules = serde_wasm_bindgen::to_value(&vec![capsule]).unwrap();

    let reencryption_request = ReencryptionRequest::new(
        ursula_address,
        capsules,
        &treasure_map,
        &receiving_sk.public_key(),
    )
    .unwrap();

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
    // Make capsules
    let alice_sk = SecretKey::random();
    let policy_encrypting_key = alice_sk.public_key();
    let plaintext = "Hello, world!".as_bytes();
    let message_kit = MessageKit::new(&policy_encrypting_key, plaintext).unwrap();
    let capsule = message_kit.capsule();
    let capsules = &vec![capsule, capsule, capsule];
    let capsules_js = serde_wasm_bindgen::to_value(capsules).unwrap();

    // Make verified key fragments
    let bob_sk = SecretKey::random();
    let kfrags = make_kfrags(&alice_sk, &bob_sk);

    assert_eq!(
        capsules.len(),
        kfrags.len(),
        "Number of Capsules and KFrags does not match"
    );

    // Simulate the reencryption
    let cfrags: Vec<VerifiedCapsuleFrag> = kfrags
        .iter()
        .map(|kfrag| reencrypt(&capsule, kfrag))
        .collect();
    let cfrags_js = serde_wasm_bindgen::to_value(&cfrags).unwrap();

    let ursula_sk = SecretKey::random();
    let signer = Signer::new(&ursula_sk);
    let reencryption_response =
        ReencryptionResponse::new(&signer, &capsules_js, &cfrags_js).unwrap();

    let verified_js = reencryption_response
        .verify(
            &capsules_js,
            &alice_sk.public_key(),
            &ursula_sk.public_key(),
            &policy_encrypting_key,
            &bob_sk.public_key(),
        )
        .unwrap();
    let verified: Vec<VerifiedCapsuleFrag> = serde_wasm_bindgen::from_value(verified_js).unwrap();

    assert_eq!(cfrags, verified, "VerifiedCapsuleFrag does not match");

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
    let alice_sk = SecretKey::random();
    let policy_encrypting_key = alice_sk.public_key();
    let plaintext = "Hello, world!".as_bytes();
    let message_kit = MessageKit::new(&policy_encrypting_key, plaintext).unwrap();

    let retrieval_kit = RetrievalKit::from_message_kit(&message_kit);

    let queried_addresses = retrieval_kit.queried_addresses();
    assert_eq!(
        queried_addresses.len(),
        0,
        "Queried addresses length does not match"
    );

    let as_bytes = retrieval_kit.to_bytes();
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
    let encrypted_kfrag =
        EncryptedKeyFrag::new(&signer, &receiving_pk, &hrac, &verified_kfrags[0]).unwrap();

    let ursula_address = "00000000000000000001".as_bytes();
    let revocation_order = RevocationOrder::new(&signer, ursula_address, &encrypted_kfrag);

    assert!(revocation_order.verify_signature(&delegating_sk.public_key()));

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

fn make_node_metadata() -> NodeMetadata {
    let canonical_address = "00000000000000000001".as_bytes();
    let domain = "localhost";
    let timestamp_epoch = 1546300800;
    let verifying_key = SecretKey::random().public_key();
    let encrypting_key = SecretKey::random().public_key();
    let certificate_bytes = "certificate_bytes".as_bytes();
    let host = "https://localhost.com";
    let port = 443;
    let decentralized_identity_evidence = Some(vec![1, 2, 3]);

    let node_metadata_payload = NodeMetadataPayload::new(
        canonical_address,
        domain,
        timestamp_epoch,
        &verifying_key,
        &encrypting_key,
        certificate_bytes,
        host,
        port,
        decentralized_identity_evidence,
    );

    let signer = Signer::new(&SecretKey::random());
    NodeMetadata::new(&signer, &node_metadata_payload)
}

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

//
// FleetStateChecksum
//

fn make_fleet_state_checksum() -> FleetStateChecksum {
    let this_node = Some(make_node_metadata());
    let other_nodes = vec![make_node_metadata(), make_node_metadata()];
    let other_nodes = serde_wasm_bindgen::to_value(&other_nodes).unwrap();
    FleetStateChecksum::new(this_node, other_nodes).unwrap()
}

#[wasm_bindgen_test]
fn fleet_state_checksum() {
    let fleet_state_checksum = make_fleet_state_checksum();

    let as_bytes = fleet_state_checksum.to_bytes();
    assert_eq!(
        as_bytes,
        FleetStateChecksum::from_bytes(&as_bytes)
            .unwrap()
            .to_bytes(),
        "FleetStateChecksum does not roundtrip"
    );
}

//
// MetadataRequest
//

#[wasm_bindgen_test]
fn metadata_request() {
    let fleet_state_checksum = make_fleet_state_checksum();
    let announce_nodes = vec![make_node_metadata(), make_node_metadata()];
    let announce_nodes_js = serde_wasm_bindgen::to_value(&announce_nodes).unwrap();

    let metadata_request = MetadataRequest::new(&fleet_state_checksum, announce_nodes_js).unwrap();

    let nodes_js = metadata_request.announce_nodes();
    let nodes: Vec<NodeMetadata> = nodes_js
        .iter()
        .cloned()
        .map(|js_node| node_metadata_of_jsval(js_node).unwrap())
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
// VerifiedMetadataResponse
//

#[wasm_bindgen_test]
fn verified_metadata_response() {
    let announce_nodes = vec![make_node_metadata(), make_node_metadata()];
    let timestamp_epoch = 1546300800;

    let verified_metadata_response = VerifiedMetadataResponse::new(
        timestamp_epoch,
        serde_wasm_bindgen::to_value(&announce_nodes).unwrap(),
    );

    let nodes_js = verified_metadata_response.announce_nodes();
    let nodes: Vec<NodeMetadata> = nodes_js
        .iter()
        .cloned()
        .map(|js_node| node_metadata_of_jsval(js_node).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(nodes, announce_nodes, "Announce nodes does not match");
}

//
// MetadataResponse
//

#[wasm_bindgen_test]
fn metadata_response() {
    let announce_nodes = vec![make_node_metadata(), make_node_metadata()];
    let timestamp_epoch = 1546300800;
    let verified_metadata_response = VerifiedMetadataResponse::new(
        timestamp_epoch,
        serde_wasm_bindgen::to_value(&announce_nodes).unwrap(),
    );
    let signer = Signer::new(&SecretKey::random());

    let metadata_response = MetadataResponse::new(&signer, &verified_metadata_response);

    let as_bytes = metadata_response.to_bytes();
    assert_eq!(
        as_bytes,
        MetadataResponse::from_bytes(&as_bytes).unwrap().to_bytes(),
        "MetadataResponse does not roundtrip"
    );
}
