import {
  Capsule,
  EncryptedKeyFrag,
  generateKFrags,
  HRAC,
  MessageKit,
  PublicKey,
  reencrypt,
  ReencryptionRequest,
  ReencryptionResponse,
  SecretKey,
  Signer,
} from "nucypher-core";

const makeHrac = (publisherSk?: SecretKey, recipientSk?: SecretKey) => {
  const publisherVerifyingKey = (publisherSk ?? SecretKey.random()).publicKey();
  const recipientVerifyingKey = (recipientSk ?? SecretKey.random()).publicKey();
  const label = Buffer.from("label");
  return new HRAC(publisherVerifyingKey, recipientVerifyingKey, label);
};

const makeCapsules = (delegatingPk: PublicKey) => {
  const messageKit = new MessageKit(
    delegatingPk,
    new Uint8Array(Buffer.from("Hello, world!"))
  );
  return [messageKit.capsule.toBytes()];
};

// const makeTreasureMap = (publisherSk: SecretKey, recipientSk: SecretKey) => {
//   const signer = new Signer(publisherSk);
//   const recipientPk = recipientSk.publicKey();
//   const hrac = makeHrac(publisherSk, recipientSk);

//   const threshold = 2;
//   const vkfrags: VerifiedKeyFrag[] = generateKFrags(
//     publisherSk,
//     PublicKey.fromBytes(recipientPk.toBytes()),
//     signer,
//     threshold,
//     3,
//     false,
//     false
//   );

//   const assignedKeyFrags = [
//     { "00000000000000000001": [SecretKey.random().publicKey(), vkfrags[0]] },
//     { "00000000000000000002": [SecretKey.random().publicKey(), vkfrags[1]] },
//     { "00000000000000000003": [SecretKey.random().publicKey(), vkfrags[2]] },
//   ];

//   return new TreasureMap(
//     signer,
//     hrac,
//     recipientPk,
//     assignedKeyFrags,
//     threshold
//   );
// };

const makeKFrags = (delegatingSk: SecretKey, recipientSk: SecretKey) =>
  generateKFrags(
    delegatingSk,
    recipientSk.publicKey(),
    new Signer(delegatingSk),
    2,
    3,
    false,
    false
  );

describe("MessageKit", () => {
  it("decrypts", () => {
    const delegatingSk = SecretKey.random();
    const delegatingPk = delegatingSk.publicKey();
    const message = new Uint8Array(Buffer.from("Hello, world!"));
    const messageKit = new MessageKit(delegatingPk, message);

    expect(messageKit.capsule).toBeTruthy();

    const decrypted = messageKit.decrypt(delegatingSk);
    expect(decrypted).toEqual(message);
  });

  it("decrypts reencrypted", () => {
    // Create a message kit
    const delegatingSk = SecretKey.random();
    const delegatingPk = delegatingSk.publicKey();
    const message = new Uint8Array(Buffer.from("Hello, world!"));
    const messageKit = new MessageKit(delegatingPk, message);

    // Create key fragments for reencryption
    const recipientSk = SecretKey.random();
    const vkfrags = makeKFrags(delegatingSk, recipientSk);

    // Reencrypt the capsule from message kit
    const capsule = Capsule.fromBytes(messageKit.capsule.toBytes());
    const capsuleFrags = vkfrags.map((kfrag) =>
      reencrypt(capsule, kfrag).toBytes()
    );

    // Decrypt the reencrypted message kit
    const decrypted = messageKit.decryptReencrypted(
      recipientSk,
      delegatingPk,
      capsuleFrags
    );

    expect(decrypted).toEqual(message);
  });

  it("serializes", () => {
    const delegatingSk = SecretKey.random();
    const delegatingPk = delegatingSk.publicKey();
    const message = new Uint8Array(Buffer.from("Hello, world!"));
    const messageKit = new MessageKit(delegatingPk, message);

    const asBytes = messageKit.toBytes();
    expect(MessageKit.fromBytes(asBytes).toBytes()).toEqual(asBytes);
  });
});

describe("HRAC", () => {
  it("serializes", () => {
    const hrac = makeHrac();
    expect(hrac.toBytes()).toBeTruthy();
  });
});

describe("EncryptedKeyFrag", () => {
  it("serializes", () => {
    const delegatingSk = SecretKey.random();
    const signer = new Signer(delegatingSk);

    const recipientSk = SecretKey.random();
    const recipientPk = recipientSk.publicKey();

    const hrac = makeHrac(delegatingSk, recipientSk);

    const vkfrags = makeKFrags(delegatingSk, recipientSk);

    const encryptedKeyFrag = new EncryptedKeyFrag(
      signer,
      recipientPk,
      hrac,
      vkfrags[0]
    );
    const asBytes = encryptedKeyFrag.toBytes();

    expect(asBytes).toEqual(EncryptedKeyFrag.fromBytes(asBytes).toBytes());
  });
});

// TODO: Assigned key frags are not serialized corretly yet
// describe("TreasureMap", () => {
//   it("serializes", () => {
//     const publisherSk = SecretKey.random();
//     const recipientSk = SecretKey.random();
//     const treasureMap = makeTreasureMap(publisherSk, recipientSk);

//     const asBytes = treasureMap.toBytes();
//     expect(asBytes).toEqual(TreasureMap.fromBytes(asBytes).toBytes());

//   });

//   it("encrypts and decrypts", () => {
//     const publisherSk = SecretKey.random();
//     const signer = new Signer(publisherSk);

//     const recipientSk = SecretKey.random();
//     const recipientPk = recipientSk.publicKey();

//     const treasureMap = makeTreasureMap(publisherSk, recipientSk);

//     const encryptedTreasureMap = treasureMap.encrypt(signer, recipientPk);

//     const decrypted = encryptedTreasureMap.decrypt(
//       recipientSk,
//       publisherSk.publicKey()
//     );

//     expect(decrypted.toBytes()).toEqual(treasureMap.toBytes());
//   });
// });

describe("RevocationOrder", () => {
  it("serializes", () => {
    console.error("TODO: implement RevocationOrder serializes");
  });
});

describe("ReencryptionRequest", () => {
  it("serializes", () => {
    const delegatingSk = SecretKey.random();
    const delegatingPk = delegatingSk.publicKey();
    const signer = new Signer(delegatingSk);

    const recipientSk = SecretKey.random();
    const recipientPk = recipientSk.publicKey();

    const capsules = makeCapsules(delegatingPk);

    const hrac = makeHrac(delegatingSk, recipientSk);

    const vkfrags = makeKFrags(delegatingSk, recipientSk);

    const encryptedKeyFrag = new EncryptedKeyFrag(
      signer,
      recipientPk,
      hrac,
      vkfrags[0]
    );

    const reencryptionRequest = new ReencryptionRequest(
      capsules,
      hrac,
      encryptedKeyFrag,
      delegatingPk,
      recipientPk
    );

    expect(reencryptionRequest).toBeTruthy();
    expect(reencryptionRequest.hrac.toBytes()).toEqual(hrac.toBytes());
    expect(reencryptionRequest.publisher_verifying_key.toBytes()).toEqual(
      delegatingPk.toBytes()
    );
    expect(reencryptionRequest.bob_verifying_key.toBytes()).toEqual(
      recipientPk.toBytes()
    );
    expect(reencryptionRequest.encrypted_kfrag.toBytes()).toEqual(
      encryptedKeyFrag.toBytes()
    );
    expect(reencryptionRequest.capsules[0].toBytes()).toEqual(capsules[0]);

    const asBytes = reencryptionRequest.toBytes();
    expect(asBytes).toEqual(ReencryptionRequest.fromBytes(asBytes).toBytes());
  });
});

// TODO:
describe("ReencryptionResponse", () => {
  it("serializes", () => {
    // TODO: Rename to Alice and Bob?
    const delegatingSk = SecretKey.random();
    const delegatingPk = delegatingSk.publicKey();

    const recipientSk = SecretKey.random();

    const message = new Uint8Array(Buffer.from("Hello, world!"));
    const messageKit = new MessageKit(delegatingPk, message);
    const capsules = [messageKit.capsule.toBytes()];

    const vkfrags = makeKFrags(delegatingSk, recipientSk);

    // Reencrypt the capsule from message kit
    const capsule = Capsule.fromBytes(messageKit.capsule.toBytes());
    const verifiedCapsuleFrags = vkfrags.map((kfrag) =>
      reencrypt(capsule, kfrag).toBytes()
    );

    const ursulaSk = SecretKey.random();

    const reencryptionResponse = new ReencryptionResponse(
      new Signer(ursulaSk),
      capsules,
      verifiedCapsuleFrags
    );

    expect(reencryptionResponse).toBeTruthy();
    expect(reencryptionResponse.toBytes()).toBeTruthy();
    
    // TODO: Fails to deserialize on Rust side
    // const isOk = reencryptionResponse.verify(
    //   capsules,
    //   delegatingPk,
    //   ursulaSk.publicKey(),
    //   delegatingPk,
    //   recipientSk.publicKey()
    // );
    // expect(isOk).toBeTruthy();
  });
});
