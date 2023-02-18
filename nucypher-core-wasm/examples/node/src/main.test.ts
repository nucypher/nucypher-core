import {
  Address,
  Conditions,
  Context,
  Capsule,
  VerifiedKeyFrag,
  VerifiedCapsuleFrag,
  EncryptedKeyFrag,
  generateKFrags,
  HRAC,
  MessageKit,
  PublicKey,
  reencrypt,
  ReencryptionRequest,
  ReencryptionResponse,
  RevocationOrder,
  SecretKey,
  Signer,
  TreasureMap,
  NodeMetadataPayload,
  NodeMetadata,
  MetadataRequest,
  MetadataResponse,
  MetadataResponsePayload,
  FleetStateChecksum,
  RecoverableSignature,
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
    new Uint8Array(Buffer.from("Hello, world!")),
    new Conditions("some condition")
  );
  return [messageKit.capsule];
};

const makeTreasureMap = (publisherSk: SecretKey, recipientSk: SecretKey) => {
  const signer = new Signer(publisherSk);
  const recipientPk = recipientSk.publicKey();
  const hrac = makeHrac(publisherSk, recipientSk);

  const threshold = 2;
  const vkfrags = generateKFrags(
    publisherSk,
    recipientPk,
    signer,
    threshold,
    3,
    false,
    false
  );

  const assigned_kfrags: [Address, [PublicKey, VerifiedKeyFrag]][] = [
    [new Address(Buffer.from("00000000000000000001")),
      [SecretKey.random().publicKey(), vkfrags[0]]],
    [new Address(Buffer.from("00000000000000000002")),
      [SecretKey.random().publicKey(), vkfrags[1]]],
    [new Address(Buffer.from("00000000000000000003")),
      [SecretKey.random().publicKey(), vkfrags[2]]]];

  return new TreasureMap(signer, hrac, recipientPk, assigned_kfrags, threshold);
};

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

const makeNodeMetadata = (sk: SecretKey) => {
  const payload = new NodeMetadataPayload(
    new Address(Buffer.from("00000000000000000000")),
    "fake-domain",
    (Date.now() / 1000) | 0,
    sk.publicKey(),
    SecretKey.random().publicKey(),
    Buffer.from("fake-certificate-bytes"),
    "example.com",
    8080,
    RecoverableSignature.fromBEBytes(
      Buffer.from("0000000000000000000000000000000100000000000000000000000000000001\x00"))
  );
  const signer = new Signer(sk);
  return new NodeMetadata(signer, payload);
};

const makefleetStateChecksum = () => {
  const sk = SecretKey.random();
  const thisNode = makeNodeMetadata(sk);
  const otherNodes = [
    makeNodeMetadata(sk),
    makeNodeMetadata(sk),
    makeNodeMetadata(sk),
  ];
  const state = new FleetStateChecksum(otherNodes, thisNode);
  return { fleetStateChecksum: state, otherNodes };
};

const makeMetadataResponsePayload = () => {
  const sk = SecretKey.random();
  const announceNodes = [
    makeNodeMetadata(sk),
    makeNodeMetadata(sk),
    makeNodeMetadata(sk),
  ];
  const timestamp = (Date.now() / 1000) | 0;
  const payload = new MetadataResponsePayload(timestamp, announceNodes);
  return { metadataResponsePayload: payload, announceNodes };
};

describe("MessageKit", () => {
  it("decrypts", () => {
    const delegatingSk = SecretKey.random();
    const delegatingPk = delegatingSk.publicKey();
    const message = new Uint8Array(Buffer.from("Hello, world!"));
    const messageKit = new MessageKit(delegatingPk, message, null);

    expect(messageKit.capsule).toBeTruthy();

    const decrypted = messageKit.decrypt(delegatingSk);
    expect(decrypted).toEqual(message);
  });

  it("decrypts reencrypted", () => {
    // Create a message kit
    const delegatingSk = SecretKey.random();
    const delegatingPk = delegatingSk.publicKey();
    const message = new Uint8Array(Buffer.from("Hello, world!"));
    const messageKit = new MessageKit(delegatingPk, message, null);

    // Create key fragments for reencryption
    const recipientSk = SecretKey.random();
    const vkfrags = makeKFrags(delegatingSk, recipientSk);

    // Reencrypt the capsule from message kit
    const capsule = Capsule.fromBytes(messageKit.capsule.toBytes());
    const capsuleFrags = vkfrags.map((kfrag) => reencrypt(capsule, kfrag));

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
    const messageKit = new MessageKit(delegatingPk, message, null);

    const asBytes = messageKit.toBytes();
    expect(MessageKit.fromBytes(asBytes).toBytes()).toEqual(asBytes);
  });
});

describe("HRAC", () => {
  it("serializes", () => {
    const hrac = makeHrac();
    const asBytes = hrac.toBytes();
    expect(asBytes).toEqual(HRAC.fromBytes(asBytes).toBytes());
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

describe("TreasureMap", () => {
  it("serializes", () => {
    const publisherSk = SecretKey.random();
    const recipientSk = SecretKey.random();
    const treasureMap = makeTreasureMap(publisherSk, recipientSk);

    const asBytes = treasureMap.toBytes();
    expect(asBytes).toEqual(TreasureMap.fromBytes(asBytes).toBytes());
  });

  it("encrypts and decrypts", () => {
    const publisherSk = SecretKey.random();
    const signer = new Signer(publisherSk);

    const recipientSk = SecretKey.random();
    const recipientPk = recipientSk.publicKey();

    const treasureMap = makeTreasureMap(publisherSk, recipientSk);
    expect(treasureMap.destinations.length).toEqual(3);

    const encryptedTreasureMap = treasureMap.encrypt(signer, recipientPk);

    const decrypted = encryptedTreasureMap.decrypt(
      recipientSk,
      publisherSk.publicKey()
    );

    expect(decrypted.toBytes()).toEqual(treasureMap.toBytes());
  });
});

describe("RevocationOrder", () => {
  it("serializes", () => {
    const delegatingSk = SecretKey.random();
    const signer = new Signer(delegatingSk);

    const ursulaAddress = new Address(Buffer.from("00000000000000000000"));

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

    const revocationOrder = new RevocationOrder(
      signer,
      ursulaAddress,
      encryptedKeyFrag
    );
    const asBytes = revocationOrder.toBytes();
    expect(RevocationOrder.fromBytes(asBytes).toBytes()).toEqual(asBytes);
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
      recipientPk,
      new Conditions("request conditions"),
      new Context("request context"),
    );

    expect(reencryptionRequest).toBeTruthy();
    expect(reencryptionRequest.hrac.toBytes()).toEqual(hrac.toBytes());
    expect(reencryptionRequest.publisherVerifyingKey.toCompressedBytes()).toEqual(
      delegatingPk.toCompressedBytes()
    );
    expect(reencryptionRequest.bobVerifyingKey.toCompressedBytes()).toEqual(
      recipientPk.toCompressedBytes()
    );
    expect(reencryptionRequest.encryptedKfrag.toBytes()).toEqual(
      encryptedKeyFrag.toBytes()
    );
    expect(reencryptionRequest.capsules[0].toBytes()).toEqual(
      capsules[0].toBytes()
    );

    const asBytes = reencryptionRequest.toBytes();
    expect(asBytes).toEqual(ReencryptionRequest.fromBytes(asBytes).toBytes());
  });
});

describe("ReencryptionResponse", () => {
  it("serializes and verifies", () => {
    const aliceSk = SecretKey.random();
    const bobSk = SecretKey.random();

    // Make verified key fragments
    const vkfrags = makeKFrags(aliceSk, bobSk);

    // Make capsules
    const policyEncryptingKey = aliceSk.publicKey();
    const message = new Uint8Array(Buffer.from("Hello, world!"));
    const messageKit = new MessageKit(policyEncryptingKey, message, null);

    // Perform the reencryption
    const vcfrags = vkfrags.map((vkfrag) => reencrypt(messageKit.capsule, vkfrag));

    // Make the reencryption response
    const ursulaSk = SecretKey.random();
    const capsules_and_vcfrags: [Capsule, VerifiedCapsuleFrag][] =
      vcfrags.map((vcfrag) => [messageKit.capsule, vcfrag]);
    const reencryptionResponse = new ReencryptionResponse(
      new Signer(ursulaSk), capsules_and_vcfrags
    );

    // Test serialization
    const asBytes = reencryptionResponse.toBytes();
    expect(ReencryptionResponse.fromBytes(asBytes).toBytes()).toEqual(asBytes);

    // Verify the reencryption response
    const capsules = vkfrags.map((_) => messageKit.capsule);
    const verified = reencryptionResponse.verify(
      capsules,
      aliceSk.publicKey(),
      ursulaSk.publicKey(),
      policyEncryptingKey,
      bobSk.publicKey()
    );
    expect(verified.length).toEqual(vkfrags.length);
  });
});

describe("NodeMetadata", () => {
  it("serializes", () => {
    const sk = SecretKey.random();
    const nodeMetadata = makeNodeMetadata(sk);
    expect(nodeMetadata.verify()).toBeTruthy();

    const asBytes = nodeMetadata.toBytes();
    expect(NodeMetadata.fromBytes(asBytes).toBytes()).toEqual(asBytes);
  });
});

describe("FleetStateChecksum", () => {
  it("serializes", () => {
    const { fleetStateChecksum } = makefleetStateChecksum();
    expect(fleetStateChecksum.toBytes().length > 0).toBeTruthy();
  });
});

describe("MetadataRequest", () => {
  it("serializes", () => {
    const { fleetStateChecksum, otherNodes } = makefleetStateChecksum();
    const metadataRequest = new MetadataRequest(fleetStateChecksum, otherNodes);
    const asBytes = metadataRequest.toBytes();
    expect(MetadataRequest.fromBytes(asBytes).toBytes()).toEqual(asBytes);
  });
});

describe("MetadataResponse", () => {
  it("verifies and serializes", () => {
    const sk = SecretKey.random();
    const verifyingKey = sk.publicKey();
    const signer = new Signer(sk);
    const { metadataResponsePayload } = makeMetadataResponsePayload();
    const metadataResponse = new MetadataResponse(
      signer,
      metadataResponsePayload
    );
    expect(metadataResponse.verify(verifyingKey)).toBeTruthy();

    const asBytes = metadataResponse.toBytes();
    expect(MetadataResponse.fromBytes(asBytes).toBytes()).toEqual(asBytes);
  });
});
