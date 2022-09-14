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
  ReencryptionRequestBuilder,
  RevocationOrder,
  SecretKey,
  Signer,
  TreasureMap,
  TreasureMapBuilder,
  ReencryptionResponseBuilder,
  NodeMetadataPayload,
  NodeMetadata,
  MetadataRequestBuilder,
  MetadataRequest,
  MetadataResponse,
  MetadataResponsePayloadBuilder,
  FleetStateChecksumBuilder,
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

  return new TreasureMapBuilder(signer, hrac, recipientPk, threshold)
    .addKfrag(
      Buffer.from("00000000000000000001"),
      SecretKey.random().publicKey(),
      vkfrags[0]
    )
    .addKfrag(
      Buffer.from("00000000000000000002"),
      SecretKey.random().publicKey(),
      vkfrags[1]
    )
    .addKfrag(
      Buffer.from("00000000000000000003"),
      SecretKey.random().publicKey(),
      vkfrags[2]
    )
    .build();
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
    Buffer.from("00000000000000000000"),
    "fake-domain",
    (Date.now() / 1000) | 0,
    sk.publicKey(),
    SecretKey.random().publicKey(),
    Buffer.from("fake-certificate-bytes"),
    "example.com",
    8080
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
  const builder = new FleetStateChecksumBuilder(thisNode);
  for (const node of otherNodes) {
    builder.addOtherNode(node);
  }
  return { fleetStateChecksum: builder.build(), otherNodes };
};

const makeMetadataResponsePayload = () => {
  const sk = SecretKey.random();
  const announceNodes = [
    makeNodeMetadata(sk),
    makeNodeMetadata(sk),
    makeNodeMetadata(sk),
  ];
  const timestamp = (Date.now() / 1000) | 0;
  const builder = new MetadataResponsePayloadBuilder(timestamp);
  for (const node of announceNodes) {
    builder.addAnnounceNode(node);
  }
  return { metadataResponsePayload: builder.build(), announceNodes };
};

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
    const capsuleFrags = vkfrags.map((kfrag) => reencrypt(capsule, kfrag));

    const messageKitWithVCfrags = messageKit.withVCFrag(capsuleFrags[0]);
    for (let i = 1; i < capsuleFrags.length; i++) {
      messageKitWithVCfrags.withVCFrag(capsuleFrags[i]);
    }

    // Decrypt the reencrypted message kit
    const decrypted = messageKitWithVCfrags.decryptReencrypted(
      recipientSk,
      delegatingPk
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

    const ursulaAddress = Buffer.from("00000000000000000000");

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

    const reencryptionRequestBuilder = new ReencryptionRequestBuilder(
      hrac,
      encryptedKeyFrag,
      delegatingPk,
      recipientPk
    );
    for (const capsule of capsules) {
      reencryptionRequestBuilder.addCapsule(capsule);
    }
    const reencryptionRequest = reencryptionRequestBuilder.build();

    expect(reencryptionRequest).toBeTruthy();
    expect(reencryptionRequest.hrac.toBytes()).toEqual(hrac.toBytes());
    expect(reencryptionRequest.publisherVerifyingKey.toBytes()).toEqual(
      delegatingPk.toBytes()
    );
    expect(reencryptionRequest.bobVerifyingKey.toBytes()).toEqual(
      recipientPk.toBytes()
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
    const messageKit = new MessageKit(policyEncryptingKey, message);
    const capsules = vkfrags.map((_) => messageKit.capsule);

    // Perform the reencryption
    const cfrags = vkfrags.map((kfrag) => reencrypt(capsules[0], kfrag));

    // Make the reencryption response
    const ursulaSk = SecretKey.random();
    const builder = new ReencryptionResponseBuilder(new Signer(ursulaSk));
    for (const capsule of capsules) {
      builder.addCapsule(capsule);
    }
    for (const cfrag of cfrags) {
      builder.addCfrag(cfrag);
    }
    const reencryptionResponse = builder.build();

    // Test serialization
    const asBytes = reencryptionResponse.toBytes();
    expect(ReencryptionResponse.fromBytes(asBytes).toBytes()).toEqual(asBytes);

    // Add capsules to the response
    let responseWithCapsules = reencryptionResponse.withCapsule(capsules[0]);
    for (const capsule of capsules.slice(1)) {
      responseWithCapsules = responseWithCapsules.withCapsule(capsule);
    }

    // Verify the reencryption response
    const verified = responseWithCapsules.verify(
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
    const builder = new MetadataRequestBuilder(fleetStateChecksum);
    for (const node of otherNodes) {
      builder.addAnnounceNode(node);
    }
    const metadataRequest = builder.build();
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
