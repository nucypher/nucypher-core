import {
  Address,
  HRAC,
  MessageKit,
  SecretKey,
} from "nucypher-core";

describe("MessageKit", () => {
  it("encrypts and decrypts", () => {
    const sk = SecretKey.random();
    const policyEncryptingKey = sk.publicKey();
    const message = Buffer.from("Hello, world!");
    const messageKit = new MessageKit(policyEncryptingKey, message);

    // TODO: Fails with: decrypted message is not equal to the original message
    const decrypted = messageKit.decrypt(sk);
    console.assert(decrypted === message, "Decrypted message matches original");

    // TODO: MessageKit::decryptReencrypted

    expect(messageKit.capsule).toBeDefined();

    const asBytes = messageKit.toBytes();
    expect(MessageKit.fromBytes(asBytes).toBytes()).toEqual(asBytes);
  });
});

describe("HRAC", () => {
  it("serializes and deserializes", () => {
    const publisherVerifyingKey = SecretKey.random().publicKey();
    const bobVerifyingKey = SecretKey.random().publicKey();
    const label = Buffer.from("label");

    const hrac = new HRAC(publisherVerifyingKey, bobVerifyingKey, label);
    // expect(HRAC.fromBytes(hrac.toBytes())).toEqual(hrac);
    expect(hrac).toBeDefined();
  });
});

describe("EncryptedKeyFrag", () => {
  it("serializes and deserializes", () => {
    // TODO: Create a VerifiedKeyFrag
    // const signer = Signer.fromSecretKey(sk);
    // const recipientKey = SecretKey.random().publicKey();
    // const encryptedKeyFrag = new EncryptedKeyFrag(signer, hrac, verifiedKeyFrag);
  });
});

describe("Address", () => {
  it("TODO", () => {
    const address = Address.fromChecksumAddress(
      "0x0000000000000000000000000000000000000000"
    );
    expect(address).toBeDefined();
  });
});

describe("TreasureMap", () => {
  it("encrypts and decrypts", () => {
    // TODO: Create assignedKeyFrags
    // const threshold = 1;
    // const treasureMap = new TreasureMap(signer, hrac, policyEncryptingKey, assignedKeyFrags, threshold)
  });
});

describe("ReencryptionRequest", () => {
  it("TODO", () => {
    // const ursulaAddress = Buffer.from("0x0000000000000000000000000000000000000000");
    // const capsules = []; // TODO: Make capsules
    // const treasureMap = undefined; // TODO: Use existing treasureMap
    // const bobVerifyingKey = SecretKey.random().publicKey();
    // const reencryptionRequest = new ReencryptionRequest(ursulaAddress, capsules, treasureMap, bobVerifyingKey);
    // expect(reencryptionRequest).toBeDefined();
  });
});

describe("ReencryptionResponse", () => {
  it("TODO", () => {
    // const signer = new Signer(SecretKey.random());
    // const capsules = undefined;
    // const verifiedCapsuleFrags = undefined;
    // const reencryptionResponse = new ReencryptionResponse(
    //   signer,
    //   capsules,
    //   verifiedCapsuleFrags
    // );

    // expect(reencryptionResponse).toBeDefined();
  });
});
