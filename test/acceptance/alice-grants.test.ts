import { CapsuleFrag, PublicKey, VerifiedKeyFrag } from 'umbral-pre';

import { Enrico } from '../../src';
import { MessageKit } from '../../src';
import { EncryptedTreasureMap } from '../../src/policies/collections';
import { ChecksumAddress } from '../../src/types';
import { bytesEqual, fromBytes, toBytes } from '../../src/utils';
import {
  mockAlice,
  mockBob,
  mockConstructTreasureMap,
  mockEncryptTreasureMap,
  mockGenerateKFrags,
  mockGetUrsulasOnce,
  mockPublishToBlockchain,
  mockRemoteBob,
  mockRetrieveCFragsRequest,
  mockStakingEscrow,
  mockUrsulas, reencryptKFrags,
} from '../utils';

describe('story: alice shares message with bob through policy', () => {
  const message = 'secret-message-from-alice';
  const threshold = 2;
  const shares = 3;
  const paymentPeriods = 7;
  const expiration = new Date(Date.now() + 60 * 1000);
  const rate = 1;
  const ursulas = mockUrsulas().slice(0, shares);

  // Intermediate variables used for mocking
  let encryptedTreasureMap: EncryptedTreasureMap;
  let verifiedKFrags: VerifiedKeyFrag[];
  let ursulaAddresses: ChecksumAddress[];

  // Application side-channel
  const label = 'fake-data-label';
  let encryptedMessage: MessageKit;
  let aliceVerifyingKey: PublicKey;
  let policyEncryptingKey: PublicKey;
  let enricoVerifyingKey: PublicKey;

  it('alice grants a new policy to bob', async () => {
    mockStakingEscrow();
    const getUrsulasSpy = mockGetUrsulasOnce(ursulas);
    const generateKFragsSpy = mockGenerateKFrags();
    const publishToBlockchainSpy = mockPublishToBlockchain();
    const constructTreasureMapSpy = mockConstructTreasureMap();
    const encryptTreasureMapSpy = mockEncryptTreasureMap();

    const alice = mockAlice();
    const bob = mockRemoteBob();
    const policyParams = { bob, label, threshold, shares, expiration, paymentPeriods, rate };
    const policy = await alice.grant(policyParams);

    expect(policy.aliceVerifyingKey).toEqual(alice.verifyingKey.toBytes());
    expect(policy.label).toBe(label);
    expect(getUrsulasSpy).toHaveBeenCalled();
    expect(generateKFragsSpy).toHaveBeenCalled();
    expect(publishToBlockchainSpy).toHaveBeenCalled();
    expect(encryptTreasureMapSpy).toHaveBeenCalled();
    expect(constructTreasureMapSpy).toHaveBeenCalled();

    // Persist side-channel
    aliceVerifyingKey = alice.verifyingKey;
    policyEncryptingKey = policy.policyKey;
    encryptedTreasureMap = await encryptTreasureMapSpy.mock.results[0].value;

    // Persist variables for mocking
    ursulaAddresses = constructTreasureMapSpy.mock.calls[0][2].map((ursula) => ursula.checksumAddress);
    verifiedKFrags = constructTreasureMapSpy.mock.calls[0][3];
  });

  it('enrico encrypts the message', () => {
    const enrico = new Enrico(policyEncryptingKey);
    encryptedMessage = enrico.encryptMessage(toBytes(message));
    enricoVerifyingKey = enrico.verifyingKey;
  });

  describe('bob', () => {
    const bob = mockBob();

    it('retrieves and decrypts the message', async () => {
      const getUrsulasSpy = mockGetUrsulasOnce(ursulas);
      const retrieveCFragsSpy = mockRetrieveCFragsRequest(ursulaAddresses, verifiedKFrags, encryptedMessage.capsule);

      const retrievedMessage = await bob.retrieveAndDecrypt(
        policyEncryptingKey,
        aliceVerifyingKey,
        [ encryptedMessage ],
        encryptedTreasureMap,
      );
      const bobPlaintext = fromBytes(retrievedMessage[0]);

      expect(getUrsulasSpy).toHaveBeenCalled();
      expect(retrieveCFragsSpy).toHaveBeenCalled();
      expect(bobPlaintext).toEqual(message);

      // Can data received by Bob be decrypted?
      const [
        _treasureMap,
        _retrievalKits,
        aliceVerifyingKey_,
        bobEncryptingKey_,
        bobVerifyingKey_,
        policyEncryptingKey_,
      ] = retrieveCFragsSpy.mock.calls[0];
      expect(bytesEqual(aliceVerifyingKey_.toBytes(), aliceVerifyingKey.toBytes()));
      expect(bytesEqual(bobEncryptingKey_.toBytes(), bob.decryptingKey.toBytes()));
      expect(bytesEqual(bobVerifyingKey_.toBytes(), bob.verifyingKey.toBytes()));
      expect(bytesEqual(policyEncryptingKey_.toBytes(), policyEncryptingKey.toBytes()));

      const { verifiedCFrags } = reencryptKFrags(verifiedKFrags, encryptedMessage.capsule);
      const cFrags = verifiedCFrags.map((verifiedCFrag) => CapsuleFrag.fromBytes(verifiedCFrag.toBytes()));
      const areVerified = cFrags.every((cFrag) => cFrag.verify(encryptedMessage.capsule, aliceVerifyingKey_, policyEncryptingKey_, bob.decryptingKey));
      expect(areVerified).toBeTruthy();
    });
  });
});