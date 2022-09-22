import { SecretKey, MessageKit } from "nucypher-core";

export function run() {
  // Create a message kit
  const delegatingSk = SecretKey.random();
  const delegatingPk = delegatingSk.publicKey();
  const message = new Uint8Array(Buffer.from("Hello"));

  const messageKit = new MessageKit(delegatingPk, message, null);

  const decrypted = messageKit.decrypt(delegatingSk);
  console.assert(
    decrypted.length === message.length,
    "Message decrypted correctly"
  );
  for (let i = 0; i < message.length; i++) {
    console.assert(message[i] === decrypted[i], "Message decrypted correctly");
  }
  console.log("Success!");
}

run();
