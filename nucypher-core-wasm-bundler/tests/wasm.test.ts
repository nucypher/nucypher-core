import { beforeAll, describe, expect, it } from "vitest";
import { SecretKey, initialize, EthereumAddress } from "..";

describe("WASM module", () => {
  beforeAll(async () => {
    await initialize();
  });

  it("can use nucypher-core objects", async () => {
    expect(
      EthereumAddress.fromString("0x0000000000000000000000000000000000000000"),
    ).toBeDefined();
    expect(SecretKey.random()).toBeDefined();
  });
});
