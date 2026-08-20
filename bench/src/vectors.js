export const PROOF_TYPEHASH =
  "0xdf48049c8032f061c47a9b74b3f54516ba0b8339560bd23c99b0c5d45061393a";

export const CHALLENGE_SOURCE = {
  chainId: "4663",
  miningCore: "0x102030405060708090a0b0c0d0e0f00112233445",
  challengeId: "19",
  previousAcceptedDigest: "0x" + "a5".repeat(32),
  seedParentBlock: "22345678",
  seedBlockhash: "0x" + "5a".repeat(32),
};

const SHARED = {
  chainId: "0x" + "00".repeat(30) + "1237",
  miningCore: "0x102030405060708090a0b0c0d0e0f00112233445",
  challengeId: "0x" + "00".repeat(31) + "13",
  challenge:
    "0xdbdf9249c8cf0d32528454ed49a5213a12eda397173e41c777459e22631e356a",
};

// Expected values were recorded from `bproof verify --json`. The browser
// refuses to start timing until the Rust/WASM and JavaScript results both equal
// these native proof-core outputs.
export const PROOF_VECTORS = [
  {
    id: "small-mining-nonce",
    ...SHARED,
    miner: "0x1111111111111111111111111111111111111111",
    miningNonce: "0x" + "00".repeat(31) + "07",
    expectedDigest:
      "0xe0728a02790ebf24be70574538af0f2e326940edc70ae1114a464f9e9adbb6d1",
  },
  {
    id: "maximum-mining-nonce",
    ...SHARED,
    miner: "0xdeadbeef000102030405060708090a0b0c0d0e0f",
    miningNonce: "0x" + "ff".repeat(32),
    expectedDigest:
      "0x2d283617f3625a1cb8890a4287050a6ad9e51eb33e98174df059c8a6cf9923f6",
  },
  {
    id: "zero-address-and-mining-nonce",
    ...SHARED,
    miner: "0x" + "00".repeat(20),
    miningNonce: "0x" + "00".repeat(32),
    expectedDigest:
      "0x68d30e5336eeaed0191320852c02a7f058bff050aafccd64c119a260704b6909",
  },
  {
    id: "u32-boundary",
    ...SHARED,
    miner: "0x2222222222222222222222222222222222222222",
    miningNonce: "0x" + "00".repeat(28) + "ffffffff",
    expectedDigest:
      "0x5f8bb979059f5a69e68eb1ed3fb184c7ce8e59f3752c073946dd3e4de283b70d",
  },
];

export const BENCHMARK_TARGET = "0x7f" + "ff".repeat(31);
export const ZERO_MINING_NONCE = "0x" + "00".repeat(32);

