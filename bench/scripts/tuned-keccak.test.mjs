import assert from "node:assert/strict";
import test from "node:test";
import { keccak_256 } from "@noble/hashes/sha3.js";

import { decodeHex, encodeHex } from "../src/hex.js";
import { TunedJsProof } from "../src/tuned-keccak.js";
import { PROOF_TYPEHASH, PROOF_VECTORS } from "../src/vectors.js";

const MAX_TARGET = "0x" + "ff".repeat(32);

test("tuned fixed-layout Keccak matches all native proof-core vectors", () => {
  for (const vector of PROOF_VECTORS) {
    const core = new TunedJsProof({ ...vector, target: MAX_TARGET });
    const digest = core.digest(decodeHex(vector.miningNonce, 32, "miningNonce"));
    assert.equal(encodeHex(digest), vector.expectedDigest, vector.id);
  }
});

test("tuned consecutive search matches allocating library reference", () => {
  const vector = PROOF_VECTORS[0];
  const target = "0x7f" + "ff".repeat(31);
  const startMiningNonce = new Uint8Array(32);
  startMiningNonce.set([0xff, 0xff, 0xff, 0xf0], 28);
  const attempts = 32;
  const core = new TunedJsProof({ ...vector, target });
  const actual = core.benchmark(startMiningNonce, attempts);
  const expected = referenceChecksum(vector, target, startMiningNonce, attempts);
  assert.equal(actual, expected);
});

function referenceChecksum(vector, targetHex, startMiningNonce, attempts) {
  const preimage = new Uint8Array(256);
  writeWord(preimage, 0, decodeHex(PROOF_TYPEHASH, 32, "proofTypehash"));
  writeWord(preimage, 1, decodeHex(vector.chainId, 32, "chainId"));
  writeAddress(preimage, 2, decodeHex(vector.miningCore, 20, "miningCore"));
  preimage[3 * 32 + 31] = 1;
  writeWord(preimage, 4, decodeHex(vector.challengeId, 32, "challengeId"));
  writeWord(preimage, 5, decodeHex(vector.challenge, 32, "challenge"));
  writeAddress(preimage, 6, decodeHex(vector.miner, 20, "miner"));
  preimage.set(startMiningNonce, 224);
  const target = decodeHex(targetHex, 32, "target");
  let checksum = 0;

  for (let attempt = 0; attempt < attempts; attempt += 1) {
    const digest = keccak_256(preimage);
    const leadingWord =
      ((digest[0] << 24) | (digest[1] << 16) | (digest[2] << 8) | digest[3]) >>> 0;
    checksum = (((checksum << 5) | (checksum >>> 27)) ^ leadingWord) >>> 0;
    if (lessThanOrEqual(digest, target)) checksum = (checksum ^ 0x9e3779b9) >>> 0;
    increment(preimage, 224);
  }
  return checksum;
}

function writeWord(output, index, value) {
  output.set(value, index * 32);
}

function writeAddress(output, index, value) {
  output.set(value, index * 32 + 12);
}

function lessThanOrEqual(left, right) {
  for (let index = 0; index < 32; index += 1) {
    if (left[index] < right[index]) return true;
    if (left[index] > right[index]) return false;
  }
  return true;
}

function increment(value, offset) {
  for (let index = offset + 31; index >= offset; index -= 1) {
    value[index] = (value[index] + 1) & 0xff;
    if (value[index] !== 0) return;
  }
}

