import { keccakP } from "../node_modules/@noble/hashes/sha3.js";

import { decodeHex } from "./hex.js";
import { PROOF_TYPEHASH } from "./vectors.js";

const PREIMAGE_BYTES = 256;
const RATE_BYTES = 136;
const TAIL_BYTES = PREIMAGE_BYTES - RATE_BYTES;
const STATE_WORDS = 50;
const RATE_WORDS = RATE_BYTES / 4;
const TAIL_WORDS = TAIL_BYTES / 4;
const MINING_NONCE_OFFSET = 224;
const KECCAK_SUFFIX = 0x01;

const endianProbe = new Uint32Array([0x01020304]);
if (new Uint8Array(endianProbe.buffer)[0] !== 0x04) {
  throw new Error("the tuned baseline requires a little-endian browser");
}

/**
 * Fixed-layout Keccak-256 for the 256-byte BondedProofV1 preimage.
 *
 * The implementation uses @noble/hashes' optimized 32-bit Keccak-f[1600]
 * permutation. It pre-absorbs the constant first rate block, reuses all typed
 * arrays, mutates only the mining nonce word, and allocates nothing per hash.
 */
export class TunedJsProof {
  constructor({ chainId, miningCore, challengeId, challenge, miner, target }) {
    this.preimage = new Uint8Array(PREIMAGE_BYTES);
    writeWord(this.preimage, 0, decodeHex(PROOF_TYPEHASH, 32, "proofTypehash"));
    writeWord(this.preimage, 1, decodeHex(chainId, 32, "chainId"));
    writeAddressWord(this.preimage, 2, decodeHex(miningCore, 20, "miningCore"));
    this.preimage[3 * 32 + 31] = 1;
    writeWord(this.preimage, 4, decodeHex(challengeId, 32, "challengeId"));
    writeWord(this.preimage, 5, decodeHex(challenge, 32, "challenge"));
    writeAddressWord(this.preimage, 6, decodeHex(miner, 20, "miner"));

    this.target = decodeHex(target, 32, "target");
    this.state = new Uint32Array(STATE_WORDS);
    this.stateBytes = new Uint8Array(this.state.buffer);
    this.firstBlockState = new Uint32Array(STATE_WORDS);
    this.firstBlockWords = new Uint32Array(
      this.preimage.buffer,
      0,
      RATE_WORDS,
    );
    this.tailWords = new Uint32Array(
      this.preimage.buffer,
      RATE_BYTES,
      TAIL_WORDS,
    );

    for (let index = 0; index < RATE_WORDS; index += 1) {
      this.firstBlockState[index] ^= this.firstBlockWords[index];
    }
    keccakP(this.firstBlockState);
  }

  digest(miningNonce) {
    this.setMiningNonce(miningNonce);
    this.#digestCurrentPreimage();
    return this.stateBytes.subarray(0, 32);
  }

  benchmark(startMiningNonce, attempts) {
    this.setMiningNonce(startMiningNonce);
    let checksum = 0;

    for (let attempt = 0; attempt < attempts; attempt += 1) {
      this.#digestCurrentPreimage();
      const leadingWord =
        ((this.stateBytes[0] << 24) |
          (this.stateBytes[1] << 16) |
          (this.stateBytes[2] << 8) |
          this.stateBytes[3]) >>>
        0;
      checksum = (((checksum << 5) | (checksum >>> 27)) ^ leadingWord) >>> 0;
      if (this.#meetsTarget()) {
        checksum = (checksum ^ 0x9e3779b9) >>> 0;
      }
      incrementBigEndian256(this.preimage, MINING_NONCE_OFFSET);
    }

    return checksum;
  }

  setMiningNonce(miningNonce) {
    if (!(miningNonce instanceof Uint8Array) || miningNonce.length !== 32) {
      throw new Error("miningNonce must be exactly 32 bytes");
    }
    this.preimage.set(miningNonce, MINING_NONCE_OFFSET);
  }

  #digestCurrentPreimage() {
    this.state.set(this.firstBlockState);
    for (let index = 0; index < TAIL_WORDS; index += 1) {
      this.state[index] ^= this.tailWords[index];
    }

    // Keccak padding for the 120-byte second block: suffix at byte 120 and the
    // final rate bit at byte 135. Typed-array words are little-endian here.
    this.state[30] ^= KECCAK_SUFFIX;
    this.state[33] ^= 0x80000000;
    keccakP(this.state);
  }

  #meetsTarget() {
    for (let index = 0; index < 32; index += 1) {
      if (this.stateBytes[index] < this.target[index]) return true;
      if (this.stateBytes[index] > this.target[index]) return false;
    }
    return true;
  }
}

function writeWord(output, wordIndex, value) {
  output.set(value, wordIndex * 32);
}

function writeAddressWord(output, wordIndex, value) {
  output.set(value, wordIndex * 32 + 12);
}

function incrementBigEndian256(value, offset) {
  for (let index = offset + 31; index >= offset; index -= 1) {
    value[index] = (value[index] + 1) & 0xff;
    if (value[index] !== 0) return;
  }
}

