import { spawnSync } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { CHALLENGE_SOURCE, PROOF_VECTORS } from "../src/vectors.js";

const benchRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const minerManifest = resolve(benchRoot, "../Cargo.toml");
const maximumTarget = "0x" + "ff".repeat(32);

for (const vector of PROOF_VECTORS) {
  const result = spawnSync(
    "cargo",
    [
      "run",
      "--quiet",
      "--manifest-path",
      minerManifest,
      "--package",
      "bproof",
      "--",
      "verify",
      "--json",
      "--chain-id",
      CHALLENGE_SOURCE.chainId,
      "--mining-core",
      CHALLENGE_SOURCE.miningCore,
      "--challenge-id",
      CHALLENGE_SOURCE.challengeId,
      "--previous-digest",
      CHALLENGE_SOURCE.previousAcceptedDigest,
      "--seed-parent-block",
      CHALLENGE_SOURCE.seedParentBlock,
      "--seed-blockhash",
      CHALLENGE_SOURCE.seedBlockhash,
      "--miner",
      vector.miner,
      "--nonce",
      vector.miningNonce,
      "--target",
      maximumTarget,
    ],
    { encoding: "utf8" },
  );
  if (result.status !== 0) {
    throw new Error(`${vector.id}: bproof verify failed: ${result.stderr.trim()}`);
  }

  const native = JSON.parse(result.stdout);
  if (native.challenge !== vector.challenge) {
    throw new Error(
      `${vector.id}: native challenge ${native.challenge} != ${vector.challenge}`,
    );
  }
  if (native.digest !== vector.expectedDigest) {
    throw new Error(
      `${vector.id}: native digest ${native.digest} != ${vector.expectedDigest}`,
    );
  }
  console.log(`${vector.id}: ${native.digest}`);
}

