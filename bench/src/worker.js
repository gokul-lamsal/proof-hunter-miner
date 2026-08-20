import { TunedJsProof } from "./tuned-keccak.js";
import { decodeHex, encodeHex } from "./hex.js";
import {
  BENCHMARK_TARGET,
  PROOF_VECTORS,
  ZERO_MINING_NONCE,
} from "./vectors.js";

self.onmessage = async (event) => {
  try {
    const settings = event.data;
    const wasmStartedAt = performance.now();
    const wasmModule = await import("../wasm/pkg/proof_benchmark_wasm.js");
    await wasmModule.default();
    const wasmColdStartMs = performance.now() - wasmStartedAt;

    const vectorAgreement = verifyVectors(wasmModule.ProofBenchmark);
    const benchmark = runBenchmark(
      wasmModule.ProofBenchmark,
      settings.runs,
      settings.attempts,
      settings.warmupAttempts,
    );

    self.postMessage({
      ok: true,
      browserLabel: settings.browserLabel,
      userAgent: navigator.userAgent,
      hardwareConcurrency: navigator.hardwareConcurrency ?? null,
      worker: true,
      wasmColdStartMs,
      vectorAgreement,
      ...benchmark,
    });
  } catch (error) {
    self.postMessage({
      ok: false,
      message: error instanceof Error ? error.message : String(error),
      stack: error instanceof Error ? error.stack : null,
    });
  }
};

function verifyVectors(ProofBenchmark) {
  return PROOF_VECTORS.map((vector) => {
    const target = "0x" + "ff".repeat(32);
    const wasm = createWasmCore(ProofBenchmark, vector, target);
    const javascript = new TunedJsProof({ ...vector, target });
    const miningNonce = decodeHex(vector.miningNonce, 32, "miningNonce");

    const wasmDigest = encodeHex(wasm.digest(miningNonce));
    const javascriptDigest = encodeHex(javascript.digest(miningNonce));
    wasm.free();

    if (wasmDigest !== vector.expectedDigest) {
      throw new Error(
        `${vector.id}: WASM ${wasmDigest} != native proof-core ${vector.expectedDigest}`,
      );
    }
    if (javascriptDigest !== vector.expectedDigest) {
      throw new Error(
        `${vector.id}: JavaScript ${javascriptDigest} != native proof-core ${vector.expectedDigest}`,
      );
    }

    return {
      id: vector.id,
      expectedDigest: vector.expectedDigest,
      wasmDigest,
      javascriptDigest,
      agreed: true,
    };
  });
}

function runBenchmark(ProofBenchmark, runs, attempts, warmupAttempts) {
  const fixture = PROOF_VECTORS[0];
  const wasm = createWasmCore(ProofBenchmark, fixture, BENCHMARK_TARGET);
  const javascript = new TunedJsProof({
    ...fixture,
    target: BENCHMARK_TARGET,
  });
  const zeroMiningNonce = decodeHex(
    ZERO_MINING_NONCE,
    32,
    "zeroMiningNonce",
  );

  const wasmWarmupChecksum = wasm.benchmark(zeroMiningNonce, warmupAttempts);
  const javascriptWarmupChecksum = javascript.benchmark(
    zeroMiningNonce,
    warmupAttempts,
  );
  assertChecksums("warmup", wasmWarmupChecksum, javascriptWarmupChecksum);

  const wasmSamples = [];
  const javascriptSamples = [];
  const checksums = [];

  for (let run = 0; run < runs; run += 1) {
    const startMiningNonce = uint256FromBigInt(BigInt(run) * BigInt(attempts));
    const engines =
      run % 2 === 0
        ? [
            ["wasm", wasm, wasmSamples],
            ["javascript", javascript, javascriptSamples],
          ]
        : [
            ["javascript", javascript, javascriptSamples],
            ["wasm", wasm, wasmSamples],
          ];
    const runChecksums = {};

    for (const [name, engine, samples] of engines) {
      const startedAt = performance.now();
      const checksum = engine.benchmark(startMiningNonce, attempts);
      const elapsedMs = performance.now() - startedAt;
      const hashesPerSecond = attempts / (elapsedMs / 1000);
      samples.push({ run: run + 1, elapsedMs, hashesPerSecond, checksum });
      runChecksums[name] = checksum;
    }

    assertChecksums(
      `timed run ${run + 1}`,
      runChecksums.wasm,
      runChecksums.javascript,
    );
    checksums.push({ run: run + 1, ...runChecksums, agreed: true });
  }

  wasm.free();
  const wasmSummary = summarize(wasmSamples);
  const javascriptSummary = summarize(javascriptSamples);

  return {
    settings: { runs, attempts, warmupAttempts, order: "alternating" },
    wasm: { samples: wasmSamples, summary: wasmSummary },
    javascript: { samples: javascriptSamples, summary: javascriptSummary },
    checksumAgreement: checksums,
    wasmToJavascriptRatio:
      wasmSummary.medianHashesPerSecond /
      javascriptSummary.medianHashesPerSecond,
  };
}

function createWasmCore(ProofBenchmark, fixture, target) {
  return new ProofBenchmark(
    decodeHex(fixture.chainId, 32, "chainId"),
    decodeHex(fixture.miningCore, 20, "miningCore"),
    decodeHex(fixture.challengeId, 32, "challengeId"),
    decodeHex(fixture.challenge, 32, "challenge"),
    decodeHex(fixture.miner, 20, "miner"),
    decodeHex(target, 32, "target"),
  );
}

function assertChecksums(label, wasm, javascript) {
  if (wasm !== javascript) {
    throw new Error(`${label}: WASM checksum ${wasm} != JavaScript ${javascript}`);
  }
}

function uint256FromBigInt(value) {
  const output = new Uint8Array(32);
  let remaining = value;
  for (let index = 31; index >= 0; index -= 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

function summarize(samples) {
  const sorted = samples
    .map((sample) => sample.hashesPerSecond)
    .sort((left, right) => left - right);
  return {
    medianHashesPerSecond: percentile(sorted, 0.5),
    minHashesPerSecond: sorted[0],
    maxHashesPerSecond: sorted.at(-1),
    p25HashesPerSecond: percentile(sorted, 0.25),
    p75HashesPerSecond: percentile(sorted, 0.75),
  };
}

function percentile(sorted, position) {
  const index = (sorted.length - 1) * position;
  const lower = Math.floor(index);
  const upper = Math.ceil(index);
  if (lower === upper) return sorted[lower];
  return sorted[lower] + (sorted[upper] - sorted[lower]) * (index - lower);
}

