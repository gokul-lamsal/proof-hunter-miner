# Bonded Proof browser hash benchmark

This benchmark lives under `miner/bench/` because it compiles the existing
`proof-core` crate and measures the browser form of the miner. It is a separate
Cargo workspace, so benchmark-only dependencies do not change the production
miner lockfile.

## What it compares

- **Rust/WASM:** a thin `wasm-bindgen` adapter calls the unchanged
  `proof_core::proof_digest` and `proof_core::meets_target` functions. A whole
  nonce range runs inside WASM, so the timed result does not include one
  JS/WASM call per hash.
- **JavaScript:** `@noble/hashes` supplies its optimized 32-bit
  `keccakP` permutation. The fixed 256-byte proof layout pre-absorbs the first
  136-byte rate block. The timed loop reuses its state, tail and preimage typed
  arrays, changes the 256-bit mining nonce in place, and makes no per-attempt
  allocation.

Both paths run in the same Web Worker. Before timing, four shared proof vectors
must match the recorded native `bproof verify --json` digests. Each timed nonce
range must also produce the same checksum from every digest and target result.

## Run it

Required tools are Node.js 20.19 or later, Rust, the
`wasm32-unknown-unknown` target, `wasm-bindgen-cli` 0.2.127, and at least one
supported browser.

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.127 --locked
cd miner/bench
npm ci
npm test
npm run benchmark -- --output results/local.json
```

The default run uses nine samples of 250,000 hashes after a 50,000-hash warmup.
It alternates which engine runs first. Chrome and Firefox run headless. Safari
runs through WebDriver when Safari Settings > Developer > Allow remote
automation is enabled. A browser that cannot run is printed and recorded as
skipped; it is not reported as a passing measurement.

Generated bindings and build output are ignored. The dated result and finding
are tracked under `results/`.

## Dependencies

- `wasm-bindgen 0.2.127` is the only direct Rust dependency added by this
  benchmark. It exposes the unchanged Rust core to a browser worker.
- The isolated lockfile contains 12 new registry crates: `wasm-bindgen`,
  `bumpalo`, `cfg-if`, `once_cell`, `proc-macro2`, `quote`, `rustversion`,
  `syn`, `unicode-ident`, `wasm-bindgen-macro`,
  `wasm-bindgen-macro-support`, and `wasm-bindgen-shared`. The latter 11 are
  binding macro and glue support. The other registry crates already belong to
  `proof-core`'s `sha3` graph.
- `@noble/hashes 2.3.0` is the only JavaScript dependency. It supplies a
  maintained, optimized Keccak-f[1600] permutation for the tuned baseline.
