# Proof Hunters CLI

The live `bproof` reader and submitter target `HunterMiningCore`: each accepted
proof mints one NFT. Mining does not pay liquid HUNTER, and token activation or
backing is a separate operation. `status --json` reports `settlementMode: nftOnly`
and `nftsMintedEver`; successful submissions include `nftTokenId`.

Build from the repository root:

```sh
cargo build --release
target/release/bproof --help
target/release/bproof wallet new --help
```

### OpenCL GPU mining

The optional OpenCL backend hashes the same canonical Ethereum Keccak-256
proof preimage as the CPU backend. It enumerates every OpenCL GPU visible to
the process and partitions nonce ranges across them. The Rust verifier checks
the returned nonce before the existing simulation, signing, journal, and
receipt-validation path is used.

On a Linux GPU host, install the NVIDIA driver and OpenCL ICD/runtime first,
then verify that `clinfo` lists the GPUs. Build with:

```sh
apt-get update
apt-get install -y build-essential pkg-config ocl-icd-libopencl1 ocl-icd-opencl-dev clinfo
clinfo | grep -E 'Device Name|Platform Name'
cargo build --release --locked --features bproof/opencl --bin bproof
```

Run all detected GPUs with `--backend opencl`:

```sh
BPROOF_OPENCL_GLOBAL=1048576 BPROOF_OPENCL_ITERS=16 \
target/release/bproof mine --backend opencl --submit --loop \
  --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" \
  --basket "$BASKET" --keystore ./miner-wallet.json \
  --max-fee "$MAX_TOTAL_FEE_WEI"
```

`BPROOF_OPENCL_GLOBAL` and `BPROOF_OPENCL_ITERS` control batch size per GPU;
increase them only after checking memory use and stale-challenge latency.
`--threads` controls CPU workers and is ignored by the OpenCL backend. If no
OpenCL GPU is visible, the command fails clearly; it does not silently submit
CPU work under a GPU label.

Create a dedicated encrypted mining wallet using `wallet new`. Keep the recovery
file private. The CLI signs with that wallet, not the browser's MetaMask account.
Phase 1 is live on Robinhood mainnet (4663). Use the verified settings in
[the setup guide](docs/getting-started.md); do not use RC1/RC2 fixtures.

```sh
target/release/bproof status \
  --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" --json

target/release/bproof mine --submit \
  --rpc-url "$RPC_URL" --chain-id "$CHAIN_ID" --mining-core "$MINING_CORE" \
  --basket "$BASKET" --keystore ./miner-wallet.json \
  --max-fee "$MAX_TOTAL_FEE_WEI" --json
```

`--max-fee` is the maximum total gas exposure in **wei**, not a gas price.
The default gas margin is 100% above `eth_estimateGas`; the full padded exposure
must fit the explicit ceiling. It is a buffer, not a guarantee of successful
execution. A reverted transaction can still spend gas. Add `--loop` for continuous
mining; Ctrl-C stops it. A restart after confirmed completion reads the chain's
account nonce and restores the same encrypted wallet.

Receipt acceptance requires the current core's `ProofAccepted` and exactly one
matching `ProofNftMinted` event, consistent with the transaction, miner, challenge,
proof digest and requested basket. RPC data remains a trust source.

Before broadcast, the CLI writes an owner-only durable journal beside the
keystore containing the exact signed transaction and the public verification
context. If the process crashes or an RPC reply is lost, the next invocation
reconciles or rebroadcasts those same signed bytes and verifies the canonical
receipt before allowing a new transaction. Corrupt, overly permissive, or
inconsistent journal state fails closed. Never delete a pending journal merely
to bypass this guard; reconcile its transaction first.

Live mining and submission automatically use the core-selected Mining Power module's
challenge-bound multiplier for the mining wallet. The HUNTER must be locked and assigned to that exact address in MiningPowerCustody;
new assignments apply from the next challenge. The current app assignment shortcut
selects its browser mining wallet, so it does not assign to a different CLI wallet.
Loose token balances do not boost mining. No assigned power means 1x.
Continuous search events report the base target, effective target and multiplier.
A failed power read pauses live search rather than silently guessing a multiplier. `schedule` and `--state-file` remain legacy offline
calculation tools; their token schedule is not the current live settlement model.

See [wallet funding and gas limits](docs/getting-started.md) for the setup flow.

## Network profiles and AI agents

The network launcher in [distribution](distribution/README.md) defaults to testnet.
The mainnet protocol is live and its public addresses/runtime hashes are recorded
in the mainnet profile. Source profile templates stay disabled. The v0.2.3 release bundles contain a
matching binary and a mainnet profile pinned to that binary. Testnet stays disabled.
Mainnet mining through a released launcher requires explicit confirmation.

```sh
python3 distribution/proof-hunters --network testnet profile
python3 -m unittest discover -s distribution -p 'test_*.py'
cargo test --workspace --locked
```

Install the public [Proof Hunters Agent Skills](https://github.com/vltgoblin/proof-hunters-skills):

```sh
npx skills add vltgoblin/proof-hunters-skills --skill proof-hunters-mining
```

It uses verified v0.2.3 bundles, bounded mining calls, explicit gas budgets,
assigned HUNTER power, and automatic seed refresh. Start with a read-only status
check. Installing the skill does not authorize transactions. A matching copy is
included at [agent-skills/proof-hunters-mining](agent-skills/proof-hunters-mining/SKILL.md).

## Release status

**Mainnet: live on Robinhood Chain (4663).** [Download v0.2.3](https://github.com/vltgoblin/proof-hunter-miner/releases/tag/v0.2.3), including assigned HUNTER mining power.
Verify download checksums and build attestations before use. The older **v0.1.0 is
legacy** and must not be used for mainnet NFT mining.

Each `proof-hunters-<system>.zip` includes the binary, Python 3.9+ launcher and
mainnet configuration. The raw `bproof-*` files are also available for users who
supply the explicit network options themselves. Read [the setup guide](docs/getting-started.md).

The approximately month-long collection model is a population scenario, not a
promise about one miner or the completion date.

Standalone Rust checks skip production-contract integration tests when the
monorepo contracts are absent. Those tests must also pass in the canonical
bonded-proof checkout with pinned Foundry 1.7.1 before release acceptance.
See [source provenance](docs/source-snapshot.json) and
[release verification](docs/verifying-a-release.md).

[Website](https://proofhunter.fun) · [App](https://app.proofhunter.fun) ·
[Documentation](https://doc.proofhunter.fun)

## Performance and fair mining

Workers search disjoint nonce ranges in 16,384-attempt batches. The native search
caches the fixed proof prefix, then hashes each nonce against the same canonical
Keccak and target rules. The optimization does not change difficulty, NFT supply,
challenge timing or HUNTER rules. Shared proof-vector tests protect compatibility
with browser proofs. Stronger hardware can search more nonces; equal rules do not
promise equal wins per device. The browser remains a valid mining path.

[An early signal](DISCOVER.md)

## Automatic seed refresh

Expired seeds are refreshed automatically when `mine --submit` is authorized.
A one-shot run sends only the refresh, reports `seedRefreshed`, and exits; invoke
it again after the seed becomes readable to mine. With `--loop`, the miner waits
for the new seed and resumes itself. Read-only commands never refresh or spend.
The refresh uses the same per-transaction `--max-fee` ceiling, has zero ETH value,
and mints no NFT. Another miner can win the refresh race; a reverted transaction
can still cost gas. Refresh fees are included in the loop's total fees.

An unresolved refresh is journaled before broadcast and reconciled on restart.
If the seed changed and no receipt is available, recovery refuses to rebroadcast
stale refresh bytes and keeps the journal for investigation. Never clear it to
force another transaction. Version 2 journals support proof and refresh calls;
existing version 1 proof journals remain readable.
