# Proof Hunter Miner

Mine **HUNTER** on the Robinhood Chain **testnet** with `bproof` — a
deterministic, non-custodial command-line miner written in Rust.

- **Your key never leaves your machine.** The wallet is generated locally,
  encrypted on your disk, and the recovery phrase is written only to a
  private file you name. Nothing is ever printed to the screen, sent over
  the network, or written to logs.
- **Every claim is checkable.** The reward schedule is a fixed, published
  table you can re-derive yourself with `bproof schedule`. The contracts
  are verified on the chain explorer.
- **No administrator.** Nobody can change the rules, the schedule, or the
  supply. Not even the people who wrote it.

Site: https://proof-hunter-eight.vercel.app

## The game in one paragraph

Each round the chain publishes a puzzle. Your machine searches for a
winning number bound to *your* wallet address — a found proof is useless
to anyone else. Submit it and you win HUNTER from a fixed, shrinking
schedule. Each accepted proof also has a **1-in-51** chance of minting a
**Proof Hunter** — a limited NFT that permanently seals that entire win
inside itself. Burn the Hunter and the sealed HUNTER comes back out.

## Testnet addresses (chain 46630)

| What | Address |
|---|---|
| MiningCore (the game) | `0x2ebb9e7F35655fE1d07c0A21FCD28Ee7e531FAE9` |
| Proof Hunters (the NFT) | `0x3ECEDD3D006929226903d5b41E893ADB36DDC944` |
| HUNTER (the token) | `0x01CEd8f4AbDD0e3F52263d69f4A6438E864967fb` |

RPC: `https://rpc.testnet.chain.robinhood.com`

## Quickstart

You need Rust (https://rustup.rs) and a little testnet gas for the
submit transactions (see the Robinhood Chain docs:
https://docs.robinhood.com/chain).

```sh
# 1. Build
cargo build --release
alias bproof=./target/release/bproof

# 2. Create your local mining wallet.
#    The 24-word recovery phrase goes ONLY into the file you name here.
#    Store that file somewhere safe, then move it off this machine.
bproof wallet new \
  --keystore ~/.proof-hunter/wallet.json \
  --recovery-out ~/.proof-hunter/recovery.txt

# 3. Fund the printed address with testnet gas, then mine continuously.
#    --max-fee is a hard ceiling in wei on what one submission may cost;
#    the miner refuses to sign anything above it.
bproof mine \
  --rpc-url https://rpc.testnet.chain.robinhood.com \
  --chain-id 46630 \
  --mining-core 0x2ebb9e7F35655fE1d07c0A21FCD28Ee7e531FAE9 \
  --keystore ~/.proof-hunter/wallet.json \
  --submit --loop \
  --max-fee 2000000000000000
```

`Ctrl-C` stops cleanly. Type `summary` and press Enter while it runs to
get a progress report. Add `--json` for machine-readable event lines.

Every subcommand documents itself: `bproof --help`,
`bproof mine --help`, `bproof wallet --help`, `bproof status --help`.

## Download a release

Download the binary for your system from
[GitHub Releases](https://github.com/vltgoblin/proof-hunter-miner/releases).
Before you run it, follow [Verify a miner release](docs/verifying-a-release.md)
to check its GitHub build attestation and SHA-256 checksum.

## Check things yourself

```sh
# Re-derive the entire fixed reward schedule and its digest locally:
bproof schedule

# Inspect live game state straight from the contract:
bproof status --rpc-url https://rpc.testnet.chain.robinhood.com \
  --chain-id 46630 \
  --mining-core 0x2ebb9e7F35655fE1d07c0A21FCD28Ee7e531FAE9

# Run the test suite:
cargo test --workspace
```

## Safety notes

- This is a **testnet**. Tokens and NFTs here have no monetary value.
- The miner never asks for a private key and never prints one. If any
  tool claiming to be part of this project asks for your key or recovery
  phrase, it is not ours — close it.
- Use a dedicated wallet for mining. Do not reuse a wallet that holds
  anything you care about.

## License

MIT — see [LICENSE](LICENSE).
