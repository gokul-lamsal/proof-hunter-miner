//! Cross-implementation agreement on the whole reward schedule.
//!
//! Verification V6 asks for identical fixtures across implementations. This
//! walks the entire lifetime of the schedule — every accepted proof from the
//! first to the last — and folds each reward and Core Reserve into one rolling
//! keccak accumulator.
//!
//! A single 32-byte value then stands for 315,580 pairs. The Solidity side
//! (`contracts/test/ScheduleCrossImpl.t.sol`) and an independent Python
//! implementation fold the identical accumulator. If any one of the three
//! differs on any single proof, the digests diverge and cannot be reconciled
//! by luck.
//!
//! The expected digest below is NOT copied from this implementation. It was
//! produced by Solidity first, matched by Python second, and only then
//! asserted here — so this test can genuinely fail.

use proof_core::schedule::{MAX_MINTED_EVER, MIN_REWARD, reserve_for, reward_at};
use sha3::{Digest, Keccak256};

/// Produced by `forge test --match-contract ScheduleCrossImpl` and independently
/// reproduced in Python before being written here.
const EXPECTED_ACCUMULATOR: &str =
    "d38a333cf285ec4969f002eda93bc58a6c9cf8389eb894383cb8cbaaf486ece3";

const EXPECTED_TOTAL_PROOFS: u128 = 315_580;
const EXPECTED_FIRST_MINIMUM_PROOF: u128 = 270_231;
const EXPECTED_HALFWAY_PROOF: u128 = 23_315;

fn word(value: u128) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[16..].copy_from_slice(&value.to_be_bytes());
    out
}

#[test]
fn whole_lifetime_agrees_with_solidity_and_python() {
    let mut accumulator = [0u8; 32];
    let mut total_minted: u128 = 0;
    let mut accepted_proofs: u128 = 0;
    let mut first_minimum_reward_proof: u128 = 0;
    let mut halfway_proof: u128 = 0;

    loop {
        let reward = reward_at(accepted_proofs, total_minted);
        if reward == 0 {
            break;
        }

        let reserve = reserve_for(reward);
        assert!(
            reserve <= reward,
            "the Core Reserve is carved out of the reward and can never exceed it"
        );

        let mut hasher = Keccak256::new();
        hasher.update(accumulator);
        hasher.update(word(reward));
        hasher.update(word(reserve));
        accumulator.copy_from_slice(&hasher.finalize());

        if first_minimum_reward_proof == 0 && reward == MIN_REWARD {
            first_minimum_reward_proof = accepted_proofs + 1;
        }
        if halfway_proof == 0 && total_minted + reward >= MAX_MINTED_EVER / 2 {
            halfway_proof = accepted_proofs + 1;
        }

        total_minted += reward;
        accepted_proofs += 1;
    }

    assert_eq!(
        total_minted, MAX_MINTED_EVER,
        "lifetime issuance must equal the cap exactly, with nothing left over and nothing over-issued"
    );
    assert_eq!(
        accepted_proofs, EXPECTED_TOTAL_PROOFS,
        "total accepted proofs"
    );
    assert_eq!(
        first_minimum_reward_proof, EXPECTED_FIRST_MINIMUM_PROOF,
        "first proof paying the one-token minimum"
    );
    assert_eq!(
        halfway_proof, EXPECTED_HALFWAY_PROOF,
        "proof at which half the supply is minted"
    );
    assert_eq!(
        hex(&accumulator),
        EXPECTED_ACCUMULATOR,
        "Rust disagrees with Solidity and Python somewhere in the schedule"
    );
}

/// The whole-reward rule checked at the required scales.
#[test]
fn reserve_equals_whole_reward() {
    let t = 1_000_000_000_000_000_000u128;
    assert_eq!(reserve_for(1), 1, "1 wei");
    assert_eq!(reserve_for(t), t, "1 token");
    assert_eq!(reserve_for(2_100 * t), 2_100 * t, "opening reward");
}

fn hex(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
