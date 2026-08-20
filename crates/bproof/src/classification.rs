//! Proof Hunter classification from one block-pinned chain snapshot.

use proof_core::{Digest, Target, Uint256};

/// Chain values needed to predict whether an accepted proof mints a Proof Hunter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NftClassificationSnapshot {
    pub accepted_target: Target,
    pub nft_odds_denominator: Uint256,
    pub max_nfts_ever: Uint256,
    pub nfts_minted_ever: Uint256,
}

/// The settlement path predicted from the accepted proof's chain snapshot.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ProofClassification {
    ProofHunter,
    Ordinary,
    Unknown { reason: String },
}

impl ProofClassification {
    #[must_use]
    pub const fn name(&self) -> &'static str {
        match self {
            Self::ProofHunter => "proofHunter",
            Self::Ordinary => "ordinary",
            Self::Unknown { .. } => "unknown",
        }
    }

    #[must_use]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Unknown { reason } => Some(reason),
            Self::ProofHunter | Self::Ordinary => None,
        }
    }
}

#[must_use]
pub fn classify_proof(
    digest: Digest,
    snapshot: &Result<NftClassificationSnapshot, String>,
) -> ProofClassification {
    let snapshot = match snapshot {
        Ok(snapshot) => snapshot,
        Err(reason) => {
            return ProofClassification::Unknown {
                reason: reason.clone(),
            };
        }
    };
    let denominator = snapshot.nft_odds_denominator.to_be_bytes();
    if denominator.iter().all(|byte| *byte == 0) {
        return ProofClassification::Unknown {
            reason: "MiningCore.NFT_ODDS_DENOMINATOR() returned zero".to_owned(),
        };
    }

    let threshold = divide_word(snapshot.accepted_target.to_be_bytes(), denominator);
    let qualifies = digest.to_bytes() <= threshold;
    let capacity_remains = snapshot.nfts_minted_ever < snapshot.max_nfts_ever;
    if qualifies && capacity_remains {
        ProofClassification::ProofHunter
    } else {
        ProofClassification::Ordinary
    }
}

fn divide_word(dividend: [u8; 32], divisor: [u8; 32]) -> [u8; 32] {
    let mut quotient = [0_u8; 32];
    let mut remainder = [0_u8; 33];
    let mut wide_divisor = [0_u8; 33];
    wide_divisor[1..].copy_from_slice(&divisor);

    for bit_index in 0..256 {
        shift_left_one(&mut remainder);
        let source_byte = bit_index / 8;
        let source_bit = 7 - (bit_index % 8);
        remainder[32] |= (dividend[source_byte] >> source_bit) & 1;
        if remainder >= wide_divisor {
            subtract_word(&mut remainder, &wide_divisor);
            quotient[source_byte] |= 1 << source_bit;
        }
    }
    quotient
}

fn shift_left_one(value: &mut [u8; 33]) {
    let mut carry = 0_u8;
    for byte in value.iter_mut().rev() {
        let next_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = next_carry;
    }
}

fn subtract_word(value: &mut [u8; 33], rhs: &[u8; 33]) {
    let mut borrow = 0_u16;
    for index in (0..value.len()).rev() {
        let lhs = u16::from(value[index]);
        let subtrahend = u16::from(rhs[index]) + borrow;
        value[index] = lhs.wrapping_sub(subtrahend) as u8;
        borrow = u16::from(lhs < subtrahend);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(target: u128, minted: u64, maximum: u64) -> NftClassificationSnapshot {
        NftClassificationSnapshot {
            accepted_target: Target::from_be_bytes(Uint256::from(target).to_be_bytes()),
            nft_odds_denominator: Uint256::from(5_u64),
            max_nfts_ever: Uint256::from(maximum),
            nfts_minted_ever: Uint256::from(minted),
        }
    }

    fn digest(value: u128) -> Digest {
        Digest::from_bytes(Uint256::from(value).to_be_bytes())
    }

    #[test]
    fn threshold_is_inclusive_and_one_above_is_ordinary() {
        let snapshot = Ok(snapshot(100, 0, 5_000));
        assert_eq!(
            classify_proof(digest(20), &snapshot),
            ProofClassification::ProofHunter
        );
        assert_eq!(
            classify_proof(digest(21), &snapshot),
            ProofClassification::Ordinary
        );
    }

    #[test]
    fn accepted_target_controls_classification_not_a_later_target() {
        let accepted_snapshot = Ok(snapshot(100, 0, 5_000));
        let later_snapshot = Ok(snapshot(50, 0, 5_000));
        assert_eq!(
            classify_proof(digest(20), &accepted_snapshot),
            ProofClassification::ProofHunter
        );
        assert_eq!(
            classify_proof(digest(20), &later_snapshot),
            ProofClassification::Ordinary
        );
    }

    #[test]
    fn collection_cap_changes_a_qualifying_digest_to_ordinary() {
        let before_cap = Ok(snapshot(100, 4_999, 5_000));
        let at_cap = Ok(snapshot(100, 5_000, 5_000));
        assert_eq!(
            classify_proof(digest(20), &before_cap),
            ProofClassification::ProofHunter
        );
        assert_eq!(
            classify_proof(digest(20), &at_cap),
            ProofClassification::Ordinary
        );
    }

    #[test]
    fn failed_required_read_is_unknown_not_ordinary() {
        let failed = Err("failed to read MiningCore.NFT_ODDS_DENOMINATOR()".to_owned());
        assert_eq!(
            classify_proof(digest(0), &failed),
            ProofClassification::Unknown {
                reason: "failed to read MiningCore.NFT_ODDS_DENOMINATOR()".to_owned()
            }
        );
    }

    #[test]
    fn division_matches_wide_uint256_boundaries() {
        let maximum = [0xff; 32];
        let quotient = divide_word(maximum, Uint256::from(2_u64).to_be_bytes());
        assert_eq!(quotient[0], 0x7f);
        assert!(quotient[1..].iter().all(|byte| *byte == 0xff));
        assert_eq!(divide_word(maximum, maximum), Uint256::ONE.to_be_bytes());

        let mut high_divisor = [0_u8; 32];
        high_divisor[0] = 0x80;
        assert_eq!(
            divide_word(maximum, high_divisor),
            Uint256::ONE.to_be_bytes()
        );

        assert_eq!(
            divide_word(
                Uint256::from(99_u64).to_be_bytes(),
                Uint256::from(5_u64).to_be_bytes()
            ),
            Uint256::from(19_u64).to_be_bytes()
        );
        assert_eq!(
            divide_word(
                Uint256::from(100_u64).to_be_bytes(),
                Uint256::from(101_u64).to_be_bytes()
            ),
            Uint256::ZERO.to_be_bytes()
        );
    }
}
