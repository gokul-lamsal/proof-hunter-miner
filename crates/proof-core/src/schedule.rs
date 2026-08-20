//! The deterministic reward schedule and whole-reward Core Reserve rule.

/// One PROOF token in base units.
pub const TOKEN_WEI: u128 = 1_000_000_000_000_000_000;

/// The permanent maximum amount of PROOF that mining can create.
pub const MAX_MINTED_EVER: u128 = 21_000_000 * TOKEN_WEI;

/// The number of accepted proofs over which the reward divisor increases.
pub const RAMP_PROOFS: u128 = 8_640;

/// The reward divisor used for the first accepted proof.
pub const OPENING_DIVISOR: u128 = 10_000;

/// The reward divisor after the opening ramp finishes.
pub const FINAL_DIVISOR: u128 = 45_350;

/// The normal minimum reward before the final capacity clip.
pub const MIN_REWARD: u128 = TOKEN_WEI;

/// Returns the reward divisor for the next accepted proof.
///
/// `accepted_proofs` is the number of proofs accepted before the current proof.
#[must_use]
pub const fn divisor_at(accepted_proofs: u128) -> u128 {
    let progress = if accepted_proofs < RAMP_PROOFS {
        accepted_proofs
    } else {
        RAMP_PROOFS
    };

    OPENING_DIVISOR + (FINAL_DIVISOR - OPENING_DIVISOR) * progress / RAMP_PROOFS
}

/// Returns the reward for the next accepted proof in PROOF base units.
///
/// `accepted_proofs` is the number of proofs accepted before the current proof.
/// `total_minted` is lifetime issuance before the current proof. A total at or
/// above [`MAX_MINTED_EVER`] has no remaining reward capacity and returns zero.
#[must_use]
pub const fn reward_at(accepted_proofs: u128, total_minted: u128) -> u128 {
    let remaining = MAX_MINTED_EVER.saturating_sub(total_minted);
    if remaining == 0 {
        return 0;
    }

    let proportional_reward = remaining / divisor_at(accepted_proofs);
    let floored_reward = if proportional_reward > MIN_REWARD {
        proportional_reward
    } else {
        MIN_REWARD
    };

    if floored_reward < remaining {
        floored_reward
    } else {
        remaining
    }
}

/// Returns the Core Reserve carved out of a proof reward.
///
/// A proof that mints a Hunter locks its whole reward inside that Hunter.
#[must_use]
pub const fn reserve_for(reward: u128) -> u128 {
    reward
}

/// Iterates over every reward in the decided schedule until the cap is spent.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct RewardSchedule {
    accepted_proofs: u128,
    total_minted: u128,
}

impl RewardSchedule {
    /// Creates a schedule at genesis with no accepted proofs or minted supply.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            accepted_proofs: 0,
            total_minted: 0,
        }
    }

    /// Returns the number of rewards emitted by this iterator.
    #[must_use]
    pub const fn accepted_proofs(&self) -> u128 {
        self.accepted_proofs
    }

    /// Returns the cumulative lifetime issuance emitted by this iterator.
    #[must_use]
    pub const fn total_minted(&self) -> u128 {
        self.total_minted
    }
}

impl Iterator for RewardSchedule {
    type Item = u128;

    fn next(&mut self) -> Option<Self::Item> {
        let reward = reward_at(self.accepted_proofs, self.total_minted);
        if reward == 0 {
            return None;
        }

        self.accepted_proofs += 1;
        self.total_minted += reward;
        Some(reward)
    }
}

impl std::iter::FusedIterator for RewardSchedule {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn divisor_uses_the_pre_acceptance_index_and_stops_at_the_final_value() {
        assert_eq!(divisor_at(0), OPENING_DIVISOR);
        assert_eq!(divisor_at(RAMP_PROOFS), FINAL_DIVISOR);
        assert_eq!(divisor_at(RAMP_PROOFS + 1), FINAL_DIVISOR);
        assert_eq!(divisor_at(u128::MAX), FINAL_DIVISOR);
    }

    #[test]
    fn first_proof_uses_the_opening_divisor() {
        assert_eq!(reward_at(0, 0), 2_100 * TOKEN_WEI);
    }

    #[test]
    fn reward_is_clipped_to_remaining_capacity() {
        let remaining = MIN_REWARD - 1;
        assert_eq!(
            reward_at(RAMP_PROOFS, MAX_MINTED_EVER - remaining),
            remaining
        );
    }

    #[test]
    fn exhausted_or_invalid_supply_has_no_reward() {
        assert_eq!(reward_at(0, MAX_MINTED_EVER), 0);
        assert_eq!(reward_at(0, MAX_MINTED_EVER + 1), 0);
    }

    #[test]
    fn full_schedule_lands_on_the_decided_cap_exactly() {
        let mut schedule = RewardSchedule::new();
        let rewards: Vec<u128> = schedule.by_ref().collect();

        assert_eq!(rewards.len(), 315_580);
        assert_eq!(schedule.accepted_proofs(), 315_580);
        assert_eq!(schedule.total_minted(), MAX_MINTED_EVER);
        assert_eq!(rewards.iter().copied().sum::<u128>(), MAX_MINTED_EVER);
        assert_eq!(rewards.first(), Some(&(2_100 * TOKEN_WEI)));
        assert_eq!(rewards.last(), Some(&512_358_404_659_727_855));
        assert!(rewards.windows(2).all(|pair| pair[0] >= pair[1]));

        // Ticket 05 says proof 270,230 starts the floor phase. Ticket 16 records
        // the recomputation: that proof remains above one token, and proof
        // 270,231 is the first reward for which the one-token floor binds.
        assert_eq!(rewards[270_230 - 1], 1_000_011_298_119_135_145);
        let first_one_token_reward = rewards
            .iter()
            .position(|reward| *reward == MIN_REWARD)
            .map(|index| index + 1);
        assert_eq!(first_one_token_reward, Some(270_231));

        assert_eq!(schedule.next(), None);
        assert_eq!(schedule.next(), None);
    }

    #[test]
    fn reserve_equals_whole_reward_at_required_edges() {
        assert_eq!(reserve_for(1), 1);
        assert_eq!(reserve_for(TOKEN_WEI), TOKEN_WEI);
        assert_eq!(reserve_for(2_100 * TOKEN_WEI), 2_100 * TOKEN_WEI);
    }

    #[test]
    fn zero_reward_has_zero_reserve() {
        assert_eq!(reserve_for(0), 0);
    }
}
