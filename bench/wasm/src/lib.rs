use proof_core::{Address, Digest, ProofInputs, Target, Uint256, meets_target, proof_digest};
use wasm_bindgen::prelude::*;

const WORD_BYTES: usize = 32;
const ADDRESS_BYTES: usize = 20;

/// A configured proof hasher used by the browser benchmark.
///
/// The timed loop calls proof-core's verified digest and target functions. The
/// wrapper only adapts byte arrays to the core's value types.
#[wasm_bindgen]
pub struct ProofBenchmark {
    chain_id: Uint256,
    mining_core: Address,
    challenge_id: Uint256,
    challenge: Digest,
    miner: Address,
    target: Target,
}

#[wasm_bindgen]
impl ProofBenchmark {
    #[wasm_bindgen(constructor)]
    pub fn new(
        chain_id: &[u8],
        mining_core: &[u8],
        challenge_id: &[u8],
        challenge: &[u8],
        miner: &[u8],
        target: &[u8],
    ) -> Result<ProofBenchmark, JsError> {
        Ok(Self {
            chain_id: Uint256::from_be_bytes(word(chain_id, "chainId")?),
            mining_core: Address::from_bytes(address(mining_core, "miningCore")?),
            challenge_id: Uint256::from_be_bytes(word(challenge_id, "challengeId")?),
            challenge: Digest::from_bytes(word(challenge, "challenge")?),
            miner: Address::from_bytes(address(miner, "miner")?),
            target: Target::from_be_bytes(word(target, "target")?),
        })
    }

    /// Returns one complete proof digest for cross-implementation vectors.
    pub fn digest(&self, mining_nonce: &[u8]) -> Result<Vec<u8>, JsError> {
        let digest = self.digest_for(Uint256::from_be_bytes(word(mining_nonce, "miningNonce")?));
        Ok(digest.to_bytes().to_vec())
    }

    /// Hashes a consecutive nonce range without crossing the JS/WASM boundary
    /// per attempt. The checksum makes every digest and target result observable.
    pub fn benchmark(&self, start_mining_nonce: &[u8], attempts: u32) -> Result<u32, JsError> {
        let mut mining_nonce =
            Uint256::from_be_bytes(word(start_mining_nonce, "startMiningNonce")?);
        let mut checksum = 0_u32;

        for _ in 0..attempts {
            let digest = self.digest_for(mining_nonce);
            let bytes = digest.to_bytes();
            let leading_word = u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
            checksum = checksum.rotate_left(5) ^ leading_word;
            if meets_target(digest, self.target) {
                checksum ^= 0x9e37_79b9;
            }
            mining_nonce = mining_nonce.wrapping_add(Uint256::ONE);
        }

        Ok(checksum)
    }
}

impl ProofBenchmark {
    fn digest_for(&self, mining_nonce: Uint256) -> Digest {
        proof_digest(&ProofInputs {
            chain_id: self.chain_id,
            mining_core: self.mining_core,
            challenge_id: self.challenge_id,
            challenge: self.challenge,
            miner: self.miner,
            nonce: mining_nonce,
        })
    }
}

fn word(value: &[u8], name: &str) -> Result<[u8; WORD_BYTES], JsError> {
    value
        .try_into()
        .map_err(|_| JsError::new(&format!("{name} must be exactly 32 bytes")))
}

fn address(value: &[u8], name: &str) -> Result<[u8; ADDRESS_BYTES], JsError> {
    value
        .try_into()
        .map_err(|_| JsError::new(&format!("{name} must be exactly 20 bytes")))
}
