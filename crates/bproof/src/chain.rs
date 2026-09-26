//! Offline and live sources for canonical mining state.

use std::path::{Path, PathBuf};
use std::time::Duration;

use proof_core::{Address, ChallengeInputs, Digest, Target, Uint256, derive_challenge, keccak256};
use serde_json::{Map, Value, json};

use crate::classification::NftClassificationSnapshot;
use crate::parse::{
    hex_string, parse_address, parse_decimal_uint256, parse_digest, parse_hex_quantity_uint256,
    parse_target, parse_u128, parse_uint256_word, uint256_to_decimal,
};

const STATE_KEYS: [&str; 9] = [
    "chainId",
    "miningCore",
    "challengeId",
    "previousAcceptedDigest",
    "seedParentBlock",
    "seedBlockhash",
    "target",
    "acceptedProofs",
    "totalMintedWei",
];

pub const FILE_STATE_SOURCE: &str = "file";
pub const CHAIN_STATE_SOURCE: &str = "chain";

const RPC_TIMEOUT: Duration = Duration::from_secs(15);
const RPC_RESPONSE_LIMIT_BYTES: u64 = 1_048_576;
const RPC_ID: u64 = 1;
const EVM_CONTEXT_HELPER_ADDRESS: &str = "0x00000000000000000000000000000000000c0de1";
const PARENT_BLOCK_NUMBER_HELPER_CODE: &str = "0x4360005260206000f3";
const PARENT_BLOCKHASH_HELPER_CODE: &str = "0x6000354060005260206000f3";

/// One canonical mining-state snapshot plus its reward schedule counters.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MiningState {
    pub challenge_inputs: ChallengeInputs,
    pub challenge: Digest,
    pub target: Target,
    pub accepted_proofs: u128,
    /// Legacy offline schedule counter; never read from HunterMiningCore.
    pub total_minted_wei: u128,
    pub nfts_minted_ever: Option<u128>,
}

/// Mining state and the optional NFT-path values read at the same block tag.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClassifiedMiningState {
    pub state: MiningState,
    pub effective_target: Target,
    pub power_multiplier_wad: Uint256,
    pub nft_classification: Result<NftClassificationSnapshot, String>,
}

/// Contract mining lifecycle values in the Solidity declaration order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChallengeStatus {
    WaitingForSeed,
    Active,
    Expired,
    Ended,
    Stopped,
}

/// The minimum block-pinned identity needed to detect stale search work.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ChallengeMarker {
    pub challenge_id: Uint256,
    pub previous_accepted_digest: Digest,
    pub challenge: Option<Digest>,
    pub status: ChallengeStatus,
}

/// Supplies a complete mining-state snapshot from one explicit source.
pub trait ChainReader {
    fn read_state(&self) -> Result<MiningState, String>;
}

/// Reads an explicitly offline mining-state snapshot from JSON.
pub struct FileChainReader {
    path: PathBuf,
}

impl FileChainReader {
    #[must_use]
    pub fn new(path: impl AsRef<Path>) -> Self {
        Self {
            path: path.as_ref().to_path_buf(),
        }
    }
}

impl ChainReader for FileChainReader {
    fn read_state(&self) -> Result<MiningState, String> {
        let contents = std::fs::read_to_string(&self.path).map_err(|error| {
            format!("failed to read state file {}: {error}", self.path.display())
        })?;
        let value: Value = serde_json::from_str(&contents)
            .map_err(|error| format!("state file contains invalid JSON: {error}"))?;
        let fields = value
            .as_object()
            .ok_or_else(|| "state file root must be a JSON object".to_owned())?;

        validate_keys(fields)?;

        let challenge_inputs = ChallengeInputs {
            chain_id: parse_decimal_uint256(field(fields, "chainId")?, "chainId")?,
            mining_core: parse_address(field(fields, "miningCore")?, "miningCore")?,
            challenge_id: parse_decimal_uint256(field(fields, "challengeId")?, "challengeId")?,
            previous_accepted_digest: parse_digest(
                field(fields, "previousAcceptedDigest")?,
                "previousAcceptedDigest",
            )?,
            seed_parent_block: parse_decimal_uint256(
                field(fields, "seedParentBlock")?,
                "seedParentBlock",
            )?,
            seed_blockhash: parse_digest(field(fields, "seedBlockhash")?, "seedBlockhash")?,
        };
        Ok(MiningState {
            challenge_inputs,
            challenge: derive_challenge(&challenge_inputs),
            target: parse_target(field(fields, "target")?, "target")?,
            accepted_proofs: parse_u128(field(fields, "acceptedProofs")?, "acceptedProofs")?,
            total_minted_wei: parse_u128(field(fields, "totalMintedWei")?, "totalMintedWei")?,
            nfts_minted_ever: None,
        })
    }
}

/// Reads a block-pinned mining snapshot directly from a verified MiningCore deployment.
pub struct RpcChainReader {
    endpoint: String,
    mining_core_address: Address,
    expected_chain_id: Uint256,
    agent: ureq::Agent,
}

impl RpcChainReader {
    #[must_use]
    pub fn new(
        endpoint: impl Into<String>,
        mining_core_address: Address,
        expected_chain_id: Uint256,
    ) -> Self {
        let config = ureq::Agent::config_builder()
            .timeout_global(Some(RPC_TIMEOUT))
            .build();
        Self {
            endpoint: endpoint.into(),
            mining_core_address,
            expected_chain_id,
            agent: ureq::Agent::new_with_config(config),
        }
    }

    pub(crate) fn rpc_result(
        &self,
        operation: &str,
        method: &str,
        params: Value,
    ) -> Result<Value, String> {
        let request = json!({
            "jsonrpc": "2.0",
            "id": RPC_ID,
            "method": method,
            "params": params,
        });
        let response = self.post(operation, &request)?;
        decode_rpc_response(operation, RPC_ID, response)
    }

    /// Issues read-only calls in one round trip, falling back to sequential
    /// requests when the endpoint cannot serve a JSON-RPC batch.
    ///
    /// Only ever call this with reads. Falling back re-issues the calls, so a
    /// batched call must never carry a side effect such as a signed send.
    pub(crate) fn rpc_batch(&self, calls: &[BatchCall<'_>]) -> Vec<Result<Value, String>> {
        if calls.len() < 2 {
            return calls
                .iter()
                .map(|call| self.rpc_result(call.operation, call.method, call.params.clone()))
                .collect();
        }

        let requests: Vec<Value> = calls
            .iter()
            .enumerate()
            .map(|(index, call)| {
                json!({
                    "jsonrpc": "2.0",
                    // Distinct ids let a response be matched to its request even
                    // when a node answers a batch out of order.
                    "id": index + 1,
                    "method": call.method,
                    "params": call.params,
                })
            })
            .collect();

        // A node that rejects batching, answers with one object instead of an
        // array, or reuses an id cannot be trusted to have served every call, so
        // the whole batch is reissued sequentially. Every call here is a read.
        let Some(decoded) = self
            .post(calls[0].operation, &Value::Array(requests))
            .ok()
            .and_then(|response| decode_rpc_batch(calls, response))
        else {
            return calls
                .iter()
                .map(|call| self.rpc_result(call.operation, call.method, call.params.clone()))
                .collect();
        };
        decoded
    }

    fn post(&self, operation: &str, request: &Value) -> Result<Value, String> {
        let request_body = serde_json::to_string(request)
            .map_err(|error| format!("failed to encode JSON-RPC {operation} request: {error}"))?;
        let mut response = self
            .agent
            .post(&self.endpoint)
            .content_type("application/json")
            .send(request_body.as_bytes())
            .map_err(|error| match error {
                ureq::Error::StatusCode(status) => {
                    format!("JSON-RPC {operation} failed with HTTP {status}")
                }
                _ => {
                    format!("failed to reach JSON-RPC endpoint while reading {operation}: {error}")
                }
            })?;
        if response
            .body()
            .content_length()
            .is_some_and(|length| length > RPC_RESPONSE_LIMIT_BYTES)
        {
            return Err(format!(
                "JSON-RPC {operation} response exceeds the {RPC_RESPONSE_LIMIT_BYTES}-byte limit"
            ));
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(RPC_RESPONSE_LIMIT_BYTES)
            .read_to_string()
            .map_err(|error| {
                format!(
                    "failed to read JSON-RPC {operation} response within the {RPC_RESPONSE_LIMIT_BYTES}-byte limit: {error}"
                )
            })?;
        serde_json::from_str(&body)
            .map_err(|error| format!("JSON-RPC {operation} returned non-JSON body: {error}"))
    }

    pub(crate) fn string_result(
        &self,
        operation: &str,
        method: &str,
        params: Value,
    ) -> Result<String, String> {
        self.rpc_result(operation, method, params)?
            .as_str()
            .map(str::to_owned)
            .ok_or_else(|| format!("JSON-RPC {operation} result must be a string"))
    }

    fn call_word(&self, signature: &str, block_tag: &str) -> Result<Uint256, String> {
        let operation = format!("MiningCore.{signature}");
        let result = self.string_result(
            &operation,
            "eth_call",
            json!([
                {
                    "to": hex_string(&self.mining_core_address.to_bytes()),
                    "data": function_selector(signature),
                },
                block_tag,
            ]),
        )?;
        parse_uint256_word(&result, &format!("{operation} return value"))
    }

    fn call_evm_context_word(
        &self,
        operation: &str,
        helper_code: &str,
        call_data: &str,
        rpc_snapshot_tag: &str,
    ) -> Result<Uint256, String> {
        let mut state_override = Map::new();
        state_override.insert(
            EVM_CONTEXT_HELPER_ADDRESS.to_owned(),
            json!({"code": helper_code}),
        );
        let result = self.string_result(
            operation,
            "eth_call",
            json!([
                {"to": EVM_CONTEXT_HELPER_ADDRESS, "data": call_data},
                rpc_snapshot_tag,
                state_override,
            ]),
        )?;
        parse_uint256_word(&result, &format!("{operation} return value"))
    }

    fn parent_block_number(&self, rpc_snapshot_tag: &str) -> Result<Uint256, String> {
        self.call_evm_context_word(
            "EVM parent block number",
            PARENT_BLOCK_NUMBER_HELPER_CODE,
            "0x",
            rpc_snapshot_tag,
        )
    }

    fn seed_blockhash(
        &self,
        seed_parent_block: Uint256,
        rpc_snapshot_tag: &str,
    ) -> Result<Digest, String> {
        let current_parent_block = self.parent_block_number(rpc_snapshot_tag)?;
        if current_parent_block <= seed_parent_block {
            return Err(format!(
                "challenge unavailable: seed parent block {} has not passed at EVM parent block {}",
                uint256_to_decimal(seed_parent_block),
                uint256_to_decimal(current_parent_block),
            ));
        }
        let blockhash = self.call_evm_context_word(
            "seed parent blockhash",
            PARENT_BLOCKHASH_HELPER_CODE,
            &hex_string(&seed_parent_block.to_be_bytes()),
            rpc_snapshot_tag,
        )?;
        if blockhash == Uint256::ZERO {
            return Err(format!(
                "challenge unavailable: seed parent block {} has no EVM blockhash at parent block {}",
                uint256_to_decimal(seed_parent_block),
                uint256_to_decimal(current_parent_block),
            ));
        }
        Ok(Digest::from_bytes(blockhash.to_be_bytes()))
    }

    pub(crate) fn verify_identity(&self) -> Result<(), String> {
        self.verified_block_tag().map(drop)
    }

    /// An expired identity pinned to a verified RPC block; no seed hash is required.
    pub(crate) fn expired_seed(&self) -> Result<Option<(Uint256, Uint256)>, String> {
        let tag = self.verified_block_tag()?;
        if ChallengeStatus::from_word(self.call_word("challengeState()", &tag)?)?
            != ChallengeStatus::Expired
        {
            return Ok(None);
        }
        Ok(Some((
            self.call_word("activeChallengeId()", &tag)?,
            self.call_word("activeSeedParentBlock()", &tag)?,
        )))
    }

    pub(crate) fn matches_deployment(&self, chain_id: Uint256, core: Address) -> bool {
        chain_id == self.expected_chain_id && core == self.mining_core_address
    }

    /// Reads only the current snapshot block tag, without any contract calls.
    ///
    /// A challenge marker is entirely determined by the block it is pinned to,
    /// so a caller that already holds an unchanged tag can skip re-reading the
    /// marker: the same tag can only ever produce the same marker.
    pub(crate) fn snapshot_block(&self) -> Result<String, String> {
        let block_tag =
            self.string_result("watcher snapshot block", "eth_blockNumber", json!([]))?;
        parse_hex_quantity_uint256(&block_tag, "eth_blockNumber watcher result")?;
        Ok(block_tag)
    }

    pub(crate) fn read_challenge_marker(&self) -> Result<ChallengeMarker, String> {
        let block_tag = self.snapshot_block()?;
        self.read_challenge_marker_at(&block_tag)
    }

    /// Reads the challenge marker at an already-resolved snapshot block tag.
    pub(crate) fn read_challenge_marker_at(
        &self,
        block_tag: &str,
    ) -> Result<ChallengeMarker, String> {
        let status = ChallengeStatus::from_word(self.call_word("challengeState()", block_tag)?)?;
        let challenge_id = self.call_word("activeChallengeId()", block_tag)?;
        let previous_accepted_digest = Digest::from_bytes(
            self.call_word("previousAcceptedDigest()", block_tag)?
                .to_be_bytes(),
        );
        let challenge = if status == ChallengeStatus::Active {
            Some(Digest::from_bytes(
                self.call_word("currentChallenge()", block_tag)?
                    .to_be_bytes(),
            ))
        } else {
            None
        };
        Ok(ChallengeMarker {
            challenge_id,
            previous_accepted_digest,
            challenge,
            status,
        })
    }

    pub(crate) fn read_classified_state(
        &self,
        miner: Option<Address>,
    ) -> Result<ClassifiedMiningState, String> {
        let block_tag = self.verified_block_tag()?;
        let state = self.read_state_at(&block_tag)?;
        let (effective_target, power_multiplier_wad) = match miner {
            Some(miner) => self.read_mining_power_at(&block_tag, &state, miner)?,
            None => (state.target, Uint256::from(crate::power::BASE_WAD)),
        };
        let nft_classification = self.read_nft_classification_at(&block_tag, effective_target);
        Ok(ClassifiedMiningState {
            state,
            effective_target,
            power_multiplier_wad,
            nft_classification,
        })
    }

    // Use the core-selected module and challenge snapshot, never loose HUNTER
    // balances or current assignment previews. eth_call discards lazy freeze writes.
    fn read_mining_power_at(
        &self,
        block_tag: &str,
        state: &MiningState,
        miner: Address,
    ) -> Result<(Target, Uint256), String> {
        let module = self.call_word("miningPower()", block_tag)?.to_be_bytes();
        if module[..12].iter().any(|byte| *byte != 0) {
            return Err("MiningCore.miningPower() returned a malformed address".to_owned());
        }
        if module == [0; 32] {
            return Ok((state.target, Uint256::from(crate::power::BASE_WAD)));
        }
        let module = hex_string(&module[12..]);
        let mut data = function_selector("powerMultiplierWad(uint256,address)");
        data.push_str(&hex_string(&state.challenge_inputs.challenge_id.to_be_bytes())[2..]);
        data.push_str(&"0".repeat(24));
        data.push_str(&hex_string(&miner.to_bytes())[2..]);
        let result = self.string_result(
            "challenge mining power", "eth_call",
            json!([{"to": module, "from": hex_string(&self.mining_core_address.to_bytes()), "data": data}, block_tag]),
        )?;
        let raw = parse_uint256_word(&result, "MiningPower.powerMultiplierWad return value")?;
        let multiplier = raw
            .max(Uint256::from(crate::power::BASE_WAD))
            .min(Uint256::from(crate::power::MAX_WAD));
        if multiplier == Uint256::from(crate::power::BASE_WAD) {
            return Ok((state.target, multiplier));
        }
        let maximum = self.call_word("MAX_TARGET()", block_tag)?;
        let effective = crate::power::effective_target(state.target, raw, maximum)?;
        Ok((effective, multiplier))
    }

    fn read_nft_classification_at(
        &self,
        block_tag: &str,
        accepted_target: Target,
    ) -> Result<NftClassificationSnapshot, String> {
        // HunterMiningCore mints one NFT for every accepted proof. There is no
        // probabilistic NFT path or liquid mining reward in this live ABI.
        let nft_odds_denominator = Uint256::ONE;
        let max_nfts_ever = self
            .call_word("MAX_NFTS_EVER()", block_tag)
            .map_err(|error| format!("proof classification unknown: {error}"))?;
        let nfts_minted_ever = self
            .call_word("nftsMintedEver()", block_tag)
            .map_err(|error| format!("proof classification unknown: {error}"))?;
        Ok(NftClassificationSnapshot {
            accepted_target,
            nft_odds_denominator,
            max_nfts_ever,
            nfts_minted_ever,
        })
    }

    fn read_state_at(&self, block_tag: &str) -> Result<MiningState, String> {
        let chain_id = self.expected_chain_id;

        let challenge_id = self.call_word("activeChallengeId()", block_tag)?;
        let previous_accepted_digest = Digest::from_bytes(
            self.call_word("previousAcceptedDigest()", block_tag)?
                .to_be_bytes(),
        );
        let seed_parent_block = self.call_word("activeSeedParentBlock()", block_tag)?;
        let target =
            Target::from_be_bytes(self.call_word("currentTarget()", block_tag)?.to_be_bytes());
        let accepted_proofs = uint256_to_u128(
            self.call_word("acceptedProofs()", block_tag)?,
            "MiningCore.acceptedProofs()",
        )?;
        let nfts_minted_ever = uint256_to_u128(
            self.call_word("nftsMintedEver()", block_tag)?,
            "HunterMiningCore.nftsMintedEver()",
        )?;
        if nfts_minted_ever != accepted_proofs {
            return Err("HunterMiningCore accepted proof and NFT counters disagree".to_owned());
        }
        let seed_blockhash = self.seed_blockhash(seed_parent_block, block_tag)?;
        let contract_challenge = Digest::from_bytes(
            self.call_word("currentChallenge()", block_tag)?
                .to_be_bytes(),
        );
        let challenge_inputs = ChallengeInputs {
            chain_id,
            mining_core: self.mining_core_address,
            challenge_id,
            previous_accepted_digest,
            seed_parent_block,
            seed_blockhash,
        };
        let locally_derived_challenge = derive_challenge(&challenge_inputs);
        if contract_challenge != locally_derived_challenge {
            return Err(format!(
                "MiningCore.currentChallenge() mismatch: contract returned {}, locally derived {}",
                hex_string(&contract_challenge.to_bytes()),
                hex_string(&locally_derived_challenge.to_bytes())
            ));
        }

        Ok(MiningState {
            challenge_inputs,
            challenge: contract_challenge,
            target,
            accepted_proofs,
            total_minted_wei: 0,
            nfts_minted_ever: Some(nfts_minted_ever),
        })
    }

    fn verified_block_tag(&self) -> Result<String, String> {
        let chain_id_text = self.string_result("chain identity", "eth_chainId", json!([]))?;
        let chain_id = parse_hex_quantity_uint256(&chain_id_text, "eth_chainId result")?;
        if chain_id != self.expected_chain_id {
            return Err(format!(
                "wrong chain id: expected {}, received {}",
                uint256_to_decimal(self.expected_chain_id),
                uint256_to_decimal(chain_id)
            ));
        }

        // Nitro exposes an L2 block namespace through JSON-RPC while EVM NUMBER
        // exposes the parent-chain estimate. This value is only an RPC snapshot
        // tag; contract-clock reads use the override helpers above.
        let block_tag = self.string_result("snapshot block", "eth_blockNumber", json!([]))?;
        parse_hex_quantity_uint256(&block_tag, "eth_blockNumber result")?;
        let code = self.string_result(
            "MiningCore code identity",
            "eth_getCode",
            json!([hex_string(&self.mining_core_address.to_bytes()), block_tag]),
        )?;
        validate_contract_code(&code)?;
        Ok(block_tag)
    }
}

/// One read-only call inside a [`RpcChainReader::rpc_batch`] round trip.
pub(crate) struct BatchCall<'a> {
    pub operation: &'a str,
    pub method: &'a str,
    pub params: Value,
}

impl<'a> BatchCall<'a> {
    pub(crate) fn new(operation: &'a str, method: &'a str, params: Value) -> Self {
        Self {
            operation,
            method,
            params,
        }
    }
}

fn decode_rpc_response(
    operation: &str,
    expected_id: u64,
    response: Value,
) -> Result<Value, String> {
    let fields = response
        .as_object()
        .ok_or_else(|| format!("JSON-RPC {operation} response must be an object"))?;
    if fields.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(format!(
            "JSON-RPC {operation} response has an invalid `jsonrpc` version"
        ));
    }
    if fields.get("id").and_then(Value::as_u64) != Some(expected_id) {
        return Err(format!(
            "JSON-RPC {operation} response has an unexpected `id`"
        ));
    }

    if let Some(error) = fields.get("error").filter(|error| !error.is_null()) {
        let code = error
            .get("code")
            .map_or_else(|| "unknown code".to_owned(), |value| value.to_string());
        let message = error
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("missing error message");
        return Err(format!(
            "JSON-RPC {operation} failed with error {code}: {message}"
        ));
    }

    fields
        .get("result")
        .cloned()
        .ok_or_else(|| format!("JSON-RPC {operation} response is missing `result`"))
}

/// Decodes a batch reply, matching each response to its request by id.
///
/// Returns `None` when the reply is not a usable batch, so the caller can fall
/// back to sequential requests. A per-call JSON-RPC error is a usable reply and
/// is returned as that call's own `Err`.
fn decode_rpc_batch(
    calls: &[BatchCall<'_>],
    response: Value,
) -> Option<Vec<Result<Value, String>>> {
    let entries = response.as_array()?.clone();
    if entries.len() != calls.len() {
        return None;
    }

    let mut by_id: Vec<Option<Value>> = vec![None; calls.len()];
    for entry in entries {
        let id = entry.get("id").and_then(Value::as_u64)?;
        let slot = usize::try_from(id.checked_sub(1)?).ok()?;
        // A repeated id would leave a call unanswered and another answered twice.
        if slot >= by_id.len() || by_id[slot].is_some() {
            return None;
        }
        by_id[slot] = Some(entry);
    }

    by_id
        .into_iter()
        .enumerate()
        .map(|(index, entry)| {
            let entry = entry?;
            Some(decode_rpc_response(
                calls[index].operation,
                index as u64 + 1,
                entry,
            ))
        })
        .collect()
}

/// Reads one string result from an already-issued batch entry.
pub(crate) fn batch_string(
    result: &Result<Value, String>,
    operation: &str,
) -> Result<String, String> {
    result
        .as_ref()
        .map_err(Clone::clone)?
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("JSON-RPC {operation} result must be a string"))
}

impl ChallengeStatus {
    fn from_word(value: Uint256) -> Result<Self, String> {
        match value {
            value if value == Uint256::ZERO => Ok(Self::WaitingForSeed),
            value if value == Uint256::ONE => Ok(Self::Active),
            value if value == Uint256::from(2_u64) => Ok(Self::Expired),
            value if value == Uint256::from(3_u64) => Ok(Self::Ended),
            value if value == Uint256::from(4_u64) => Ok(Self::Stopped),
            _ => Err("MiningCore.challengeState() returned an unknown enum value".to_owned()),
        }
    }
}

impl ChainReader for RpcChainReader {
    fn read_state(&self) -> Result<MiningState, String> {
        let block_tag = self.verified_block_tag()?;
        self.read_state_at(&block_tag)
    }
}

fn function_selector(signature: &str) -> String {
    hex_string(&keccak256(signature.as_bytes()).to_bytes()[..4])
}

fn validate_contract_code(code: &str) -> Result<(), String> {
    let Some(hex) = code.strip_prefix("0x") else {
        return Err("eth_getCode result must be 0x-prefixed hexadecimal bytecode".to_owned());
    };
    if hex.is_empty() {
        return Err("MiningCore address has no code".to_owned());
    }
    if hex.len() % 2 != 0 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("eth_getCode result contains malformed bytecode".to_owned());
    }
    Ok(())
}

fn uint256_to_u128(value: Uint256, name: &str) -> Result<u128, String> {
    let bytes = value.to_be_bytes();
    if bytes[..16].iter().any(|byte| *byte != 0) {
        return Err(format!("{name} exceeds the supported u128 range"));
    }
    let mut lower = [0_u8; 16];
    lower.copy_from_slice(&bytes[16..]);
    Ok(u128::from_be_bytes(lower))
}

fn validate_keys(fields: &Map<String, Value>) -> Result<(), String> {
    if let Some(key) = fields
        .keys()
        .find(|key| !STATE_KEYS.contains(&key.as_str()))
    {
        return Err(format!("unknown state key `{key}`"));
    }

    for key in STATE_KEYS {
        if !fields.contains_key(key) {
            return Err(format!("missing state key `{key}`"));
        }
    }

    Ok(())
}

fn field<'a>(fields: &'a Map<String, Value>, key: &str) -> Result<&'a str, String> {
    fields
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("state key `{key}` must be a string"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::process::{Child, Command, Stdio};
    use std::thread::{self, JoinHandle};
    use std::time::Duration;

    use serde::Deserialize;

    use super::*;

    mod cli_fixture {
        include!(concat!(env!("CARGO_MANIFEST_DIR"), "/tests/common/mod.rs"));
    }

    const FIXTURE: &str = include_str!("../tests/fixtures/rpc-chain-state.json");
    const MINING_CORE: Address = Address::from_bytes([
        0x5f, 0xbd, 0xb2, 0x31, 0x56, 0x78, 0xaf, 0xec, 0xb3, 0x67, 0xf0, 0x32, 0xd9, 0x3f, 0x64,
        0x2f, 0x64, 0x18, 0x0a, 0xa3,
    ]);
    const EXPECTED_CHAIN_ID: Uint256 = Uint256::from_be_bytes([
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0x7a, 0x69,
    ]);

    #[derive(Clone, Deserialize)]
    struct RecordedExchange {
        request: Value,
        response: Value,
    }

    #[derive(Deserialize)]
    struct RecordedFixture {
        exchanges: Vec<RecordedExchange>,
    }

    struct MockResponse {
        expected_request: Value,
        status: u16,
        body: String,
    }

    #[test]
    fn recorded_rpc_pairs_decode_every_mining_field() {
        let exchanges = recorded_exchanges();
        let responses = exchanges
            .into_iter()
            .map(|exchange| MockResponse {
                expected_request: exchange.request,
                status: 200,
                body: serde_json::to_string(&exchange.response).expect("fixture response is JSON"),
            })
            .collect();
        let (endpoint, server) = spawn_mock_server(responses);

        let state = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect("recorded RPC state must decode");
        server.join().expect("mock server must finish");

        assert_eq!(state.challenge_inputs.chain_id, EXPECTED_CHAIN_ID);
        assert_eq!(state.challenge_inputs.mining_core, MINING_CORE);
        assert_eq!(state.challenge_inputs.challenge_id, Uint256::ONE);
        assert_eq!(
            state.challenge_inputs.previous_accepted_digest,
            Digest::ZERO
        );
        assert_eq!(
            state.challenge_inputs.seed_parent_block,
            Uint256::from(1_003_u64)
        );
        assert_eq!(
            state.challenge_inputs.seed_blockhash,
            parse_digest(
                "0x339c5b791ca228c88bd748e2d60bed465b5c164b0a765d54dc3a7494c0b197ae",
                "recorded seed blockhash",
            )
            .expect("recorded seed blockhash must parse")
        );
        assert_eq!(
            state.target,
            Target::from_be_bytes([
                0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ])
        );
        assert_eq!(state.accepted_proofs, 0);
        assert_eq!(state.total_minted_wei, 0);
        assert_eq!(state.challenge, derive_challenge(&state.challenge_inputs));
        assert_eq!(
            state.challenge,
            parse_digest(
                "0x328b728dc6235ad1558ca33742c7312be2fda16bb98e717eb0727fee9b648cf8",
                "recorded challenge",
            )
            .expect("recorded challenge must parse")
        );
    }

    #[test]
    fn arbitrum_parent_blockhash_uses_evm_helper_not_l2_block_namespace() {
        let l2_exchange = fixture_exchanges()
            .into_iter()
            .find(|exchange| exchange.request["method"] == "eth_getBlockByNumber")
            .expect("fixture must contain the conflicting L2 block read");
        let mut responses = vec![json_response(l2_exchange)];
        responses.extend(recorded_exchanges().into_iter().map(json_response));
        let (endpoint, server) = spawn_mock_server(responses);
        let reader = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID);

        let l2_block = reader
            .rpc_result(
                "test-only conflicting L2 block",
                "eth_getBlockByNumber",
                json!(["0x3eb", false]),
            )
            .expect("mock L2 block must read");
        let l2_hash = parse_digest(
            l2_block["hash"].as_str().expect("mock L2 hash is text"),
            "mock L2 block hash",
        )
        .expect("mock L2 hash must parse");
        let state = reader
            .read_state()
            .expect("EVM helper blockhash must reproduce the contract challenge");
        server.join().expect("mock server must finish");

        assert_ne!(l2_hash, state.challenge_inputs.seed_blockhash);
        assert_eq!(
            state.challenge_inputs.seed_blockhash,
            parse_digest(
                "0x339c5b791ca228c88bd748e2d60bed465b5c164b0a765d54dc3a7494c0b197ae",
                "EVM helper blockhash",
            )
            .expect("EVM helper blockhash must parse")
        );
    }

    #[test]
    fn zero_evm_blockhash_reports_the_challenge_unavailable() {
        let mut exchanges = recorded_exchanges();
        let blockhash_index = exchanges
            .iter()
            .position(|exchange| is_context_helper(exchange, PARENT_BLOCKHASH_HELPER_CODE))
            .expect("fixture must call the EVM blockhash helper");
        exchanges[blockhash_index].response["result"] =
            Value::String(hex_string(&Uint256::ZERO.to_be_bytes()));
        exchanges.truncate(blockhash_index + 1);
        let (endpoint, server) =
            spawn_mock_server(exchanges.into_iter().map(json_response).collect::<Vec<_>>());

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("zero EVM blockhash must not derive a challenge");
        server.join().expect("mock server must finish");

        assert!(error.contains("challenge unavailable"), "error: {error}");
        assert!(error.contains("no EVM blockhash"), "error: {error}");
        assert!(!error.contains("mismatch"), "error: {error}");
        assert_no_secret_labels(&error);
    }

    #[test]
    fn seed_availability_uses_evm_parent_number_not_l2_snapshot_height() {
        let mut exchanges = recorded_exchanges();
        let number_index = exchanges
            .iter()
            .position(|exchange| is_context_helper(exchange, PARENT_BLOCK_NUMBER_HELPER_CODE))
            .expect("fixture must call the EVM parent-number helper");
        exchanges[number_index].response["result"] =
            Value::String(hex_string(&Uint256::from(1_003_u64).to_be_bytes()));
        exchanges.truncate(number_index + 1);
        let (endpoint, server) =
            spawn_mock_server(exchanges.into_iter().map(json_response).collect::<Vec<_>>());

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("a seed at the current EVM parent block must be unavailable");
        server.join().expect("mock server must finish");

        assert!(error.contains("challenge unavailable"), "error: {error}");
        assert!(error.contains("has not passed"), "error: {error}");
        assert!(error.contains("EVM parent block 1003"), "error: {error}");
        assert_no_secret_labels(&error);
    }

    #[test]
    fn genuinely_wrong_challenge_still_fires_the_mismatch_guard() {
        let mut exchanges = recorded_exchanges();
        let challenge = exchanges
            .iter_mut()
            .find(|exchange| {
                exchange.request["params"][0]["data"] == function_selector("currentChallenge()")
            })
            .expect("fixture must read currentChallenge()");
        challenge.response["result"] = Value::String(hex_string(&[0xbb; 32]));
        let (endpoint, server) =
            spawn_mock_server(exchanges.into_iter().map(json_response).collect::<Vec<_>>());

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("wrong contract challenge must refuse");
        server.join().expect("mock server must finish");

        assert!(
            error.contains("MiningCore.currentChallenge() mismatch"),
            "error: {error}"
        );
        assert!(error.contains(&hex_string(&[0xbb; 32])), "error: {error}");
        assert!(error.contains("locally derived"), "error: {error}");
        assert_no_secret_labels(&error);
    }

    #[test]
    fn mining_power_reads_share_snapshot_and_classify_bonus_proofs_as_nfts() {
        let miner = Address::from_bytes([0x11; 20]);
        let module_word = Uint256::from(0x1234_u64);
        let mut responses = recorded_exchanges()
            .into_iter()
            .map(json_response)
            .collect::<Vec<_>>();
        responses.push(word_response("miningPower()", "0x3ec", module_word));
        responses.push(power_response(miner, json!({"result": hex_string(&Uint256::from(2_000_000_000_000_000_000_u64).to_be_bytes())})));
        responses.push(word_response(
            "MAX_TARGET()",
            "0x3ec",
            Uint256::from_be_bytes([255; 32]),
        ));
        responses.push(word_response(
            "MAX_NFTS_EVER()",
            "0x3ec",
            Uint256::from(5000_u64),
        ));
        responses.push(word_response("nftsMintedEver()", "0x3ec", Uint256::ZERO));
        let (endpoint, server) = spawn_mock_server(responses);
        let snapshot = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_classified_state(Some(miner))
            .unwrap();
        server.join().unwrap();
        assert!(snapshot.effective_target.to_be_bytes() > snapshot.state.target.to_be_bytes());
        assert_eq!(
            snapshot.power_multiplier_wad,
            Uint256::from(2_000_000_000_000_000_000_u64)
        );
        let mut bonus_digest = snapshot.state.target.to_be_bytes();
        bonus_digest[0] = 0x80;
        assert_eq!(
            crate::classification::classify_proof(
                Digest::from_bytes(bonus_digest),
                &snapshot.nft_classification
            ),
            crate::classification::ProofClassification::ProofHunter
        );
    }

    #[test]
    fn power_rpc_failure_or_malformed_word_never_falls_back_silently() {
        for response in [
            json!({"error":{"code":-32000,"message":"module unavailable"}}),
            json!({"result":"0x12"}),
        ] {
            let miner = Address::from_bytes([0x11; 20]);
            let mut responses = recorded_exchanges()
                .into_iter()
                .map(json_response)
                .collect::<Vec<_>>();
            responses.push(word_response(
                "miningPower()",
                "0x3ec",
                Uint256::from(0x1234_u64),
            ));
            responses.push(power_response(miner, response));
            let (endpoint, server) = spawn_mock_server(responses);
            assert!(
                RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
                    .read_classified_state(Some(miner))
                    .is_err()
            );
            server.join().unwrap();
        }
    }

    fn power_response(miner: Address, mut response: Value) -> MockResponse {
        let mut data = function_selector("powerMultiplierWad(uint256,address)");
        data.push_str(&hex_string(&Uint256::ONE.to_be_bytes())[2..]);
        data.push_str(&"0".repeat(24));
        data.push_str(&hex_string(&miner.to_bytes())[2..]);
        response["jsonrpc"] = json!("2.0");
        response["id"] = json!(1);
        MockResponse {
            expected_request: json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":"0x0000000000000000000000000000000000001234","from":hex_string(&MINING_CORE.to_bytes()),"data":data},"0x3ec"]}),
            status: 200,
            body: response.to_string(),
        }
    }

    #[test]
    fn classification_values_share_the_accepted_target_block_tag() {
        let mut responses = recorded_exchanges()
            .into_iter()
            .map(json_response)
            .collect::<Vec<_>>();
        responses.extend([
            word_response("MAX_NFTS_EVER()", "0x3ec", Uint256::from(5_000_u64)),
            word_response("nftsMintedEver()", "0x3ec", Uint256::from(4_999_u64)),
        ]);
        let (endpoint, server) = spawn_mock_server(responses);

        let snapshot = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_classified_state(None)
            .expect("base mining state must decode");
        server.join().expect("mock server must finish");

        let nft = snapshot
            .nft_classification
            .expect("classification values must decode");
        assert_eq!(nft.accepted_target, snapshot.state.target);
        assert_eq!(nft.nft_odds_denominator, Uint256::ONE);
        assert_eq!(nft.max_nfts_ever, Uint256::from(5_000_u64));
        assert_eq!(nft.nfts_minted_ever, Uint256::from(4_999_u64));
    }

    #[test]
    fn failed_classification_read_preserves_state_and_reports_unknown() {
        let mut responses = recorded_exchanges()
            .into_iter()
            .map(json_response)
            .collect::<Vec<_>>();
        responses.push(MockResponse {
            expected_request: call_request("MAX_NFTS_EVER()", "0x3ec"),
            status: 200,
            body: serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32000, "message": "getter unavailable"}
            }))
            .expect("error response is JSON"),
        });
        let (endpoint, server) = spawn_mock_server(responses);

        let snapshot = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_classified_state(None)
            .expect("classification failure must not discard usable mining state");
        server.join().expect("mock server must finish");

        let error = snapshot
            .nft_classification
            .expect_err("failed getter must make classification unknown");
        assert!(
            error.contains("proof classification unknown"),
            "error: {error}"
        );
        assert!(error.contains("MAX_NFTS_EVER()"), "error: {error}");
        assert!(error.contains("getter unavailable"), "error: {error}");
    }

    #[test]
    fn wrong_chain_id_fails_closed() {
        let mut exchange = recorded_exchanges().remove(0);
        exchange.response["result"] = Value::String("0x1".to_owned());
        let (endpoint, server) = spawn_mock_server(vec![json_response(exchange)]);

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("wrong chain must refuse");
        server.join().expect("mock server must finish");
        assert!(error.contains("wrong chain id"), "error: {error}");
        assert!(error.contains("31337"), "error: {error}");
        assert!(error.contains('1'), "error: {error}");
    }

    #[test]
    fn address_without_code_fails_closed() {
        let mut exchanges = recorded_exchanges();
        exchanges.truncate(3);
        exchanges[2].response["result"] = Value::String("0x".to_owned());
        let responses = exchanges.into_iter().map(json_response).collect();
        let (endpoint, server) = spawn_mock_server(responses);

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("address without code must refuse");
        server.join().expect("mock server must finish");
        assert!(error.contains("has no code"), "error: {error}");
    }

    #[test]
    fn json_rpc_error_object_is_clear_and_does_not_panic() {
        let exchange = RecordedExchange {
            request: recorded_exchanges().remove(0).request,
            response: json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32000, "message": "upstream unavailable"}
            }),
        };
        let (endpoint, server) = spawn_mock_server(vec![json_response(exchange)]);

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("JSON-RPC error must refuse");
        server.join().expect("mock server must finish");
        assert!(error.contains("chain identity"), "error: {error}");
        assert!(error.contains("-32000"), "error: {error}");
        assert!(error.contains("upstream unavailable"), "error: {error}");
    }

    #[test]
    fn http_500_is_clear_and_does_not_panic() {
        let expected_request = recorded_exchanges().remove(0).request;
        let (endpoint, server) = spawn_mock_server(vec![MockResponse {
            expected_request,
            status: 500,
            body: "server failure".to_owned(),
        }]);

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("HTTP 500 must refuse");
        server.join().expect("mock server must finish");
        assert!(error.contains("chain identity"), "error: {error}");
        assert!(error.contains("HTTP 500"), "error: {error}");
    }

    #[test]
    fn non_json_body_is_clear_and_does_not_panic() {
        let expected_request = recorded_exchanges().remove(0).request;
        let (endpoint, server) = spawn_mock_server(vec![MockResponse {
            expected_request,
            status: 200,
            body: "not JSON".to_owned(),
        }]);

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("non-JSON body must refuse");
        server.join().expect("mock server must finish");
        assert!(error.contains("chain identity"), "error: {error}");
        assert!(error.contains("non-JSON body"), "error: {error}");
    }

    #[test]
    fn oversized_declared_rpc_body_is_rejected_before_reading_it() {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            RPC_RESPONSE_LIMIT_BYTES + 1
        );
        let (endpoint, server) = spawn_raw_rpc_server(response.into_bytes());

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .rpc_result("oversized declared response", "eth_chainId", json!([]))
            .expect_err("oversized declared response must refuse");
        server.join().expect("mock server must finish");
        assert!(error.contains("exceeds"), "error: {error}");
        assert!(error.contains("byte limit"), "error: {error}");
    }

    #[test]
    fn oversized_chunked_rpc_body_is_rejected_while_streaming() {
        let body = vec![b'a'; usize::try_from(RPC_RESPONSE_LIMIT_BYTES).unwrap() + 1];
        let mut response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            body.len()
        )
        .into_bytes();
        response.extend_from_slice(&body);
        response.extend_from_slice(b"\r\n0\r\n\r\n");
        let (endpoint, server) = spawn_raw_rpc_server(response);

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .rpc_result("oversized chunked response", "eth_chainId", json!([]))
            .expect_err("oversized chunked response must refuse");
        server.join().expect("mock server must finish");
        assert!(error.contains("byte limit"), "error: {error}");
    }

    #[test]
    fn truncated_call_result_is_clear_and_does_not_panic() {
        let mut exchanges = recorded_exchanges();
        exchanges.truncate(4);
        exchanges[3].response["result"] = Value::String("0x1234".to_owned());
        let responses = exchanges.into_iter().map(json_response).collect();
        let (endpoint, server) = spawn_mock_server(responses);

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("truncated ABI word must refuse");
        server.join().expect("mock server must finish");
        assert!(error.contains("activeChallengeId()"), "error: {error}");
        assert!(error.contains("exactly 32 bytes"), "error: {error}");
    }

    #[test]
    fn unreachable_endpoint_is_clear_and_does_not_panic() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port must bind");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("listener has an address")
        );
        drop(listener);

        let error = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID)
            .read_state()
            .expect_err("unreachable endpoint must refuse");
        assert!(error.contains("failed to reach JSON-RPC endpoint"));
        assert!(error.contains("chain identity"));
    }

    #[test]
    fn live_anvil_deployment_matches_the_contract_state() {
        let contracts_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../contracts");
        if !contracts_dir.exists() {
            report_live_skip("the monorepo contracts tree is unavailable in this checkout");
            return;
        }
        match Command::new("anvil").arg("--version").output() {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                report_live_skip(&format!("`anvil` is unavailable: {error}"));
                return;
            }
            Err(error) => panic!("failed to check anvil availability: {error}"),
            Ok(output) if !output.status.success() => {
                report_live_skip(&format!(
                    "`anvil --version` failed: {}",
                    String::from_utf8_lossy(&output.stderr)
                ));
                return;
            }
            Ok(_) => {}
        }

        let port = unused_local_port();
        let endpoint = format!("http://127.0.0.1:{port}");
        let broadcast_dir = std::env::temp_dir().join(format!(
            "bproof-live-anvil-broadcast-{}-{port}",
            std::process::id()
        ));
        fs::create_dir_all(&broadcast_dir).expect("temporary broadcast directory must exist");
        let child = Command::new("anvil")
            .args([
                "--host",
                "127.0.0.1",
                "--port",
                &port.to_string(),
                "--chain-id",
                "31337",
                "--timestamp",
                "1800000000",
                "--block-base-fee-per-gas",
                "0",
                "--silent",
            ])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("available anvil must start");
        let mut anvil = AnvilGuard {
            child,
            broadcast_dir,
        };
        wait_for_anvil(&endpoint, &mut anvil.child);
        let mining_core = parse_address(cli_fixture::MINING_CORE, "live MiningCore")
            .expect("deterministic first Anvil deployment address must parse");
        let expected_chain_id = Uint256::from(31_337_u64);
        let reader = RpcChainReader::new(&endpoint, mining_core, expected_chain_id);
        reader
            .rpc_result(
                "Anvil basket fixture code",
                "anvil_setCode",
                json!(["0x00000000000000000000000000000000000ba5e7", "0x00"]),
            )
            .expect("local Anvil basket fixture must have code");

        cli_fixture::deploy(&endpoint, &anvil.broadcast_dir);

        // The RC2 composition uses a 64-block auto-seed margin. Mine beyond
        // that margin instead of relying on the older 40-block fixture value.
        reader
            .rpc_result("Anvil seed activation", "anvil_mine", json!(["0x80"]))
            .expect("local Anvil must mine through the genesis seed block");

        let state = reader
            .read_state()
            .expect("live deployed MiningCore state must read");
        assert_eq!(state.challenge_inputs.chain_id, expected_chain_id);
        assert_eq!(state.challenge_inputs.mining_core, mining_core);
        assert_eq!(state.challenge_inputs.challenge_id, Uint256::ONE);
        assert_eq!(
            state.challenge_inputs.previous_accepted_digest,
            Digest::ZERO
        );
        assert!(state.challenge_inputs.seed_parent_block > Uint256::ZERO);
        assert_ne!(state.challenge_inputs.seed_blockhash, Digest::ZERO);
        assert_eq!(
            state.target,
            Target::from_be_bytes([
                0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                0xff, 0xff, 0xff, 0xff,
            ])
        );
        assert_eq!(state.accepted_proofs, 0);
        assert_eq!(state.total_minted_wei, 0);
        assert_eq!(state.challenge, derive_challenge(&state.challenge_inputs));
        println!("live Anvil integration ran against {endpoint}");
    }

    fn fixture_exchanges() -> Vec<RecordedExchange> {
        serde_json::from_str::<RecordedFixture>(FIXTURE)
            .expect("recorded RPC fixture must be valid")
            .exchanges
    }

    fn recorded_exchanges() -> Vec<RecordedExchange> {
        fixture_exchanges()
            .into_iter()
            .filter(|exchange| exchange.request["method"] != "eth_getBlockByNumber")
            .collect()
    }

    fn is_context_helper(exchange: &RecordedExchange, helper_code: &str) -> bool {
        exchange.request["params"][2][EVM_CONTEXT_HELPER_ADDRESS]["code"] == helper_code
    }

    fn assert_no_secret_labels(output: &str) {
        for forbidden in ["privateKey", "passphrase", "mnemonic", "backupPhrase"] {
            assert!(!output.contains(forbidden), "output contained {forbidden}");
        }
    }

    fn json_response(exchange: RecordedExchange) -> MockResponse {
        MockResponse {
            expected_request: exchange.request,
            status: 200,
            body: serde_json::to_string(&exchange.response).expect("fixture response is JSON"),
        }
    }

    fn call_request(signature: &str, block_tag: &str) -> Value {
        json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "eth_call",
            "params": [{
                "to": hex_string(&MINING_CORE.to_bytes()),
                "data": function_selector(signature),
            }, block_tag],
        })
    }

    fn word_response(signature: &str, block_tag: &str, value: Uint256) -> MockResponse {
        MockResponse {
            expected_request: call_request(signature, block_tag),
            status: 200,
            body: serde_json::to_string(&json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": hex_string(&value.to_be_bytes()),
            }))
            .expect("word response is JSON"),
        }
    }

    fn spawn_mock_server(responses: Vec<MockResponse>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server must bind");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("listener has an address")
        );
        let server = thread::spawn(move || {
            for response in responses {
                let (mut stream, _) = listener.accept().expect("mock request must connect");
                let body = read_request_body(&mut stream);
                let request: Value =
                    serde_json::from_slice(&body).expect("mock request body must be JSON");
                assert_eq!(request, response.expected_request);
                write_response(&mut stream, response.status, &response.body);
            }
        });
        (endpoint, server)
    }

    /// Serves one scripted reply per connection and hands back every request it
    /// saw, so a test can assert how many round trips a client actually needed.
    fn spawn_scripted_rpc_server(responses: Vec<Value>) -> (String, JoinHandle<Vec<Value>>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server must bind");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("listener has an address")
        );
        let server = thread::spawn(move || {
            let mut seen = Vec::new();
            for response in responses {
                let (mut stream, _) = listener.accept().expect("mock request must connect");
                let body = read_request_body(&mut stream);
                seen.push(serde_json::from_slice(&body).expect("mock request body must be JSON"));
                write_response(&mut stream, 200, &response.to_string());
            }
            seen
        });
        (endpoint, server)
    }

    fn batch_result(id: u64, result: &str) -> Value {
        json!({ "jsonrpc": "2.0", "id": id, "result": result })
    }

    fn sample_batch_calls() -> Vec<BatchCall<'static>> {
        vec![
            BatchCall::new("proof simulation", "eth_call", json!(["0x01", "latest"])),
            BatchCall::new("proof gas estimate", "eth_estimateGas", json!(["0x02"])),
            BatchCall::new(
                "miner account transaction count",
                "eth_getTransactionCount",
                json!(["0x03", "pending"]),
            ),
        ]
    }

    #[test]
    fn a_batch_of_reads_travels_in_one_round_trip() {
        let calls = sample_batch_calls();
        // Answered out of order to prove each result is matched by id, not position.
        let (endpoint, server) = spawn_scripted_rpc_server(vec![json!([
            batch_result(3, "0x2a"),
            batch_result(1, "0x01"),
            batch_result(2, "0x5208"),
        ])]);
        let reader = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID);

        let results = reader.rpc_batch(&calls);

        let seen = server.join().expect("mock server must finish");
        assert_eq!(seen.len(), 1, "a batch must cost exactly one round trip");
        let sent = seen[0].as_array().expect("the client must send an array");
        assert_eq!(sent.len(), 3);
        assert_eq!(
            sent.iter()
                .map(|entry| entry["id"].as_u64())
                .collect::<Vec<_>>(),
            vec![Some(1), Some(2), Some(3)]
        );
        assert_eq!(
            sent.iter()
                .map(|entry| entry["method"].as_str().unwrap_or_default().to_owned())
                .collect::<Vec<_>>(),
            vec!["eth_call", "eth_estimateGas", "eth_getTransactionCount"]
        );
        assert_eq!(
            results.iter().map(batch_string_result).collect::<Vec<_>>(),
            vec![
                Ok("0x01".to_owned()),
                Ok("0x5208".to_owned()),
                Ok("0x2a".to_owned())
            ]
        );
    }

    fn batch_string_result(result: &Result<Value, String>) -> Result<String, String> {
        batch_string(result, "read")
    }

    #[test]
    fn a_per_call_error_is_reported_without_reissuing_the_batch() {
        let calls = sample_batch_calls();
        let (endpoint, server) = spawn_scripted_rpc_server(vec![json!([
            json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": { "code": 3, "message": "execution reverted: StaleChallengeId(1, 2)" }
            }),
            batch_result(2, "0x5208"),
            batch_result(3, "0x2a"),
        ])]);
        let reader = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID);

        let results = reader.rpc_batch(&calls);

        let seen = server.join().expect("mock server must finish");
        assert_eq!(
            seen.len(),
            1,
            "a per-call error is an answer, not a failure"
        );
        let error = results[0]
            .as_ref()
            .expect_err("the simulation must report its error");
        assert!(
            error.contains("StaleChallengeId"),
            "a reverted simulation must survive batching: {error}"
        );
        assert_eq!(batch_string_result(&results[1]), Ok("0x5208".to_owned()));
        assert_eq!(batch_string_result(&results[2]), Ok("0x2a".to_owned()));
    }

    #[test]
    fn a_node_that_answers_with_one_object_forces_a_sequential_reread() {
        let calls = sample_batch_calls();
        let (endpoint, server) = spawn_scripted_rpc_server(vec![
            // A node that ignores batching replies to the array with one object.
            batch_result(1, "0x01"),
            batch_result(1, "0x01"),
            batch_result(1, "0x5208"),
            batch_result(1, "0x2a"),
        ]);
        let reader = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID);

        let results = reader.rpc_batch(&calls);

        let seen = server.join().expect("mock server must finish");
        assert_eq!(
            seen.len(),
            4,
            "an unusable batch must be reissued one by one"
        );
        // The first request is the batch that was refused; the rest are the rereads.
        for (request, expected_method) in
            seen[1..]
                .iter()
                .zip(["eth_call", "eth_estimateGas", "eth_getTransactionCount"])
        {
            assert_eq!(request["method"], expected_method);
        }
        assert_eq!(
            results.iter().map(batch_string_result).collect::<Vec<_>>(),
            vec![
                Ok("0x01".to_owned()),
                Ok("0x5208".to_owned()),
                Ok("0x2a".to_owned())
            ]
        );
    }

    #[test]
    fn a_repeated_id_in_a_batch_reply_forces_a_sequential_reread() {
        let calls = sample_batch_calls();
        let (endpoint, server) = spawn_scripted_rpc_server(vec![
            // A repeated id leaves one call answered twice and another unanswered.
            json!([
                batch_result(1, "0x01"),
                batch_result(1, "0x5208"),
                batch_result(3, "0x2a")
            ]),
            batch_result(1, "0x01"),
            batch_result(1, "0x5208"),
            batch_result(1, "0x2a"),
        ]);
        let reader = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID);

        let results = reader.rpc_batch(&calls);

        let seen = server.join().expect("mock server must finish");
        assert_eq!(seen.len(), 4, "a mismatched id must be reissued one by one");
        assert_eq!(batch_string_result(&results[0]), Ok("0x01".to_owned()));
        assert_eq!(batch_string_result(&results[2]), Ok("0x2a".to_owned()));
    }

    #[test]
    fn a_short_batch_reply_forces_a_sequential_reread() {
        let calls = sample_batch_calls();
        let (endpoint, server) = spawn_scripted_rpc_server(vec![
            json!([batch_result(1, "0x01"), batch_result(2, "0x5208")]),
            batch_result(1, "0x01"),
            batch_result(1, "0x5208"),
            batch_result(1, "0x2a"),
        ]);
        let reader = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID);

        let results = reader.rpc_batch(&calls);

        let seen = server.join().expect("mock server must finish");
        assert_eq!(
            seen.len(),
            4,
            "a missing answer must be reissued one by one"
        );
        assert_eq!(batch_string_result(&results[2]), Ok("0x2a".to_owned()));
    }

    #[test]
    fn a_single_read_is_never_wrapped_in_a_batch() {
        let calls = vec![BatchCall::new(
            "proof simulation",
            "eth_call",
            json!(["0x01", "latest"]),
        )];
        let (endpoint, server) = spawn_scripted_rpc_server(vec![batch_result(1, "0x01")]);
        let reader = RpcChainReader::new(endpoint, MINING_CORE, EXPECTED_CHAIN_ID);

        let results = reader.rpc_batch(&calls);

        let seen = server.join().expect("mock server must finish");
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0]["method"], "eth_call", "one read needs no array");
        assert_eq!(batch_string_result(&results[0]), Ok("0x01".to_owned()));
    }

    fn spawn_raw_rpc_server(response: Vec<u8>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("mock server must bind");
        let endpoint = format!(
            "http://{}",
            listener.local_addr().expect("listener has an address")
        );
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("mock request must connect");
            let _ = read_request_body(&mut stream);
            let _ = stream.write_all(&response);
        });
        (endpoint, server)
    }

    fn read_request_body(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4_096];
        let (header_end, content_length) = loop {
            let read = stream.read(&mut buffer).expect("mock request must read");
            assert_ne!(read, 0, "request ended before headers");
            request.extend_from_slice(&buffer[..read]);
            if let Some(header_end) = find_bytes(&request, b"\r\n\r\n") {
                let headers = std::str::from_utf8(&request[..header_end])
                    .expect("request headers must be UTF-8");
                let content_length = headers
                    .lines()
                    .find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().expect("valid content length"))
                    })
                    .expect("request must have content length");
                break (header_end + 4, content_length);
            }
        };
        while request.len() < header_end + content_length {
            let read = stream
                .read(&mut buffer)
                .expect("mock request body must read");
            assert_ne!(read, 0, "request ended before body");
            request.extend_from_slice(&buffer[..read]);
        }
        request[header_end..header_end + content_length].to_vec()
    }

    fn write_response(stream: &mut TcpStream, status: u16, body: &str) {
        let reason = if status == 200 {
            "OK"
        } else {
            "Internal Server Error"
        };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream
            .write_all(response.as_bytes())
            .expect("mock response must write");
    }

    fn find_bytes(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack
            .windows(needle.len())
            .position(|window| window == needle)
    }

    fn unused_local_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral port must bind");
        listener
            .local_addr()
            .expect("listener has an address")
            .port()
    }

    fn wait_for_anvil(endpoint: &str, child: &mut Child) {
        let address = endpoint
            .strip_prefix("http://")
            .expect("local endpoint is HTTP");
        for _ in 0..50 {
            if let Some(status) = child.try_wait().expect("anvil status must read") {
                panic!("anvil exited before becoming ready: {status}");
            }
            if TcpStream::connect(address).is_ok() {
                return;
            }
            thread::sleep(Duration::from_millis(100));
        }
        panic!("anvil did not become ready at {endpoint}");
    }

    fn report_live_skip(reason: &str) {
        // Write directly so libtest's successful-test capture cannot hide the skip reason.
        let mut stderr = std::io::stderr().lock();
        let _ = writeln!(stderr, "SKIP live Anvil integration: {reason}");
    }

    struct AnvilGuard {
        child: Child,
        broadcast_dir: PathBuf,
    }

    impl Drop for AnvilGuard {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = fs::remove_dir_all(&self.broadcast_dir);
        }
    }
}
