//! Live JSON-RPC preparation and single-shot submission of one proof.

use std::thread;
use std::time::{Duration, Instant};

use bproof::keystore::UnlockedWallet;
use bproof::transaction::{Eip1559Transaction, sign_eip1559_transaction, submit_proof_call_data};
use proof_core::{
    Address, Digest, ProofInputs, Uint256, derive_challenge, keccak256, proof_digest,
};
use serde_json::{Value, json};

use crate::chain::RpcChainReader;
use crate::parse::{
    hex_string, parse_address, parse_digest, parse_hex_quantity_uint256, parse_uint256_word,
};

pub const FEE_REFUSAL_EXIT_CODE: u8 = 3;
pub const SUBMISSION_WARNING: &str = "Another miner may consume this challenge before inclusion, and this transaction may fail. Receipt success is accepted only after transaction and event consistency checks; the configured RPC can still withhold or delay data and remains a trust source.";
pub const PROOF_HUNTER_FEE_WARNING: &str = "An accepted Proof Hunter win pays zero liquid HUNTER because the whole reward locks inside the Hunter. It costs materially more than an ordinary proof; --max-fee must cover that larger transaction or the miner will refuse and forfeit the whole reward.";

const DEFAULT_GAS_MARGIN_PERCENT: u64 = 25;
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(60);
const RECEIPT_POLL_INTERVAL: Duration = Duration::from_millis(250);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeOptions {
    pub fee_ceiling_wei: u128,
    pub base_fee_per_gas_override_wei: Option<u128>,
    pub priority_fee_per_gas_override_wei: Option<u128>,
    pub gas_margin_percent: u64,
}

impl FeeOptions {
    #[must_use]
    pub const fn default_gas_margin_percent() -> u64 {
        DEFAULT_GAS_MARGIN_PERCENT
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeQuote {
    pub base_fee_per_gas_wei: u128,
    pub priority_fee_per_gas_wei: u128,
    pub max_fee_per_gas_wei: u128,
    pub estimated_gas: u64,
    pub gas_margin_percent: u64,
    pub gas_limit: u64,
    pub maximum_exposure_wei: u128,
    pub fee_ceiling_wei: u128,
}

pub struct PreparedSubmission {
    pub mining_nonce: Uint256,
    pub account_nonce: Uint256,
    pub fee_quote: FeeQuote,
    miner: Address,
    challenge_id: Uint256,
    seed_parent_block: Uint256,
    challenge: Digest,
    expected_digest: Digest,
    transaction: Eip1559Transaction,
}

impl std::fmt::Debug for PreparedSubmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PreparedSubmission")
            .field("mining_nonce", &self.mining_nonce)
            .field("account_nonce", &self.account_nonce)
            .field("fee_quote", &self.fee_quote)
            .field("miner", &self.miner)
            .field("challenge_id", &self.challenge_id)
            .field("seed_parent_block", &self.seed_parent_block)
            .field("challenge", &self.challenge)
            .field("expected_digest", &self.expected_digest)
            .field("transaction", &self.transaction)
            .finish()
    }
}

#[derive(Debug)]
pub enum PreparationOutcome {
    Ready(Box<PreparedSubmission>),
    SimulationRejected { reason: String },
    FeeRefused(FeeQuote),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MinedSubmission {
    pub transaction_hash: Digest,
    pub mining_nonce: Uint256,
    pub account_nonce: Uint256,
    pub fee_quote: FeeQuote,
    pub fee_paid_wei: u128,
    pub succeeded: bool,
    pub proof_nft_minted: bool,
}

pub fn prepare_submission(
    reader: &RpcChainReader,
    challenge_inputs: proof_core::ChallengeInputs,
    miner: Address,
    mining_nonce: Uint256,
    fee_options: FeeOptions,
) -> Result<PreparationOutcome, String> {
    let challenge = derive_challenge(&challenge_inputs);
    let expected_digest = proof_digest(&ProofInputs {
        chain_id: challenge_inputs.chain_id,
        mining_core: challenge_inputs.mining_core,
        challenge_id: challenge_inputs.challenge_id,
        challenge,
        miner,
        nonce: mining_nonce,
    });
    let call_data = submit_proof_call_data(
        challenge_inputs.challenge_id,
        challenge_inputs.seed_parent_block,
        mining_nonce,
    );
    let call = transaction_call(miner, challenge_inputs.mining_core, &call_data);

    if let Err(error) = reader.rpc_result(
        "proof simulation",
        "eth_call",
        json!([call.clone(), "latest"]),
    ) {
        if error.contains("JSON-RPC proof simulation failed with error") {
            return Ok(PreparationOutcome::SimulationRejected {
                reason: disambiguate_mining_nonce(&error),
            });
        }
        return Err(error);
    }

    let estimated_gas_text =
        reader.string_result("proof gas estimate", "eth_estimateGas", json!([call]))?;
    let estimated_gas = uint256_to_u64(
        parse_hex_quantity_uint256(&estimated_gas_text, "eth_estimateGas result")?,
        "eth_estimateGas result",
    )?;
    let base_fee_per_gas_wei = match fee_options.base_fee_per_gas_override_wei {
        Some(value) => value,
        None => read_base_fee_per_gas(reader)?,
    };
    let priority_fee_per_gas_wei = match fee_options.priority_fee_per_gas_override_wei {
        Some(value) => value,
        None => read_priority_fee_per_gas(reader)?,
    };
    let fee_quote = fee_quote(
        base_fee_per_gas_wei,
        priority_fee_per_gas_wei,
        estimated_gas,
        fee_options.gas_margin_percent,
        fee_options.fee_ceiling_wei,
    )?;
    if fee_quote.maximum_exposure_wei > fee_quote.fee_ceiling_wei {
        return Ok(PreparationOutcome::FeeRefused(fee_quote));
    }

    let account_nonce_text = reader.string_result(
        "miner account transaction count",
        "eth_getTransactionCount",
        json!([hex_string(&miner.to_bytes()), "pending"]),
    )?;
    let account_nonce = parse_hex_quantity_uint256(
        &account_nonce_text,
        "eth_getTransactionCount result for account nonce",
    )?;
    let transaction = Eip1559Transaction {
        chain_id: challenge_inputs.chain_id,
        account_nonce,
        max_priority_fee_per_gas: Uint256::from(priority_fee_per_gas_wei),
        max_fee_per_gas: Uint256::from(fee_quote.max_fee_per_gas_wei),
        gas_limit: Uint256::from(fee_quote.gas_limit),
        to: challenge_inputs.mining_core,
        data: call_data,
    };

    Ok(PreparationOutcome::Ready(Box::new(PreparedSubmission {
        mining_nonce,
        account_nonce,
        fee_quote,
        miner,
        challenge_id: challenge_inputs.challenge_id,
        seed_parent_block: challenge_inputs.seed_parent_block,
        challenge,
        expected_digest,
        transaction,
    })))
}

pub fn send_prepared_submission(
    reader: &RpcChainReader,
    wallet: &UnlockedWallet,
    prepared: PreparedSubmission,
) -> Result<MinedSubmission, String> {
    if parse_address(wallet.address(), "unlocked wallet address")? != prepared.miner {
        return Err("unlocked wallet does not match the prepared proof miner".to_owned());
    }
    let signed = sign_eip1559_transaction(wallet, &prepared.transaction)?;
    let expected_transaction_hash = signed.transaction_hash();
    let raw_transaction = hex_string(signed.raw_bytes());
    let sent_hash_text = reader
        .string_result(
            "signed proof submission",
            "eth_sendRawTransaction",
            json!([raw_transaction]),
        )
        .map_err(|error| disambiguate_account_nonce(&error))?;
    let sent_hash = parse_digest(&sent_hash_text, "eth_sendRawTransaction transaction hash")?;
    if sent_hash != expected_transaction_hash {
        return Err(format!(
            "eth_sendRawTransaction returned transaction hash {}, but the signed transaction hash is {}",
            hex_string(&sent_hash.to_bytes()),
            hex_string(&expected_transaction_hash.to_bytes())
        ));
    }

    let receipt = wait_for_receipt(reader, sent_hash, &prepared)?;
    verify_mined_transaction(reader, sent_hash, &receipt, &prepared)?;
    let fee_paid_wei = receipt
        .gas_used
        .checked_mul(receipt.effective_gas_price_wei)
        .ok_or_else(|| "actual transaction fee exceeds the supported u128 range".to_owned())?;
    if fee_paid_wei > prepared.fee_quote.maximum_exposure_wei {
        return Err(format!(
            "actual transaction fee {fee_paid_wei} wei exceeds the authorised maximum exposure {} wei",
            prepared.fee_quote.maximum_exposure_wei
        ));
    }
    Ok(MinedSubmission {
        transaction_hash: sent_hash,
        mining_nonce: prepared.mining_nonce,
        account_nonce: prepared.account_nonce,
        fee_quote: prepared.fee_quote,
        fee_paid_wei,
        succeeded: receipt.succeeded,
        proof_nft_minted: receipt.proof_nft_minted,
    })
}

fn transaction_call(from: Address, to: Address, data: &[u8]) -> Value {
    json!({
        "from": hex_string(&from.to_bytes()),
        "to": hex_string(&to.to_bytes()),
        "data": hex_string(data),
    })
}

fn read_base_fee_per_gas(reader: &RpcChainReader) -> Result<u128, String> {
    let block = reader.rpc_result(
        "latest block base fee",
        "eth_getBlockByNumber",
        json!(["latest", false]),
    )?;
    let base_fee = block
        .as_object()
        .and_then(|fields| fields.get("baseFeePerGas"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            "latest block has no baseFeePerGas; use --base-fee-per-gas to provide raw wei"
                .to_owned()
        })?;
    uint256_to_u128(
        parse_hex_quantity_uint256(base_fee, "latest block baseFeePerGas")?,
        "latest block baseFeePerGas",
    )
}

fn read_priority_fee_per_gas(reader: &RpcChainReader) -> Result<u128, String> {
    let priority_fee = reader
        .string_result(
            "priority fee quote",
            "eth_maxPriorityFeePerGas",
            json!([]),
        )
        .map_err(|error| {
            format!(
                "{error}; use --priority-fee-per-gas to provide the tip in raw wei when the node does not offer eth_maxPriorityFeePerGas"
            )
        })?;
    uint256_to_u128(
        parse_hex_quantity_uint256(&priority_fee, "eth_maxPriorityFeePerGas result")?,
        "eth_maxPriorityFeePerGas result",
    )
}

fn fee_quote(
    base_fee_per_gas_wei: u128,
    priority_fee_per_gas_wei: u128,
    estimated_gas: u64,
    gas_margin_percent: u64,
    fee_ceiling_wei: u128,
) -> Result<FeeQuote, String> {
    // The doubled base fee is the recorded liveness policy. The total-exposure
    // comparison below, not this multiplier, is the operator's safety boundary.
    let max_fee_per_gas_wei = base_fee_per_gas_wei
        .checked_mul(2)
        .and_then(|value| value.checked_add(priority_fee_per_gas_wei))
        .ok_or_else(|| "base fee times two plus priority fee exceeds the u128 range".to_owned())?;
    let gas_limit = padded_gas_limit(estimated_gas, gas_margin_percent)?;
    let maximum_exposure_wei = u128::from(gas_limit)
        .checked_mul(max_fee_per_gas_wei)
        .ok_or_else(|| "maximum transaction exposure exceeds the u128 range".to_owned())?;
    Ok(FeeQuote {
        base_fee_per_gas_wei,
        priority_fee_per_gas_wei,
        max_fee_per_gas_wei,
        estimated_gas,
        gas_margin_percent,
        gas_limit,
        maximum_exposure_wei,
        fee_ceiling_wei,
    })
}

fn padded_gas_limit(estimated_gas: u64, gas_margin_percent: u64) -> Result<u64, String> {
    // Round up so the recorded margin is never weakened by integer division.
    let multiplier = 100_u128
        .checked_add(u128::from(gas_margin_percent))
        .ok_or_else(|| "--gas-margin-percent is too large".to_owned())?;
    let padded = u128::from(estimated_gas)
        .checked_mul(multiplier)
        .and_then(|value| value.checked_add(99))
        .map(|value| value / 100)
        .ok_or_else(|| "padded gas limit exceeds the supported range".to_owned())?;
    u64::try_from(padded).map_err(|_| "padded gas limit exceeds the u64 range".to_owned())
}

#[derive(Debug)]
struct TransactionReceipt {
    succeeded: bool,
    gas_used: u128,
    effective_gas_price_wei: u128,
    proof_nft_minted: bool,
    block_hash: Digest,
    block_number: Uint256,
}

fn wait_for_receipt(
    reader: &RpcChainReader,
    transaction_hash: Digest,
    prepared: &PreparedSubmission,
) -> Result<TransactionReceipt, String> {
    let transaction_hash_text = hex_string(&transaction_hash.to_bytes());
    let deadline = Instant::now() + RECEIPT_TIMEOUT;
    loop {
        let value = reader.rpc_result(
            "proof transaction receipt",
            "eth_getTransactionReceipt",
            json!([&transaction_hash_text]),
        )?;
        if !value.is_null() {
            return parse_receipt(&value, transaction_hash, prepared);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "timed out waiting for proof transaction receipt {transaction_hash_text}"
            ));
        }
        thread::sleep(RECEIPT_POLL_INTERVAL);
    }
}

fn parse_receipt(
    value: &Value,
    transaction_hash: Digest,
    prepared: &PreparedSubmission,
) -> Result<TransactionReceipt, String> {
    let fields = value
        .as_object()
        .ok_or_else(|| "proof transaction receipt must be an object".to_owned())?;
    require_digest_field(fields, "transactionHash", "receipt", transaction_hash)?;
    require_address_field(fields, "from", "receipt", prepared.miner)?;
    require_address_field(fields, "to", "receipt", prepared.transaction.to)?;
    let block_hash = digest_field(fields, "blockHash", "receipt")?;
    let block_number = quantity_field(fields, "blockNumber", "receipt")?;
    let status = receipt_quantity(fields, "status")?;
    if status != Uint256::ZERO && status != Uint256::ONE {
        return Err("proof transaction receipt status must be 0x0 or 0x1".to_owned());
    }
    let gas_used = uint256_to_u128(receipt_quantity(fields, "gasUsed")?, "receipt gasUsed")?;
    let effective_gas_price_wei = uint256_to_u128(
        receipt_quantity(fields, "effectiveGasPrice")?,
        "receipt effectiveGasPrice",
    )?;
    let logs = fields
        .get("logs")
        .and_then(Value::as_array)
        .ok_or_else(|| "proof transaction receipt is missing `logs`".to_owned())?;
    let succeeded = status == Uint256::ONE;
    if succeeded {
        verify_proof_accepted_event(logs, transaction_hash, block_hash, block_number, prepared)?;
    }
    let proof_nft_minted =
        verify_proof_nft_event(logs, transaction_hash, block_hash, block_number, prepared)?;
    Ok(TransactionReceipt {
        succeeded,
        gas_used,
        effective_gas_price_wei,
        proof_nft_minted,
        block_hash,
        block_number,
    })
}

fn verify_mined_transaction(
    reader: &RpcChainReader,
    transaction_hash: Digest,
    receipt: &TransactionReceipt,
    prepared: &PreparedSubmission,
) -> Result<(), String> {
    let transaction_hash_text = hex_string(&transaction_hash.to_bytes());
    let value = reader.rpc_result(
        "mined proof transaction",
        "eth_getTransactionByHash",
        json!([transaction_hash_text]),
    )?;
    let fields = value
        .as_object()
        .ok_or_else(|| "mined proof transaction must be an object".to_owned())?;

    require_digest_field(fields, "hash", "mined transaction", transaction_hash)?;
    require_address_field(fields, "from", "mined transaction", prepared.miner)?;
    require_address_field(fields, "to", "mined transaction", prepared.transaction.to)?;
    require_digest_field(fields, "blockHash", "mined transaction", receipt.block_hash)?;
    require_quantity_field(
        fields,
        "blockNumber",
        "mined transaction",
        receipt.block_number,
    )?;
    require_quantity_field(
        fields,
        "chainId",
        "mined transaction",
        prepared.transaction.chain_id,
    )?;
    require_quantity_field(
        fields,
        "nonce",
        "mined transaction",
        prepared.transaction.account_nonce,
    )?;
    require_quantity_field(
        fields,
        "gas",
        "mined transaction",
        prepared.transaction.gas_limit,
    )?;
    require_quantity_field(
        fields,
        "maxFeePerGas",
        "mined transaction",
        prepared.transaction.max_fee_per_gas,
    )?;
    require_quantity_field(
        fields,
        "maxPriorityFeePerGas",
        "mined transaction",
        prepared.transaction.max_priority_fee_per_gas,
    )?;
    require_quantity_field(fields, "value", "mined transaction", Uint256::ZERO)?;
    require_quantity_field(fields, "type", "mined transaction", Uint256::from(2_u64))?;
    require_hex_bytes_field(
        fields,
        "input",
        "mined transaction",
        &prepared.transaction.data,
    )?;

    // These bindings reject an internally inconsistent RPC account. One endpoint
    // can still fabricate a fully self-consistent chain view or withhold/delay data;
    // stronger unattended assurance requires agreement from an independent endpoint.
    Ok(())
}

fn verify_proof_accepted_event(
    logs: &[Value],
    transaction_hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    prepared: &PreparedSubmission,
) -> Result<(), String> {
    let signature = event_signature(
        b"ProofAccepted(address,uint256,bytes32,uint256,bytes32,uint256,uint256,uint256,uint256,uint256,uint256,bool)",
    );
    let candidates = event_candidates(logs, signature)?;
    if candidates.len() != 1 {
        return Err(format!(
            "successful proof receipt must contain exactly one ProofAccepted event; found {}",
            candidates.len()
        ));
    }
    let fields = event_fields(
        candidates[0],
        "ProofAccepted",
        transaction_hash,
        block_hash,
        block_number,
        prepared.transaction.to,
    )?;
    let topics = event_topics(fields, "ProofAccepted", 4)?;
    require_topic_address(topics, 1, "ProofAccepted miner", prepared.miner)?;
    require_topic_uint256(
        topics,
        2,
        "ProofAccepted challengeId",
        prepared.challenge_id,
    )?;
    require_topic_digest(topics, 3, "ProofAccepted digest", prepared.expected_digest)?;
    let words = event_data_words(fields, "ProofAccepted", 9)?;
    require_word_uint256(
        &words,
        0,
        "ProofAccepted seedParentBlock",
        prepared.seed_parent_block,
    )?;
    require_word_digest(&words, 1, "ProofAccepted challenge", prepared.challenge)?;
    require_word_uint256(
        &words,
        2,
        "ProofAccepted mining nonce",
        prepared.mining_nonce,
    )
}

fn verify_proof_nft_event(
    logs: &[Value],
    transaction_hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    prepared: &PreparedSubmission,
) -> Result<bool, String> {
    let signature = event_signature(
        b"ProofNftMinted(address,uint256,uint256,bytes32,uint8,uint256,uint256,uint256)",
    );
    let candidates = event_candidates(logs, signature)?;
    if candidates.is_empty() {
        return Ok(false);
    }
    if candidates.len() != 1 {
        return Err(format!(
            "proof receipt must contain at most one ProofNftMinted event; found {}",
            candidates.len()
        ));
    }
    let fields = event_fields(
        candidates[0],
        "ProofNftMinted",
        transaction_hash,
        block_hash,
        block_number,
        prepared.transaction.to,
    )?;
    let topics = event_topics(fields, "ProofNftMinted", 4)?;
    require_topic_address(topics, 1, "ProofNftMinted miner", prepared.miner)?;
    require_topic_uint256(
        topics,
        3,
        "ProofNftMinted challengeId",
        prepared.challenge_id,
    )?;
    let words = event_data_words(fields, "ProofNftMinted", 5)?;
    require_word_digest(&words, 0, "ProofNftMinted digest", prepared.expected_digest)?;
    Ok(true)
}

fn event_candidates(logs: &[Value], signature: Digest) -> Result<Vec<&Value>, String> {
    let signature = hex_string(&signature.to_bytes());
    logs.iter()
        .filter_map(|log| {
            let fields = match log.as_object() {
                Some(fields) => fields,
                None => return Some(Err("proof receipt log must be an object".to_owned())),
            };
            let first_topic = fields
                .get("topics")
                .and_then(Value::as_array)
                .and_then(|topics| topics.first())
                .and_then(Value::as_str);
            match first_topic {
                Some(topic) if topic.eq_ignore_ascii_case(&signature) => Some(Ok(log)),
                _ => None,
            }
        })
        .collect()
}

fn event_fields<'a>(
    log: &'a Value,
    event: &str,
    transaction_hash: Digest,
    block_hash: Digest,
    block_number: Uint256,
    emitter: Address,
) -> Result<&'a serde_json::Map<String, Value>, String> {
    let fields = log
        .as_object()
        .ok_or_else(|| format!("{event} log must be an object"))?;
    require_address_field(fields, "address", event, emitter)?;
    require_digest_field(fields, "transactionHash", event, transaction_hash)?;
    require_digest_field(fields, "blockHash", event, block_hash)?;
    require_quantity_field(fields, "blockNumber", event, block_number)?;
    match fields.get("removed").and_then(Value::as_bool) {
        Some(false) => {}
        _ => return Err(format!("{event} log must have `removed` set to false")),
    }
    Ok(fields)
}

fn event_topics<'a>(
    fields: &'a serde_json::Map<String, Value>,
    event: &str,
    expected_len: usize,
) -> Result<&'a [Value], String> {
    let topics = fields
        .get("topics")
        .and_then(Value::as_array)
        .ok_or_else(|| format!("{event} log is missing `topics`"))?;
    if topics.len() != expected_len {
        return Err(format!(
            "{event} log must have exactly {expected_len} topics"
        ));
    }
    Ok(topics)
}

fn event_data_words(
    fields: &serde_json::Map<String, Value>,
    event: &str,
    expected_words: usize,
) -> Result<Vec<String>, String> {
    let data = fields
        .get("data")
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{event} log is missing `data`"))?;
    let hex = data
        .strip_prefix("0x")
        .ok_or_else(|| format!("{event} data must be 0x-prefixed"))?;
    if hex.len() != expected_words * 64 || !hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "{event} data must contain exactly {expected_words} ABI words"
        ));
    }
    Ok(hex
        .as_bytes()
        .chunks_exact(64)
        .map(|word| format!("0x{}", std::str::from_utf8(word).expect("hex is ASCII")))
        .collect())
}

fn require_topic_address(
    topics: &[Value],
    index: usize,
    name: &str,
    expected: Address,
) -> Result<(), String> {
    let word = topic_word(topics, index, name)?.to_be_bytes();
    let mut expected_word = [0_u8; 32];
    expected_word[12..].copy_from_slice(&expected.to_bytes());
    if word != expected_word {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn require_topic_uint256(
    topics: &[Value],
    index: usize,
    name: &str,
    expected: Uint256,
) -> Result<(), String> {
    if topic_word(topics, index, name)? != expected {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn require_topic_digest(
    topics: &[Value],
    index: usize,
    name: &str,
    expected: Digest,
) -> Result<(), String> {
    let actual = topics
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} must be a 32-byte topic"))?;
    if parse_digest(actual, name)? != expected {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn topic_word(topics: &[Value], index: usize, name: &str) -> Result<Uint256, String> {
    let value = topics
        .get(index)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{name} must be a 32-byte topic"))?;
    parse_uint256_word(value, name)
}

fn require_word_uint256(
    words: &[String],
    index: usize,
    name: &str,
    expected: Uint256,
) -> Result<(), String> {
    if parse_uint256_word(&words[index], name)? != expected {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn require_word_digest(
    words: &[String],
    index: usize,
    name: &str,
    expected: Digest,
) -> Result<(), String> {
    if parse_digest(&words[index], name)? != expected {
        return Err(format!("{name} does not match the prepared proof"));
    }
    Ok(())
}

fn event_signature(signature: &[u8]) -> Digest {
    keccak256(signature)
}

fn require_digest_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
    expected: Digest,
) -> Result<(), String> {
    if digest_field(fields, name, context)? != expected {
        return Err(format!(
            "{context} `{name}` does not match the locally signed transaction"
        ));
    }
    Ok(())
}

fn digest_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
) -> Result<Digest, String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing `{name}`"))?;
    parse_digest(value, &format!("{context} {name}"))
}

fn require_address_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
    expected: Address,
) -> Result<(), String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing `{name}`"))?;
    if parse_address(value, &format!("{context} {name}"))? != expected {
        return Err(format!(
            "{context} `{name}` does not match the prepared proof"
        ));
    }
    Ok(())
}

fn require_quantity_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
    expected: Uint256,
) -> Result<(), String> {
    if quantity_field(fields, name, context)? != expected {
        return Err(format!(
            "{context} `{name}` does not match the locally signed transaction"
        ));
    }
    Ok(())
}

fn quantity_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
) -> Result<Uint256, String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing `{name}`"))?;
    parse_hex_quantity_uint256(value, &format!("{context} {name}"))
}

fn require_hex_bytes_field(
    fields: &serde_json::Map<String, Value>,
    name: &str,
    context: &str,
    expected: &[u8],
) -> Result<(), String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("{context} is missing `{name}`"))?;
    if !value.eq_ignore_ascii_case(&hex_string(expected)) {
        return Err(format!(
            "{context} `{name}` does not match the locally signed transaction"
        ));
    }
    Ok(())
}

fn receipt_quantity(
    fields: &serde_json::Map<String, Value>,
    name: &str,
) -> Result<Uint256, String> {
    let value = fields
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("proof transaction receipt is missing `{name}`"))?;
    parse_hex_quantity_uint256(value, &format!("receipt {name}"))
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

fn uint256_to_u64(value: Uint256, name: &str) -> Result<u64, String> {
    let bytes = value.to_be_bytes();
    if bytes[..24].iter().any(|byte| *byte != 0) {
        return Err(format!("{name} exceeds the supported u64 range"));
    }
    let mut lower = [0_u8; 8];
    lower.copy_from_slice(&bytes[24..]);
    Ok(u64::from_be_bytes(lower))
}

fn disambiguate_mining_nonce(error: &str) -> String {
    error
        .replace("Nonce", "__MINING_NONCE__")
        .replace("nonce", "mining nonce")
        .replace("__MINING_NONCE__", "Mining nonce")
}

fn disambiguate_account_nonce(error: &str) -> String {
    error
        .replace("Nonce", "__ACCOUNT_NONCE__")
        .replace("nonce", "account nonce")
        .replace("__ACCOUNT_NONCE__", "Account nonce")
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;

    use proof_core::{ChallengeInputs, Target, derive_challenge};

    use super::*;

    #[test]
    fn recorded_fee_formula_and_margin_bound_total_exposure() {
        let quote = fee_quote(10, 3, 21_001, 25, 1_000_000).unwrap();
        assert_eq!(quote.max_fee_per_gas_wei, 23);
        assert_eq!(quote.gas_limit, 26_252);
        assert_eq!(quote.maximum_exposure_wei, 603_796);
    }

    #[test]
    fn fee_ceiling_is_compared_to_maximum_exposure_inclusively() {
        let exact = fee_quote(10, 3, 100, 25, 2_875).unwrap();
        assert_eq!(exact.maximum_exposure_wei, exact.fee_ceiling_wei);
        assert!(exact.maximum_exposure_wei <= exact.fee_ceiling_wei);

        let below = fee_quote(10, 3, 100, 25, 2_874).unwrap();
        assert!(below.maximum_exposure_wei > below.fee_ceiling_wei);
    }

    #[test]
    fn error_disambiguation_never_leaves_a_plain_transaction_count_name() {
        let error = disambiguate_account_nonce("nonce too low; Nonce already used");
        assert_eq!(error, "account nonce too low; Account nonce already used");
    }

    #[test]
    fn successful_receipt_requires_the_exact_locally_prepared_proof_event() {
        let prepared = prepared_fixture();
        let transaction_hash = Digest::from_bytes([0x77; 32]);
        let block_hash = Digest::from_bytes([0x88; 32]);
        let block_number = Uint256::from(21_u64);
        let receipt_value = json!({
            "transactionHash": hex_string(&transaction_hash.to_bytes()),
            "from": hex_string(&prepared.miner.to_bytes()),
            "to": hex_string(&prepared.transaction.to.to_bytes()),
            "blockHash": hex_string(&block_hash.to_bytes()),
            "blockNumber": "0x15",
            "status": "0x1",
            "gasUsed": "0x5208",
            "effectiveGasPrice": "0x2",
            "logs": [{
                "address": hex_string(&prepared.transaction.to.to_bytes()),
                "transactionHash": hex_string(&transaction_hash.to_bytes()),
                "blockHash": hex_string(&block_hash.to_bytes()),
                "blockNumber": "0x15",
                "removed": false,
                "topics": [
                    hex_string(&event_signature(b"ProofAccepted(address,uint256,bytes32,uint256,bytes32,uint256,uint256,uint256,uint256,uint256,uint256,bool)").to_bytes()),
                    address_topic(prepared.miner),
                    hex_string(&prepared.challenge_id.to_be_bytes()),
                    hex_string(&prepared.expected_digest.to_bytes()),
                ],
                "data": abi_data(&[
                    prepared.seed_parent_block.to_be_bytes(),
                    prepared.challenge.to_bytes(),
                    prepared.mining_nonce.to_be_bytes(),
                    Uint256::from(100_u64).to_be_bytes(),
                    Uint256::from(10_u64).to_be_bytes(),
                    Uint256::from(2_u64).to_be_bytes(),
                    Uint256::from(22_u64).to_be_bytes(),
                    Uint256::from(90_u64).to_be_bytes(),
                    Uint256::ZERO.to_be_bytes(),
                ]),
            }],
        });
        let receipt = parse_receipt(&receipt_value, transaction_hash, &prepared).unwrap();
        assert!(receipt.succeeded);
        assert!(!receipt.proof_nft_minted);
        assert_eq!(receipt.block_hash, block_hash);
        assert_eq!(receipt.block_number, block_number);

        let mut forged = receipt_value;
        forged["logs"][0]["topics"][3] = json!(hex_string(&[0x99; 32]));
        let error = parse_receipt(&forged, transaction_hash, &prepared)
            .expect_err("a different proof digest must not be accepted");
        assert!(error.contains("ProofAccepted digest"), "error: {error}");
    }

    fn prepared_fixture() -> PreparedSubmission {
        let miner = Address::from_bytes([0x11; 20]);
        let mining_core = Address::from_bytes([0x22; 20]);
        let challenge_id = Uint256::ONE;
        let seed_parent_block = Uint256::from(1_003_u64);
        let challenge = Digest::from_bytes([0x33; 32]);
        let mining_nonce = Uint256::from(9_u64);
        let expected_digest = proof_digest(&ProofInputs {
            chain_id: Uint256::from(31_337_u64),
            mining_core,
            challenge_id,
            challenge,
            miner,
            nonce: mining_nonce,
        });
        PreparedSubmission {
            mining_nonce,
            account_nonce: Uint256::ZERO,
            fee_quote: fee_quote(1, 1, 21_000, 25, u128::MAX).unwrap(),
            miner,
            challenge_id,
            seed_parent_block,
            challenge,
            expected_digest,
            transaction: Eip1559Transaction {
                chain_id: Uint256::from(31_337_u64),
                account_nonce: Uint256::ZERO,
                max_priority_fee_per_gas: Uint256::ONE,
                max_fee_per_gas: Uint256::from(3_u64),
                gas_limit: Uint256::from(26_250_u64),
                to: mining_core,
                data: submit_proof_call_data(challenge_id, seed_parent_block, mining_nonce),
            },
        }
    }

    fn address_topic(address: Address) -> String {
        let mut word = [0_u8; 32];
        word[12..].copy_from_slice(&address.to_bytes());
        hex_string(&word)
    }

    fn abi_data(words: &[[u8; 32]]) -> String {
        let mut data = Vec::with_capacity(words.len() * 32);
        for word in words {
            data.extend_from_slice(word);
        }
        hex_string(&data)
    }

    #[test]
    fn stale_challenge_simulation_is_rejected_before_any_send_request() {
        let (endpoint, server) = one_simulation_revert_server();
        let mining_core = Address::from_bytes([0x22; 20]);
        let challenge_inputs = ChallengeInputs {
            chain_id: Uint256::from(31_337_u64),
            mining_core,
            challenge_id: Uint256::ONE,
            previous_accepted_digest: Digest::ZERO,
            seed_parent_block: Uint256::from(1_003_u64),
            seed_blockhash: Digest::from_bytes([0x33; 32]),
        };
        let state = MiningStateFixture {
            challenge_inputs,
            challenge: derive_challenge(&challenge_inputs),
            target: Target::from_be_bytes([0xff; 32]),
        };
        assert_ne!(state.challenge, Digest::ZERO);
        assert_eq!(state.target, Target::from_be_bytes([0xff; 32]));
        let reader = RpcChainReader::new(endpoint, mining_core, challenge_inputs.chain_id);

        let outcome = prepare_submission(
            &reader,
            state.challenge_inputs,
            Address::from_bytes([0x11; 20]),
            Uint256::from(9_u64),
            FeeOptions {
                fee_ceiling_wei: u128::MAX,
                base_fee_per_gas_override_wei: Some(1),
                priority_fee_per_gas_override_wei: Some(1),
                gas_margin_percent: 25,
            },
        )
        .unwrap();
        server.join().unwrap();

        match outcome {
            PreparationOutcome::SimulationRejected { reason } => {
                assert!(reason.contains("StaleChallengeId"), "reason: {reason}");
            }
            _ => panic!("stale challenge must stop at simulation"),
        }
    }

    #[test]
    fn unreachable_simulation_is_an_rpc_failure_not_a_proof_rejection() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            drop(stream);
        });
        let mining_core = Address::from_bytes([0x22; 20]);
        let challenge_inputs = ChallengeInputs {
            chain_id: Uint256::from(31_337_u64),
            mining_core,
            challenge_id: Uint256::ONE,
            previous_accepted_digest: Digest::ZERO,
            seed_parent_block: Uint256::from(1_003_u64),
            seed_blockhash: Digest::from_bytes([0x33; 32]),
        };
        let reader = RpcChainReader::new(endpoint, mining_core, challenge_inputs.chain_id);
        let error = prepare_submission(
            &reader,
            challenge_inputs,
            Address::from_bytes([0x11; 20]),
            Uint256::ZERO,
            FeeOptions {
                fee_ceiling_wei: u128::MAX,
                base_fee_per_gas_override_wei: Some(1),
                priority_fee_per_gas_override_wei: Some(1),
                gas_margin_percent: 25,
            },
        )
        .expect_err("unreachable endpoint must be retried, not called a rejected proof");
        server.join().unwrap();
        assert!(error.contains("failed to reach JSON-RPC endpoint"));
    }

    struct MiningStateFixture {
        challenge_inputs: ChallengeInputs,
        challenge: Digest,
        target: Target,
    }

    fn one_simulation_revert_server() -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let endpoint = format!("http://{}", listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let body = read_request_body(&mut stream);
            let request: Value = serde_json::from_slice(&body).unwrap();
            assert_eq!(request["method"], "eth_call");
            let response = json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {
                    "code": 3,
                    "message": "execution reverted: StaleChallengeId(1, 2)"
                }
            })
            .to_string();
            write_response(&mut stream, &response);
            listener.set_nonblocking(true).unwrap();
            thread::sleep(Duration::from_millis(100));
            assert!(
                matches!(listener.accept(), Err(error) if error.kind() == std::io::ErrorKind::WouldBlock)
            );
        });
        (endpoint, server)
    }

    fn read_request_body(stream: &mut TcpStream) -> Vec<u8> {
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4_096];
        let (header_end, content_length) = loop {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
            let Some(header_start) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n")
            else {
                continue;
            };
            let header_end = header_start + 4;
            let headers = std::str::from_utf8(&request[..header_start]).unwrap();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap();
            break (header_end, content_length);
        };
        while request.len() < header_end + content_length {
            let read = stream.read(&mut buffer).unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&buffer[..read]);
        }
        request[header_end..header_end + content_length].to_vec()
    }

    fn write_response(stream: &mut TcpStream, body: &str) {
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).unwrap();
    }
}
