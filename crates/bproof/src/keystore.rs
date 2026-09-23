//! Local wallet generation, encrypted storage, and approved passphrase inputs.

use std::fmt;
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::Path;
use std::str::FromStr;

use argon2::{Algorithm, Argon2, Params, Version};
use bip32::secp256k1::ecdsa::SigningKey;
use bip32::secp256k1::elliptic_curve::sec1::ToEncodedPoint;
use bip32::{DerivationPath, XPrv};
use bip39::Mnemonic;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use proof_core::keccak256;
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

const KEYSTORE_FORMAT: &str = "bproof-keystore";
const KEYSTORE_VERSION: u32 = 1;
const DERIVATION_PATH: &str = "m/44'/60'/0'/0/0";
const KDF_NAME: &str = "argon2id";
const KDF_VERSION: u32 = 19;
const KDF_MEMORY_KIB: u32 = 65_536;
const KDF_ITERATIONS: u32 = 3;
const KDF_PARALLELISM: u32 = 1;
const CIPHER_NAME: &str = "xchacha20-poly1305";
const SALT_BYTES: usize = 16;
const NONCE_BYTES: usize = 24;
const PRIVATE_KEY_BYTES: usize = 32;
const CIPHERTEXT_BYTES: usize = PRIVATE_KEY_BYTES + 16;
const MAX_KEYSTORE_BYTES: u64 = 64 * 1024;
const MAX_PASSPHRASE_BYTES: u64 = 4 * 1024;
const REDACTED: &str = "[REDACTED]";
const UNLOCK_FAILED: &str = "could not unlock keystore; check the file and passphrase";

pub const PASSPHRASE_ENVIRONMENT_VARIABLE: &str = "BPROOF_PASSPHRASE";
const ALLOW_INSECURE_PASSPHRASE_ENVIRONMENT_VARIABLE: &str = "BPROOF_ALLOW_INSECURE_PASSPHRASE";
const PASSPHRASE_ENVIRONMENT_VARIABLES: [&str; 4] = [
    PASSPHRASE_ENVIRONMENT_VARIABLE,
    "BPROOF_KEYSTORE_PASSPHRASE",
    "BPROOF_PASSWORD",
    "BPROOF_KEYSTORE_PASSWORD",
];

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KeystoreDocument {
    format: String,
    version: u32,
    address: String,
    derivation_path: String,
    crypto: CryptoDocument,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CryptoDocument {
    kdf: KdfDocument,
    cipher: String,
    nonce: String,
    ciphertext: String,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct KdfDocument {
    name: String,
    version: u32,
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
    salt: String,
}

/// A passphrase whose bytes are wiped when it leaves scope.
pub struct SecretPassphrase(Zeroizing<Vec<u8>>);

impl SecretPassphrase {
    fn from_string(value: String) -> Result<Self, String> {
        let bytes = Zeroizing::new(value.into_bytes());
        if bytes.is_empty() {
            return Err("passphrase must not be empty".to_owned());
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

impl fmt::Debug for SecretPassphrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("SecretPassphrase")
            .field(&REDACTED)
            .finish()
    }
}

/// A generated backup phrase whose words are wiped when it leaves scope.
pub struct BackupPhrase(Mnemonic);

impl BackupPhrase {
    pub fn expose_once(self) -> Zeroizing<String> {
        Zeroizing::new(self.0.to_string())
    }
}

impl fmt::Debug for BackupPhrase {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("BackupPhrase")
            .field(&REDACTED)
            .finish()
    }
}

/// The public result of creating a fresh mining wallet.
pub struct CreatedWallet {
    address: String,
    backup_phrase: BackupPhrase,
}

impl CreatedWallet {
    pub fn address(&self) -> &str {
        &self.address
    }

    #[cfg(test)]
    fn backup_phrase(&self) -> &BackupPhrase {
        &self.backup_phrase
    }

    pub fn into_backup_phrase(self) -> BackupPhrase {
        self.backup_phrase
    }
}

impl fmt::Debug for CreatedWallet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CreatedWallet")
            .field("address", &self.address)
            .field("backup_phrase", &REDACTED)
            .finish()
    }
}

/// One decrypted mining wallet whose key never leaves this type.
pub struct UnlockedWallet {
    private_key: Zeroizing<[u8; PRIVATE_KEY_BYTES]>,
    address: String,
}

impl UnlockedWallet {
    fn from_private_key(private_key: Zeroizing<[u8; PRIVATE_KEY_BYTES]>) -> Result<Self, String> {
        let secret_key = bip32::secp256k1::SecretKey::from_slice(private_key.as_slice())
            .map_err(|_| "decrypted wallet key is invalid".to_owned())?;
        let encoded = secret_key.public_key().to_encoded_point(false);
        let digest = keccak256(&encoded.as_bytes()[1..]);
        let address = hex_prefixed(&digest.to_bytes()[12..]);
        Ok(Self {
            private_key,
            address,
        })
    }

    pub fn address(&self) -> &str {
        &self.address
    }

    pub(crate) fn sign_digest(&self, digest: &[u8; 32]) -> Result<([u8; 64], u8), String> {
        let signing_key = SigningKey::from_slice(self.private_key.as_slice())
            .map_err(|_| "decrypted wallet key is invalid".to_owned())?;
        let (signature, recovery_id) = signing_key
            .sign_prehash_recoverable(digest)
            .map_err(|_| "failed to sign transaction digest".to_owned())?;
        let recovery_id = recovery_id.to_byte();
        if recovery_id > 1 {
            return Err(
                "failed to produce an Ethereum-compatible transaction signature".to_owned(),
            );
        }
        Ok((signature.to_bytes().into(), recovery_id))
    }

    #[cfg(test)]
    fn private_key_for_test(&self) -> &[u8; PRIVATE_KEY_BYTES] {
        &self.private_key
    }
}

impl fmt::Debug for UnlockedWallet {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("UnlockedWallet")
            .field("private_key", &REDACTED)
            .field("address", &self.address)
            .finish()
    }
}

/// The only approved sources for a keystore passphrase.
pub enum PassphraseSource<'a> {
    Prompt,
    File(&'a Path),
}

/// Reads a passphrase without accepting one from the environment.
pub fn read_passphrase(
    source: PassphraseSource<'_>,
    confirm_prompt: bool,
) -> Result<SecretPassphrase, String> {
    if matches!(source, PassphraseSource::Prompt)
        && std::env::var(ALLOW_INSECURE_PASSPHRASE_ENVIRONMENT_VARIABLE).as_deref() == Ok("1")
    {
        if let Some(value) = std::env::var_os(PASSPHRASE_ENVIRONMENT_VARIABLE) {
            let bytes = value.to_string_lossy().as_bytes().to_vec();
            if bytes.is_empty() {
                return Err(format!("{PASSPHRASE_ENVIRONMENT_VARIABLE} must not be empty"));
            }
            if bytes.len() as u64 > MAX_PASSPHRASE_BYTES {
                return Err(format!(
                    "{PASSPHRASE_ENVIRONMENT_VARIABLE} exceeds the maximum passphrase length"
                ));
            }
            ensure_core_dumps_disabled()?;
            return Ok(SecretPassphrase(bytes.into()));
        }
    }
    refuse_environment_passphrase()?;
    ensure_core_dumps_disabled()?;

    match source {
        PassphraseSource::Prompt => read_prompted_passphrase(confirm_prompt),
        PassphraseSource::File(path) => read_passphrase_file(path),
    }
}

/// Generates and stores one new wallet. Existing paths are never overwritten.
pub fn create_keystore(
    path: &Path,
    passphrase: &SecretPassphrase,
) -> Result<CreatedWallet, String> {
    ensure_core_dumps_disabled()?;
    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing keystore {}",
            path.display()
        ));
    }

    let mut entropy = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(entropy.as_mut());
    let mnemonic = Mnemonic::from_entropy(entropy.as_slice())
        .map_err(|_| "failed to create a BIP-39 backup phrase".to_owned())?;
    let seed = Zeroizing::new(mnemonic.to_seed(""));
    let derivation_path = DerivationPath::from_str(DERIVATION_PATH)
        .map_err(|_| "the built-in wallet derivation path is invalid".to_owned())?;
    let derived = XPrv::derive_from_path(seed.as_slice(), &derivation_path)
        .map_err(|_| "failed to derive the mining wallet key".to_owned())?;
    let mut derived_bytes = derived.to_bytes();
    let mut private_key = Zeroizing::new([0_u8; PRIVATE_KEY_BYTES]);
    private_key.copy_from_slice(derived_bytes.as_slice());
    derived_bytes.zeroize();
    let wallet = UnlockedWallet::from_private_key(private_key)?;
    let document = encrypt_document(&wallet, passphrase)?;
    write_document(path, &document)?;

    Ok(CreatedWallet {
        address: wallet.address().to_owned(),
        backup_phrase: BackupPhrase(mnemonic),
    })
}

/// Atomically publishes a generated recovery phrase in a new owner-only file.
///
/// The final path is linked only after the complete 0600 temporary file has
/// been synced. Existing destinations are never replaced.
pub fn write_recovery_phrase(path: &Path, phrase: BackupPhrase) -> Result<(), String> {
    ensure_core_dumps_disabled()?;
    let phrase = phrase.expose_once();
    write_recovery_phrase_bytes(path, phrase.as_bytes())
}

#[cfg(unix)]
fn write_recovery_phrase_bytes(path: &Path, phrase: &[u8]) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    if path.exists() {
        return Err(format!(
            "refusing to overwrite existing recovery file {}",
            path.display()
        ));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .ok_or_else(|| "recovery output path must name a file".to_owned())?;

    let (temporary_path, mut temporary_file) = (0..16)
        .find_map(|_| {
            let mut random = [0_u8; 16];
            OsRng.fill_bytes(&mut random);
            let temporary_name = format!(
                ".{}.bproof-recovery-{}.tmp",
                file_name.to_string_lossy(),
                encode_hex(&random)
            );
            let temporary_path = parent.join(temporary_name);
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary_path)
            {
                Ok(file) => Some(Ok((temporary_path, file))),
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => None,
                Err(error) => Some(Err(format!(
                    "failed to create temporary recovery file in {}: {error}",
                    parent.display()
                ))),
            }
        })
        .transpose()?
        .ok_or_else(|| {
            format!(
                "failed to allocate a temporary recovery file in {}",
                parent.display()
            )
        })?;

    let publish_result = (|| {
        verify_owner_only(&temporary_file, "recovery file")?;
        temporary_file
            .write_all(phrase)
            .and_then(|()| temporary_file.write_all(b"\n"))
            .and_then(|()| temporary_file.sync_all())
            .map_err(|error| {
                format!("failed to write recovery file {}: {error}", path.display())
            })?;
        fs::hard_link(&temporary_path, path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!(
                    "refusing to overwrite existing recovery file {}",
                    path.display()
                )
            } else {
                format!(
                    "failed to atomically publish recovery file {}: {error}",
                    path.display()
                )
            }
        })?;
        fs::remove_file(&temporary_path).map_err(|error| {
            format!(
                "failed to remove temporary recovery file {}: {error}",
                temporary_path.display()
            )
        })?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .map_err(|error| {
                format!(
                    "failed to sync recovery directory {}: {error}",
                    parent.display()
                )
            })
    })();

    if publish_result.is_err() {
        let _ = fs::remove_file(&temporary_path);
    }
    publish_result
}

#[cfg(not(unix))]
fn write_recovery_phrase_bytes(_path: &Path, _phrase: &[u8]) -> Result<(), String> {
    Err(
        "recovery-file creation is unavailable because this platform cannot enforce owner-only permissions"
            .to_owned(),
    )
}

/// Reads the recorded public address without decrypting the wallet key.
pub fn read_keystore_address(path: &Path) -> Result<String, String> {
    let mut file = open_owner_only_file(path, "keystore")?;
    let contents = read_limited(&mut file, MAX_KEYSTORE_BYTES, "keystore")?;
    let document: KeystoreDocument = serde_json::from_slice(&contents)
        .map_err(|_| "keystore is not a supported bproof keystore".to_owned())?;
    validate_document_header(&document)
        .map_err(|_| "keystore is not a supported bproof keystore".to_owned())?;
    decode_prefixed_hex_exact::<20>(&document.address)
        .map_err(|()| "keystore address must be 0x-prefixed and exactly 20 bytes".to_owned())?;
    Ok(document.address)
}

/// Decrypts one local keystore. All malformed and authentication failures match.
pub fn unlock_keystore(
    path: &Path,
    passphrase: &SecretPassphrase,
) -> Result<UnlockedWallet, String> {
    ensure_core_dumps_disabled()?;
    let mut file = open_owner_only_file(path, "keystore")?;
    unlock_from_reader(&mut file, passphrase).map_err(|_| UNLOCK_FAILED.to_owned())
}

fn read_prompted_passphrase(confirm: bool) -> Result<SecretPassphrase, String> {
    let first = rpassword::prompt_password("Keystore passphrase: ")
        .map_err(|error| format!("failed to read passphrase from terminal: {error}"))?;
    let first = SecretPassphrase::from_string(first)?;
    if confirm {
        let second = rpassword::prompt_password("Confirm keystore passphrase: ")
            .map_err(|error| format!("failed to confirm passphrase from terminal: {error}"))?;
        let second = SecretPassphrase::from_string(second)?;
        if first.as_bytes() != second.as_bytes() {
            return Err("passphrase confirmation does not match".to_owned());
        }
    }
    Ok(first)
}

fn read_passphrase_file(path: &Path) -> Result<SecretPassphrase, String> {
    let mut file = open_owner_only_file(path, "passphrase file")?;
    let mut bytes = read_secret_limited(&mut file, MAX_PASSPHRASE_BYTES, "passphrase file")?;
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty() {
        return Err("passphrase file must not be empty".to_owned());
    }
    Ok(SecretPassphrase(bytes))
}

fn refuse_environment_passphrase() -> Result<(), String> {
    if let Some(name) = PASSPHRASE_ENVIRONMENT_VARIABLES
        .into_iter()
        .find(|name| std::env::var_os(name).is_some())
    {
        return Err(format!(
            "{name} is not accepted because environment variables can leak secrets; use the no-echo prompt or --passphrase-file"
        ));
    }
    Ok(())
}

fn encrypt_document(
    wallet: &UnlockedWallet,
    passphrase: &SecretPassphrase,
) -> Result<KeystoreDocument, String> {
    let mut salt = [0_u8; SALT_BYTES];
    let mut nonce = [0_u8; NONCE_BYTES];
    OsRng.fill_bytes(&mut salt);
    OsRng.fill_bytes(&mut nonce);

    let mut document = KeystoreDocument {
        format: KEYSTORE_FORMAT.to_owned(),
        version: KEYSTORE_VERSION,
        address: wallet.address().to_owned(),
        derivation_path: DERIVATION_PATH.to_owned(),
        crypto: CryptoDocument {
            kdf: KdfDocument {
                name: KDF_NAME.to_owned(),
                version: KDF_VERSION,
                memory_kib: KDF_MEMORY_KIB,
                iterations: KDF_ITERATIONS,
                parallelism: KDF_PARALLELISM,
                salt: encode_hex(&salt),
            },
            cipher: CIPHER_NAME.to_owned(),
            nonce: encode_hex(&nonce),
            ciphertext: String::new(),
        },
    };
    let key = derive_encryption_key(passphrase, &salt)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice())
        .map_err(|_| "failed to initialize keystore encryption".to_owned())?;
    let aad = document_aad(&document);
    let ciphertext = cipher
        .encrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: wallet.private_key.as_slice(),
                aad: aad.as_bytes(),
            },
        )
        .map_err(|_| "failed to encrypt the wallet key".to_owned())?;
    document.crypto.ciphertext = encode_hex(&ciphertext);
    Ok(document)
}

fn unlock_from_reader(
    reader: &mut File,
    passphrase: &SecretPassphrase,
) -> Result<UnlockedWallet, ()> {
    let contents = read_limited(reader, MAX_KEYSTORE_BYTES, "keystore").map_err(|_| ())?;
    let document: KeystoreDocument = serde_json::from_slice(&contents).map_err(|_| ())?;
    validate_document_header(&document)?;
    let salt = decode_hex_exact::<SALT_BYTES>(&document.crypto.kdf.salt)?;
    let nonce = decode_hex_exact::<NONCE_BYTES>(&document.crypto.nonce)?;
    let ciphertext = decode_hex_exact::<CIPHERTEXT_BYTES>(&document.crypto.ciphertext)?;
    let key = derive_encryption_key(passphrase, &salt).map_err(|_| ())?;
    let cipher = XChaCha20Poly1305::new_from_slice(key.as_slice()).map_err(|_| ())?;
    let plaintext = cipher
        .decrypt(
            XNonce::from_slice(&nonce),
            Payload {
                msg: &ciphertext,
                aad: document_aad(&document).as_bytes(),
            },
        )
        .map_err(|_| ())?;
    let plaintext = Zeroizing::new(plaintext);
    let private_key = Zeroizing::new(plaintext.as_slice().try_into().map_err(|_| ())?);
    let wallet = UnlockedWallet::from_private_key(private_key).map_err(|_| ())?;
    if wallet.address() != document.address {
        return Err(());
    }
    Ok(wallet)
}

fn validate_document_header(document: &KeystoreDocument) -> Result<(), ()> {
    if document.format != KEYSTORE_FORMAT
        || document.version != KEYSTORE_VERSION
        || document.derivation_path != DERIVATION_PATH
        || document.crypto.kdf.name != KDF_NAME
        || document.crypto.kdf.version != KDF_VERSION
        || document.crypto.kdf.memory_kib != KDF_MEMORY_KIB
        || document.crypto.kdf.iterations != KDF_ITERATIONS
        || document.crypto.kdf.parallelism != KDF_PARALLELISM
        || document.crypto.cipher != CIPHER_NAME
        || decode_prefixed_hex_exact::<20>(&document.address).is_err()
    {
        return Err(());
    }
    Ok(())
}

fn derive_encryption_key(
    passphrase: &SecretPassphrase,
    salt: &[u8; SALT_BYTES],
) -> Result<Zeroizing<[u8; 32]>, String> {
    let params = Params::new(KDF_MEMORY_KIB, KDF_ITERATIONS, KDF_PARALLELISM, Some(32))
        .map_err(|_| "the built-in Argon2id parameters are invalid".to_owned())?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = Zeroizing::new([0_u8; 32]);
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, output.as_mut())
        .map_err(|_| "failed to derive the keystore encryption key".to_owned())?;
    Ok(output)
}

fn document_aad(document: &KeystoreDocument) -> String {
    format!(
        "{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}|{}",
        document.format,
        document.version,
        document.address,
        document.derivation_path,
        document.crypto.kdf.name,
        document.crypto.kdf.version,
        document.crypto.kdf.memory_kib,
        document.crypto.kdf.iterations,
        document.crypto.kdf.parallelism,
        document.crypto.kdf.salt,
        document.crypto.cipher,
        document.crypto.nonce,
    )
}

#[cfg(unix)]
fn write_document(path: &Path, document: &KeystoreDocument) -> Result<(), String> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt;

    let mut encoded = serde_json::to_vec_pretty(document)
        .map_err(|error| format!("failed to encode keystore: {error}"))?;
    encoded.push(b'\n');

    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                format!("refusing to overwrite existing keystore {}", path.display())
            } else {
                format!("failed to create keystore {}: {error}", path.display())
            }
        })?;
    verify_owner_only(&file, "keystore")?;
    file.write_all(&encoded)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("failed to write keystore {}: {error}", path.display()))
}

#[cfg(not(unix))]
fn write_document(_path: &Path, _document: &KeystoreDocument) -> Result<(), String> {
    Err(
        "wallet creation is unavailable because this platform cannot enforce owner-only keystore permissions"
            .to_owned(),
    )
}

fn open_owner_only_file(path: &Path, label: &str) -> Result<File, String> {
    let file = File::open(path).map_err(|error| format!("failed to open {label}: {error}"))?;
    verify_owner_only(&file, label)?;
    Ok(file)
}

#[cfg(unix)]
fn verify_owner_only(file: &File, label: &str) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file
        .metadata()
        .map_err(|error| format!("failed to inspect {label}: {error}"))?;
    if !metadata.file_type().is_file() {
        return Err(format!("{label} must be a regular file"));
    }
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(format!("{label} must be owned by the current user"));
    }
    let mode = metadata.mode() & 0o777;
    if mode & 0o077 != 0 {
        return Err(format!(
            "{label} must be readable only by its owner; set permissions to 0600 (found {mode:04o})"
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn verify_owner_only(_file: &File, label: &str) -> Result<(), String> {
    Err(format!(
        "{label} cannot be used because this platform cannot verify owner-only permissions"
    ))
}

#[cfg(unix)]
fn ensure_core_dumps_disabled() -> Result<(), String> {
    let (soft_limit, _) = rlimit::Resource::CORE
        .get()
        .map_err(|error| format!("failed to check whether core dumps are enabled: {error}"))?;
    validate_core_dump_soft_limit(soft_limit)
}

#[cfg(unix)]
fn validate_core_dump_soft_limit(soft_limit: u64) -> Result<(), String> {
    if soft_limit != 0 {
        return Err(
            "core dumps are enabled; disable them before handling wallet secrets (for example, run `ulimit -c 0`)"
                .to_owned(),
        );
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_core_dumps_disabled() -> Result<(), String> {
    Ok(())
}

fn read_limited(file: &mut File, limit: u64, label: &str) -> Result<Vec<u8>, String> {
    let mut contents = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut contents)
        .map_err(|error| format!("failed to read {label}: {error}"))?;
    if contents.len() as u64 > limit {
        return Err(format!("{label} is too large"));
    }
    Ok(contents)
}

fn read_secret_limited(
    file: &mut File,
    limit: u64,
    label: &str,
) -> Result<Zeroizing<Vec<u8>>, String> {
    let mut contents = Zeroizing::new(Vec::new());
    file.take(limit + 1)
        .read_to_end(contents.as_mut())
        .map_err(|error| format!("failed to read {label}: {error}"))?;
    if contents.len() as u64 > limit {
        return Err(format!("{label} is too large"));
    }
    Ok(contents)
}

fn encode_hex(bytes: &[u8]) -> String {
    hex_prefixed(bytes).trim_start_matches("0x").to_owned()
}

fn hex_prefixed(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut output = String::with_capacity(2 + bytes.len() * 2);
    output.push_str("0x");
    for byte in bytes {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    output
}

fn decode_prefixed_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    let hex = value.strip_prefix("0x").ok_or(())?;
    decode_hex_exact(hex)
}

fn decode_hex_exact<const N: usize>(value: &str) -> Result<[u8; N], ()> {
    if value.len() != N * 2 {
        return Err(());
    }
    let mut output = [0_u8; N];
    for (index, byte) in output.iter_mut().enumerate() {
        let high = hex_nibble(value.as_bytes()[index * 2]).ok_or(())?;
        let low = hex_nibble(value.as_bytes()[index * 2 + 1]).ok_or(())?;
        *byte = (high << 4) | low;
    }
    Ok(output)
}

const fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    #[test]
    fn generate_write_unlock_round_trip_preserves_address() {
        disable_core_dumps_for_test();
        let directory = temp_directory();
        let path = directory.join("wallet.json");
        let passphrase = runtime_passphrase();

        let created = create_keystore(&path, &passphrase).expect("wallet creation must succeed");
        let unlocked = unlock_keystore(&path, &passphrase).expect("wallet unlock must succeed");

        assert_eq!(unlocked.address(), created.address());
        assert_eq!(read_keystore_address(&path).unwrap(), created.address());
        cleanup(&directory, &[&path]);
    }

    #[test]
    fn wrong_passphrase_and_malformed_keystore_have_the_same_error() {
        disable_core_dumps_for_test();
        let directory = temp_directory();
        let valid_path = directory.join("valid.json");
        let malformed_path = directory.join("malformed.json");
        let passphrase = runtime_passphrase();
        let wrong_passphrase = runtime_passphrase();
        create_keystore(&valid_path, &passphrase).expect("wallet creation must succeed");
        write_owner_only(&malformed_path, b"not a keystore");

        let wrong_error = unlock_keystore(&valid_path, &wrong_passphrase).unwrap_err();
        let malformed_error = unlock_keystore(&malformed_path, &passphrase).unwrap_err();

        assert_eq!(wrong_error, UNLOCK_FAILED);
        assert_eq!(wrong_error, malformed_error);
        cleanup(&directory, &[&valid_path, &malformed_path]);
    }

    #[cfg(unix)]
    #[test]
    fn passphrase_file_refuses_other_readers_and_accepts_0600() {
        use std::os::unix::fs::PermissionsExt;

        disable_core_dumps_for_test();
        let directory = temp_directory();
        let path = directory.join("passphrase");
        let source = runtime_passphrase();
        fs::write(&path, source.as_bytes()).expect("passphrase file must be writable");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();

        let error = read_passphrase(PassphraseSource::File(&path), false).unwrap_err();
        assert!(error.contains("readable only by its owner"));
        assert!(error.contains("0600"));

        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let accepted = read_passphrase(PassphraseSource::File(&path), false).unwrap();
        assert!(accepted.as_bytes() == source.as_bytes());
        cleanup(&directory, &[&path]);
    }

    #[test]
    fn existing_keystore_is_never_overwritten() {
        disable_core_dumps_for_test();
        let directory = temp_directory();
        let path = directory.join("wallet.json");
        write_owner_only(&path, b"existing bytes");
        let original = fs::read(&path).unwrap();

        let error = create_keystore(&path, &runtime_passphrase()).unwrap_err();

        assert!(error.contains("refusing to overwrite"));
        assert_eq!(fs::read(&path).unwrap(), original);
        cleanup(&directory, &[&path]);
    }

    #[test]
    fn backup_phrase_is_not_written_to_the_keystore() {
        disable_core_dumps_for_test();
        let directory = temp_directory();
        let path = directory.join("wallet.json");
        let created = create_keystore(&path, &runtime_passphrase()).unwrap();
        let phrase = created.into_backup_phrase().expose_once();
        let stored = fs::read_to_string(&path).unwrap();

        assert!(!stored.contains(phrase.as_str()));
        cleanup(&directory, &[&path]);
    }

    #[test]
    fn every_secret_holding_type_has_redacted_debug_output() {
        disable_core_dumps_for_test();
        let directory = temp_directory();
        let path = directory.join("wallet.json");
        let passphrase = runtime_passphrase();
        let passphrase_bytes = Zeroizing::new(encode_hex(passphrase.as_bytes()));
        let created = create_keystore(&path, &passphrase).unwrap();
        let unlocked = unlock_keystore(&path, &passphrase).unwrap();
        let key = Zeroizing::new(encode_hex(unlocked.private_key_for_test()));

        let mut cases = [
            format!("{passphrase:?}"),
            format!("{:?}", created.backup_phrase()),
            format!("{created:?}"),
            format!("{unlocked:?}"),
        ];
        let phrase = created.into_backup_phrase().expose_once();
        for output in &cases {
            assert!(output.contains(REDACTED));
            assert!(!output.contains(passphrase_bytes.as_str()));
            assert!(!output.contains(phrase.as_str()));
            assert!(!output.contains(key.as_str()));
        }
        for output in &mut cases {
            output.zeroize();
        }
        cleanup(&directory, &[&path]);
    }

    #[test]
    fn secret_names_are_not_sent_to_logging_or_panic_macros() {
        let source_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let sensitive_names = [
            "passphrase",
            "mnemonic",
            "private_key",
            "secret_key",
            "backup_phrase",
        ];
        let dangerous_macros = ["dbg!(", "log::", "tracing::", "panic!("];

        for entry in fs::read_dir(source_directory).unwrap() {
            let path = entry.unwrap().path();
            if path.extension().and_then(|value| value.to_str()) != Some("rs") {
                continue;
            }
            let source = fs::read_to_string(&path).unwrap();
            for line in source.lines() {
                let lower = line.to_ascii_lowercase();
                let names_secret = sensitive_names.iter().any(|name| lower.contains(name));
                let logs_or_panics = dangerous_macros.iter().any(|name| lower.contains(name));
                assert!(
                    !(names_secret && logs_or_panics),
                    "secret-shaped field used by logging or panic macro in {}",
                    path.display()
                );
            }
        }
    }

    #[cfg(unix)]
    #[test]
    fn enabled_core_dumps_are_refused() {
        let error = validate_core_dump_soft_limit(1).unwrap_err();
        assert!(error.contains("core dumps are enabled"));
        assert!(validate_core_dump_soft_limit(0).is_ok());
    }

    fn runtime_passphrase() -> SecretPassphrase {
        let mut bytes = Zeroizing::new([0_u8; 32]);
        OsRng.fill_bytes(bytes.as_mut());
        SecretPassphrase::from_string(encode_hex(bytes.as_slice())).unwrap()
    }

    fn temp_directory() -> std::path::PathBuf {
        let id = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("bproof-keystore-test-{}-{id}", std::process::id()));
        fs::create_dir(&path).expect("temporary directory must be created");
        path
    }

    #[cfg(unix)]
    fn write_owner_only(path: &Path, contents: &[u8]) {
        use std::fs::OpenOptions;
        use std::os::unix::fs::OpenOptionsExt;

        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .unwrap();
        file.write_all(contents).unwrap();
    }

    #[cfg(not(unix))]
    fn write_owner_only(path: &Path, contents: &[u8]) {
        fs::write(path, contents).unwrap();
    }

    fn cleanup(directory: &Path, files: &[&Path]) {
        for path in files {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(directory).unwrap();
    }

    #[cfg(unix)]
    fn disable_core_dumps_for_test() {
        let (_, hard_limit) = rlimit::Resource::CORE.get().unwrap();
        rlimit::Resource::CORE.set(0, hard_limit).unwrap();
    }

    #[cfg(not(unix))]
    fn disable_core_dumps_for_test() {}
}
