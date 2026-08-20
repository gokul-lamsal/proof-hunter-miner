use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use rand_core::{OsRng, RngCore};
use serde_json::Value;
use zeroize::Zeroizing;

static NEXT_TEMP_DIRECTORY: AtomicU64 = AtomicU64::new(0);

#[test]
fn wallet_new_stores_phrase_only_in_owner_only_recovery_file() {
    disable_core_dumps_for_children();
    let directory = temp_directory();
    let keystore = directory.join("wallet.json");
    let recovery_file = directory.join("recovery.txt");
    let passphrase_file = directory.join("passphrase");
    let passphrase = runtime_secret();
    write_owner_only(&passphrase_file, passphrase.as_bytes());

    let output = run([
        "wallet",
        "new",
        "--keystore",
        keystore.to_str().unwrap(),
        "--recovery-out",
        recovery_file.to_str().unwrap(),
        "--passphrase-file",
        passphrase_file.to_str().unwrap(),
        "--json",
    ]);
    let Output {
        status,
        stdout,
        stderr,
    } = output;
    let stdout = Zeroizing::new(stdout);
    let stderr = Zeroizing::new(stderr);
    assert_eq!(status.code(), Some(0));
    assert!(stderr.is_empty());
    let value: Value = serde_json::from_slice(stdout.as_slice()).unwrap();
    assert!(value.get("backupPhrase").is_none());
    assert!(!find_bytes(stdout.as_slice(), b"backupPhrase"));
    let recovery_contents = Zeroizing::new(fs::read_to_string(&recovery_file).unwrap());
    let phrase = recovery_contents.trim();
    assert_eq!(count_bytes(stdout.as_slice(), phrase.as_bytes()), 0);
    assert_eq!(phrase.split_whitespace().count(), 24);
    assert_eq!(value["recoveryFile"], recovery_file.display().to_string());
    assert_eq!(value["recoveryStatus"], "writtenOwnerOnly0600");
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>(),
        ["address", "keystore", "recoveryFile", "recoveryStatus"]
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    let address = value["address"].as_str().unwrap().to_owned();
    let stored = fs::read(&keystore).unwrap();
    assert_eq!(count_bytes(&stored, phrase.as_bytes()), 0);
    let stored_value: Value = serde_json::from_slice(&stored).unwrap();
    assert_eq!(stored_value["format"], "bproof-keystore");
    assert_eq!(stored_value["version"], 1);
    assert_eq!(stored_value["derivationPath"], "m/44'/60'/0'/0/0");
    assert_eq!(stored_value["crypto"]["cipher"], "xchacha20-poly1305");
    assert_eq!(stored_value["crypto"]["kdf"]["name"], "argon2id");
    assert_eq!(stored_value["crypto"]["kdf"]["version"], 19);
    assert_eq!(stored_value["crypto"]["kdf"]["memoryKib"], 65_536);
    assert_eq!(stored_value["crypto"]["kdf"]["iterations"], 3);
    assert_eq!(stored_value["crypto"]["kdf"]["parallelism"], 1);
    assert_owner_only(&keystore);
    assert_owner_only(&recovery_file);

    let unused_environment_secret = runtime_secret();
    let address_output = Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args([
            "wallet",
            "address",
            "--keystore",
            keystore.to_str().unwrap(),
            "--json",
        ])
        .env("BPROOF_PASSPHRASE", unused_environment_secret.as_str())
        .output()
        .unwrap();
    assert_eq!(address_output.status.code(), Some(0));
    assert!(address_output.stderr.is_empty());
    let address_value: Value = serde_json::from_slice(&address_output.stdout).unwrap();
    assert_eq!(address_value["address"], address);
    assert_eq!(address_value["unlocked"], false);

    cleanup(&directory, &[&keystore, &recovery_file, &passphrase_file]);
}

#[test]
fn environment_passphrase_is_refused_without_reading_its_value() {
    disable_core_dumps_for_children();
    let directory = temp_directory();
    let keystore = directory.join("wallet.json");
    let recovery_file = directory.join("recovery.txt");
    let passphrase_file = directory.join("passphrase");
    let passphrase = runtime_secret();
    let environment_secret = runtime_secret();
    write_owner_only(&passphrase_file, passphrase.as_bytes());

    let output = Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args([
            "wallet",
            "new",
            "--keystore",
            keystore.to_str().unwrap(),
            "--recovery-out",
            recovery_file.to_str().unwrap(),
            "--passphrase-file",
            passphrase_file.to_str().unwrap(),
        ])
        .env("BPROOF_PASSPHRASE", environment_secret.as_str())
        .output()
        .unwrap();

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("BPROOF_PASSPHRASE is not accepted"));
    assert!(!find_bytes(&output.stderr, environment_secret.as_bytes()));
    assert!(!keystore.exists());
    cleanup(&directory, &[&passphrase_file]);
}

#[test]
fn wallet_new_refuses_to_overwrite_an_existing_path() {
    disable_core_dumps_for_children();
    let directory = temp_directory();
    let keystore = directory.join("wallet.json");
    let recovery_file = directory.join("recovery.txt");
    let passphrase_file = directory.join("passphrase");
    let passphrase = runtime_secret();
    let marker = b"existing file";
    write_owner_only(&keystore, marker);
    write_owner_only(&passphrase_file, passphrase.as_bytes());

    let output = run([
        "wallet",
        "new",
        "--keystore",
        keystore.to_str().unwrap(),
        "--recovery-out",
        recovery_file.to_str().unwrap(),
        "--passphrase-file",
        passphrase_file.to_str().unwrap(),
    ]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("refusing to overwrite"));
    assert_eq!(fs::read(&keystore).unwrap(), marker);
    cleanup(&directory, &[&keystore, &passphrase_file]);
}

#[test]
fn wallet_surface_has_no_import_or_existing_key_path() {
    let wallet_help = run(["wallet", "--help"]);
    let new_help = run(["wallet", "new", "--help"]);

    assert_eq!(wallet_help.status.code(), Some(0));
    assert_eq!(new_help.status.code(), Some(0));
    let wallet_help = String::from_utf8_lossy(&wallet_help.stdout);
    let new_help = String::from_utf8_lossy(&new_help.stdout);
    assert!(wallet_help.contains("new"));
    assert!(wallet_help.contains("address"));
    assert!(!wallet_help.to_ascii_lowercase().contains("import"));
    assert!(!new_help.to_ascii_lowercase().contains("private key"));
    assert!(!new_help.to_ascii_lowercase().contains("seed phrase"));
    assert!(new_help.contains("--passphrase-file"));
    assert!(new_help.contains("--recovery-out"));
    assert!(new_help.contains("Environment passphrases are refused"));
    assert!(new_help.contains("never written to standard output or JSON"));
}

fn run<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_bproof"))
        .args(args)
        .output()
        .expect("bproof must run")
}

fn runtime_secret() -> Zeroizing<String> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";

    let mut bytes = Zeroizing::new([0_u8; 32]);
    OsRng.fill_bytes(bytes.as_mut());
    let mut output = String::with_capacity(64);
    for byte in bytes.iter() {
        output.push(char::from(DIGITS[usize::from(byte >> 4)]));
        output.push(char::from(DIGITS[usize::from(byte & 0x0f)]));
    }
    Zeroizing::new(output)
}

fn temp_directory() -> PathBuf {
    let id = NEXT_TEMP_DIRECTORY.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "bproof-wallet-cli-test-{}-{id}",
        std::process::id()
    ));
    fs::create_dir(&path).unwrap();
    path
}

#[cfg(unix)]
fn write_owner_only(path: &Path, contents: &[u8]) {
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

#[cfg(unix)]
fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt;

    assert_eq!(
        fs::metadata(path).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[cfg(not(unix))]
fn assert_owner_only(_path: &Path) {}

fn count_bytes(haystack: &[u8], needle: &[u8]) -> usize {
    haystack
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn find_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

fn cleanup(directory: &Path, files: &[&Path]) {
    for path in files {
        fs::remove_file(path).unwrap();
    }
    fs::remove_dir(directory).unwrap();
}

#[cfg(unix)]
fn disable_core_dumps_for_children() {
    let (_, hard_limit) = rlimit::Resource::CORE.get().unwrap();
    rlimit::Resource::CORE.set(0, hard_limit).unwrap();
}

#[cfg(not(unix))]
fn disable_core_dumps_for_children() {}
