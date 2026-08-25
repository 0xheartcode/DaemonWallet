//! End-to-end tests over the public API.

use daemon_wallet_vault::{Error, KdfParams, Meta, Vault};

// Fast parameters so the suite stays quick. Real use should keep the strong
// defaults. These only exercise wiring, not resistance.
fn fast() -> KdfParams {
    KdfParams::new(64, 1, 1)
}

// Header byte offsets, from the documented layout. Used to tamper with
// specific header fields.
const M_COST_OFFSET: usize = 12; // u32 at bytes 12..16
const M_COST_LSB_OFFSET: usize = 15; // low byte of the u32 at bytes 12..16
const T_COST_OFFSET: usize = 16; // u32 at bytes 16..20
const FLAGS_OFFSET: usize = 24; // flags byte
const SALT_OFFSET: usize = 27; // first salt byte
const SALT_RANGE: std::ops::Range<usize> = 27..43; // 16-byte salt
const NONCE_RANGE: std::ops::Range<usize> = 44..68; // 24-byte nonce, after nonce_len byte

fn tmp_path(dir: &std::path::Path) -> std::path::PathBuf {
    dir.join("store.vault")
}

#[test]
fn round_trip_get_equals_original() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"a strong test passphrase";

    {
        let mut vault = Vault::create(&path, pw, None, fast()).unwrap();
        let mut meta = Meta::new("First");
        meta.tags = vec!["alpha".into(), "beta".into()];
        meta.notes = "some notes".into();
        vault.put("one", b"secret-one-bytes", meta);
        vault.put("two", &[0u8, 1, 2, 3, 255], Meta::new("Second"));
        vault.put("empty", b"", Meta::new("Empty"));
        vault.save().unwrap();
    }

    let vault = Vault::open(&path, pw, None).unwrap();
    assert_eq!(vault.len(), 3);
    assert_eq!(vault.get("one").unwrap().secret(), b"secret-one-bytes");
    assert_eq!(vault.get("two").unwrap().secret(), &[0u8, 1, 2, 3, 255]);
    assert_eq!(vault.get("empty").unwrap().secret(), b"");

    let m = vault.get("one").unwrap().meta();
    assert_eq!(m.name, "First");
    assert_eq!(m.tags, vec!["alpha".to_string(), "beta".to_string()]);
    assert_eq!(m.notes, "some notes");

    let ids: Vec<&str> = vault.ids().collect();
    assert_eq!(ids, vec!["empty", "one", "two"]);

    assert!(!vault.is_empty());
    assert!(!vault.uses_keyfile());
}

#[test]
fn wrong_password_returns_auth_error() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());

    let mut vault = Vault::create(&path, b"right password", None, fast()).unwrap();
    vault.put("k", b"v", Meta::new("k"));
    vault.save().unwrap();

    let err = Vault::open(&path, b"wrong password", None).unwrap_err();
    assert!(matches!(err, Error::Auth), "expected Auth, got {err:?}");
}

#[test]
fn keyfile_flows() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"passphrase with keyfile";
    let keyfile = b"the keyfile contents that act as a second factor";

    let mut vault = Vault::create(&path, pw, Some(keyfile), fast()).unwrap();
    vault.put("k", b"v", Meta::new("k"));
    vault.save().unwrap();

    // Missing keyfile is rejected before any crypto.
    assert!(matches!(
        Vault::open(&path, pw, None).unwrap_err(),
        Error::KeyfileRequired
    ));

    // Wrong keyfile fails the tag check.
    assert!(matches!(
        Vault::open(&path, pw, Some(b"not the keyfile")).unwrap_err(),
        Error::Auth
    ));

    // Correct keyfile opens.
    let opened = Vault::open(&path, pw, Some(keyfile)).unwrap();
    assert_eq!(opened.get("k").unwrap().secret(), b"v");
    assert!(opened.uses_keyfile());
}

#[test]
fn keyfile_on_non_keyfile_vault_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"no keyfile here";

    Vault::create(&path, pw, None, fast()).unwrap();
    assert!(matches!(
        Vault::open(&path, pw, Some(b"unexpected")).unwrap_err(),
        Error::UnexpectedKeyfile
    ));
}

#[test]
fn tamper_in_header_params_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"tamper params";

    Vault::create(&path, pw, None, fast()).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[M_COST_LSB_OFFSET] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    // The stored params changed, so both the key and the AAD differ.
    assert!(Vault::open(&path, pw, None).is_err());
}

#[test]
fn tamper_in_header_unused_flag_bit_fails_auth() {
    // This isolates AAD coverage. Bit 7 of flags is unused, so it does not
    // change keyfile handling or key derivation. It only lives in the AAD.
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"tamper flags";

    Vault::create(&path, pw, None, fast()).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[FLAGS_OFFSET] ^= 0x80;
    std::fs::write(&path, &bytes).unwrap();

    let err = Vault::open(&path, pw, None).unwrap_err();
    assert!(matches!(err, Error::Auth), "expected Auth, got {err:?}");
}

#[test]
fn tamper_in_salt_fails() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"tamper salt";

    Vault::create(&path, pw, None, fast()).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[SALT_OFFSET] ^= 0xff;
    std::fs::write(&path, &bytes).unwrap();

    assert!(Vault::open(&path, pw, None).is_err());
}

#[test]
fn tamper_in_ciphertext_fails_auth() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"tamper ciphertext";

    let mut vault = Vault::create(&path, pw, None, fast()).unwrap();
    vault.put("k", b"payload", Meta::new("k"));
    vault.save().unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    let last = bytes.len() - 1; // part of the Poly1305 tag
    bytes[last] ^= 0x01;
    std::fs::write(&path, &bytes).unwrap();

    let err = Vault::open(&path, pw, None).unwrap_err();
    assert!(matches!(err, Error::Auth), "expected Auth, got {err:?}");
}

#[test]
fn truncated_ciphertext_is_rejected_cleanly() {
    // Header stays intact and ct_len is unchanged, but trailing ciphertext
    // bytes are dropped. open() must return a clean error, never panic or slice
    // out of bounds.
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"truncation test";

    let mut vault = Vault::create(&path, pw, None, fast()).unwrap();
    vault.put("k", b"a payload worth several bytes", Meta::new("k"));
    vault.save().unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes.truncate(bytes.len() - 4); // drop 4 trailing ciphertext bytes
    std::fs::write(&path, &bytes).unwrap();

    let err = Vault::open(&path, pw, None).unwrap_err();
    assert!(matches!(err, Error::MalformedHeader), "got {err:?}");
}

#[test]
fn salt_and_nonce_are_randomized_per_file() {
    // A no-op RNG would leave the salt and nonce all-zero and identical across
    // files, which is catastrophic nonce reuse. Two files with the same
    // password must differ in both regions and never be all-zero.
    let dir = tempfile::tempdir().unwrap();
    let path_a = dir.path().join("a.vault");
    let path_b = dir.path().join("b.vault");
    let pw = b"identical password";

    Vault::create(&path_a, pw, None, fast()).unwrap();
    Vault::create(&path_b, pw, None, fast()).unwrap();

    let a = std::fs::read(&path_a).unwrap();
    let b = std::fs::read(&path_b).unwrap();

    let salt_a = &a[SALT_RANGE];
    let salt_b = &b[SALT_RANGE];
    let nonce_a = &a[NONCE_RANGE];
    let nonce_b = &b[NONCE_RANGE];

    assert_ne!(salt_a, salt_b, "salts must differ between files");
    assert_ne!(nonce_a, nonce_b, "nonces must differ between files");
    assert!(salt_a.iter().any(|&x| x != 0), "salt must not be all zero");
    assert!(
        nonce_a.iter().any(|&x| x != 0),
        "nonce must not be all zero"
    );
}

#[test]
fn extreme_header_params_rejected_fast() {
    // A file claiming m_cost = t_cost = u32::MAX must be refused before any key
    // derivation, so it cannot exhaust memory or hang. This returns quickly.
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"ceiling test";

    Vault::create(&path, pw, None, fast()).unwrap();

    let mut bytes = std::fs::read(&path).unwrap();
    bytes[M_COST_OFFSET..M_COST_OFFSET + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    bytes[T_COST_OFFSET..T_COST_OFFSET + 4].copy_from_slice(&u32::MAX.to_be_bytes());
    std::fs::write(&path, &bytes).unwrap();

    let start = std::time::Instant::now();
    let err = Vault::open(&path, pw, None).unwrap_err();
    assert!(matches!(err, Error::ParamsOutOfRange), "got {err:?}");
    // Even the wrong password path would be fast, but this proves no big work ran.
    assert!(start.elapsed() < std::time::Duration::from_secs(2));
}

#[test]
fn param_evolution_reads_stored_then_upgrades() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"evolving parameters";
    let low = KdfParams::new(64, 1, 1);
    let higher = KdfParams::new(1024, 3, 1);

    {
        let mut vault = Vault::create(&path, pw, None, low).unwrap();
        vault.put("k", b"v", Meta::new("k"));
        vault.save().unwrap();
    }

    // Open must use the stored low params, not the strong defaults.
    let mut vault = Vault::open(&path, pw, None).unwrap();
    assert_eq!(vault.params(), low);
    assert_ne!(vault.params(), KdfParams::default());
    assert_eq!(vault.get("k").unwrap().secret(), b"v");

    // Re-save with stronger params, then confirm the file now carries them.
    vault.set_params(higher).unwrap();
    vault.save().unwrap();

    let reopened = Vault::open(&path, pw, None).unwrap();
    assert_eq!(reopened.params(), higher);
    assert_eq!(reopened.get("k").unwrap().secret(), b"v");
}

#[test]
fn atomic_save_keeps_exactly_one_file() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"one file only";

    let mut vault = Vault::create(&path, pw, None, fast()).unwrap();
    for i in 0..5 {
        vault.put(format!("k{i}"), format!("v{i}").as_bytes(), Meta::new("k"));
        vault.save().unwrap();
    }

    let count = std::fs::read_dir(dir.path()).unwrap().count();
    assert_eq!(count, 1, "exactly one canonical vault file must remain");
    assert!(path.exists());
}

#[test]
fn set_and_remove_and_meta() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"metadata ops";

    let mut vault = Vault::create(&path, pw, None, fast()).unwrap();
    assert!(vault.is_empty());
    vault.put("k", b"v", Meta::new("original"));
    assert!(vault.contains("k"));
    assert!(!vault.is_empty());

    let mut updated = Meta::new("renamed");
    updated.notes = "changed".into();
    vault.set_meta("k", updated).unwrap();
    assert_eq!(vault.meta("k").unwrap().name, "renamed");

    assert!(matches!(
        vault.set_meta("missing", Meta::new("x")),
        Err(Error::NotFound)
    ));

    let removed = vault.remove("k").unwrap();
    assert_eq!(removed.secret(), b"v");
    assert!(!vault.contains("k"));
    assert!(vault.is_empty());
}

#[test]
fn debug_never_prints_secrets() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());

    let mut vault = Vault::create(&path, b"super secret passphrase", None, fast()).unwrap();
    vault.put("k", b"TOPSECRETVALUE", Meta::new("k"));

    let vault_dbg = format!("{vault:?}");
    assert!(!vault_dbg.contains("super secret passphrase"));
    assert!(!vault_dbg.contains("TOPSECRETVALUE"));
    // Guard against a trivially empty Debug passing: the safe fields must show.
    assert!(vault_dbg.contains("entries"));
    assert!(vault_dbg.contains("path"));

    let entry_dbg = format!("{:?}", vault.get("k").unwrap());
    assert!(!entry_dbg.contains("TOPSECRETVALUE"));
    assert!(entry_dbg.contains("meta"));
}

#[test]
fn put_entry_round_trips() {
    use daemon_wallet_vault::Entry;

    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    let pw = b"put_entry test";

    let mut vault = Vault::create(&path, pw, None, fast()).unwrap();
    let entry = Entry::new(b"prebuilt-secret", Meta::new("prebuilt"));
    assert!(vault.put_entry("k", entry).is_none());
    vault.save().unwrap();

    let reopened = Vault::open(&path, pw, None).unwrap();
    let got = reopened.get("k").unwrap();
    assert_eq!(got.secret(), b"prebuilt-secret");
    assert_eq!(got.meta().name, "prebuilt");
}

#[test]
fn empty_entry_secret_is_never_locked() {
    use daemon_wallet_vault::Entry;

    let entry = Entry::new(b"", Meta::new("x"));
    assert!(!entry.is_secret_locked());
}

#[test]
fn not_a_vault_file_is_rejected() {
    let dir = tempfile::tempdir().unwrap();
    let path = tmp_path(dir.path());
    std::fs::write(&path, b"this is not a vault file at all").unwrap();

    assert!(matches!(
        Vault::open(&path, b"whatever", None).unwrap_err(),
        Error::BadMagic
    ));
}
