# daemon-wallet-vault

A generic, wallet-agnostic encrypted secret vault for Rust. It stores arbitrary
secret blobs plus metadata, encrypted at rest, in a small self-describing
binary file. Nothing in this crate knows about wallets, keys, or any
particular use of the stored bytes, it is just an id mapped to opaque secret
bytes and a metadata record.

## What it does

- Key derivation: Argon2id, 32-byte output, with the parameters used stored
  in the file and honored on read, so old files keep opening after the
  defaults change.
- Encryption: XChaCha20-Poly1305 with a random 24-byte nonce. The entire file
  header is authenticated as associated data, so tampering with any header
  field fails the tag check.
- Optional keyfile second factor: a BLAKE2b-256 digest of keyfile bytes is
  mixed into Argon2id as its secret input. Without the correct keyfile the
  derived key differs and the open fails.
- In-memory secrets are held in a zeroize-on-drop buffer that is mlock-ed
  where the OS allows it, so plaintext is wiped promptly and, best effort,
  never swapped to disk.
- Saves are atomic: the vault is encoded, encrypted, written to a temp file
  in the same directory, fsynced, then renamed over the target, so a reader
  never observes a partially written file.
- The on-disk format is versioned and self-describing (magic bytes, format
  version, KDF and AEAD identifiers, parameters, salt, nonce), defined and
  parsed entirely by this crate.

## Usage

```rust
use daemon_wallet_vault::{KdfParams, Meta, Vault};

fn main() -> daemon_wallet_vault::Result<()> {
    let path = "secrets.vault";
    let mut vault = Vault::create(path, b"a strong passphrase", None, KdfParams::default())?;
    vault.put("api-token", b"s3cr3t-bytes", Meta::new("Service API token"));
    vault.save()?;

    let reopened = Vault::open(path, b"a strong passphrase", None)?;
    assert_eq!(
        reopened.get("api-token").map(|e| e.secret()),
        Some(&b"s3cr3t-bytes"[..])
    );
    Ok(())
}
```

## Security properties

- Confidentiality and integrity of the whole entry map come from
  XChaCha20-Poly1305, a 256-bit AEAD. A wrong password, a wrong keyfile, and
  a tampered file all fail the same way (`Error::Auth`), so an attacker
  cannot distinguish the cause.
- Argon2id key derivation resists both GPU and side-channel attacks better
  than PBKDF2 or bcrypt at comparable cost.
- Parameters read from a file are checked against a ceiling before any key
  derivation runs, so a hostile file cannot force an unbounded allocation or
  hang before authentication.
- Plaintext secrets and the resident master password are zeroized on drop
  and mlock-ed when the OS permits it.
- The keyfile digest is derived, never stored, so possession of the vault
  file alone does not reveal whether a keyfile is required beyond a single
  header flag bit.

This crate has not been independently audited. Use at your own risk.
