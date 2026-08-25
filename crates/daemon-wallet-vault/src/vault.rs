//! The vault type, its entries, and their metadata.
//!
//! A [`Vault`] holds entries in memory once unlocked. Each entry is an id mapped
//! to a secret byte blob plus [`Meta`]. On [`Vault::save`] the entry map is
//! encoded with CBOR, encrypted, and written atomically to the single canonical
//! path.
//!
//! While unlocked the vault keeps the password (in a locked, zeroizing
//! [`SecretBytes`] buffer) and the keyfile digest so it can re-derive the key on
//! save without prompting again. A fresh salt and nonce are generated on every
//! save.

use std::collections::BTreeMap;
use std::fmt;
use std::fs::File;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::crypto;
use crate::error::{Error, Result};
use crate::format::{
    AEAD_XCHACHA20POLY1305, FLAG_KEYFILE, FORMAT_VERSION, Header, KDF_ARGON2ID, KdfParams,
    NONCE_LEN, SALT_LEN,
};
use crate::secret::SecretBytes;

/// Schema version for the encrypted entry map. Independent of the file format
/// version, this lets the plaintext model evolve on its own.
const PLAINTEXT_VERSION: u16 = 1;

/// Per-entry metadata. Holds no secret material.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    /// Human name for the entry.
    pub name: String,
    /// Free-form tags.
    pub tags: Vec<String>,
    /// Free-form notes.
    pub notes: String,
    /// Creation time, unix seconds.
    pub created: u64,
    /// Last modification time, unix seconds.
    pub modified: u64,
}

impl Meta {
    /// New metadata with the given name and timestamps set to now.
    pub fn new(name: impl Into<String>) -> Self {
        let now = now_unix();
        Self {
            name: name.into(),
            tags: Vec::new(),
            notes: String::new(),
            created: now,
            modified: now,
        }
    }

    /// Bump the modified timestamp to now.
    pub fn touch(&mut self) {
        self.modified = now_unix();
    }
}

/// A single vault entry: secret bytes plus metadata.
#[derive(Clone)]
pub struct Entry {
    secret: SecretBytes,
    meta: Meta,
}

impl Entry {
    /// Build an entry from secret bytes and metadata.
    pub fn new(secret: &[u8], meta: Meta) -> Self {
        Self {
            secret: SecretBytes::new(secret),
            meta,
        }
    }

    /// Borrow the secret bytes.
    pub fn secret(&self) -> &[u8] {
        self.secret.as_slice()
    }

    /// Borrow the metadata.
    pub fn meta(&self) -> &Meta {
        &self.meta
    }

    /// Mutably borrow the metadata.
    pub fn meta_mut(&mut self) -> &mut Meta {
        &mut self.meta
    }

    /// Whether this entry's secret pages are mlock-ed.
    pub fn is_secret_locked(&self) -> bool {
        self.secret.is_locked()
    }
}

impl fmt::Debug for Entry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Entry")
            .field("meta", &self.meta)
            .field("secret", &self.secret)
            .finish()
    }
}

/// An unlocked encrypted vault.
pub struct Vault {
    path: PathBuf,
    entries: BTreeMap<String, Entry>,
    params: KdfParams,
    keyfile_required: bool,
    keyfile_secret: Option<Zeroizing<[u8; 32]>>,
    // The resident master password gets the same mlock + zeroize treatment as
    // the entry secrets it protects.
    password: SecretBytes,
}

impl fmt::Debug for Vault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Never print the password or the keyfile digest.
        f.debug_struct("Vault")
            .field("path", &self.path)
            .field("entries", &self.entries.len())
            .field("params", &self.params)
            .field("keyfile", &self.keyfile_required)
            .finish()
    }
}

impl Vault {
    /// Create a new empty vault and write it to `path`.
    ///
    /// Pass `keyfile` bytes to require that same keyfile on every future open.
    pub fn create(
        path: impl Into<PathBuf>,
        password: &[u8],
        keyfile: Option<&[u8]>,
        params: KdfParams,
    ) -> Result<Self> {
        params.validate()?;
        let vault = Self {
            path: path.into(),
            entries: BTreeMap::new(),
            params,
            keyfile_required: keyfile.is_some(),
            keyfile_secret: keyfile.map(crypto::keyfile_secret),
            password: SecretBytes::new(password),
        };
        vault.save()?;
        Ok(vault)
    }

    /// Open an existing vault at `path`.
    ///
    /// The stored Argon2id parameters are read from the file and used for this
    /// open. A keyfile is required exactly when the vault was created with one.
    pub fn open(path: impl Into<PathBuf>, password: &[u8], keyfile: Option<&[u8]>) -> Result<Self> {
        let path = path.into();
        let raw = std::fs::read(&path)?;
        let (header, header_len) = Header::parse(&raw)?;

        // Reject extreme KDF parameters before deriving anything, so a hostile
        // file cannot force a huge allocation or an unbounded hang pre-auth.
        header.params.check_read_ceiling()?;

        let requires_keyfile = header.requires_keyfile();
        match (requires_keyfile, keyfile.is_some()) {
            (true, false) => return Err(Error::KeyfileRequired),
            (false, true) => return Err(Error::UnexpectedKeyfile),
            _ => {}
        }

        let end = header_len
            .checked_add(header.ct_len as usize)
            .ok_or(Error::MalformedHeader)?;
        if raw.len() < end {
            return Err(Error::MalformedHeader);
        }
        let aad = &raw[..header_len];
        let ciphertext = &raw[header_len..end];

        let keyfile_secret = keyfile.map(crypto::keyfile_secret);
        let key = crypto::derive_key(
            &header.params,
            &header.salt,
            password,
            keyfile_secret.as_ref().map(|s| s.as_slice()),
        )?;

        let plaintext = crypto::open(&key, &header.nonce, aad, ciphertext)?;
        let entries = decode_entries(plaintext.as_slice())?;

        Ok(Self {
            path,
            entries,
            params: header.params,
            keyfile_required: requires_keyfile,
            keyfile_secret,
            password: SecretBytes::new(password),
        })
    }

    /// Encrypt and atomically write the vault to its canonical path.
    pub fn save(&self) -> Result<()> {
        let plaintext = encode_entries(&self.entries)?;

        let mut salt = [0u8; SALT_LEN];
        crypto::fill_random(&mut salt)?;
        let mut nonce = [0u8; NONCE_LEN];
        crypto::fill_random(&mut nonce)?;

        let ct_len = (plaintext.len() + crypto::TAG_LEN) as u64;
        let flags = if self.keyfile_required {
            FLAG_KEYFILE
        } else {
            0
        };
        let header = Header {
            version: FORMAT_VERSION,
            kdf_id: KDF_ARGON2ID,
            aead_id: AEAD_XCHACHA20POLY1305,
            params: self.params,
            flags,
            salt: salt.to_vec(),
            nonce: nonce.to_vec(),
            ct_len,
        };
        let aad = header.to_bytes();

        let key = crypto::derive_key(
            &self.params,
            &salt,
            self.password.as_slice(),
            self.keyfile_secret.as_ref().map(|s| s.as_slice()),
        )?;
        let ciphertext = crypto::seal(&key, &nonce, &aad, &plaintext)?;

        let mut file_bytes = Vec::with_capacity(aad.len() + ciphertext.len());
        file_bytes.extend_from_slice(&aad);
        file_bytes.extend_from_slice(&ciphertext);

        atomic_write(&self.path, &file_bytes)
    }

    /// Insert or replace an entry, returning the previous one if any.
    pub fn put(&mut self, id: impl Into<String>, secret: &[u8], meta: Meta) -> Option<Entry> {
        self.entries.insert(id.into(), Entry::new(secret, meta))
    }

    /// Insert or replace a fully built entry.
    pub fn put_entry(&mut self, id: impl Into<String>, entry: Entry) -> Option<Entry> {
        self.entries.insert(id.into(), entry)
    }

    /// Borrow an entry by id.
    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// Remove an entry, returning it if it existed.
    pub fn remove(&mut self, id: &str) -> Option<Entry> {
        self.entries.remove(id)
    }

    /// Whether an entry exists.
    pub fn contains(&self, id: &str) -> bool {
        self.entries.contains_key(id)
    }

    /// Number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the vault has no entries.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Iterate entry ids in sorted order.
    pub fn ids(&self) -> impl Iterator<Item = &str> {
        self.entries.keys().map(String::as_str)
    }

    /// Borrow an entry's metadata.
    pub fn meta(&self, id: &str) -> Option<&Meta> {
        self.entries.get(id).map(Entry::meta)
    }

    /// Replace an entry's metadata.
    pub fn set_meta(&mut self, id: &str, meta: Meta) -> Result<()> {
        match self.entries.get_mut(id) {
            Some(entry) => {
                *entry.meta_mut() = meta;
                Ok(())
            }
            None => Err(Error::NotFound),
        }
    }

    /// The Argon2id parameters that will be used on the next save.
    pub fn params(&self) -> KdfParams {
        self.params
    }

    /// Set the Argon2id parameters for the next save. Use this to upgrade an
    /// old low-cost vault: set stronger params, then call [`Vault::save`].
    pub fn set_params(&mut self, params: KdfParams) -> Result<()> {
        params.validate()?;
        self.params = params;
        Ok(())
    }

    /// Whether this vault is keyfile protected.
    pub fn uses_keyfile(&self) -> bool {
        self.keyfile_required
    }

    /// The canonical path this vault reads from and writes to.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

// --- serde wire model ---------------------------------------------------------

/// Serialize side. Borrows straight from the locked secrets so no plaintext
/// copies are made beyond the CBOR output buffer.
#[derive(Serialize)]
struct DbOut<'a> {
    version: u16,
    entries: BTreeMap<&'a str, EntryOut<'a>>,
}

#[derive(Serialize)]
struct EntryOut<'a> {
    #[serde(with = "serde_bytes")]
    secret: &'a [u8],
    meta: &'a Meta,
}

/// Deserialize side. Owns the decoded bytes, which are moved into locked buffers.
#[derive(Deserialize)]
struct DbIn {
    version: u16,
    entries: BTreeMap<String, EntryIn>,
}

#[derive(Deserialize)]
struct EntryIn {
    #[serde(with = "serde_bytes")]
    secret: Vec<u8>,
    meta: Meta,
}

fn encode_entries(entries: &BTreeMap<String, Entry>) -> Result<Zeroizing<Vec<u8>>> {
    let db = DbOut {
        version: PLAINTEXT_VERSION,
        entries: entries
            .iter()
            .map(|(id, entry)| {
                (
                    id.as_str(),
                    EntryOut {
                        secret: entry.secret(),
                        meta: entry.meta(),
                    },
                )
            })
            .collect(),
    };
    let mut buf = Zeroizing::new(Vec::new());
    ciborium::into_writer(&db, &mut *buf).map_err(|_| Error::Serialize)?;
    Ok(buf)
}

fn decode_entries(plaintext: &[u8]) -> Result<BTreeMap<String, Entry>> {
    // Known gap: ciborium's internal decode scratch is not zeroized. The source
    // plaintext buffer and the final secret buffers below are. Left for review.
    let db: DbIn = ciborium::from_reader(plaintext).map_err(|_| Error::Deserialize)?;
    if db.version != PLAINTEXT_VERSION {
        return Err(Error::Deserialize);
    }
    let mut out = BTreeMap::new();
    for (id, entry) in db.entries {
        out.insert(
            id,
            Entry {
                secret: SecretBytes::from_vec(entry.secret),
                meta: entry.meta,
            },
        );
    }
    Ok(out)
}

// --- helpers ------------------------------------------------------------------

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Write `bytes` to `path` by writing a temp file in the same directory,
/// fsyncing it, then renaming over the target. The rename is atomic on the
/// same filesystem, so a reader ever sees the old file or the new one whole.
fn atomic_write(path: &Path, bytes: &[u8]) -> Result<()> {
    let dir = match path.parent() {
        Some(p) if !p.as_os_str().is_empty() => p,
        _ => Path::new("."),
    };

    let mut tmp = tempfile::Builder::new()
        .prefix(".dwvault-")
        .suffix(".tmp")
        .tempfile_in(dir)?;
    tmp.write_all(bytes)?;
    tmp.as_file().sync_all()?;
    tmp.persist(path).map_err(|e| Error::Io(e.error))?;

    // Best-effort directory fsync so the rename itself is durable. Not every
    // platform supports this, so failures are ignored.
    if let Ok(dir_file) = File::open(dir) {
        let _ = dir_file.sync_all();
    }
    Ok(())
}
