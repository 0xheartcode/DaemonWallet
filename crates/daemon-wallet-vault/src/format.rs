//! On-disk file format.
//!
//! The layout is hand-rolled and self-describing so the KDF parameters that
//! were actually used travel with the file. The read path always honors the
//! stored parameters, it never assumes the current defaults. That lets the
//! defaults grow over time without locking anyone out of an old vault.
//!
//! Byte layout (all multi-byte integers are big-endian):
//!
//! ```text
//! offset  size  field
//! 0       8     magic  b"DWVAULT\0"
//! 8       2     format_version  u16
//! 10      1     kdf_id          u8   (1 = Argon2id)
//! 11      1     aead_id         u8   (1 = XChaCha20-Poly1305)
//! 12      4     argon2 m_cost   u32  (memory, KiB)
//! 16      4     argon2 t_cost   u32  (iterations)
//! 20      4     argon2 p_cost   u32  (lanes)
//! 24      1     flags           u8   (bit0 = keyfile required)
//! 25      2     salt_len        u16
//! 27      N     salt            salt_len bytes
//! ..      1     nonce_len       u8
//! ..      M     nonce           nonce_len bytes
//! ..      8     ct_len          u64  (ciphertext + tag length)
//! ..      L     ciphertext+tag  ct_len bytes
//! ```
//!
//! Everything from `magic` through `ct_len` (the whole header) is fed to the
//! AEAD as associated data, so flipping any header field breaks the tag.

use crate::error::{Error, Result};

/// File magic. The trailing byte is not a version, it just keeps the magic
/// eight bytes wide and non-printable at the end.
pub const MAGIC: [u8; 8] = *b"DWVAULT\0";

/// Current on-disk format version.
pub const FORMAT_VERSION: u16 = 1;

/// KDF identifier for Argon2id.
pub const KDF_ARGON2ID: u8 = 1;

/// AEAD identifier for XChaCha20-Poly1305.
pub const AEAD_XCHACHA20POLY1305: u8 = 1;

/// Header flag bit that marks a vault as keyfile protected.
pub const FLAG_KEYFILE: u8 = 0b0000_0001;

/// Salt length in bytes.
pub const SALT_LEN: usize = 16;

/// XChaCha20 nonce length in bytes.
pub const NONCE_LEN: usize = 24;

/// Derived key length in bytes.
pub const KEY_LEN: usize = 32;

/// Argon2id cost parameters stored with, and read back from, each file.
///
/// `m_cost` is memory in KiB, `t_cost` is the iteration count, `p_cost` is the
/// degree of parallelism. The named constants are policy. [`KdfParams::validate`]
/// only enforces the algorithm's hard minimums so old low-cost files still open.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory cost in KiB.
    pub m_cost: u32,
    /// Time cost (iterations).
    pub t_cost: u32,
    /// Parallelism (lanes).
    pub p_cost: u32,
}

impl KdfParams {
    /// OWASP floor for Argon2id, 19 MiB / t=2 / p=1.
    pub const OWASP_FLOOR: KdfParams = KdfParams {
        m_cost: 19_456,
        t_cost: 2,
        p_cost: 1,
    };

    /// Strong desktop default, 64 MiB / t=3 / p=1. Sits well above the floor.
    pub const RECOMMENDED: KdfParams = KdfParams {
        m_cost: 65_536,
        t_cost: 3,
        p_cost: 1,
    };

    /// Read-path memory ceiling in KiB (1 GiB). Anything larger is refused
    /// before allocation so a hostile file cannot exhaust memory.
    pub const MAX_M_COST: u32 = 1_048_576;

    /// Read-path iteration ceiling. Bounds the work an attacker can force.
    pub const MAX_T_COST: u32 = 16;

    /// Read-path parallelism ceiling.
    pub const MAX_P_COST: u32 = 16;

    /// Build a parameter set from raw values.
    pub const fn new(m_cost: u32, t_cost: u32, p_cost: u32) -> Self {
        Self {
            m_cost,
            t_cost,
            p_cost,
        }
    }

    /// Check the values against Argon2's hard minimums.
    ///
    /// This is deliberately loose. It rejects only what the algorithm itself
    /// cannot run, so a file written with weak-but-valid parameters still opens.
    /// Choosing strong parameters is the job of [`KdfParams::RECOMMENDED`].
    pub fn validate(&self) -> Result<()> {
        // saturating_mul avoids a u32 overflow panic on hostile p_cost values.
        let ok = self.p_cost >= 1
            && self.t_cost >= 1
            && self.m_cost >= self.p_cost.max(1).saturating_mul(8);
        if ok {
            Ok(())
        } else {
            Err(Error::InvalidParams)
        }
    }

    /// Reject parameters that exceed the read-path ceiling.
    ///
    /// This runs on open before any key derivation, so a file claiming
    /// `m_cost = u32::MAX` or `t_cost = u32::MAX` is refused instantly rather
    /// than triggering a huge allocation or an unbounded hang. It is separate
    /// from [`KdfParams::validate`], which keeps a loose floor for old files.
    pub fn check_read_ceiling(&self) -> Result<()> {
        let ok = self.m_cost <= Self::MAX_M_COST
            && self.t_cost <= Self::MAX_T_COST
            && self.p_cost <= Self::MAX_P_COST;
        if ok {
            Ok(())
        } else {
            Err(Error::ParamsOutOfRange)
        }
    }
}

impl Default for KdfParams {
    fn default() -> Self {
        Self::RECOMMENDED
    }
}

/// Parsed file header.
#[derive(Clone, Debug)]
pub struct Header {
    /// On-disk format version.
    pub version: u16,
    /// KDF identifier.
    pub kdf_id: u8,
    /// AEAD identifier.
    pub aead_id: u8,
    /// Argon2id parameters used for this file.
    pub params: KdfParams,
    /// Header flags.
    pub flags: u8,
    /// Argon2 salt.
    pub salt: Vec<u8>,
    /// AEAD nonce.
    pub nonce: Vec<u8>,
    /// Length of the ciphertext plus tag that follows the header.
    pub ct_len: u64,
}

impl Header {
    /// Whether the keyfile flag is set.
    pub fn requires_keyfile(&self) -> bool {
        self.flags & FLAG_KEYFILE != 0
    }

    /// Serialize the header to its on-disk byte form. This is also the exact
    /// byte range used as AEAD associated data.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(27 + self.salt.len() + 1 + self.nonce.len() + 8);
        out.extend_from_slice(&MAGIC);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.kdf_id);
        out.push(self.aead_id);
        out.extend_from_slice(&self.params.m_cost.to_be_bytes());
        out.extend_from_slice(&self.params.t_cost.to_be_bytes());
        out.extend_from_slice(&self.params.p_cost.to_be_bytes());
        out.push(self.flags);
        // salt length fits in u16 by construction, guarded on the write path.
        out.extend_from_slice(&(self.salt.len() as u16).to_be_bytes());
        out.extend_from_slice(&self.salt);
        out.push(self.nonce.len() as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.ct_len.to_be_bytes());
        out
    }

    /// Parse a header from the start of `input`.
    ///
    /// Returns the header and the number of bytes it occupied, so the caller
    /// can slice the associated data and the ciphertext.
    pub fn parse(input: &[u8]) -> Result<(Header, usize)> {
        let mut cur = Cursor::new(input);

        let magic = cur.take(8)?;
        if magic != MAGIC {
            return Err(Error::BadMagic);
        }

        let version = cur.u16()?;
        if version != FORMAT_VERSION {
            return Err(Error::UnsupportedVersion(version));
        }

        let kdf_id = cur.u8()?;
        if kdf_id != KDF_ARGON2ID {
            return Err(Error::UnsupportedKdf(kdf_id));
        }

        let aead_id = cur.u8()?;
        if aead_id != AEAD_XCHACHA20POLY1305 {
            return Err(Error::UnsupportedAead(aead_id));
        }

        let m_cost = cur.u32()?;
        let t_cost = cur.u32()?;
        let p_cost = cur.u32()?;
        let flags = cur.u8()?;

        let salt_len = cur.u16()? as usize;
        let salt = cur.take(salt_len)?.to_vec();

        let nonce_len = cur.u8()? as usize;
        if nonce_len != NONCE_LEN {
            return Err(Error::MalformedHeader);
        }
        let nonce = cur.take(nonce_len)?.to_vec();

        let ct_len = cur.u64()?;

        let params = KdfParams::new(m_cost, t_cost, p_cost);
        let header = Header {
            version,
            kdf_id,
            aead_id,
            params,
            flags,
            salt,
            nonce,
            ct_len,
        };
        Ok((header, cur.pos))
    }
}

/// Tiny bounds-checked reader over a byte slice.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.checked_add(n).ok_or(Error::MalformedHeader)?;
        if end > self.buf.len() {
            return Err(Error::MalformedHeader);
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }

    fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_be_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trips() {
        let header = Header {
            version: FORMAT_VERSION,
            kdf_id: KDF_ARGON2ID,
            aead_id: AEAD_XCHACHA20POLY1305,
            params: KdfParams::new(32, 1, 1),
            flags: FLAG_KEYFILE,
            salt: vec![7u8; SALT_LEN],
            nonce: vec![9u8; NONCE_LEN],
            ct_len: 12345,
        };
        let bytes = header.to_bytes();
        let (parsed, consumed) = Header::parse(&bytes).unwrap();
        assert_eq!(consumed, bytes.len());
        assert_eq!(parsed.version, header.version);
        assert_eq!(parsed.params, header.params);
        assert_eq!(parsed.flags, header.flags);
        assert_eq!(parsed.salt, header.salt);
        assert_eq!(parsed.nonce, header.nonce);
        assert_eq!(parsed.ct_len, header.ct_len);
        assert!(parsed.requires_keyfile());
    }

    #[test]
    fn bad_magic_is_rejected() {
        let mut bytes = Header {
            version: FORMAT_VERSION,
            kdf_id: KDF_ARGON2ID,
            aead_id: AEAD_XCHACHA20POLY1305,
            params: KdfParams::new(32, 1, 1),
            flags: 0,
            salt: vec![0u8; SALT_LEN],
            nonce: vec![0u8; NONCE_LEN],
            ct_len: 0,
        }
        .to_bytes();
        bytes[0] ^= 0xff;
        assert!(matches!(Header::parse(&bytes), Err(Error::BadMagic)));
    }

    #[test]
    fn truncated_header_is_rejected() {
        let bytes = Header {
            version: FORMAT_VERSION,
            kdf_id: KDF_ARGON2ID,
            aead_id: AEAD_XCHACHA20POLY1305,
            params: KdfParams::new(32, 1, 1),
            flags: 0,
            salt: vec![0u8; SALT_LEN],
            nonce: vec![0u8; NONCE_LEN],
            ct_len: 0,
        }
        .to_bytes();
        assert!(matches!(
            Header::parse(&bytes[..bytes.len() - 4]),
            Err(Error::MalformedHeader)
        ));
    }

    #[test]
    fn validate_rejects_zero_and_accepts_low() {
        assert!(KdfParams::new(0, 0, 0).validate().is_err());
        assert!(KdfParams::new(8, 1, 1).validate().is_ok());
        assert!(KdfParams::OWASP_FLOOR.validate().is_ok());
        assert!(KdfParams::RECOMMENDED.validate().is_ok());
    }

    #[test]
    fn validate_does_not_overflow_on_hostile_p_cost() {
        // 0x2000_0000 * 8 overflows u32. This must return an error, not panic.
        let hostile = KdfParams::new(1, 1, 0x2000_0000);
        assert!(hostile.validate().is_err());
    }

    #[test]
    fn read_ceiling_rejects_extreme_params() {
        let bomb = KdfParams::new(u32::MAX, u32::MAX, u32::MAX);
        assert!(matches!(
            bomb.check_read_ceiling(),
            Err(Error::ParamsOutOfRange)
        ));
        assert!(KdfParams::RECOMMENDED.check_read_ceiling().is_ok());
        assert!(KdfParams::new(64, 1, 1).check_read_ceiling().is_ok());
    }

    #[test]
    fn read_ceiling_rejects_each_clause_alone() {
        // Exactly one parameter over the ceiling, the other two modest, so each
        // clause of the check is isolated. A single-clause bypass is caught.
        assert!(matches!(
            KdfParams::new(2_000_000, 1, 1).check_read_ceiling(),
            Err(Error::ParamsOutOfRange)
        ));
        assert!(matches!(
            KdfParams::new(64, u32::MAX, 1).check_read_ceiling(),
            Err(Error::ParamsOutOfRange)
        ));
        assert!(matches!(
            KdfParams::new(64, 1, u32::MAX).check_read_ceiling(),
            Err(Error::ParamsOutOfRange)
        ));
    }

    // Base header bytes, valid, that individual bytes can be mutated from.
    fn valid_header_bytes() -> Vec<u8> {
        Header {
            version: FORMAT_VERSION,
            kdf_id: KDF_ARGON2ID,
            aead_id: AEAD_XCHACHA20POLY1305,
            params: KdfParams::new(64, 1, 1),
            flags: 0,
            salt: vec![1u8; SALT_LEN],
            nonce: vec![2u8; NONCE_LEN],
            ct_len: 0,
        }
        .to_bytes()
    }

    #[test]
    fn parse_rejects_bad_version() {
        let mut bytes = valid_header_bytes();
        bytes[9] = 2; // low byte of the version u16 at 8..10
        assert!(matches!(
            Header::parse(&bytes),
            Err(Error::UnsupportedVersion(2))
        ));
    }

    #[test]
    fn parse_rejects_bad_kdf_id() {
        let mut bytes = valid_header_bytes();
        bytes[10] = 2;
        assert!(matches!(
            Header::parse(&bytes),
            Err(Error::UnsupportedKdf(2))
        ));
    }

    #[test]
    fn parse_rejects_bad_aead_id() {
        let mut bytes = valid_header_bytes();
        bytes[11] = 2;
        assert!(matches!(
            Header::parse(&bytes),
            Err(Error::UnsupportedAead(2))
        ));
    }

    #[test]
    fn parse_rejects_bad_nonce_len() {
        let mut bytes = valid_header_bytes();
        // nonce_len sits right after the 16-byte salt at 27..43.
        bytes[27 + SALT_LEN] = 23;
        assert!(matches!(Header::parse(&bytes), Err(Error::MalformedHeader)));
    }
}
