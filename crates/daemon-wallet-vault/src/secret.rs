//! In-memory secret buffer.
//!
//! Plaintext lives in a [`Zeroizing`] buffer that is wiped on drop, and the
//! pages are locked with `mlock` so they cannot be swapped to disk. Locking is
//! best effort. On a system where `RLIMIT_MEMLOCK` is too low the lock fails
//! and we keep going unlocked rather than refuse to run.
//!
//! Caveat: `mlock` works on whole pages, so two small secrets that share a page
//! share a lock. This is not a per-secret guarantee, it raises the bar without
//! a dedicated locked allocator.

use std::fmt;

use zeroize::Zeroizing;

/// Owned plaintext bytes, zeroized on drop and mlock-ed when possible.
pub struct SecretBytes {
    // Declared before the lock so the bytes are wiped while the pages are still
    // locked. Drop runs fields in declaration order.
    bytes: Zeroizing<Vec<u8>>,
    lock: Option<region::LockGuard>,
}

impl SecretBytes {
    /// Copy `data` into a new locked, zeroizing buffer.
    pub fn new(data: &[u8]) -> Self {
        Self::from_vec(data.to_vec())
    }

    /// Take ownership of `v` without copying, then lock and guard it.
    pub fn from_vec(v: Vec<u8>) -> Self {
        let bytes = Zeroizing::new(v);
        let lock = try_lock(bytes.as_slice());
        Self { bytes, lock }
    }

    /// Borrow the plaintext.
    pub fn as_slice(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    /// Length in bytes.
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the buffer is empty.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Whether the pages are currently mlock-ed.
    pub fn is_locked(&self) -> bool {
        self.lock.is_some()
    }
}

impl Clone for SecretBytes {
    fn clone(&self) -> Self {
        Self::new(self.bytes.as_slice())
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretBytes")
            .field("len", &self.bytes.len())
            .field("locked", &self.lock.is_some())
            .finish()
    }
}

/// Try to lock the pages backing `buf`. Returns `None` when the buffer is empty
/// or the operating system refuses the lock.
fn try_lock(buf: &[u8]) -> Option<region::LockGuard> {
    if buf.is_empty() {
        return None;
    }
    region::lock(buf.as_ptr(), buf.len()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_bytes() {
        let s = SecretBytes::new(b"hello");
        assert_eq!(s.as_slice(), b"hello");
        assert_eq!(s.len(), 5);
        assert!(!s.is_empty());
    }

    #[test]
    fn empty_is_not_locked() {
        let s = SecretBytes::new(b"");
        assert!(s.is_empty());
        assert!(!s.is_locked());
    }

    #[test]
    fn debug_hides_contents() {
        let s = SecretBytes::new(b"topsecret");
        let shown = format!("{s:?}");
        assert!(!shown.contains("topsecret"));
        assert!(shown.contains("len"));
    }

    #[test]
    fn clone_is_independent() {
        let a = SecretBytes::new(b"abc");
        let b = a.clone();
        assert_eq!(a.as_slice(), b.as_slice());
    }
}
