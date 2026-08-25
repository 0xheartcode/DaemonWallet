//! Password strength assessment.
//!
//! This scores a password rather than blocking it. The caller decides what to
//! do with a low score. The floor is configurable and starts at 12 characters,
//! well above the old 8-character habit.
//!
//! The entropy figure is a rough estimate from character-class variety and
//! length. It is a guide, not a promise, since it cannot see dictionary words
//! or reuse.

/// Policy thresholds for what counts as acceptable.
#[derive(Clone, Debug)]
pub struct StrengthPolicy {
    /// Minimum character length to be considered acceptable.
    pub min_length: usize,
    /// Minimum estimated entropy in bits to be considered acceptable.
    pub min_bits: f64,
}

impl Default for StrengthPolicy {
    fn default() -> Self {
        Self {
            min_length: 12,
            min_bits: 60.0,
        }
    }
}

/// Result of assessing a password.
#[derive(Clone, Debug)]
pub struct StrengthReport {
    /// Character length.
    pub length: usize,
    /// Rough entropy estimate in bits.
    pub estimated_bits: f64,
    /// Bucketed score from 0 (weak) to 4 (strong).
    pub score: u8,
    /// Whether the password meets the policy.
    pub acceptable: bool,
    /// Human-readable notes about weaknesses.
    pub warnings: Vec<String>,
}

/// Assess `password` against `policy`.
pub fn assess_password(password: &str, policy: &StrengthPolicy) -> StrengthReport {
    let length = password.chars().count();

    let mut has_lower = false;
    let mut has_upper = false;
    let mut has_digit = false;
    let mut has_symbol = false;
    let mut has_other = false;
    for c in password.chars() {
        if c.is_ascii_lowercase() {
            has_lower = true;
        } else if c.is_ascii_uppercase() {
            has_upper = true;
        } else if c.is_ascii_digit() {
            has_digit = true;
        } else if c.is_ascii() {
            has_symbol = true;
        } else {
            has_other = true;
        }
    }

    let mut pool = 0u32;
    if has_lower {
        pool += 26;
    }
    if has_upper {
        pool += 26;
    }
    if has_digit {
        pool += 10;
    }
    if has_symbol {
        pool += 33;
    }
    if has_other {
        // Conservative allowance for non-ascii input.
        pool += 100;
    }

    let estimated_bits = if pool == 0 || length == 0 {
        0.0
    } else {
        length as f64 * (pool as f64).log2()
    };

    let mut warnings = Vec::new();
    if length < policy.min_length {
        warnings.push(format!(
            "shorter than the {}-character minimum",
            policy.min_length
        ));
    }
    let classes = [has_lower, has_upper, has_digit, has_symbol, has_other]
        .iter()
        .filter(|x| **x)
        .count();
    if classes <= 1 {
        warnings.push("uses only one kind of character".to_string());
    }
    if estimated_bits < policy.min_bits {
        warnings.push(format!(
            "estimated entropy {estimated_bits:.0} bits is below the {:.0}-bit target",
            policy.min_bits
        ));
    }

    let score = match estimated_bits {
        b if b < 28.0 => 0,
        b if b < 40.0 => 1,
        b if b < 60.0 => 2,
        b if b < 100.0 => 3,
        _ => 4,
    };

    let acceptable = length >= policy.min_length && estimated_bits >= policy.min_bits;

    StrengthReport {
        length,
        estimated_bits,
        score,
        acceptable,
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_password_is_weak() {
        let r = assess_password("", &StrengthPolicy::default());
        assert_eq!(r.score, 0);
        assert!(!r.acceptable);
        assert_eq!(r.estimated_bits, 0.0);
    }

    #[test]
    fn short_password_is_flagged() {
        let r = assess_password("abc", &StrengthPolicy::default());
        assert!(!r.acceptable);
        assert!(r.warnings.iter().any(|w| w.contains("minimum")));
    }

    #[test]
    fn long_mixed_password_is_acceptable() {
        let r = assess_password("Tr0ub4dor&3xtra-Long-Phrase", &StrengthPolicy::default());
        assert!(r.acceptable);
        assert!(r.score >= 3);
    }

    #[test]
    fn policy_is_configurable() {
        let strict = StrengthPolicy {
            min_length: 40,
            min_bits: 200.0,
        };
        let r = assess_password("Tr0ub4dor&3", &strict);
        assert!(!r.acceptable);
    }

    // Assert the entropy for each isolated character class. Each single-class
    // password pins one branch of the pool sum, so a mutated contribution
    // (for example += turned into *= or -=, which zeroes or underflows the
    // pool) is caught by the exact-bits check.
    fn assert_bits(password: &str, expected: f64) {
        let r = assess_password(password, &StrengthPolicy::default());
        assert!(
            (r.estimated_bits - expected).abs() < 0.5,
            "{password:?} gave {} bits, expected ~{expected}",
            r.estimated_bits
        );
    }

    #[test]
    fn entropy_estimate_is_exact_per_class() {
        assert_bits("abcdefghijklmnop", 75.2); // 16 lower, pool 26
        assert_bits("ABCDEFGHIJKLMNOP", 75.2); // 16 upper, pool 26
        assert_bits("0123456789012345", 53.2); // 16 digit, pool 10
        assert_bits("!@#$%^&*()_+-=[]", 80.7); // 16 symbols, pool 33
        assert_bits("日本語一二三四五六七", 66.4); // 10 non-ascii, pool 100
    }

    #[test]
    fn twelve_lowercase_meets_length_but_fails_entropy() {
        // 12 lowercase is exactly the length floor but only ~56.4 bits, under 60.
        let r = assess_password("abcdefghijkl", &StrengthPolicy::default());
        assert_eq!(r.length, 12);
        assert!(!r.acceptable);
        assert!(r.warnings.iter().all(|w| !w.contains("minimum")));
        assert!(r.warnings.iter().any(|w| w.contains("entropy")));
    }

    #[test]
    fn single_class_warns_but_multi_class_does_not() {
        let single = assess_password("abc", &StrengthPolicy::default());
        assert!(single.warnings.iter().any(|w| w.contains("one kind")));

        let multi = assess_password("Ab1!wxyz", &StrengthPolicy::default());
        assert!(multi.warnings.iter().all(|w| !w.contains("one kind")));
    }

    #[test]
    fn min_length_warning_boundary() {
        let default = StrengthPolicy::default();
        let at_floor = assess_password("abcdefghijkl", &default); // 12 chars
        assert!(at_floor.warnings.iter().all(|w| !w.contains("minimum")));

        let below = assess_password("abcdefghijk", &default); // 11 chars
        assert!(below.warnings.iter().any(|w| w.contains("minimum")));
    }

    #[test]
    fn score_buckets_are_exact() {
        let default = StrengthPolicy::default();
        // 7 lowercase -> 32.9 bits -> bucket 1.
        assert_eq!(assess_password("abcdefg", &default).score, 1);
        // 9 lowercase -> 42.3 bits -> bucket 2.
        assert_eq!(assess_password("abcdefghi", &default).score, 2);
        // 16 lowercase -> 75.2 bits -> bucket 3. Pins the 60..100 arm so it is
        // not folded into bucket 4.
        assert_eq!(assess_password("abcdefghijklmnop", &default).score, 3);
        // 16 chars over a 95-symbol pool -> 105.1 bits -> bucket 4.
        assert_eq!(assess_password("Abcdef1!Ghijkl2@", &default).score, 4);
    }
}
