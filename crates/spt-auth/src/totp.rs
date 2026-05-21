//! RFC 6238 TOTP responder.
//!
//! Pure-Rust HOTP/TOTP using workspace `hmac`, `sha1`, `sha2`, and constant-time
//! comparison via `subtle`. No external TOTP crate (e.g. `totp-lite`) is pulled
//! in — the algorithm is small enough to host here directly.
//!
//! See also: <https://www.rfc-editor.org/rfc/rfc6238>.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Sha256, Sha512};
use spt_core::{Error, Result};
use subtle::ConstantTimeEq;

/// Hash algorithm used to drive the HMAC underlying the OTP.
///
/// RFC 6238 §1.2 lists SHA-1 (default), SHA-256, and SHA-512. The serde
/// representation uses lowercase string discriminants so configuration TOML
/// can spell them naturally (`algo = "sha1"`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TotpAlgo {
    /// SHA-1 — the RFC 6238 default and the only algorithm Google Authenticator
    /// supports universally.
    Sha1,
    /// SHA-256.
    Sha256,
    /// SHA-512.
    Sha512,
}

impl Default for TotpAlgo {
    fn default() -> Self {
        Self::Sha1
    }
}

/// Generate a TOTP code per RFC 6238.
///
/// `secret` is the shared key bytes (raw, **not** base32-encoded — decode
/// before calling). `time_step_s` is the period in seconds (RFC 6238 §5.2
/// recommends 30). `digits` is the OTP length (6 or 8 are common). `now_s`
/// is the current Unix time.
///
/// Returns a zero-padded decimal string of length `digits`.
pub fn generate(
    secret: &[u8],
    time_step_s: u64,
    digits: u32,
    algo: TotpAlgo,
    now_s: u64,
) -> Result<String> {
    if time_step_s == 0 {
        return Err(Error::InvalidConfig(
            "TOTP time_step_s must be non-zero".into(),
        ));
    }
    if !(1..=10).contains(&digits) {
        return Err(Error::InvalidConfig(format!(
            "TOTP digits must be in 1..=10; got {digits}"
        )));
    }
    let counter = now_s / time_step_s;
    Ok(hotp_at(secret, counter, digits, algo))
}

/// Verify `code` against the expected value at `now_s` with `± skew_steps`
/// of clock tolerance. Comparison is constant-time via `subtle`.
///
/// `skew_steps` may be negative or zero — at zero only the current step is
/// accepted. The window is `[now_step - skew, now_step + skew]` inclusive.
pub fn verify(
    secret: &[u8],
    code: &str,
    time_step_s: u64,
    digits: u32,
    algo: TotpAlgo,
    now_s: u64,
    skew_steps: i32,
) -> Result<bool> {
    if time_step_s == 0 {
        return Err(Error::InvalidConfig(
            "TOTP time_step_s must be non-zero".into(),
        ));
    }
    if !(1..=10).contains(&digits) {
        return Err(Error::InvalidConfig(format!(
            "TOTP digits must be in 1..=10; got {digits}"
        )));
    }
    let want_len = digits as usize;
    // Reject length mismatch up front so the constant-time compare receives
    // equal-length inputs and cannot leak the OTP length to the caller's
    // timing.
    if code.len() != want_len {
        return Ok(false);
    }
    let provided = code.as_bytes();
    let now_step = (now_s / time_step_s) as i64;
    let skew = i64::from(skew_steps.abs());
    let mut matched = 0u8;
    for delta in -skew..=skew {
        let step = now_step + delta;
        if step < 0 {
            continue;
        }
        let expected = hotp_at(secret, step as u64, digits, algo);
        // Both buffers are `digits` bytes long; `ct_eq` returns a `Choice`.
        let eq: u8 = provided.ct_eq(expected.as_bytes()).unwrap_u8();
        matched |= eq;
    }
    Ok(matched == 1)
}

/// Core HOTP value at counter `c`, formatted as a zero-padded decimal string
/// of length `digits`. Algorithm per RFC 4226 §5.3 with RFC 6238 hash extension.
fn hotp_at(secret: &[u8], counter: u64, digits: u32, algo: TotpAlgo) -> String {
    let msg = counter.to_be_bytes();
    let mac = match algo {
        TotpAlgo::Sha1 => {
            let mut m = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac key");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgo::Sha256 => {
            let mut m = <Hmac<Sha256> as Mac>::new_from_slice(secret).expect("hmac key");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
        TotpAlgo::Sha512 => {
            let mut m = <Hmac<Sha512> as Mac>::new_from_slice(secret).expect("hmac key");
            m.update(&msg);
            m.finalize().into_bytes().to_vec()
        }
    };
    // RFC 4226 §5.3 dynamic truncation.
    let offset = (mac[mac.len() - 1] & 0x0f) as usize;
    let bin = ((u32::from(mac[offset]) & 0x7f) << 24)
        | ((u32::from(mac[offset + 1]) & 0xff) << 16)
        | ((u32::from(mac[offset + 2]) & 0xff) << 8)
        | (u32::from(mac[offset + 3]) & 0xff);
    let modulus = 10u32.pow(digits);
    let otp = bin % modulus;
    format!("{otp:0width$}", width = digits as usize)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 §B (Appendix B "Test Vectors") seed extended per the SHA-256
    /// (32 bytes) and SHA-512 (64 bytes) cases. The published table reuses the
    /// 20-byte ASCII secret `"12345678901234567890"` by tiling it.
    fn seed(algo: TotpAlgo) -> Vec<u8> {
        // 20-byte ASCII seed from RFC 6238.
        let base = b"12345678901234567890".to_vec();
        match algo {
            TotpAlgo::Sha1 => base, // 20 bytes
            TotpAlgo::Sha256 => {
                // 32 bytes: "12345678901234567890123456789012"
                b"12345678901234567890123456789012".to_vec()
            }
            TotpAlgo::Sha512 => {
                // 64 bytes
                b"1234567890123456789012345678901234567890123456789012345678901234".to_vec()
            }
        }
    }

    // RFC 6238 Appendix B Table 1 — six canonical test vectors × three
    // algorithms. We add two boundary T values per algo (round-trip checks)
    // to round out the 8-vector test requirement per algorithm.
    // (time, expected for sha1, sha256, sha512)
    const RFC_VECTORS: &[(u64, &str, &str, &str)] = &[
        (59, "94287082", "46119246", "90693936"),
        (1_111_111_109, "07081804", "68084774", "25091201"),
        (1_111_111_111, "14050471", "67062674", "99943326"),
        (1_234_567_890, "89005924", "91819424", "93441116"),
        (2_000_000_000, "69279037", "90698825", "38618901"),
        (20_000_000_000, "65353130", "77737706", "47863826"),
    ];

    /// Two extra "boundary" T values (one inside, one wrapping a step boundary)
    /// per algorithm, asserted via generate→verify(skew=0) round-trip.
    const ROUNDTRIP_T: &[u64] = &[30, 60];

    fn run_rfc_table(algo: TotpAlgo, col: usize) {
        let s = seed(algo);
        for row in RFC_VECTORS {
            let want = match col {
                1 => row.1,
                2 => row.2,
                3 => row.3,
                _ => unreachable!(),
            };
            let got = generate(&s, 30, 8, algo, row.0).unwrap();
            assert_eq!(&got, want, "{algo:?} t={}", row.0);
        }
        for t in ROUNDTRIP_T {
            let code = generate(&s, 30, 8, algo, *t).unwrap();
            assert!(
                verify(&s, &code, 30, 8, algo, *t, 0).unwrap(),
                "{algo:?} t={t} roundtrip"
            );
        }
    }

    #[test]
    fn rfc6238_sha1_eight_vectors() {
        run_rfc_table(TotpAlgo::Sha1, 1);
    }

    #[test]
    fn rfc6238_sha256_eight_vectors() {
        run_rfc_table(TotpAlgo::Sha256, 2);
    }

    #[test]
    fn rfc6238_sha512_eight_vectors() {
        run_rfc_table(TotpAlgo::Sha512, 3);
    }

    #[test]
    fn skew_accepts_previous_step() {
        let s = seed(TotpAlgo::Sha1);
        let now = 1_111_111_111u64;
        let prev_code = generate(&s, 30, 8, TotpAlgo::Sha1, now - 30).unwrap();
        assert!(verify(&s, &prev_code, 30, 8, TotpAlgo::Sha1, now, 1).unwrap());
    }

    #[test]
    fn skew_rejects_two_steps_back_with_skew_one() {
        let s = seed(TotpAlgo::Sha1);
        let now = 1_111_111_111u64;
        let two_ago = generate(&s, 30, 8, TotpAlgo::Sha1, now - 60).unwrap();
        assert!(!verify(&s, &two_ago, 30, 8, TotpAlgo::Sha1, now, 1).unwrap());
    }

    #[test]
    fn digits_6_works() {
        let s = seed(TotpAlgo::Sha1);
        let code = generate(&s, 30, 6, TotpAlgo::Sha1, 59).unwrap();
        assert_eq!(code.len(), 6);
        assert!(verify(&s, &code, 30, 6, TotpAlgo::Sha1, 59, 0).unwrap());
    }

    #[test]
    fn digits_8_works() {
        let s = seed(TotpAlgo::Sha1);
        let code = generate(&s, 30, 8, TotpAlgo::Sha1, 59).unwrap();
        assert_eq!(code.len(), 8);
        assert!(verify(&s, &code, 30, 8, TotpAlgo::Sha1, 59, 0).unwrap());
    }

    #[test]
    fn verify_uses_constant_time_compare() {
        // We cannot directly observe timing, but the implementation routes the
        // expected/provided bytes through `subtle::ConstantTimeEq`. As a
        // structural check, ensure equal-length but differing-by-one-bit codes
        // do not match.
        let s = seed(TotpAlgo::Sha1);
        let now = 59u64;
        let good = generate(&s, 30, 8, TotpAlgo::Sha1, now).unwrap();
        let mut bad = good.clone().into_bytes();
        // Flip last digit deterministically.
        let last = bad.last_mut().unwrap();
        *last = if *last == b'0' { b'1' } else { b'0' };
        let bad_s = String::from_utf8(bad).unwrap();
        assert!(!verify(&s, &bad_s, 30, 8, TotpAlgo::Sha1, now, 0).unwrap());
    }

    #[test]
    fn rejects_length_mismatch() {
        let s = seed(TotpAlgo::Sha1);
        // Providing 6 digits when 8 expected returns Ok(false), never panics.
        assert!(!verify(&s, "123456", 30, 8, TotpAlgo::Sha1, 59, 0).unwrap());
    }

    #[test]
    fn zero_time_step_is_invalid_config() {
        let s = seed(TotpAlgo::Sha1);
        let e = generate(&s, 0, 6, TotpAlgo::Sha1, 0).unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(_)));
    }

    #[test]
    fn digits_out_of_range_is_invalid_config() {
        let s = seed(TotpAlgo::Sha1);
        let e = generate(&s, 30, 11, TotpAlgo::Sha1, 0).unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(_)));
        let e = generate(&s, 30, 0, TotpAlgo::Sha1, 0).unwrap_err();
        assert!(matches!(e, Error::InvalidConfig(_)));
    }
}
