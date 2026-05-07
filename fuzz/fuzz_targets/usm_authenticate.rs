#![no_main]
//! Fuzz USM authentication primitives. Exercises auth_digest with all three
//! HMAC variants over arbitrary key + message inputs, plus the password→key
//! and key-localization flows. We're hunting for panics (slice-out-of-bounds,
//! integer overflow) — the cryptographic correctness is covered by KAT tests.
use libfuzzer_sys::fuzz_target;

use arbitrary::{Arbitrary, Unstructured};
use spt_snmp::usm::{
    auth_digest, derive_keys, digests_match, localize_key, password_to_key, AuthProtocol,
    SecretBytes, UsmUser,
};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    auth_choice: u8,
    key: &'a [u8],
    message: &'a [u8],
    engine_id: &'a [u8],
    password: &'a [u8],
    other_digest: &'a [u8],
}

fn pick_auth(c: u8) -> AuthProtocol {
    match c % 3 {
        0 => AuthProtocol::HmacMd5,
        1 => AuthProtocol::HmacSha1,
        _ => AuthProtocol::HmacSha256,
    }
}

fuzz_target!(|data: &[u8]| {
    let mut u = Unstructured::new(data);
    let Ok(inp) = Input::arbitrary(&mut u) else { return };
    let auth = pick_auth(inp.auth_choice);

    // password_to_key: must accept any-length password without panic.
    let ku = password_to_key(auth, inp.password);

    // localize_key: must accept any engine_id and any ku.
    let _kul_from_ku = localize_key(auth, &ku, inp.engine_id);

    // auth_digest: HMAC variants accept any key length per RFC 2104, but our
    // wrapper uses HMAC's `new_from_slice` which does too. Should never panic.
    if let Ok(digest) = auth_digest(auth, inp.key, inp.message) {
        // Constant-time comparison must accept arbitrary lengths.
        let _ = digests_match(&digest, inp.other_digest);
        // Self-comparison should always be true.
        debug_assert!(digests_match(&digest, &digest));
    }

    // Full UsmUser-driven derivation.
    let user = UsmUser::auth_only(
        "fuzz",
        auth,
        SecretBytes::new(inp.password.to_vec()),
    );
    let _ = derive_keys(&user, inp.engine_id);
});
