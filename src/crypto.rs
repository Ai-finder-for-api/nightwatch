//! Unkeyed fingerprints for exported report bytes; not signatures or encryption.
use anyhow::{ensure, Result};
use std::ffi::c_int;

extern "C" {
    fn nw_sha256(input: *const u8, n: usize, output: *mut u8) -> c_int;
}

pub fn sha256_hex(input: &[u8]) -> Result<String> {
    let mut output = [0_u8; 32];
    // SAFETY: both buffers remain live for the synchronous call. The adapter
    // reads exactly input.len() bytes and writes exactly 32 bytes on success.
    let rc = unsafe { nw_sha256(input.as_ptr(), input.len(), output.as_mut_ptr()) };
    ensure!(rc == 0, "qs_crypt SHA-256 failed (code {rc})");
    Ok(output.iter().map(|b| format!("{b:02x}")).collect())
}

#[test]
fn sha256_known_answers() {
    for (input, expected) in [
        (
            &b""[..],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        ),
        (
            &b"abc"[..],
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        ),
        (
            &b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"[..],
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        ),
    ] {
        assert_eq!(sha256_hex(input).unwrap(), expected);
    }
}
