//! Safe wrapper over the vendored `qs_crypt` C library (FFI).
//!
//! Used for: SHA3-256 integrity digests of reports, ChaCha20-Poly1305 sealed
//! (encrypted + authenticated) report export, and OS-entropy key generation.
//! The C library is built by `build.rs` on Linux, macOS and Windows.
//! Nothing here touches the network.

use anyhow::{anyhow, bail, Result};
use std::os::raw::c_char;
use std::sync::Once;

#[repr(C)]
struct Slice {
    data: *const u8,
    length: u64,
}
#[repr(C)]
struct Buffer {
    data: *mut u8,
    length: u64,
}
#[repr(C)]
struct Digest {
    data: [u8; 64],
    length: u64,
}
#[repr(C)]
struct KeyHandle {
    _p: [u8; 0],
}

const ALG_CHACHA20_POLY1305: u32 = 0x0110;
const ALG_SHA3_256: u32 = 0x0210;

extern "C" {
    fn qsc_init() -> u32;
    fn qsc_build_info() -> *const c_char;
    fn qsc_hash(alg: u32, input: Slice, out: *mut Digest) -> u32;
    fn qsc_key_generate(alg: u32, key: *mut *mut KeyHandle) -> u32;
    fn qsc_key_import(alg: u32, raw: Slice, key: *mut *mut KeyHandle) -> u32;
    fn qsc_key_destroy(key: *mut KeyHandle);
    fn qsc_seal(key: *const KeyHandle, aad: Slice, pt: Slice, out: *mut Buffer) -> u32;
    fn qsc_open(key: *const KeyHandle, aad: Slice, ct: Slice, out: *mut Buffer) -> u32;
    fn qsc_buffer_free(buf: *mut Buffer);
}

pub const KEY_LEN: usize = 32;
const AAD: &[u8] = b"nightwatch-report-v1";

fn slice(b: &[u8]) -> Slice {
    Slice { data: b.as_ptr(), length: b.len() as u64 }
}

/// Initialise the library once (checks OS entropy availability).
pub fn init() -> Result<()> {
    static ONCE: Once = Once::new();
    let mut rc = 0;
    ONCE.call_once(|| rc = unsafe { qsc_init() });
    if rc != 0 {
        bail!("qs_crypt init failed (code {rc}); OS entropy unavailable");
    }
    Ok(())
}

pub fn build_info() -> String {
    unsafe { std::ffi::CStr::from_ptr(qsc_build_info()).to_string_lossy().into_owned() }
}

/// SHA3-256 digest as lowercase hex.
pub fn sha3_256_hex(data: &[u8]) -> Result<String> {
    init()?;
    let mut d = Digest { data: [0; 64], length: 0 };
    let rc = unsafe { qsc_hash(ALG_SHA3_256, slice(data), &mut d) };
    if rc != 0 {
        bail!("qs_crypt hash failed (code {rc})");
    }
    Ok(d.data[..d.length as usize].iter().map(|b| format!("{b:02x}")).collect())
}

/// A 256-bit ChaCha20-Poly1305 key owned by the C library (zeroized on drop).
pub struct Key(*mut KeyHandle);

impl Key {
    pub fn generate() -> Result<Key> {
        init()?;
        let mut k = std::ptr::null_mut();
        let rc = unsafe { qsc_key_generate(ALG_CHACHA20_POLY1305, &mut k) };
        if rc != 0 || k.is_null() {
            bail!("key generation failed (code {rc})");
        }
        Ok(Key(k))
    }
    pub fn from_bytes(raw: &[u8]) -> Result<Key> {
        init()?;
        if raw.len() != KEY_LEN {
            bail!("key must be exactly {KEY_LEN} bytes, got {}", raw.len());
        }
        let mut k = std::ptr::null_mut();
        let rc = unsafe { qsc_key_import(ALG_CHACHA20_POLY1305, slice(raw), &mut k) };
        if rc != 0 || k.is_null() {
            bail!("key import rejected (code {rc}; weak or invalid key)");
        }
        Ok(Key(k))
    }
    /// Encrypt + authenticate. Output is a self-describing qs_crypt container.
    pub fn seal(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Buffer { data: std::ptr::null_mut(), length: 0 };
        let rc = unsafe { qsc_seal(self.0, slice(AAD), slice(plaintext), &mut out) };
        if rc != 0 {
            return Err(anyhow!("seal failed (code {rc})"));
        }
        let v = unsafe { std::slice::from_raw_parts(out.data, out.length as usize).to_vec() };
        unsafe { qsc_buffer_free(&mut out) };
        Ok(v)
    }
    /// Verify + decrypt. Any tampering or wrong key returns an error.
    pub fn open(&self, container: &[u8]) -> Result<Vec<u8>> {
        let mut out = Buffer { data: std::ptr::null_mut(), length: 0 };
        let rc = unsafe { qsc_open(self.0, slice(AAD), slice(container), &mut out) };
        if rc != 0 {
            return Err(anyhow!("open failed (code {rc}): wrong key, corrupted or tampered data"));
        }
        let v = unsafe { std::slice::from_raw_parts(out.data, out.length as usize).to_vec() };
        unsafe { qsc_buffer_free(&mut out) };
        Ok(v)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        unsafe { qsc_key_destroy(self.0) }
    }
}

/// Generate a fresh random key using qs_crypt's OS entropy source, as raw bytes.
pub fn random_key_bytes() -> Result<Vec<u8>> {
    // qs_crypt does not export key bytes from Key here; read OS entropy via a
    // freshly hashed pair of keys would be indirect, so use the OS RNG directly.
    crate::platform::os_random(KEY_LEN)
}
