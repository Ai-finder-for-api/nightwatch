//! Compiles the vendored qs_crypt C subset on Linux, macOS and Windows.
//!
//! NIGHTWATCH needs hashing, key handling, ChaCha20-Poly1305 and sealed
//! containers. Intentionally unsupported qs_crypt modules (X25519, RSA,
//! ML-KEM, etc.) are not compiled: they are not used here, and some require
//! compiler extensions that MSVC does not support.
use std::path::PathBuf;

const SOURCES: &[&str] = &[
    "src/core/qs_crypt_alloc.c",
    "src/core/qs_crypt_core.c",
    "src/core/qs_crypt_registry.c",
    "src/random/qs_crypt_random.c",
    "src/hash/qs_crypt_hash_dispatch.c",
    "src/hash/qs_crypt_hstate.c",
    "src/hash/qs_crypt_keccak.c",
    "src/hash/qs_crypt_sha256.c",
    "src/hash/qs_crypt_sha512.c",
    "src/mac/qs_crypt_hmac.c",
    "src/kdf/qs_crypt_hkdf.c",
    "src/symmetric/qs_crypt_chacha20.c",
    "src/aead/qs_crypt_poly1305.c",
    "src/aead/qs_crypt_chacha20poly1305.c",
    "src/aead/qs_crypt_aes_gcm.c",
    "src/aead/qs_crypt_aead_dispatch.c",
    "src/serialization/qs_crypt_wire.c",
    "src/containers/qs_crypt_seal.c",
    "src/key_management/qs_crypt_keys.c",
];

fn main() {
    let root = PathBuf::from("vendor/qs_crypt");
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();

    let mut build = cc::Build::new();
    build
        .include(root.join("include"))
        .warnings(false)
        .opt_level(2)
        .define("_CRT_SECURE_NO_WARNINGS", None);

    for source in SOURCES {
        let path = root.join(source);
        assert!(
            path.is_file(),
            "missing vendored qs_crypt source: {}",
            path.display()
        );
        build.file(&path);
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let msvc = build.get_compiler().is_like_msvc();
    if msvc {
        // Needed for C11 _Static_assert and compound literals.
        build.flag_if_supported("/std:c11");
    } else {
        build.flag_if_supported("-std=c11");
    }
    if target_os == "windows" {
        println!("cargo:rustc-link-lib=bcrypt");
    } else {
        build.define("_GNU_SOURCE", None);
        if target_os == "linux" {
            build.flag("-pthread");
            println!("cargo:rustc-link-lib=pthread");
        }
    }

    build.compile("qs_crypt");
    println!("cargo:rerun-if-changed=vendor/qs_crypt/include");
    println!("cargo:rerun-if-changed=build.rs");
}
