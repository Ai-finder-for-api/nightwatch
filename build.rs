use std::path::Path;

fn main() {
    let root = Path::new("third_party/qs_crypt");
    assert!(
        root.join("include/qs_crypt/qs_crypt.h").exists(),
        "missing qs_crypt: run git submodule update --init --recursive"
    );
    let mut c = cc::Build::new();
    c.std("c11")
        .include(root.join("include"))
        .file("native/report_digest.c");
    // Limit the build to the public hash API and its transitive dependencies.
    for src in [
        "hash/qs_crypt_hash_dispatch",
        "hash/qs_crypt_hstate",
        "hash/qs_crypt_sha256",
        "hash/qs_crypt_sha512",
        "hash/qs_crypt_keccak",
        "core/qs_crypt_alloc",
        "core/qs_crypt_core",
        "random/qs_crypt_random",
        "aead/qs_crypt_aes_gcm",
        "mac/qs_crypt_hmac",
    ] {
        c.file(root.join(format!("src/{src}.c")));
    }
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    if os == "linux" {
        c.define("_GNU_SOURCE", None).flag("-pthread");
    }
    c.compile("nightwatch_qs_crypt");
    if os == "windows" {
        println!("cargo:rustc-link-lib=bcrypt");
    }
    if os == "linux" {
        println!("cargo:rustc-link-lib=pthread");
    }
    for path in [
        "native",
        "third_party/qs_crypt/include",
        "third_party/qs_crypt/src",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }
}
