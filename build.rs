//! Compiles the vendored qs_crypt C library (cross-platform: Linux, macOS, Windows).
use std::path::{Path, PathBuf};

fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            collect(&p, out);
        } else if p.extension().map_or(false, |x| x == "c") {
            out.push(p);
        }
    }
}

fn main() {
    let root = PathBuf::from("vendor/qs_crypt");
    let mut files = Vec::new();
    collect(&root.join("src"), &mut files);
    files.sort();
    let target = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    let mut b = cc::Build::new();
    b.include(root.join("include")).files(&files).warnings(false).opt_level(2);
    if target != "windows" {
        b.define("_GNU_SOURCE", None).flag_if_supported("-std=c11").flag("-pthread");
    }
    b.compile("qs_crypt");
    match target.as_str() {
        "windows" => println!("cargo:rustc-link-lib=bcrypt"),
        "linux" => println!("cargo:rustc-link-lib=pthread"),
        _ => {}
    }
    println!("cargo:rerun-if-changed=vendor/qs_crypt");
    println!("cargo:rerun-if-changed=build.rs");
}
