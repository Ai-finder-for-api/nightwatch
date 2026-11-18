# Third-party notices

## qs_crypt

- Source: <https://github.com/Ai-finder-for-api/qs_crypt>
- Vendored from upstream commit `7c6683042a4fb0fe43a7c8cb49e43702a996a5cd`
  on `main`; the upstream licensing notice was introduced in parent commit
  `f4dd57f9aa9a58e9f34f2ea98599895d05e92fb5`.
- Location in this repository: `vendor/qs_crypt/`
- License: `MIT OR Apache-2.0`, declared by the upstream repository owner in
  `LICENSE`, `LICENSE-MIT`, `LICENSE-APACHE`, `NOTICE` and `README.md`. Copies
  are included in `vendor/qs_crypt/` and in this crate's package.
- Use: SHA3-256 hashing, symmetric key handling, OS entropy and
  ChaCha20-Poly1305 sealed report containers.
- Build: `build.rs` compiles only the subset of C files needed by NIGHTWATCH.

The upstream `HANDOFF.md` states that qs_crypt has not received an independent
security audit, and describes its known limitations. It is not represented as
production-grade cryptography. Review that document before relying on sealed
reports for sensitive data.

The rest of NIGHTWATCH is dual-licensed under `MIT OR Apache-2.0`; see
`LICENSE-MIT`, `LICENSE-APACHE` and `NOTICE`.
