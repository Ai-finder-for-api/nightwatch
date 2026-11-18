# Vendored qs_crypt subset

The `src/` and `include/` trees are a copy from
<https://github.com/Ai-finder-for-api/qs_crypt> at upstream commit
`7c6683042a4fb0fe43a7c8cb49e43702a996a5cd`, which includes the dual
`MIT OR Apache-2.0` licensing added in parent commit
`f4dd57f9aa9a58e9f34f2ea98599895d05e92fb5`. Copies of the license texts and the attribution
notice are in this directory.

`../../build.rs` compiles only the C files NIGHTWATCH uses (hashes, keys, OS
entropy, ChaCha20-Poly1305 and sealed containers), with `cc`, on Linux, macOS
and Windows. It deliberately excludes upstream modules that NIGHTWATCH does not
call, including X25519 code that requires `unsigned __int128` and cannot compile
with MSVC.

qs_crypt is not independently audited. See `HANDOFF.md` and
`../../THIRD_PARTY_NOTICES.md`.
