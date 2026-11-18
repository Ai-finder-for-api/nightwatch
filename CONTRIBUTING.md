# Contributing

NIGHTWATCH is a passive analyzer: contributions must never transmit captured
packets or actively probe external systems.

## Before opening a pull request

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo test --locked --all-targets
cargo package --locked --list
cargo publish --dry-run --locked
```

The same checks run in GitHub Actions on Linux, macOS and Windows. Add tests
for malformed-packet handling, parser changes, rule changes and any new
platform-specific behavior.

## Licensing

By contributing, you agree that your contribution is dual-licensed under
`MIT OR Apache-2.0`. Do not add code whose license is unclear. See
`THIRD_PARTY_NOTICES.md` for vendored code.
