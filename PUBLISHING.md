# Publishing to crates.io

The crate is named **`nightwatch-ndr`** because the crates.io name
`nightwatch` is already registered. The command-line executable remains
`nightwatch`; the library crate is `nightwatch_ndr`.

## One-time setup

1. Create a crates.io API token with publish rights for `nightwatch-ndr`.
2. In GitHub, open **Settings → Environments**, create the `crates-io`
   environment used by the release workflow, and add an environment secret
   named `CARGO_REGISTRY_TOKEN` containing that token.
3. Ensure the crates.io account has permission to publish the crate name. For a
   first release, the token owner may need to create the crate once locally
   with `cargo publish --locked` or claim the name on crates.io.

No crates.io token was supplied in the session that configured this repository,
so the secret is intentionally not set here and version 0.1.0 is **not yet
published**.

## Release checklist

1. Update `Cargo.toml` to the new version and add a `CHANGELOG.md` entry.
2. Verify locally:

   ```sh
   cargo test --locked --all-targets
   cargo publish --dry-run --locked
   ```

3. Merge to `main` after the [CI workflow](.github/workflows/ci.yml) passes on
   Ubuntu, Windows and macOS.
4. Tag the exact release commit with a tag matching the manifest version:

   ```sh
   git tag v0.1.0
   git push origin v0.1.0
   ```

5. The [release workflow](.github/workflows/release.yml) checks that the tag
   matches `Cargo.toml`, runs the tests and `cargo publish --dry-run --locked`,
   publishes with `cargo publish --locked` using `CARGO_REGISTRY_TOKEN`, then
   creates a GitHub release with generated notes.
6. Confirm the release on <https://crates.io/crates/nightwatch-ndr>,
   <https://docs.rs/nightwatch-ndr> and the repository Releases page.

`workflow_dispatch` on the release workflow performs verification only; only a
`v*` tag can publish. Each crates.io version is immutable, so a failed upload
requires a version bump.
