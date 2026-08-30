# Release process

The repository has three public Capability crates:

- `lenso-capability-privacy-request`
- `lenso-capability-privacy-request-admin`
- `lenso-capability-privacy-request-worker`

`lenso-privacy-request-postgres-plugin` is a linked, stateful implementation and
inherits `publish = false`. It is not a portable `.lenso-plugin` archive and is
not published to crates.io by this workflow.

Release planning is automatic, while publication is manual-only. A push to
`main` refreshes the Release-plz PR. Merging that PR does not publish. The
workflow offers a read-only dry run and a live job gated by `ref=main`,
`live=true`, and the literal confirmation `publish`.

## Trusted publishing and first releases

Trusted Publishing cannot allocate a new crate name. Publish version `0.1.0` of
each new Capability crate once from a reviewed, clean `main` checkout using a
temporary crates.io token restricted to new-package publication, then revoke it
immediately. Do not store it in Cargo credentials, repository secrets, workflow
logs, or shell history.

After each crate exists, configure its crates.io Trusted Publisher with:

- repository: `LioRael/lenso-privacy-request-plugin`
- workflow: `release-plz.yml`
- environment: unset

The live workflow obtains a short-lived crates.io credential through GitHub
OIDC. It has `id-token: write` and intentionally has no Cargo registry-token
fallback. Its GitHub token is used only for repository releases.

Bootstrap commands, with the temporary credential supplied by a credential
helper, are:

```sh
cargo publish --locked -p lenso-capability-privacy-request
cargo publish --locked -p lenso-capability-privacy-request-admin
cargo publish --locked -p lenso-capability-privacy-request-worker
```

Create matching GitHub tags/releases from the exact reviewed `main` commit using
`<package>@<version>`. Do not run the live workflow until all three Trusted
Publisher records exactly match the repository and workflow above.

## Release gates

```sh
cargo fmt --all -- --check
cargo check --locked --workspace --all-targets --all-features
cargo test --locked --workspace --all-features
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo package --locked -p lenso-capability-privacy-request
cargo package --locked -p lenso-capability-privacy-request-admin
cargo package --locked -p lenso-capability-privacy-request-worker
./scripts/check-repository-boundary.sh
gh workflow run release-plz.yml --ref main -f live=false
```

After reviewing the dry run and confirming registry state:

```sh
gh workflow run release-plz.yml --ref main -f live=true -f confirm=publish
```

Generated Rust projections must be fresh before packaging. Regenerate them with
`lenso-contract-codegen`; never edit `src/generated.rs` manually.
