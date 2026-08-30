# Lenso Privacy Request Plugin

A removable, PostgreSQL-backed workflow for handling privacy-related requests
inside a Lenso App. It coordinates product-owned data providers; it does not
claim that installing the Plugin makes an Organization legally compliant.

## Capabilities

The Plugin provides three deliberately separate roles:

- `lenso.privacy-request@1`: requester-owned `create_request`, `get_request`,
  `list_requests`, and `withdraw_request` operations.
- `lenso.privacy-request-admin@1`: bounded status/type queue discovery,
  identity verification, legal hold, pause/resume/reject decisions, and paged
  activity evidence.
- `lenso.privacy-request-worker@1`: atomic `claim_next`, explicit-ID claim,
  bounded processing, completion, failure, and retry operations.

It requires one Provider for each of `lenso.secrets@1`,
`lenso.organization-membership@1`, and `lenso.access-control@1`, plus bounded
many-provider bindings for `lenso.data-export-source@1` and
`lenso.retention-participant@1`. Privacy Request owns no identity, membership,
or RBAC policy.

## Workflow guarantees

- Request kinds are `access`, `export`, `erasure`, `correction`, and
  `restriction`.
- Every request has a UUID and a stable Organization-local `PRV-N` identifier.
- Creation records an explicit configured deadline. `overdue` is evidence for
  operators; it is not a legal conclusion or an automatic state transition.
- Identity verification is required before work can be claimed. Legal hold
  pauses work, and clearing it does not silently resume execution.
- Every mutation carries a caller-scoped idempotency key. Non-create mutations
  also require an expected decimal revision and use PostgreSQL row locking for
  compare-and-swap.
- Request and activity lists use stable keyset cursors. Worker processing uses
  a request-bound provider-step cursor and a configured per-call bound.
- Worker queue discovery is an atomic deadline-ordered `FOR UPDATE SKIP LOCKED`
  claim. Its returned revision and assignee are the fencing conditions for
  every subsequent worker mutation.
- The first process call freezes a typed, ordered provider Instance snapshot.
  Completed steps are never invoked again. A rejected, unavailable, oversized,
  or failed provider remains retryable and prevents the request from reaching
  `awaiting_completion`.
- `complete_request` succeeds only after every frozen step completed and while
  identity remains verified and no legal hold is active.
- Access/export payloads are stored only after per-provider and aggregate size
  validation, and are returned only to the owning requester after explicit
  completion. Erasure uses stable participant action IDs.
- Correction and restriction use an explicit manual-evidence step in v1 because
  no standard downstream correction/restriction Capability currently exists.

## Authorization

Every operation requires an exact configured caller Instance, an Auth
`ActorAssertion` addressed to that exact capability and operation, active
Organization membership, and an Access Control decision in Organization scope.
Requester reads and withdrawal add a final storage-level owner predicate;
worker progress, completion, failure, and retry add a final assignee predicate.

Permissions are `privacy.requests.use`, `privacy.requests.verify`,
`privacy.requests.hold`, `privacy.requests.decide`, `privacy.requests.audit`,
and `privacy.requests.process`.

## Lifecycle and verification

`PrivacyRequestOperator::setup` and `PrivacyRequestOperator::upgrade` are the
only schema-changing workflows. Runtime activation resolves the database URL
through Secrets and calls `OwnedPostgres::prepare`; it never runs DDL and has no
in-memory fallback.

```sh
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo fmt --all -- --check
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo check --locked --workspace --all-targets --all-features
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo test --locked --workspace --all-features
/Users/leosouthey/Projects/framework/.lenso-tools/bin/lenso-cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
./scripts/check-repository-boundary.sh
```

Set `LENSO_PRIVACY_REQUEST_TEST_DATABASE_URL` to a dedicated PostgreSQL database
whose name contains `test` to run the real restart/concurrency acceptance slice.

## Honest v1 limits

The existing `lenso.data-export-source@1` contract returns one bounded inline
item set and has no intra-provider continuation cursor. This Plugin adds a
cursor only between frozen providers and rejects oversize output rather than
truncating it. The aggregate stored payload defaults to 4 MiB and cannot be
configured above 8 MiB; total item count is independently bounded, leaving
envelope headroom for the public response. v1
has no automated identity proofing, secure download delivery,
jurisdiction policy engine, notification transport, Console contribution, or
standard correction/restriction participant contract.
