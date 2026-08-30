# Privacy Request v1 Plugin card

## Owner and deletion boundary

The PostgreSQL Plugin owns Organization-local request numbers, requests,
provider snapshots and outcomes, bounded export items, caller-scoped command
receipts, process leases, and append-only activity evidence. Removing its
package, Instance, bindings, and owned schema removes this workflow without
deleting Organizations, Auth identities, memberships, Access Control policy, or
the product data owned by export/retention providers.

## Role contracts

`lenso.privacy-request@1` is the resource-owner role. Its storage predicates
prevent a requester from reading, listing, or withdrawing another subject's
request even if a caller or policy is misconfigured.

`lenso.privacy-request-admin@1` is the verification, decision, legal-hold, and
evidence role. Its bounded list is ordered by deadline and supports status,
type, and requester filters. It does not execute provider side effects.

`lenso.privacy-request-worker@1` is the assigned execution role. It cannot
verify identity, set a legal hold, or make a rejection decision. `claim_next`
uses `FOR UPDATE SKIP LOCKED`; the returned revision plus assignee relationship
fences every later process/complete/fail/retry call. Explicit-ID claim and
process remain available for durable recovery and external dispatchers.

## Provider orchestration

Access and export snapshot every bound `lenso.data-export-source@1` Instance.
Erasure snapshots every bound `lenso.retention-participant@1` Instance.
Correction and restriction snapshot one manual-evidence step until a standard
participant contract exists.

The stable snapshot lives in PostgreSQL. A process command records a renewable,
bounded lease before provider calls, persists every outcome separately, and
stores its exact response only after recomputing all step counts. Same-key calls
during the lease return `operation_in_progress`; an expired lease resumes only
unfinished steps. New providers do not silently join an in-flight request.

Provider rejection, protocol violations, runtime failure, missing providers,
and size-limit failures are durable failed steps. They return a truthful partial
result and can be retried, but they never satisfy the completion guard.

The source contract itself has no cursor. Each source must therefore return one
bounded inline result. The worker cursor is only a keyset over frozen provider
steps, and public/admin cursors are keysets over owned requests/activity.

## State machine

The normal path is `pending_verification -> ready -> claimed -> processing ->
awaiting_completion -> completed`. `paused`, `failed`, `rejected`, and
`withdrawn` are explicit branches. Failed identity verification leaves the
request awaiting a new verification decision. Legal hold forces `paused`; its
removal still requires `resume_request`. Withdrawal is allowed only before a
provider/manual step exists, because downstream side effects may be
irreversible.

The configured deadline and computed overdue flag are operational evidence,
not a statement about a statutory deadline. Neither this state machine nor its
activity records are a legal-compliance certification.

A legal hold blocks dispatch at each process-call boundary and prevents final
completion. It cannot undo a provider call that was already dispatched when the
hold arrived; the finishing transaction preserves the paused state and records
the provider outcome as evidence instead of silently resuming the request.

## Security and durability

All three roles require exact caller allowlists, exact-operation ActorAssertion,
active membership, and Access Control. Request-owner and worker-assignee checks
are performed in storage after locking the target row. Dependency domain errors
never become allow decisions.

Setup and upgrade are operator-managed. Activation only checks the authored
migration plan. PostgreSQL is the sole durable state, so idempotency receipts,
revisions, legal holds, provider progress, and activity survive restart.
