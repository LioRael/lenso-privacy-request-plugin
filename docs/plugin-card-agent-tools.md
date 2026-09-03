# Privacy Request Agent Tools Plugin cards

## Requester adapter

`lenso.privacy-request.requester.agent-tools` is a private, stateless adapter
for an App Agent. Removing it removes only the Agent's ability to create, list,
inspect metadata for, and withdraw the authenticated requester's own privacy
requests. Privacy Request retains every workflow fact, authorization decision,
idempotency receipt, revision, result payload, and PostgreSQL lifecycle.

It provides `lenso.agent.tool-provider@2` in the `tool-providers` root slot and
requires exactly one `lenso.privacy-request@1`. The invocation context is
forwarded unchanged. Its metadata inspection Tool omits access/export payloads
from model and Session context while preserving item names, media types, and
provider provenance.

## Administrator adapter

`lenso.privacy-request.admin.agent-tools` is a separate private, stateless
adapter for a Console Agent. Removing it removes only Agent-driven queue and
activity inspection, identity decisions, legal hold, pause/resume, and
rejection. It provides `lenso.agent.tool-provider@2` and requires exactly one
`lenso.privacy-request-admin@1`.

Privacy Request retains exact caller admission, operation-scoped Auth,
Organization membership, Access Control, revision checks, idempotency, state
transitions, evidence bounds, and final authorization. The adapter does not
claim legal compliance and exposes no requester result payloads.

## Deliberate exclusions

Neither adapter provides or requires `lenso.privacy-request-worker@1`. Claim,
process, complete, fail, and retry remain worker-owned operations. The two Tool
Providers share no configuration, state, or authority and can be selected or
removed independently by their respective Agent identities.
