CREATE TABLE privacy_request_sequences (
    organization_id TEXT PRIMARY KEY,
    next_number BIGINT NOT NULL CHECK (next_number > 0)
);

CREATE TABLE privacy_requests (
    request_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    identifier TEXT NOT NULL,
    requester_subject TEXT NOT NULL,
    kind TEXT NOT NULL CHECK (kind IN ('access', 'export', 'erasure', 'correction', 'restriction')),
    description TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('pending_verification', 'ready', 'claimed', 'processing', 'awaiting_completion', 'paused', 'completed', 'rejected', 'withdrawn', 'failed')),
    identity_status TEXT NOT NULL CHECK (identity_status IN ('pending', 'verified', 'failed')),
    identity_evidence_reference TEXT,
    legal_hold BOOLEAN NOT NULL DEFAULT FALSE,
    legal_hold_reason TEXT,
    paused_from_state TEXT,
    paused_reason TEXT,
    assignee_subject TEXT,
    failure_reason TEXT,
    retryable BOOLEAN NOT NULL DEFAULT FALSE,
    revision BIGINT NOT NULL CHECK (revision > 0),
    deadline_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    completed_at TIMESTAMPTZ,
    UNIQUE (organization_id, identifier)
);

CREATE INDEX privacy_requests_owner_page_idx
    ON privacy_requests (organization_id, requester_subject, created_at DESC, request_id DESC);
CREATE INDEX privacy_requests_state_deadline_idx
    ON privacy_requests (organization_id, state, deadline_at ASC, request_id ASC);

CREATE TABLE privacy_request_steps (
    request_id UUID NOT NULL REFERENCES privacy_requests(request_id) ON DELETE CASCADE,
    sequence INTEGER NOT NULL CHECK (sequence > 0),
    provider_kind TEXT NOT NULL CHECK (provider_kind IN ('export', 'retention', 'manual')),
    provider_instance TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'completed', 'failed')),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    error_code TEXT,
    receipt TEXT,
    evidence_reference TEXT,
    item_count BIGINT NOT NULL DEFAULT 0 CHECK (item_count >= 0),
    total_bytes BIGINT NOT NULL DEFAULT 0 CHECK (total_bytes >= 0),
    attempted_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    PRIMARY KEY (request_id, sequence),
    UNIQUE (request_id, provider_kind, provider_instance)
);

CREATE INDEX privacy_request_steps_status_idx
    ON privacy_request_steps (request_id, status, sequence);

CREATE TABLE privacy_export_items (
    request_id UUID NOT NULL REFERENCES privacy_requests(request_id) ON DELETE CASCADE,
    provider_instance TEXT NOT NULL,
    item_name TEXT NOT NULL,
    media_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    payload_bytes BIGINT NOT NULL CHECK (payload_bytes >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (request_id, provider_instance, item_name)
);

CREATE TABLE privacy_request_activity (
    activity_id UUID PRIMARY KEY,
    organization_id TEXT NOT NULL,
    request_id UUID NOT NULL REFERENCES privacy_requests(request_id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    actor_subject TEXT NOT NULL,
    request_revision BIGINT NOT NULL CHECK (request_revision > 0),
    evidence JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX privacy_request_activity_page_idx
    ON privacy_request_activity (request_id, created_at ASC, activity_id ASC);

CREATE TABLE privacy_request_commands (
    caller_instance TEXT NOT NULL,
    idempotency_key TEXT NOT NULL,
    organization_id TEXT NOT NULL,
    request_id UUID NOT NULL REFERENCES privacy_requests(request_id) ON DELETE CASCADE,
    operation TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('started', 'completed')),
    response JSONB,
    lease_until TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (caller_instance, idempotency_key)
);

CREATE INDEX privacy_request_commands_scope_idx
    ON privacy_request_commands (organization_id, request_id);
