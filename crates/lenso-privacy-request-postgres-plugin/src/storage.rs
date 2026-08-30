use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use sqlx::{Postgres, Row, Transaction, types::Json};
use thiserror::Error;
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use uuid::Uuid;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct RequestRecord {
    pub(crate) request_id: Uuid,
    pub(crate) identifier: String,
    pub(crate) organization_id: String,
    pub(crate) requester_subject: String,
    pub(crate) kind: String,
    pub(crate) description: String,
    pub(crate) state: String,
    pub(crate) identity_status: String,
    pub(crate) legal_hold: bool,
    pub(crate) assignee_subject: Option<String>,
    #[serde(with = "decimal_i64")]
    pub(crate) revision: i64,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) deadline_at: OffsetDateTime,
    pub(crate) overdue: bool,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) created_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) updated_at: OffsetDateTime,
    #[serde(with = "time::serde::rfc3339::option")]
    pub(crate) completed_at: Option<OffsetDateTime>,
    pub(crate) paused_reason: Option<String>,
    pub(crate) failure_reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ActivityRecord {
    pub(crate) activity_id: Uuid,
    pub(crate) kind: String,
    pub(crate) actor_subject: String,
    #[serde(with = "decimal_i64")]
    pub(crate) request_revision: i64,
    pub(crate) evidence_json: String,
    #[serde(with = "time::serde::rfc3339")]
    pub(crate) created_at: OffsetDateTime,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct StepRecord {
    pub(crate) sequence: i32,
    pub(crate) provider_kind: String,
    pub(crate) provider_instance: String,
    pub(crate) status: String,
    pub(crate) attempts: i32,
    pub(crate) error_code: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub(crate) struct ProcessResult {
    pub(crate) request: RequestRecord,
    pub(crate) steps: Vec<StepRecord>,
    pub(crate) next_cursor: Option<String>,
    pub(crate) completed_steps: i64,
    pub(crate) failed_steps: i64,
    pub(crate) pending_steps: i64,
    pub(crate) all_steps_completed: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct ExportItemRecord {
    pub(crate) provider_instance: String,
    pub(crate) item_name: String,
    pub(crate) media_type: String,
    pub(crate) payload: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RequestCursor {
    pub(crate) created_at: OffsetDateTime,
    pub(crate) request_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ActivityCursor {
    pub(crate) created_at: OffsetDateTime,
    pub(crate) activity_id: Uuid,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct AdminRequestCursor {
    pub(crate) deadline_at: OffsetDateTime,
    pub(crate) request_id: Uuid,
}

#[derive(Clone, Debug)]
pub(crate) struct RequestFilters<'a> {
    pub(crate) organization_id: &'a str,
    pub(crate) requester_subject: &'a str,
    pub(crate) state: Option<&'a str>,
    pub(crate) cursor: Option<&'a RequestCursor>,
    pub(crate) limit: i64,
}

#[derive(Clone, Debug)]
pub(crate) struct AdminRequestFilters<'a> {
    pub(crate) organization_id: &'a str,
    pub(crate) state: Option<&'a str>,
    pub(crate) kind: Option<&'a str>,
    pub(crate) requester_subject: Option<&'a str>,
    pub(crate) cursor: Option<&'a AdminRequestCursor>,
    pub(crate) limit: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ProviderSnapshot {
    pub(crate) kind: &'static str,
    pub(crate) instance: String,
}

#[derive(Clone, Debug, PartialEq)]
pub(crate) enum ProcessStart {
    Replay(ProcessResult),
    Execute {
        request: RequestRecord,
        steps: Vec<StepRecord>,
    },
}

#[derive(Clone, Debug)]
pub(crate) enum Mutation<'a> {
    Withdraw {
        reason: &'a str,
    },
    VerifyIdentity {
        outcome: &'a str,
        evidence_reference: &'a str,
    },
    LegalHold {
        active: bool,
        reason: &'a str,
    },
    Pause {
        reason: &'a str,
    },
    Resume,
    Reject {
        reason: &'a str,
    },
    Claim,
    Complete {
        completion_reference: &'a str,
    },
    Fail {
        reason: &'a str,
        retryable: bool,
    },
    Retry,
}

impl Mutation<'_> {
    pub(crate) fn activity_kind(&self) -> &'static str {
        match self {
            Self::Withdraw { .. } => "request.withdrawn",
            Self::VerifyIdentity {
                outcome: "verified",
                ..
            } => "request.identity_verified",
            Self::VerifyIdentity { .. } => "request.identity_verification_failed",
            Self::LegalHold { active: true, .. } => "request.legal_hold_set",
            Self::LegalHold { active: false, .. } => "request.legal_hold_cleared",
            Self::Pause { .. } => "request.paused",
            Self::Resume => "request.resumed",
            Self::Reject { .. } => "request.rejected",
            Self::Claim => "request.claimed",
            Self::Complete { .. } => "request.completed",
            Self::Fail { .. } => "request.failed",
            Self::Retry => "request.retry_started",
        }
    }

    fn evidence(&self) -> Value {
        match self {
            Self::Withdraw { reason }
            | Self::Pause { reason }
            | Self::Reject { reason }
            | Self::Fail { reason, .. } => json!({"reason": reason}),
            Self::VerifyIdentity {
                outcome,
                evidence_reference,
            } => json!({"outcome": outcome, "evidence_reference": evidence_reference}),
            Self::LegalHold { active, reason } => json!({"active": active, "reason": reason}),
            Self::Complete {
                completion_reference,
            } => json!({"completion_reference": completion_reference}),
            Self::Claim | Self::Resume | Self::Retry => json!({}),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum DomainFailure {
    RequestNotFound,
    RevisionConflict,
    IdempotencyConflict,
    InvalidTransition,
    Forbidden,
    OperationInProgress,
}

#[derive(Debug, Error)]
pub(crate) enum StorageError {
    #[error("PostgreSQL operation `{operation}` failed")]
    Database {
        operation: &'static str,
        #[source]
        source: sqlx::Error,
    },
    #[error("stored Privacy Request data is invalid: {detail}")]
    InvalidStoredData { detail: String },
    #[error("Privacy Request command serialization failed")]
    Serialization(#[from] serde_json::Error),
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn create_request(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    requester: &str,
    kind: &str,
    description: &str,
    deadline_seconds: i64,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin privacy request creation").await?;
    match command_replay::<RequestRecord>(
        &mut transaction,
        caller,
        idempotency_key,
        "create_request",
        request_hash,
    )
    .await?
    {
        Ok(Some(replay)) => {
            commit(transaction, "commit privacy request creation replay").await?;
            return Ok(Ok(replay));
        }
        Ok(None) => {}
        Err(failure) => return Ok(Err(failure)),
    }
    let sequence = sqlx::query(
        "INSERT INTO privacy_request_sequences(organization_id,next_number) VALUES($1,2) ON CONFLICT(organization_id) DO UPDATE SET next_number=privacy_request_sequences.next_number+1 RETURNING next_number-1 AS allocated",
    )
    .bind(organization_id)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("allocate privacy request identifier", source))?;
    let number: i64 = sequence
        .try_get("allocated")
        .map_err(|source| database("decode privacy request identifier", source))?;
    if number <= 0 {
        return Err(StorageError::InvalidStoredData {
            detail: "request sequence is not positive".to_owned(),
        });
    }
    let request_id = Uuid::new_v4();
    let identifier = format!("PRV-{number}");
    let row = sqlx::query(
        "INSERT INTO privacy_requests(request_id,organization_id,identifier,requester_subject,kind,description,state,identity_status,revision,deadline_at) VALUES($1,$2,$3,$4,$5,$6,'pending_verification','pending',1,CURRENT_TIMESTAMP+($7::bigint * INTERVAL '1 second')) RETURNING *",
    )
    .bind(request_id)
    .bind(organization_id)
    .bind(&identifier)
    .bind(requester)
    .bind(kind)
    .bind(description)
    .bind(deadline_seconds)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("insert privacy request", source))?;
    let record = decode_request(&row)?;
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        "request.created",
        requester,
        record.revision,
        json!({"identifier": identifier, "kind": kind, "deadline_at": record.deadline_at}),
    )
    .await?;
    save_completed_command(
        &mut transaction,
        caller,
        idempotency_key,
        organization_id,
        request_id,
        "create_request",
        request_hash,
        &record,
    )
    .await?;
    commit(transaction, "commit privacy request creation").await?;
    Ok(Ok(record))
}

pub(crate) async fn get_owned_request(
    postgres: &OwnedPostgres,
    organization_id: &str,
    request_ref: &str,
    requester: &str,
) -> Result<Option<RequestRecord>, StorageError> {
    let parsed = Uuid::parse_str(request_ref).ok();
    let row = sqlx::query(
        "SELECT * FROM privacy_requests WHERE organization_id=$1 AND requester_subject=$2 AND (($3::uuid IS NOT NULL AND request_id=$3) OR ($3::uuid IS NULL AND identifier=$4))",
    )
    .bind(organization_id)
    .bind(requester)
    .bind(parsed)
    .bind(request_ref)
    .fetch_optional(postgres.pool())
    .await
    .map_err(|source| database("get owned privacy request", source))?;
    row.as_ref().map(decode_request).transpose()
}

pub(crate) async fn list_owned_requests(
    postgres: &OwnedPostgres,
    filters: &RequestFilters<'_>,
) -> Result<Vec<RequestRecord>, StorageError> {
    let cursor_time = filters.cursor.map(|cursor| cursor.created_at);
    let cursor_id = filters.cursor.map(|cursor| cursor.request_id);
    let rows = sqlx::query(
        "SELECT * FROM privacy_requests WHERE organization_id=$1 AND requester_subject=$2 AND ($3::text IS NULL OR state=$3) AND ($4::timestamptz IS NULL OR (created_at,request_id)<($4,$5)) ORDER BY created_at DESC,request_id DESC LIMIT $6",
    )
    .bind(filters.organization_id)
    .bind(filters.requester_subject)
    .bind(filters.state)
    .bind(cursor_time)
    .bind(cursor_id)
    .bind(filters.limit)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list owned privacy requests", source))?;
    rows.iter().map(decode_request).collect()
}

pub(crate) async fn list_admin_requests(
    postgres: &OwnedPostgres,
    filters: &AdminRequestFilters<'_>,
) -> Result<Vec<RequestRecord>, StorageError> {
    let cursor_deadline = filters.cursor.map(|cursor| cursor.deadline_at);
    let cursor_id = filters.cursor.map(|cursor| cursor.request_id);
    let rows = sqlx::query(
        "SELECT * FROM privacy_requests WHERE organization_id=$1 AND ($2::text IS NULL OR state=$2) AND ($3::text IS NULL OR kind=$3) AND ($4::text IS NULL OR requester_subject=$4) AND ($5::timestamptz IS NULL OR (deadline_at,request_id)>($5,$6)) ORDER BY deadline_at ASC,request_id ASC LIMIT $7",
    )
    .bind(filters.organization_id)
    .bind(filters.state)
    .bind(filters.kind)
    .bind(filters.requester_subject)
    .bind(cursor_deadline)
    .bind(cursor_id)
    .bind(filters.limit)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list administrative privacy requests", source))?;
    rows.iter().map(decode_request).collect()
}

pub(crate) async fn get_export_items(
    postgres: &OwnedPostgres,
    request_id: Uuid,
) -> Result<Vec<ExportItemRecord>, StorageError> {
    let rows = sqlx::query("SELECT provider_instance,item_name,media_type,payload FROM privacy_export_items WHERE request_id=$1 ORDER BY provider_instance ASC,item_name ASC")
        .bind(request_id).fetch_all(postgres.pool()).await
        .map_err(|source| database("read privacy request export items", source))?;
    rows.iter()
        .map(|row| {
            Ok(ExportItemRecord {
                provider_instance: decode(row, "provider_instance", "decode export provider")?,
                item_name: decode(row, "item_name", "decode export item name")?,
                media_type: decode(row, "media_type", "decode export media type")?,
                payload: decode(row, "payload", "decode export payload")?,
            })
        })
        .collect()
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn mutate_request(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    operation: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    actor: &str,
    expected_revision: i64,
    mutation: &Mutation<'_>,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin privacy request mutation").await?;
    match command_replay::<RequestRecord>(
        &mut transaction,
        caller,
        idempotency_key,
        operation,
        request_hash,
    )
    .await?
    {
        Ok(Some(replay)) => {
            commit(transaction, "commit privacy request mutation replay").await?;
            return Ok(Ok(replay));
        }
        Ok(None) => {}
        Err(failure) => return Ok(Err(failure)),
    }
    let Some(current) = locked_request(&mut transaction, organization_id, request_id).await? else {
        return Ok(Err(DomainFailure::RequestNotFound));
    };
    if current.revision != expected_revision {
        return Ok(Err(DomainFailure::RevisionConflict));
    }
    if matches!(mutation, Mutation::Withdraw { .. }) && current.requester_subject != actor {
        return Ok(Err(DomainFailure::Forbidden));
    }
    if matches!(
        mutation,
        Mutation::Complete { .. } | Mutation::Fail { .. } | Mutation::Retry
    ) && current.assignee_subject.as_deref() != Some(actor)
    {
        return Ok(Err(DomainFailure::Forbidden));
    }
    let allowed = match mutation {
        Mutation::Withdraw { .. } => {
            matches!(
                current.state.as_str(),
                "pending_verification" | "ready" | "claimed"
            ) && step_count(&mut transaction, request_id).await? == 0
        }
        Mutation::VerifyIdentity { .. }
        | Mutation::LegalHold { .. }
        | Mutation::Pause { .. }
        | Mutation::Reject { .. } => !terminal(&current.state),
        Mutation::Resume => current.state == "paused" && !current.legal_hold,
        Mutation::Claim => {
            current.state == "ready" && current.identity_status == "verified" && !current.legal_hold
        }
        Mutation::Complete { .. } => {
            current.state == "awaiting_completion"
                && current.identity_status == "verified"
                && !current.legal_hold
                && all_steps_completed(&mut transaction, request_id).await?
        }
        Mutation::Fail { .. } => matches!(
            current.state.as_str(),
            "claimed" | "processing" | "awaiting_completion"
        ),
        Mutation::Retry => {
            current.state == "failed"
                && current.retryable
                && current.identity_status == "verified"
                && !current.legal_hold
        }
    };
    if !allowed {
        return Ok(Err(DomainFailure::InvalidTransition));
    }
    match mutation {
        Mutation::Withdraw { .. } => {
            sqlx::query("UPDATE privacy_requests SET state='withdrawn',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).execute(&mut *transaction).await
                .map_err(|source| database("withdraw privacy request", source))?;
        }
        Mutation::VerifyIdentity {
            outcome,
            evidence_reference,
        } => {
            let (state, paused_from, paused_reason) =
                if *outcome == "verified" && current.state == "pending_verification" {
                    ("ready", None, None)
                } else if *outcome == "failed" && current.state != "paused" {
                    (
                        "paused",
                        Some(current.state.as_str()),
                        Some("identity_verification_failed"),
                    )
                } else {
                    (current.state.as_str(), None, None)
                };
            sqlx::query("UPDATE privacy_requests SET identity_status=$2,identity_evidence_reference=$3,state=$4,paused_from_state=COALESCE($5,paused_from_state),paused_reason=COALESCE($6,paused_reason),revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).bind(outcome).bind(evidence_reference).bind(state).bind(paused_from).bind(paused_reason)
                .execute(&mut *transaction).await
                .map_err(|source| database("record identity verification", source))?;
        }
        Mutation::LegalHold { active, reason } => {
            let next_state = if *active {
                "paused"
            } else {
                current.state.as_str()
            };
            let paused_from = if *active && current.state != "paused" {
                Some(current.state.as_str())
            } else {
                None
            };
            sqlx::query("UPDATE privacy_requests SET legal_hold=$2,legal_hold_reason=CASE WHEN $2 THEN $3 ELSE NULL END,state=$4,paused_from_state=COALESCE($5,paused_from_state),paused_reason=CASE WHEN $2 THEN $3 ELSE paused_reason END,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).bind(active).bind(reason).bind(next_state).bind(paused_from)
                .execute(&mut *transaction).await
                .map_err(|source| database("change privacy request legal hold", source))?;
        }
        Mutation::Pause { reason } => {
            sqlx::query("UPDATE privacy_requests SET state='paused',paused_from_state=CASE WHEN state='paused' THEN paused_from_state ELSE state END,paused_reason=$2,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).bind(reason).execute(&mut *transaction).await
                .map_err(|source| database("pause privacy request", source))?;
        }
        Mutation::Resume => {
            let resume_state = resume_state(&current);
            sqlx::query("UPDATE privacy_requests SET state=$2,paused_from_state=NULL,paused_reason=NULL,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).bind(resume_state).execute(&mut *transaction).await
                .map_err(|source| database("resume privacy request", source))?;
        }
        Mutation::Reject { reason } => {
            sqlx::query("UPDATE privacy_requests SET state='rejected',failure_reason=$2,retryable=FALSE,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).bind(reason).execute(&mut *transaction).await
                .map_err(|source| database("reject privacy request", source))?;
        }
        Mutation::Claim => {
            sqlx::query("UPDATE privacy_requests SET state='claimed',assignee_subject=$2,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).bind(actor).execute(&mut *transaction).await
                .map_err(|source| database("claim privacy request", source))?;
        }
        Mutation::Complete { .. } => {
            sqlx::query("UPDATE privacy_requests SET state='completed',completed_at=CURRENT_TIMESTAMP,failure_reason=NULL,retryable=FALSE,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).execute(&mut *transaction).await
                .map_err(|source| database("complete privacy request", source))?;
        }
        Mutation::Fail { reason, retryable } => {
            sqlx::query("UPDATE privacy_requests SET state='failed',failure_reason=$2,retryable=$3,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).bind(reason).bind(retryable).execute(&mut *transaction).await
                .map_err(|source| database("fail privacy request", source))?;
        }
        Mutation::Retry => {
            sqlx::query("UPDATE privacy_request_steps SET status='pending',error_code=NULL WHERE request_id=$1 AND status='failed'")
                .bind(request_id).execute(&mut *transaction).await
                .map_err(|source| database("reset failed privacy request steps", source))?;
            let state = if step_count(&mut transaction, request_id).await? == 0 {
                "ready"
            } else {
                "processing"
            };
            sqlx::query("UPDATE privacy_requests SET state=$2,failure_reason=NULL,retryable=FALSE,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
                .bind(request_id).bind(state).execute(&mut *transaction).await
                .map_err(|source| database("retry privacy request", source))?;
        }
    }
    let row = sqlx::query("SELECT * FROM privacy_requests WHERE request_id=$1")
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|source| database("read mutated privacy request", source))?;
    let record = decode_request(&row)?;
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        mutation.activity_kind(),
        actor,
        record.revision,
        mutation.evidence(),
    )
    .await?;
    save_completed_command(
        &mut transaction,
        caller,
        idempotency_key,
        organization_id,
        request_id,
        operation,
        request_hash,
        &record,
    )
    .await?;
    commit(transaction, "commit privacy request mutation").await?;
    Ok(Ok(record))
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn claim_next_request(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    kind: Option<&str>,
    actor: &str,
) -> Result<Result<RequestRecord, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin next privacy request claim").await?;
    match command_replay::<RequestRecord>(
        &mut transaction,
        caller,
        idempotency_key,
        "claim_next",
        request_hash,
    )
    .await?
    {
        Ok(Some(replay)) => {
            commit(transaction, "commit next privacy request claim replay").await?;
            return Ok(Ok(replay));
        }
        Ok(None) => {}
        Err(failure) => return Ok(Err(failure)),
    }
    let row = sqlx::query(
        "SELECT request_id FROM privacy_requests WHERE organization_id=$1 AND state='ready' AND identity_status='verified' AND legal_hold=FALSE AND ($2::text IS NULL OR kind=$2) ORDER BY deadline_at ASC,request_id ASC FOR UPDATE SKIP LOCKED LIMIT 1",
    )
    .bind(organization_id)
    .bind(kind)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("select next claimable privacy request", source))?;
    let Some(row) = row else {
        return Ok(Err(DomainFailure::RequestNotFound));
    };
    let request_id: Uuid = row
        .try_get("request_id")
        .map_err(|source| database("decode next claimable privacy request", source))?;
    let row = sqlx::query("UPDATE privacy_requests SET state='claimed',assignee_subject=$2,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1 RETURNING *")
        .bind(request_id).bind(actor).fetch_one(&mut *transaction).await
        .map_err(|source| database("claim next privacy request", source))?;
    let record = decode_request(&row)?;
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        "request.claimed",
        actor,
        record.revision,
        json!({"selection": "deadline_ordered_skip_locked", "fence_revision": record.revision}),
    )
    .await?;
    save_completed_command(
        &mut transaction,
        caller,
        idempotency_key,
        organization_id,
        request_id,
        "claim_next",
        request_hash,
        &record,
    )
    .await?;
    commit(transaction, "commit next privacy request claim").await?;
    Ok(Ok(record))
}

pub(crate) async fn list_activity(
    postgres: &OwnedPostgres,
    organization_id: &str,
    request_id: Uuid,
    cursor: Option<&ActivityCursor>,
    limit: i64,
) -> Result<Option<Vec<ActivityRecord>>, StorageError> {
    let exists = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS(SELECT 1 FROM privacy_requests WHERE organization_id=$1 AND request_id=$2)",
    )
    .bind(organization_id)
    .bind(request_id)
    .fetch_one(postgres.pool())
    .await
    .map_err(|source| database("find privacy request for activity", source))?;
    if !exists {
        return Ok(None);
    }
    let cursor_time = cursor.map(|value| value.created_at);
    let cursor_id = cursor.map(|value| value.activity_id);
    let rows = sqlx::query(
        "SELECT activity_id,kind,actor_subject,request_revision,evidence,created_at FROM privacy_request_activity WHERE request_id=$1 AND ($2::timestamptz IS NULL OR (created_at,activity_id)>($2,$3)) ORDER BY created_at ASC,activity_id ASC LIMIT $4",
    )
    .bind(request_id)
    .bind(cursor_time)
    .bind(cursor_id)
    .bind(limit)
    .fetch_all(postgres.pool())
    .await
    .map_err(|source| database("list privacy request activity", source))?;
    rows.iter()
        .map(decode_activity)
        .collect::<Result<Vec<_>, _>>()
        .map(Some)
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(crate) async fn begin_process(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    actor: &str,
    expected_revision: i64,
    snapshots: &[ProviderSnapshot],
    cursor: Option<i32>,
    limit: i64,
    lease_seconds: i64,
) -> Result<Result<ProcessStart, DomainFailure>, StorageError> {
    let mut transaction = begin(postgres, "begin privacy request processing").await?;
    advisory_lock(&mut transaction, caller, idempotency_key).await?;
    let command = sqlx::query(
        "SELECT operation,request_hash,status,response,COALESCE(lease_until>CURRENT_TIMESTAMP,FALSE) AS lease_active FROM privacy_request_commands WHERE caller_instance=$1 AND idempotency_key=$2 FOR UPDATE",
    )
    .bind(caller)
    .bind(idempotency_key)
    .fetch_optional(&mut *transaction)
    .await
    .map_err(|source| database("read process command", source))?;
    let resumed = if let Some(row) = command {
        let operation: String = row
            .try_get("operation")
            .map_err(|source| database("decode process command operation", source))?;
        let stored_hash: Vec<u8> = row
            .try_get("request_hash")
            .map_err(|source| database("decode process command hash", source))?;
        if operation != "process_request" || stored_hash != request_hash {
            return Ok(Err(DomainFailure::IdempotencyConflict));
        }
        let status: String = row
            .try_get("status")
            .map_err(|source| database("decode process command status", source))?;
        if status == "completed" {
            let response: Json<Value> = row
                .try_get("response")
                .map_err(|source| database("decode process command response", source))?;
            let replay = serde_json::from_value(response.0)?;
            commit(transaction, "commit privacy process replay").await?;
            return Ok(Ok(ProcessStart::Replay(replay)));
        }
        let lease_active: bool = row
            .try_get("lease_active")
            .map_err(|source| database("decode process command lease", source))?;
        if lease_active {
            return Ok(Err(DomainFailure::OperationInProgress));
        }
        sqlx::query("UPDATE privacy_request_commands SET lease_until=CURRENT_TIMESTAMP+($3::bigint * INTERVAL '1 second') WHERE caller_instance=$1 AND idempotency_key=$2")
            .bind(caller).bind(idempotency_key).bind(lease_seconds)
            .execute(&mut *transaction).await
            .map_err(|source| database("renew privacy process lease", source))?;
        true
    } else {
        false
    };
    let Some(current) = locked_request(&mut transaction, organization_id, request_id).await? else {
        return Ok(Err(DomainFailure::RequestNotFound));
    };
    if current.assignee_subject.as_deref() != Some(actor) {
        return Ok(Err(DomainFailure::Forbidden));
    }
    if resumed
        && (!matches!(current.state.as_str(), "claimed" | "processing")
            || current.identity_status != "verified"
            || current.legal_hold)
    {
        return Ok(Err(DomainFailure::InvalidTransition));
    }
    if !resumed {
        if current.revision != expected_revision {
            return Ok(Err(DomainFailure::RevisionConflict));
        }
        if !matches!(current.state.as_str(), "claimed" | "processing")
            || current.identity_status != "verified"
            || current.legal_hold
        {
            return Ok(Err(DomainFailure::InvalidTransition));
        }
        if step_count(&mut transaction, request_id).await? == 0 {
            let selected = snapshots
                .iter()
                .filter(|snapshot| provider_kind_for_request(&current.kind) == Some(snapshot.kind))
                .collect::<Vec<_>>();
            if selected.is_empty() {
                return Ok(Err(DomainFailure::InvalidTransition));
            }
            for (index, snapshot) in selected.iter().enumerate() {
                let sequence =
                    i32::try_from(index + 1).map_err(|_| StorageError::InvalidStoredData {
                        detail: "provider snapshot exceeds i32 sequence".to_owned(),
                    })?;
                sqlx::query("INSERT INTO privacy_request_steps(request_id,sequence,provider_kind,provider_instance,status) VALUES($1,$2,$3,$4,'pending')")
                    .bind(request_id).bind(sequence).bind(snapshot.kind).bind(&snapshot.instance)
                    .execute(&mut *transaction).await
                    .map_err(|source| database("snapshot privacy request provider", source))?;
            }
        }
        sqlx::query("UPDATE privacy_requests SET state='processing',revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1")
            .bind(request_id).execute(&mut *transaction).await
            .map_err(|source| database("start privacy request processing", source))?;
        sqlx::query("INSERT INTO privacy_request_commands(caller_instance,idempotency_key,organization_id,request_id,operation,request_hash,status,lease_until) VALUES($1,$2,$3,$4,'process_request',$5,'started',CURRENT_TIMESTAMP+($6::bigint * INTERVAL '1 second'))")
            .bind(caller).bind(idempotency_key).bind(organization_id).bind(request_id).bind(request_hash).bind(lease_seconds)
            .execute(&mut *transaction).await
            .map_err(|source| database("store started privacy process command", source))?;
        let revision = current.revision + 1;
        let snapshotted_count = step_count(&mut transaction, request_id).await?;
        insert_activity(
            &mut transaction,
            organization_id,
            request_id,
            "request.processing_started",
            actor,
            revision,
            json!({"step_count": snapshotted_count}),
        )
        .await?;
    }
    let row = sqlx::query("SELECT * FROM privacy_requests WHERE request_id=$1")
        .bind(request_id)
        .fetch_one(&mut *transaction)
        .await
        .map_err(|source| database("read processing privacy request", source))?;
    let request = decode_request(&row)?;
    let rows = sqlx::query("SELECT sequence,provider_kind,provider_instance,status,attempts,error_code FROM privacy_request_steps WHERE request_id=$1 AND status<>'completed' AND sequence>$2 ORDER BY sequence ASC LIMIT $3")
        .bind(request_id).bind(cursor.unwrap_or(0)).bind(limit)
        .fetch_all(&mut *transaction).await
        .map_err(|source| database("select privacy request process window", source))?;
    let steps = rows
        .iter()
        .map(decode_step)
        .collect::<Result<Vec<_>, _>>()?;
    commit(transaction, "commit privacy process start").await?;
    Ok(Ok(ProcessStart::Execute { request, steps }))
}

pub(crate) async fn record_export_success(
    postgres: &OwnedPostgres,
    request_id: Uuid,
    sequence: i32,
    provider: &str,
    items: &[(String, String, String)],
    max_total_items: usize,
    max_total_bytes: usize,
) -> Result<bool, StorageError> {
    let mut transaction = begin(postgres, "begin export step completion").await?;
    let existing: i64 = sqlx::query_scalar("SELECT COALESCE(SUM(payload_bytes),0)::bigint FROM privacy_export_items WHERE request_id=$1 AND provider_instance<>$2")
        .bind(request_id).bind(provider).fetch_one(&mut *transaction).await
        .map_err(|source| database("sum stored privacy export bytes", source))?;
    let added = items
        .iter()
        .try_fold(0_usize, |total, (_, _, payload)| {
            total.checked_add(payload.len())
        })
        .ok_or(StorageError::InvalidStoredData {
            detail: "export byte count overflow".to_owned(),
        })?;
    let existing = usize::try_from(existing).map_err(|_| StorageError::InvalidStoredData {
        detail: "stored export byte count is negative".to_owned(),
    })?;
    let existing_items: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM privacy_export_items WHERE request_id=$1 AND provider_instance<>$2",
    )
    .bind(request_id)
    .bind(provider)
    .fetch_one(&mut *transaction)
    .await
    .map_err(|source| database("count stored privacy export items", source))?;
    let existing_items =
        usize::try_from(existing_items).map_err(|_| StorageError::InvalidStoredData {
            detail: "stored export item count is negative".to_owned(),
        })?;
    if existing.saturating_add(added) > max_total_bytes
        || existing_items.saturating_add(items.len()) > max_total_items
    {
        return Ok(false);
    }
    sqlx::query("DELETE FROM privacy_export_items WHERE request_id=$1 AND provider_instance=$2")
        .bind(request_id)
        .bind(provider)
        .execute(&mut *transaction)
        .await
        .map_err(|source| database("replace privacy export provider items", source))?;
    for (name, media_type, payload) in items {
        sqlx::query("INSERT INTO privacy_export_items(request_id,provider_instance,item_name,media_type,payload,payload_bytes) VALUES($1,$2,$3,$4,$5,$6)")
            .bind(request_id).bind(provider).bind(name).bind(media_type).bind(payload)
            .bind(i64::try_from(payload.len()).map_err(|_| StorageError::InvalidStoredData { detail: "export item byte count exceeds i64".to_owned() })?)
            .execute(&mut *transaction).await
            .map_err(|source| database("store privacy export item", source))?;
    }
    sqlx::query("UPDATE privacy_request_steps SET status='completed',attempts=attempts+1,error_code=NULL,item_count=$3,total_bytes=$4,attempted_at=CURRENT_TIMESTAMP,completed_at=CURRENT_TIMESTAMP WHERE request_id=$1 AND sequence=$2 AND status<>'completed'")
        .bind(request_id).bind(sequence)
        .bind(i64::try_from(items.len()).map_err(|_| StorageError::InvalidStoredData { detail: "export item count exceeds i64".to_owned() })?)
        .bind(i64::try_from(added).map_err(|_| StorageError::InvalidStoredData { detail: "export byte count exceeds i64".to_owned() })?)
        .execute(&mut *transaction).await
        .map_err(|source| database("complete privacy export step", source))?;
    commit(transaction, "commit export step completion").await?;
    Ok(true)
}

pub(crate) async fn record_step_success(
    postgres: &OwnedPostgres,
    request_id: Uuid,
    sequence: i32,
    receipt: Option<&str>,
    evidence_reference: Option<&str>,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE privacy_request_steps SET status='completed',attempts=attempts+1,error_code=NULL,receipt=$3,evidence_reference=$4,attempted_at=CURRENT_TIMESTAMP,completed_at=CURRENT_TIMESTAMP WHERE request_id=$1 AND sequence=$2 AND status<>'completed'")
        .bind(request_id).bind(sequence).bind(receipt).bind(evidence_reference)
        .execute(postgres.pool()).await
        .map_err(|source| database("complete privacy request step", source))?;
    Ok(())
}

pub(crate) async fn record_step_failure(
    postgres: &OwnedPostgres,
    request_id: Uuid,
    sequence: i32,
    error_code: &str,
) -> Result<(), StorageError> {
    sqlx::query("UPDATE privacy_request_steps SET status='failed',attempts=attempts+1,error_code=$3,attempted_at=CURRENT_TIMESTAMP WHERE request_id=$1 AND sequence=$2 AND status<>'completed'")
        .bind(request_id).bind(sequence).bind(error_code)
        .execute(postgres.pool()).await
        .map_err(|source| database("record privacy request step failure", source))?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn finish_process(
    postgres: &OwnedPostgres,
    caller: &str,
    idempotency_key: &str,
    request_hash: &[u8],
    organization_id: &str,
    request_id: Uuid,
    actor: &str,
    last_sequence: Option<i32>,
) -> Result<ProcessResult, StorageError> {
    let mut transaction = begin(postgres, "begin privacy process completion").await?;
    let Some(current) = locked_request(&mut transaction, organization_id, request_id).await? else {
        return Err(StorageError::InvalidStoredData {
            detail: "processing request disappeared before completion".to_owned(),
        });
    };
    let counts = step_counts(&mut transaction, request_id).await?;
    let all_completed = counts.0 > 0 && counts.1 == 0 && counts.2 == 0;
    let state = if terminal(&current.state)
        || current.state == "paused"
        || current.state == "failed"
        || current.legal_hold
    {
        current.state.as_str()
    } else if all_completed {
        "awaiting_completion"
    } else {
        "processing"
    };
    let row = sqlx::query("UPDATE privacy_requests SET state=$2,revision=revision+1,updated_at=CURRENT_TIMESTAMP WHERE request_id=$1 RETURNING *")
        .bind(request_id).bind(state).fetch_one(&mut *transaction).await
        .map_err(|source| database("finish privacy request processing", source))?;
    let request = decode_request(&row)?;
    insert_activity(
        &mut transaction,
        organization_id,
        request_id,
        "request.processing_advanced",
        actor,
        request.revision,
        json!({"completed_steps": counts.0, "failed_steps": counts.1, "pending_steps": counts.2, "all_steps_completed": all_completed}),
    )
    .await?;
    let rows = sqlx::query("SELECT sequence,provider_kind,provider_instance,status,attempts,error_code FROM privacy_request_steps WHERE request_id=$1 ORDER BY sequence ASC")
        .bind(request_id).fetch_all(&mut *transaction).await
        .map_err(|source| database("list completed process steps", source))?;
    let steps = rows
        .iter()
        .map(decode_step)
        .collect::<Result<Vec<_>, _>>()?;
    let next_cursor = if let Some(last) = last_sequence {
        let remaining: bool = sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM privacy_request_steps WHERE request_id=$1 AND status<>'completed' AND sequence>$2)")
            .bind(request_id).bind(last).fetch_one(&mut *transaction).await
            .map_err(|source| database("find remaining process steps", source))?;
        remaining.then(|| encode_process_cursor(request_id, last))
    } else {
        None
    };
    let result = ProcessResult {
        request,
        steps,
        next_cursor,
        completed_steps: counts.0,
        failed_steps: counts.1,
        pending_steps: counts.2,
        all_steps_completed: all_completed,
    };
    let completed = sqlx::query("UPDATE privacy_request_commands SET status='completed',response=$4,lease_until=NULL WHERE caller_instance=$1 AND idempotency_key=$2 AND request_hash=$3 AND status='started'")
        .bind(caller).bind(idempotency_key).bind(request_hash).bind(Json(serde_json::to_value(&result)?))
        .execute(&mut *transaction).await
        .map_err(|source| database("complete privacy process command", source))?;
    if completed.rows_affected() != 1 {
        return Err(StorageError::InvalidStoredData {
            detail: "process command disappeared or was already completed".to_owned(),
        });
    }
    commit(transaction, "commit privacy process completion").await?;
    Ok(result)
}

async fn begin<'a>(
    postgres: &OwnedPostgres,
    operation: &'static str,
) -> Result<Transaction<'a, Postgres>, StorageError> {
    postgres
        .pool()
        .begin()
        .await
        .map_err(|source| database(operation, source))
}

async fn commit(
    transaction: Transaction<'_, Postgres>,
    operation: &'static str,
) -> Result<(), StorageError> {
    transaction
        .commit()
        .await
        .map_err(|source| database(operation, source))
}

async fn command_replay<T: DeserializeOwned>(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    key: &str,
    operation: &str,
    request_hash: &[u8],
) -> Result<Result<Option<T>, DomainFailure>, StorageError> {
    advisory_lock(transaction, caller, key).await?;
    let row = sqlx::query("SELECT operation,request_hash,status,response FROM privacy_request_commands WHERE caller_instance=$1 AND idempotency_key=$2")
        .bind(caller).bind(key).fetch_optional(&mut **transaction).await
        .map_err(|source| database("read privacy request command", source))?;
    let Some(row) = row else {
        return Ok(Ok(None));
    };
    let stored_operation: String = row
        .try_get("operation")
        .map_err(|source| database("decode command operation", source))?;
    let stored_hash: Vec<u8> = row
        .try_get("request_hash")
        .map_err(|source| database("decode command hash", source))?;
    if stored_operation != operation || stored_hash != request_hash {
        return Ok(Err(DomainFailure::IdempotencyConflict));
    }
    let status: String = row
        .try_get("status")
        .map_err(|source| database("decode command status", source))?;
    if status != "completed" {
        return Ok(Err(DomainFailure::OperationInProgress));
    }
    let response: Json<Value> = row
        .try_get("response")
        .map_err(|source| database("decode command response", source))?;
    Ok(Ok(Some(serde_json::from_value(response.0)?)))
}

#[allow(clippy::too_many_arguments)]
async fn save_completed_command<T: Serialize>(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    key: &str,
    organization_id: &str,
    request_id: Uuid,
    operation: &str,
    request_hash: &[u8],
    response: &T,
) -> Result<(), StorageError> {
    sqlx::query("INSERT INTO privacy_request_commands(caller_instance,idempotency_key,organization_id,request_id,operation,request_hash,status,response) VALUES($1,$2,$3,$4,$5,$6,'completed',$7)")
        .bind(caller).bind(key).bind(organization_id).bind(request_id).bind(operation).bind(request_hash)
        .bind(Json(serde_json::to_value(response)?)).execute(&mut **transaction).await
        .map_err(|source| database("save privacy request command", source))?;
    Ok(())
}

async fn advisory_lock(
    transaction: &mut Transaction<'_, Postgres>,
    caller: &str,
    key: &str,
) -> Result<(), StorageError> {
    let digest = Sha256::digest(format!("{caller}\0{key}"));
    let lock_key = i64::from_be_bytes(digest[..8].try_into().expect("SHA-256 prefix is 8 bytes"));
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(lock_key)
        .execute(&mut **transaction)
        .await
        .map_err(|source| database("lock privacy request idempotency key", source))?;
    Ok(())
}

async fn locked_request(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    request_id: Uuid,
) -> Result<Option<StoredRequest>, StorageError> {
    let row = sqlx::query(
        "SELECT * FROM privacy_requests WHERE organization_id=$1 AND request_id=$2 FOR UPDATE",
    )
    .bind(organization_id)
    .bind(request_id)
    .fetch_optional(&mut **transaction)
    .await
    .map_err(|source| database("lock privacy request", source))?;
    row.as_ref().map(decode_stored_request).transpose()
}

async fn insert_activity(
    transaction: &mut Transaction<'_, Postgres>,
    organization_id: &str,
    request_id: Uuid,
    kind: &str,
    actor: &str,
    revision: i64,
    evidence: Value,
) -> Result<(), StorageError> {
    sqlx::query("INSERT INTO privacy_request_activity(activity_id,organization_id,request_id,kind,actor_subject,request_revision,evidence) VALUES($1,$2,$3,$4,$5,$6,$7)")
        .bind(Uuid::new_v4()).bind(organization_id).bind(request_id).bind(kind).bind(actor).bind(revision).bind(Json(evidence))
        .execute(&mut **transaction).await
        .map_err(|source| database("insert privacy request activity", source))?;
    Ok(())
}

async fn step_count(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<i64, StorageError> {
    sqlx::query_scalar("SELECT COUNT(*) FROM privacy_request_steps WHERE request_id=$1")
        .bind(request_id)
        .fetch_one(&mut **transaction)
        .await
        .map_err(|source| database("count privacy request steps", source))
}

async fn all_steps_completed(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<bool, StorageError> {
    let (total, incomplete): (i64, i64) = sqlx::query_as("SELECT COUNT(*),COUNT(*) FILTER (WHERE status<>'completed') FROM privacy_request_steps WHERE request_id=$1")
        .bind(request_id).fetch_one(&mut **transaction).await
        .map_err(|source| database("check privacy request steps", source))?;
    Ok(total > 0 && incomplete == 0)
}

async fn step_counts(
    transaction: &mut Transaction<'_, Postgres>,
    request_id: Uuid,
) -> Result<(i64, i64, i64), StorageError> {
    sqlx::query_as("SELECT COUNT(*) FILTER (WHERE status='completed'),COUNT(*) FILTER (WHERE status='failed'),COUNT(*) FILTER (WHERE status='pending') FROM privacy_request_steps WHERE request_id=$1")
        .bind(request_id).fetch_one(&mut **transaction).await
        .map_err(|source| database("count privacy request step states", source))
}

#[derive(Clone, Debug)]
struct StoredRequest {
    requester_subject: String,
    kind: String,
    state: String,
    identity_status: String,
    legal_hold: bool,
    paused_from_state: Option<String>,
    assignee_subject: Option<String>,
    retryable: bool,
    revision: i64,
}

fn decode_stored_request(row: &sqlx::postgres::PgRow) -> Result<StoredRequest, StorageError> {
    Ok(StoredRequest {
        requester_subject: decode(row, "requester_subject", "decode request owner")?,
        kind: decode(row, "kind", "decode request kind")?,
        state: decode(row, "state", "decode request state")?,
        identity_status: decode(row, "identity_status", "decode identity status")?,
        legal_hold: decode(row, "legal_hold", "decode legal hold")?,
        paused_from_state: decode(row, "paused_from_state", "decode paused state")?,
        assignee_subject: decode(row, "assignee_subject", "decode request assignee")?,
        retryable: decode(row, "retryable", "decode request retryability")?,
        revision: decode(row, "revision", "decode request revision")?,
    })
}

fn decode_request(row: &sqlx::postgres::PgRow) -> Result<RequestRecord, StorageError> {
    let deadline_at: OffsetDateTime = decode(row, "deadline_at", "decode request deadline")?;
    let state: String = decode(row, "state", "decode request state")?;
    Ok(RequestRecord {
        request_id: decode(row, "request_id", "decode request id")?,
        identifier: decode(row, "identifier", "decode request identifier")?,
        organization_id: decode(row, "organization_id", "decode request organization")?,
        requester_subject: decode(row, "requester_subject", "decode request owner")?,
        kind: decode(row, "kind", "decode request kind")?,
        description: decode(row, "description", "decode request description")?,
        state: state.clone(),
        identity_status: decode(row, "identity_status", "decode identity status")?,
        legal_hold: decode(row, "legal_hold", "decode legal hold")?,
        assignee_subject: decode(row, "assignee_subject", "decode request assignee")?,
        revision: decode(row, "revision", "decode request revision")?,
        deadline_at,
        overdue: deadline_at < OffsetDateTime::now_utc() && !terminal(&state),
        created_at: decode(row, "created_at", "decode request creation time")?,
        updated_at: decode(row, "updated_at", "decode request update time")?,
        completed_at: decode(row, "completed_at", "decode request completion time")?,
        paused_reason: decode(row, "paused_reason", "decode request pause reason")?,
        failure_reason: decode(row, "failure_reason", "decode request failure reason")?,
    })
}

fn decode_activity(row: &sqlx::postgres::PgRow) -> Result<ActivityRecord, StorageError> {
    let evidence: Json<Value> = decode(row, "evidence", "decode activity evidence")?;
    Ok(ActivityRecord {
        activity_id: decode(row, "activity_id", "decode activity id")?,
        kind: decode(row, "kind", "decode activity kind")?,
        actor_subject: decode(row, "actor_subject", "decode activity actor")?,
        request_revision: decode(row, "request_revision", "decode activity revision")?,
        evidence_json: serde_json::to_string(&evidence.0)?,
        created_at: decode(row, "created_at", "decode activity time")?,
    })
}

fn decode_step(row: &sqlx::postgres::PgRow) -> Result<StepRecord, StorageError> {
    Ok(StepRecord {
        sequence: decode(row, "sequence", "decode step sequence")?,
        provider_kind: decode(row, "provider_kind", "decode step provider kind")?,
        provider_instance: decode(row, "provider_instance", "decode step provider")?,
        status: decode(row, "status", "decode step status")?,
        attempts: decode(row, "attempts", "decode step attempts")?,
        error_code: decode(row, "error_code", "decode step error")?,
    })
}

fn decode<T: for<'a> sqlx::Decode<'a, Postgres> + sqlx::Type<Postgres>>(
    row: &sqlx::postgres::PgRow,
    column: &'static str,
    operation: &'static str,
) -> Result<T, StorageError> {
    row.try_get(column)
        .map_err(|source| database(operation, source))
}

pub(crate) fn encode_request_cursor(record: &RequestRecord) -> Result<String, StorageError> {
    Ok(format!(
        "v1:{}:{}",
        format_time(record.created_at)?,
        record.request_id
    ))
}

pub(crate) fn decode_request_cursor(value: &str) -> Option<RequestCursor> {
    let rest = value.strip_prefix("v1:")?;
    let (time, id) = rest.rsplit_once(':')?;
    Some(RequestCursor {
        created_at: OffsetDateTime::parse(time, &Rfc3339).ok()?,
        request_id: Uuid::parse_str(id).ok()?,
    })
}

pub(crate) fn encode_activity_cursor(record: &ActivityRecord) -> Result<String, StorageError> {
    Ok(format!(
        "v1:{}:{}",
        format_time(record.created_at)?,
        record.activity_id
    ))
}

pub(crate) fn encode_admin_request_cursor(record: &RequestRecord) -> Result<String, StorageError> {
    Ok(format!(
        "v1:{}:{}",
        format_time(record.deadline_at)?,
        record.request_id
    ))
}

pub(crate) fn decode_admin_request_cursor(value: &str) -> Option<AdminRequestCursor> {
    let rest = value.strip_prefix("v1:")?;
    let (time, id) = rest.rsplit_once(':')?;
    Some(AdminRequestCursor {
        deadline_at: OffsetDateTime::parse(time, &Rfc3339).ok()?,
        request_id: Uuid::parse_str(id).ok()?,
    })
}

pub(crate) fn decode_activity_cursor(value: &str) -> Option<ActivityCursor> {
    let rest = value.strip_prefix("v1:")?;
    let (time, id) = rest.rsplit_once(':')?;
    Some(ActivityCursor {
        created_at: OffsetDateTime::parse(time, &Rfc3339).ok()?,
        activity_id: Uuid::parse_str(id).ok()?,
    })
}

pub(crate) fn encode_process_cursor(request_id: Uuid, sequence: i32) -> String {
    format!("v1:{request_id}:{sequence}")
}

pub(crate) fn decode_process_cursor(value: &str, request_id: Uuid) -> Option<i32> {
    let rest = value.strip_prefix("v1:")?;
    let (id, sequence) = rest.rsplit_once(':')?;
    (Uuid::parse_str(id).ok()? == request_id)
        .then(|| sequence.parse::<i32>().ok().filter(|value| *value >= 0))
        .flatten()
}

fn format_time(value: OffsetDateTime) -> Result<String, StorageError> {
    value
        .format(&Rfc3339)
        .map_err(|error| StorageError::InvalidStoredData {
            detail: error.to_string(),
        })
}

fn resume_state(current: &StoredRequest) -> &'static str {
    match current.paused_from_state.as_deref() {
        Some("claimed") if current.assignee_subject.is_some() => "claimed",
        Some("processing") if current.assignee_subject.is_some() => "processing",
        Some("awaiting_completion") if current.assignee_subject.is_some() => "awaiting_completion",
        _ if current.identity_status == "verified" => "ready",
        _ => "pending_verification",
    }
}

pub(crate) fn terminal(state: &str) -> bool {
    matches!(state, "completed" | "rejected" | "withdrawn")
}

fn provider_kind_for_request(kind: &str) -> Option<&'static str> {
    match kind {
        "access" | "export" => Some("export"),
        "erasure" => Some("retention"),
        "correction" | "restriction" => Some("manual"),
        _ => None,
    }
}

fn database(operation: &'static str, source: sqlx::Error) -> StorageError {
    StorageError::Database { operation, source }
}

mod decimal_i64 {
    use serde::{Deserialize, Deserializer, Serializer, de};

    #[allow(clippy::trivially_copy_pass_by_ref)]
    pub(super) fn serialize<S: Serializer>(value: &i64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<i64, D::Error> {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cursors_are_scope_bound_and_round_trip() {
        let request_id = Uuid::new_v4();
        let cursor = encode_process_cursor(request_id, 7);
        assert_eq!(decode_process_cursor(&cursor, request_id), Some(7));
        assert_eq!(decode_process_cursor(&cursor, Uuid::new_v4()), None);
    }

    #[test]
    fn terminal_states_are_explicit() {
        assert!(terminal("completed"));
        assert!(terminal("rejected"));
        assert!(terminal("withdrawn"));
        assert!(!terminal("failed"));
        assert!(!terminal("paused"));
    }

    #[test]
    fn process_lease_is_bounded_time_not_a_completion_claim() {
        assert!(time::Duration::minutes(15) < time::Duration::hours(1));
    }

    #[test]
    fn every_request_kind_has_an_explicit_execution_path() {
        assert_eq!(provider_kind_for_request("access"), Some("export"));
        assert_eq!(provider_kind_for_request("export"), Some("export"));
        assert_eq!(provider_kind_for_request("erasure"), Some("retention"));
        assert_eq!(provider_kind_for_request("correction"), Some("manual"));
        assert_eq!(provider_kind_for_request("restriction"), Some("manual"));
        assert_eq!(provider_kind_for_request("unknown"), None);
    }
}
