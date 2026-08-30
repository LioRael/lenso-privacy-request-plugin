//! PostgreSQL-backed Privacy Request workflow with separate requester, administrator, and worker roles.

mod operator;
#[cfg(all(test, feature = "postgres-acceptance"))]
mod postgres_tests;
mod schema;
mod storage;

use std::{cell::RefCell, collections::BTreeSet, fmt, rc::Rc, time::Duration};

use lenso::prelude::*;
use lenso_auth_sdk::{
    ActorAssertion, ActorAssertionVerifier, ActorProjectionError, AssertionClock, TypedActor,
};
use lenso_capability_access_control as access;
use lenso_capability_access_control::{
    AccessControlInvocationError, CheckPermissionRequest, CheckPermissionRequestScope,
};
use lenso_capability_data_export_source as export_source;
use lenso_capability_data_export_source::{CollectExportRequest, DataExportSourceInvocationError};
use lenso_capability_organization_membership as membership;
use lenso_capability_organization_membership::{
    CheckMembershipRequest, OrganizationMembershipInvocationError,
};
use lenso_capability_privacy_request as public;
use lenso_capability_privacy_request_admin as admin;
use lenso_capability_privacy_request_worker as worker;
use lenso_capability_retention_participant as retention;
use lenso_capability_retention_participant::{
    ApplyRetentionRequest, ApplyRetentionRequestMode, RetentionParticipantInvocationError,
};
use lenso_capability_secrets as secrets;
use lenso_capability_secrets::{ResolveRequest, SecretsClient, SecretsInvocationError};
use lenso_kernel::{PluginDependencies, RuntimeFailure};
use lenso_postgres_kit::OwnedPostgres;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

pub use operator::{PrivacyRequestOperator, PrivacyRequestOperatorError};

const DEPENDENCY_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CALLERS: usize = 64;
const MAX_ID_BYTES: usize = 512;
const MAX_DESCRIPTION_BYTES: usize = 50_000;
const MAX_REASON_BYTES: usize = 4_000;
const MAX_REFERENCE_BYTES: usize = 2_000;
const MAX_IDEMPOTENCY_BYTES: usize = 200;
const DEFAULT_DEADLINE_SECONDS: i64 = 30 * 24 * 60 * 60;
const DEFAULT_MAX_SOURCES: usize = 32;
const DEFAULT_MAX_PARTICIPANTS: usize = 32;
const DEFAULT_MAX_PROCESS_STEPS: usize = 25;
const DEFAULT_MAX_ITEMS_PER_PROVIDER: usize = 100;
const DEFAULT_MAX_TOTAL_ITEMS: usize = 1_000;
const DEFAULT_MAX_ITEM_BYTES: usize = 1024 * 1024;
const DEFAULT_MAX_TOTAL_EXPORT_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_PROCESS_LEASE_SECONDS: i64 = 15 * 60;

const REQUEST_USE: &str = "privacy.requests.use";
const REQUEST_VERIFY: &str = "privacy.requests.verify";
const REQUEST_HOLD: &str = "privacy.requests.hold";
const REQUEST_DECIDE: &str = "privacy.requests.decide";
const REQUEST_AUDIT: &str = "privacy.requests.audit";
const REQUEST_PROCESS: &str = "privacy.requests.process";

/// Immutable configuration for one Privacy Request Plugin Instance.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrivacyRequestConfig {
    schema: String,
    database_url_secret: String,
    auth_issuer: String,
    auth_assertion_public_key: String,
    public_callers: Vec<String>,
    admin_callers: Vec<String>,
    worker_callers: Vec<String>,
    #[serde(default = "default_deadline_seconds")]
    deadline_seconds: i64,
    #[serde(default = "default_max_sources")]
    max_sources: usize,
    #[serde(default = "default_max_participants")]
    max_participants: usize,
    #[serde(default = "default_max_process_steps")]
    max_process_steps_per_call: usize,
    #[serde(default = "default_max_items_per_provider")]
    max_items_per_provider: usize,
    #[serde(default = "default_max_total_items")]
    max_total_items: usize,
    #[serde(default = "default_max_item_bytes")]
    max_item_bytes: usize,
    #[serde(default = "default_max_total_export_bytes")]
    max_total_export_bytes: usize,
    #[serde(default = "default_process_lease_seconds")]
    process_lease_seconds: i64,
}

impl PrivacyRequestConfig {
    /// Creates and validates immutable Privacy Request configuration.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        schema: impl Into<String>,
        database_url_secret: impl Into<String>,
        auth_issuer: impl Into<String>,
        auth_assertion_public_key: impl Into<String>,
        public_callers: Vec<String>,
        admin_callers: Vec<String>,
        worker_callers: Vec<String>,
    ) -> Result<Self, PrivacyRequestConfigError> {
        let config = Self {
            schema: schema.into(),
            database_url_secret: database_url_secret.into(),
            auth_issuer: auth_issuer.into(),
            auth_assertion_public_key: auth_assertion_public_key.into(),
            public_callers,
            admin_callers,
            worker_callers,
            deadline_seconds: DEFAULT_DEADLINE_SECONDS,
            max_sources: DEFAULT_MAX_SOURCES,
            max_participants: DEFAULT_MAX_PARTICIPANTS,
            max_process_steps_per_call: DEFAULT_MAX_PROCESS_STEPS,
            max_items_per_provider: DEFAULT_MAX_ITEMS_PER_PROVIDER,
            max_total_items: DEFAULT_MAX_TOTAL_ITEMS,
            max_item_bytes: DEFAULT_MAX_ITEM_BYTES,
            max_total_export_bytes: DEFAULT_MAX_TOTAL_EXPORT_BYTES,
            process_lease_seconds: DEFAULT_PROCESS_LEASE_SECONDS,
        };
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<(), PrivacyRequestConfigError> {
        schema::schema_plan(self.schema.clone())
            .map_err(|_| PrivacyRequestConfigError::InvalidSchema)?;
        if !valid_secret_reference(&self.database_url_secret) {
            return Err(PrivacyRequestConfigError::InvalidSecretReference);
        }
        if !valid_identifier(&self.auth_issuer, 256) {
            return Err(PrivacyRequestConfigError::InvalidAuthIssuer);
        }
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| PrivacyRequestConfigError::InvalidAuthPublicKey)?;
        validate_callers(&self.public_callers)
            .map_err(|()| PrivacyRequestConfigError::InvalidPublicCallers)?;
        validate_callers(&self.admin_callers)
            .map_err(|()| PrivacyRequestConfigError::InvalidAdminCallers)?;
        validate_callers(&self.worker_callers)
            .map_err(|()| PrivacyRequestConfigError::InvalidWorkerCallers)?;
        if !(3_600..=31_536_000).contains(&self.deadline_seconds) {
            return Err(PrivacyRequestConfigError::InvalidDeadline);
        }
        if !(1..=100).contains(&self.max_sources)
            || !(1..=100).contains(&self.max_participants)
            || !(1..=100).contains(&self.max_process_steps_per_call)
            || !(1..=1_000).contains(&self.max_items_per_provider)
            || !(1..=10_000).contains(&self.max_total_items)
            || !(1..=8 * 1024 * 1024).contains(&self.max_item_bytes)
            || !(1..=8 * 1024 * 1024).contains(&self.max_total_export_bytes)
            || self.max_item_bytes > self.max_total_export_bytes
            || !(60..=3_600).contains(&self.process_lease_seconds)
        {
            return Err(PrivacyRequestConfigError::InvalidBounds);
        }
        Ok(())
    }

    fn verifier(&self) -> Result<ActorAssertionVerifier, RuntimeFailure> {
        ActorAssertionVerifier::from_public_key_base64(
            self.auth_issuer.clone(),
            &self.auth_assertion_public_key,
        )
        .map_err(|_| RuntimeFailure::InvalidResolvedPlan {
            detail: "Privacy Request Auth verification key is invalid".to_owned(),
        })
    }
}

/// Invalid immutable Privacy Request configuration.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum PrivacyRequestConfigError {
    #[error("invalid owned PostgreSQL schema")]
    InvalidSchema,
    #[error("invalid database URL secret reference")]
    InvalidSecretReference,
    #[error("invalid Auth issuer")]
    InvalidAuthIssuer,
    #[error("invalid Auth assertion public key")]
    InvalidAuthPublicKey,
    #[error("public_callers must contain unique exact Instance keys")]
    InvalidPublicCallers,
    #[error("admin_callers must contain unique exact Instance keys")]
    InvalidAdminCallers,
    #[error("worker_callers must contain unique exact Instance keys")]
    InvalidWorkerCallers,
    #[error("deadline_seconds must be between one hour and one year")]
    InvalidDeadline,
    #[error("provider, process, artifact, or lease bounds are invalid")]
    InvalidBounds,
}

fn validate_config(config: &PrivacyRequestConfig) -> Result<(), RuntimeFailure> {
    config
        .validate()
        .map_err(|error| RuntimeFailure::InvalidResolvedPlan {
            detail: format!("Privacy Request configuration is invalid: {error}"),
        })
}

#[derive(Clone, Debug)]
struct PreparedPrivacyRequest {
    postgres: OwnedPostgres,
}

#[lenso::plugin(
    lifecycle,
    configuration_schema = "configuration.schema.json",
    validate = validate_config
)]
#[derive(Clone)]
struct PostgresPrivacyRequestPlugin {
    #[config]
    config: PrivacyRequestConfig,
    secrets: Port<secrets::SecretsClient>,
    membership: Port<membership::OrganizationMembershipClient>,
    access: Port<access::AccessControlClient>,
    sources: ManyPort<export_source::DataExportSourceClient>,
    participants: ManyPort<retention::RetentionParticipantClient>,
    prepared: Rc<RefCell<Option<PreparedPrivacyRequest>>>,
}

impl fmt::Debug for PostgresPrivacyRequestPlugin {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PostgresPrivacyRequestPlugin")
            .field("schema", &self.config.schema)
            .field("prepared", &self.prepared.borrow().is_some())
            .field("source_count", &self.sources.len())
            .field("participant_count", &self.participants.len())
            .finish_non_exhaustive()
    }
}

#[lenso::provides(
    public::PrivacyRequest,
    admin::PrivacyRequestAdmin,
    worker::PrivacyRequestWorker
)]
impl PostgresPrivacyRequestPlugin {}

impl PostgresPrivacyRequestPlugin {
    async fn create_request(
        &self,
        context: Ctx,
        request: public::CreateRequestRequest,
    ) -> PluginResult<public::CreateRequestResponse, public::CreateRequestError> {
        let (caller, actor) = self
            .authorize::<public::CreateRequestError>(
                &context,
                &self.config.public_callers,
                public::CAPABILITY_ID,
                public::CREATE_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_USE,
            )
            .await?;
        if !valid_opaque_id(&request.organization_id, MAX_ID_BYTES)
            || !valid_text(&request.description, MAX_DESCRIPTION_BYTES, true)
            || !valid_idempotency_key(&request.idempotency_key)
        {
            return Err(PluginError::domain(
                public::CreateRequestError::InvalidRequest,
            ));
        }
        let kind = public_kind(&request.kind);
        let hash = request_hash(&request)?;
        let record = storage::create_request(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            &actor,
            kind,
            &request.description,
            self.config.deadline_seconds,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| {
            PluginError::domain(public::CreateRequestError::from_failure(failure))
        })?;
        wire_cast(&record)
    }

    async fn get_request(
        &self,
        context: Ctx,
        request: public::GetRequestRequest,
    ) -> PluginResult<public::GetRequestResponse, public::GetRequestError> {
        let (_, actor) = self
            .authorize::<public::GetRequestError>(
                &context,
                &self.config.public_callers,
                public::CAPABILITY_ID,
                public::GET_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_USE,
            )
            .await?;
        if !valid_opaque_id(&request.organization_id, MAX_ID_BYTES)
            || !valid_request_ref(&request.request_ref)
        {
            return Err(PluginError::domain(public::GetRequestError::InvalidRequest));
        }
        let postgres = self.prepared().map_err(PluginError::runtime)?.postgres;
        let record = storage::get_owned_request(
            &postgres,
            &request.organization_id,
            &request.request_ref,
            &actor,
        )
        .await
        .map_err(storage_runtime)?
        .ok_or_else(|| PluginError::domain(public::GetRequestError::RequestNotFound))?;
        let result_items =
            if record.state == "completed" && matches!(record.kind.as_str(), "access" | "export") {
                storage::get_export_items(&postgres, record.request_id)
                    .await
                    .map_err(storage_runtime)?
            } else {
                Vec::new()
            };
        let mut value = serde_json::to_value(&record).map_err(serialization_runtime)?;
        value
            .as_object_mut()
            .ok_or_else(|| {
                PluginError::runtime(RuntimeFailure::Internal {
                    detail: "Privacy Request record did not serialize as an object".to_owned(),
                })
            })?
            .insert(
                "result_items".to_owned(),
                serde_json::to_value(result_items).map_err(serialization_runtime)?,
            );
        serde_json::from_value(value).map_err(serialization_runtime)
    }

    async fn list_requests(
        &self,
        context: Ctx,
        request: public::ListRequestsRequest,
    ) -> PluginResult<public::ListRequestsResponse, public::ListRequestsError> {
        let (_, actor) = self
            .authorize::<public::ListRequestsError>(
                &context,
                &self.config.public_callers,
                public::CAPABILITY_ID,
                public::LIST_REQUESTS_OPERATION,
                &request.organization_id,
                REQUEST_USE,
            )
            .await?;
        let cursor =
            parse_optional_cursor(request.cursor.as_deref(), storage::decode_request_cursor)
                .map_err(|()| PluginError::domain(public::ListRequestsError::InvalidRequest))?;
        if !valid_opaque_id(&request.organization_id, MAX_ID_BYTES)
            || !(1..=200).contains(&request.limit)
        {
            return Err(PluginError::domain(
                public::ListRequestsError::InvalidRequest,
            ));
        }
        let state = request.state.as_ref().map(public_list_state);
        let mut records = storage::list_owned_requests(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &storage::RequestFilters {
                organization_id: &request.organization_id,
                requester_subject: &actor,
                state,
                cursor: cursor.as_ref(),
                limit: request.limit + 1,
            },
        )
        .await
        .map_err(storage_runtime)?;
        let page_size = usize::try_from(request.limit)
            .map_err(|_| PluginError::domain(public::ListRequestsError::InvalidRequest))?;
        let has_more = records.len() > page_size;
        if has_more {
            records.pop();
        }
        let next_cursor = if has_more {
            records
                .last()
                .map(storage::encode_request_cursor)
                .transpose()
                .map_err(storage_runtime)?
        } else {
            None
        };
        let requests = records
            .iter()
            .map(wire_cast)
            .collect::<PluginResult<Vec<public::ListRequestsResponseRequestsItem>, _>>()?;
        Ok(public::ListRequestsResponse {
            requests,
            next_cursor,
        })
    }

    async fn withdraw_request(
        &self,
        context: Ctx,
        request: public::WithdrawRequestRequest,
    ) -> PluginResult<public::WithdrawRequestResponse, public::WithdrawRequestError> {
        let (caller, actor) = self
            .authorize::<public::WithdrawRequestError>(
                &context,
                &self.config.public_callers,
                public::CAPABILITY_ID,
                public::WITHDRAW_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_USE,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            public::WITHDRAW_REQUEST_OPERATION,
            storage::Mutation::Withdraw {
                reason: &request.reason,
            },
        )
        .await
    }

    async fn verify_identity(
        &self,
        context: Ctx,
        request: admin::VerifyIdentityRequest,
    ) -> PluginResult<admin::VerifyIdentityResponse, admin::VerifyIdentityError> {
        let (caller, actor) = self
            .authorize::<admin::VerifyIdentityError>(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::VERIFY_IDENTITY_OPERATION,
                &request.organization_id,
                REQUEST_VERIFY,
            )
            .await?;
        let outcome = match request.outcome {
            admin::VerifyIdentityRequestOutcome::Verified => "verified",
            admin::VerifyIdentityRequestOutcome::Failed => "failed",
        };
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            admin::VERIFY_IDENTITY_OPERATION,
            storage::Mutation::VerifyIdentity {
                outcome,
                evidence_reference: &request.evidence_reference,
            },
        )
        .await
    }

    async fn list_admin_requests(
        &self,
        context: Ctx,
        request: admin::ListAdminRequestsRequest,
    ) -> PluginResult<admin::ListAdminRequestsResponse, admin::ListAdminRequestsError> {
        self.authorize::<admin::ListAdminRequestsError>(
            &context,
            &self.config.admin_callers,
            admin::CAPABILITY_ID,
            admin::LIST_ADMIN_REQUESTS_OPERATION,
            &request.organization_id,
            REQUEST_AUDIT,
        )
        .await?;
        let cursor = parse_optional_cursor(
            request.cursor.as_deref(),
            storage::decode_admin_request_cursor,
        )
        .map_err(|()| PluginError::domain(admin::ListAdminRequestsError::InvalidRequest))?;
        if !(1..=200).contains(&request.limit)
            || request
                .requester_subject
                .as_deref()
                .is_some_and(|value| !valid_opaque_id(value, MAX_ID_BYTES))
        {
            return Err(PluginError::domain(
                admin::ListAdminRequestsError::InvalidRequest,
            ));
        }
        let state = request.state.as_ref().map(admin_list_state);
        let kind = request.kind.as_ref().map(admin_list_kind);
        let mut records = storage::list_admin_requests(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &storage::AdminRequestFilters {
                organization_id: &request.organization_id,
                state,
                kind,
                requester_subject: request.requester_subject.as_deref(),
                cursor: cursor.as_ref(),
                limit: request.limit + 1,
            },
        )
        .await
        .map_err(storage_runtime)?;
        let page_size = usize::try_from(request.limit)
            .map_err(|_| PluginError::domain(admin::ListAdminRequestsError::InvalidRequest))?;
        let has_more = records.len() > page_size;
        if has_more {
            records.pop();
        }
        let next_cursor = if has_more {
            records
                .last()
                .map(storage::encode_admin_request_cursor)
                .transpose()
                .map_err(storage_runtime)?
        } else {
            None
        };
        let requests = records
            .iter()
            .map(wire_cast)
            .collect::<PluginResult<Vec<admin::ListAdminRequestsResponseRequestsItem>, _>>()?;
        Ok(admin::ListAdminRequestsResponse {
            requests,
            next_cursor,
        })
    }

    async fn set_legal_hold(
        &self,
        context: Ctx,
        request: admin::SetLegalHoldRequest,
    ) -> PluginResult<admin::SetLegalHoldResponse, admin::SetLegalHoldError> {
        let (caller, actor) = self
            .authorize::<admin::SetLegalHoldError>(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::SET_LEGAL_HOLD_OPERATION,
                &request.organization_id,
                REQUEST_HOLD,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            admin::SET_LEGAL_HOLD_OPERATION,
            storage::Mutation::LegalHold {
                active: request.active,
                reason: &request.reason,
            },
        )
        .await
    }

    async fn pause_request(
        &self,
        context: Ctx,
        request: admin::PauseRequestRequest,
    ) -> PluginResult<admin::PauseRequestResponse, admin::PauseRequestError> {
        let (caller, actor) = self
            .authorize::<admin::PauseRequestError>(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::PAUSE_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_DECIDE,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            admin::PAUSE_REQUEST_OPERATION,
            storage::Mutation::Pause {
                reason: &request.reason,
            },
        )
        .await
    }

    async fn resume_request(
        &self,
        context: Ctx,
        request: admin::ResumeRequestRequest,
    ) -> PluginResult<admin::ResumeRequestResponse, admin::ResumeRequestError> {
        let (caller, actor) = self
            .authorize::<admin::ResumeRequestError>(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::RESUME_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_DECIDE,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            admin::RESUME_REQUEST_OPERATION,
            storage::Mutation::Resume,
        )
        .await
    }

    async fn reject_request(
        &self,
        context: Ctx,
        request: admin::RejectRequestRequest,
    ) -> PluginResult<admin::RejectRequestResponse, admin::RejectRequestError> {
        let (caller, actor) = self
            .authorize::<admin::RejectRequestError>(
                &context,
                &self.config.admin_callers,
                admin::CAPABILITY_ID,
                admin::REJECT_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_DECIDE,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            admin::REJECT_REQUEST_OPERATION,
            storage::Mutation::Reject {
                reason: &request.reason,
            },
        )
        .await
    }

    async fn list_activity(
        &self,
        context: Ctx,
        request: admin::ListActivityRequest,
    ) -> PluginResult<admin::ListActivityResponse, admin::ListActivityError> {
        self.authorize::<admin::ListActivityError>(
            &context,
            &self.config.admin_callers,
            admin::CAPABILITY_ID,
            admin::LIST_ACTIVITY_OPERATION,
            &request.organization_id,
            REQUEST_AUDIT,
        )
        .await?;
        let request_id =
            parse_read_request(&request.organization_id, &request.request_id, request.limit)
                .ok_or_else(|| PluginError::domain(admin::ListActivityError::InvalidRequest))?;
        let cursor =
            parse_optional_cursor(request.cursor.as_deref(), storage::decode_activity_cursor)
                .map_err(|()| PluginError::domain(admin::ListActivityError::InvalidRequest))?;
        let mut records = storage::list_activity(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &request.organization_id,
            request_id,
            cursor.as_ref(),
            request.limit + 1,
        )
        .await
        .map_err(storage_runtime)?
        .ok_or_else(|| PluginError::domain(admin::ListActivityError::RequestNotFound))?;
        let page_size = usize::try_from(request.limit)
            .map_err(|_| PluginError::domain(admin::ListActivityError::InvalidRequest))?;
        let has_more = records.len() > page_size;
        if has_more {
            records.pop();
        }
        let next_cursor = if has_more {
            records
                .last()
                .map(storage::encode_activity_cursor)
                .transpose()
                .map_err(storage_runtime)?
        } else {
            None
        };
        let activities = records
            .iter()
            .map(wire_cast)
            .collect::<PluginResult<Vec<admin::ListActivityResponseActivitiesItem>, _>>()?;
        Ok(admin::ListActivityResponse {
            activities,
            next_cursor,
        })
    }

    async fn claim_request(
        &self,
        context: Ctx,
        request: worker::ClaimRequestRequest,
    ) -> PluginResult<worker::ClaimRequestResponse, worker::ClaimRequestError> {
        let (caller, actor) = self
            .authorize::<worker::ClaimRequestError>(
                &context,
                &self.config.worker_callers,
                worker::CAPABILITY_ID,
                worker::CLAIM_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_PROCESS,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            worker::CLAIM_REQUEST_OPERATION,
            storage::Mutation::Claim,
        )
        .await
    }

    async fn claim_next(
        &self,
        context: Ctx,
        request: worker::ClaimNextRequest,
    ) -> PluginResult<worker::ClaimNextResponse, worker::ClaimNextError> {
        let (caller, actor) = self
            .authorize::<worker::ClaimNextError>(
                &context,
                &self.config.worker_callers,
                worker::CAPABILITY_ID,
                worker::CLAIM_NEXT_OPERATION,
                &request.organization_id,
                REQUEST_PROCESS,
            )
            .await?;
        if !valid_idempotency_key(&request.idempotency_key) {
            return Err(PluginError::domain(worker::ClaimNextError::InvalidRequest));
        }
        let kind = request.kind.as_ref().map(worker_claim_kind);
        let hash = request_hash(&request)?;
        let record = storage::claim_next_request(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            kind,
            &actor,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(worker::ClaimNextError::from_failure(failure)))?;
        wire_cast(&record)
    }

    #[allow(clippy::too_many_lines)]
    async fn process_request(
        &self,
        context: Ctx,
        request: worker::ProcessRequestRequest,
    ) -> PluginResult<worker::ProcessRequestResponse, worker::ProcessRequestError> {
        let (caller, actor) = self
            .authorize::<worker::ProcessRequestError>(
                &context,
                &self.config.worker_callers,
                worker::CAPABILITY_ID,
                worker::PROCESS_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_PROCESS,
            )
            .await?;
        let (request_id, expected_revision) = parse_mutation_request(
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
        )
        .ok_or_else(|| PluginError::domain(worker::ProcessRequestError::InvalidRequest))?;
        if !(1..=i64::try_from(self.config.max_process_steps_per_call)
            .expect("configured process bound fits i64"))
            .contains(&request.limit)
            || request
                .manual_evidence_reference
                .as_deref()
                .is_some_and(|value| !valid_text(value, MAX_REFERENCE_BYTES, false))
        {
            return Err(PluginError::domain(
                worker::ProcessRequestError::InvalidRequest,
            ));
        }
        let cursor = match request.cursor.as_deref() {
            Some(value) => storage::decode_process_cursor(value, request_id)
                .ok_or_else(|| PluginError::domain(worker::ProcessRequestError::InvalidRequest))?
                .into(),
            None => None,
        };
        let hash = request_hash(&request)?;
        let snapshots = self.provider_snapshots();
        let start = storage::begin_process(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            request_id,
            &actor,
            expected_revision,
            &snapshots,
            cursor,
            request.limit,
            self.config.process_lease_seconds,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| {
            PluginError::domain(worker::ProcessRequestError::from_failure(failure))
        })?;
        let (record, steps) = match start {
            storage::ProcessStart::Replay(result) => return wire_cast(&result),
            storage::ProcessStart::Execute { request, steps } => (request, steps),
        };
        let postgres = self.prepared().map_err(PluginError::runtime)?.postgres;
        let mut last_sequence = None;
        for step in &steps {
            last_sequence = Some(step.sequence);
            match step.provider_kind.as_str() {
                "export" => {
                    self.execute_export_step(&context, &postgres, &record, step)
                        .await?;
                }
                "retention" => {
                    self.execute_retention_step(&context, &postgres, &record, step)
                        .await?;
                }
                "manual" => {
                    if let Some(reference) = request.manual_evidence_reference.as_deref() {
                        storage::record_step_success(
                            &postgres,
                            request_id,
                            step.sequence,
                            None,
                            Some(reference),
                        )
                        .await
                        .map_err(storage_runtime)?;
                    } else {
                        storage::record_step_failure(
                            &postgres,
                            request_id,
                            step.sequence,
                            "manual_evidence_required",
                        )
                        .await
                        .map_err(storage_runtime)?;
                    }
                }
                _ => {
                    return Err(PluginError::runtime(RuntimeFailure::ProtocolViolation {
                        capability: worker::CAPABILITY_ID,
                    }));
                }
            }
        }
        let result = storage::finish_process(
            &postgres,
            &caller,
            &request.idempotency_key,
            &hash,
            &request.organization_id,
            request_id,
            &actor,
            last_sequence,
        )
        .await
        .map_err(storage_runtime)?;
        wire_cast(&result)
    }

    async fn complete_request(
        &self,
        context: Ctx,
        request: worker::CompleteRequestRequest,
    ) -> PluginResult<worker::CompleteRequestResponse, worker::CompleteRequestError> {
        let (caller, actor) = self
            .authorize::<worker::CompleteRequestError>(
                &context,
                &self.config.worker_callers,
                worker::CAPABILITY_ID,
                worker::COMPLETE_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_PROCESS,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            worker::COMPLETE_REQUEST_OPERATION,
            storage::Mutation::Complete {
                completion_reference: &request.completion_reference,
            },
        )
        .await
    }

    async fn fail_request(
        &self,
        context: Ctx,
        request: worker::FailRequestRequest,
    ) -> PluginResult<worker::FailRequestResponse, worker::FailRequestError> {
        let (caller, actor) = self
            .authorize::<worker::FailRequestError>(
                &context,
                &self.config.worker_callers,
                worker::CAPABILITY_ID,
                worker::FAIL_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_PROCESS,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            worker::FAIL_REQUEST_OPERATION,
            storage::Mutation::Fail {
                reason: &request.reason,
                retryable: request.retryable,
            },
        )
        .await
    }

    async fn retry_request(
        &self,
        context: Ctx,
        request: worker::RetryRequestRequest,
    ) -> PluginResult<worker::RetryRequestResponse, worker::RetryRequestError> {
        let (caller, actor) = self
            .authorize::<worker::RetryRequestError>(
                &context,
                &self.config.worker_callers,
                worker::CAPABILITY_ID,
                worker::RETRY_REQUEST_OPERATION,
                &request.organization_id,
                REQUEST_PROCESS,
            )
            .await?;
        self.run_mutation(
            &request,
            &caller,
            &actor,
            &request.organization_id,
            &request.request_id,
            &request.expected_revision,
            &request.idempotency_key,
            worker::RETRY_REQUEST_OPERATION,
            storage::Mutation::Retry,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_mutation<T, R, E>(
        &self,
        request: &T,
        caller: &str,
        actor: &str,
        organization_id: &str,
        request_id: &str,
        expected_revision: &str,
        idempotency_key: &str,
        operation: &'static str,
        mutation: storage::Mutation<'_>,
    ) -> PluginResult<R, E>
    where
        T: Serialize,
        R: DeserializeOwned,
        E: RoleError,
    {
        let (request_id, expected_revision) = parse_mutation_request(
            organization_id,
            request_id,
            expected_revision,
            idempotency_key,
        )
        .ok_or_else(|| PluginError::domain(E::invalid_request()))?;
        if !valid_mutation_payload(&mutation) {
            return Err(PluginError::domain(E::invalid_request()));
        }
        let hash = request_hash(request)?;
        let record = storage::mutate_request(
            &self.prepared().map_err(PluginError::runtime)?.postgres,
            caller,
            idempotency_key,
            operation,
            &hash,
            organization_id,
            request_id,
            actor,
            expected_revision,
            &mutation,
        )
        .await
        .map_err(storage_runtime)?
        .map_err(|failure| PluginError::domain(E::from_failure(failure)))?;
        wire_cast(&record)
    }

    #[allow(clippy::too_many_arguments)]
    async fn authorize<E: RoleError>(
        &self,
        context: &Ctx,
        allowed_callers: &[String],
        capability: &str,
        operation: &str,
        organization_id: &str,
        permission: &str,
    ) -> Result<(String, String), PluginError<E>> {
        let caller = Self::allowed_caller(context, allowed_callers)
            .ok_or_else(|| PluginError::domain(E::forbidden()))?;
        let actor = self
            .authenticated_subject(context, capability, operation)
            .map_err(|()| PluginError::domain(E::unauthenticated()))?;
        if !valid_opaque_id(organization_id, MAX_ID_BYTES) {
            return Err(PluginError::domain(E::invalid_request()));
        }
        let active = self
            .require_membership(context, organization_id, &actor)
            .await
            .map_err(PluginError::runtime)?;
        let allowed = self
            .permission(context, organization_id, &actor, permission)
            .await
            .map_err(PluginError::runtime)?;
        if !active || !allowed {
            return Err(PluginError::domain(E::forbidden()));
        }
        Ok((caller, actor))
    }

    async fn execute_export_step(
        &self,
        context: &Ctx,
        postgres: &OwnedPostgres,
        request: &storage::RequestRecord,
        step: &storage::StepRecord,
    ) -> Result<(), PluginError<worker::ProcessRequestError>> {
        let Some(provider) = self
            .sources
            .iter()
            .find(|provider| provider.provider_instance() == step.provider_instance)
        else {
            storage::record_step_failure(
                postgres,
                request.request_id,
                step.sequence,
                "provider_unavailable",
            )
            .await
            .map_err(storage_runtime)?;
            return Ok(());
        };
        let result = provider
            .collect_export_with_context(
                context.clone(),
                CollectExportRequest {
                    export_id: format!("privacy-export-{}", request.request_id),
                    scope_kind: "organization".to_owned(),
                    scope_id: request.organization_id.clone(),
                    subject: request.requester_subject.clone(),
                },
            )
            .await;
        let response = match result {
            Ok(response) => response,
            Err(DataExportSourceInvocationError::Domain(_)) => {
                storage::record_step_failure(
                    postgres,
                    request.request_id,
                    step.sequence,
                    "source_rejected",
                )
                .await
                .map_err(storage_runtime)?;
                return Ok(());
            }
            Err(DataExportSourceInvocationError::Runtime(_)) => {
                storage::record_step_failure(
                    postgres,
                    request.request_id,
                    step.sequence,
                    "runtime_failure",
                )
                .await
                .map_err(storage_runtime)?;
                return Ok(());
            }
        };
        let mut names = BTreeSet::new();
        let valid = response.items.len() <= self.config.max_items_per_provider
            && response.items.iter().all(|item| {
                item.payload.len() <= self.config.max_item_bytes
                    && valid_item_name(&item.item_name)
                    && valid_media_type(&item.media_type)
                    && !item.payload.contains('\0')
                    && names.insert(item.item_name.clone())
            });
        if !valid {
            storage::record_step_failure(
                postgres,
                request.request_id,
                step.sequence,
                "protocol_violation",
            )
            .await
            .map_err(storage_runtime)?;
            return Ok(());
        }
        let items = response
            .items
            .into_iter()
            .map(|item| (item.item_name, item.media_type, item.payload))
            .collect::<Vec<_>>();
        if !storage::record_export_success(
            postgres,
            request.request_id,
            step.sequence,
            &step.provider_instance,
            &items,
            self.config.max_total_items,
            self.config.max_total_export_bytes,
        )
        .await
        .map_err(storage_runtime)?
        {
            storage::record_step_failure(
                postgres,
                request.request_id,
                step.sequence,
                "artifact_too_large",
            )
            .await
            .map_err(storage_runtime)?;
        }
        Ok(())
    }

    async fn execute_retention_step(
        &self,
        context: &Ctx,
        postgres: &OwnedPostgres,
        request: &storage::RequestRecord,
        step: &storage::StepRecord,
    ) -> Result<(), PluginError<worker::ProcessRequestError>> {
        let Some(provider) = self
            .participants
            .iter()
            .find(|provider| provider.provider_instance() == step.provider_instance)
        else {
            storage::record_step_failure(
                postgres,
                request.request_id,
                step.sequence,
                "provider_unavailable",
            )
            .await
            .map_err(storage_runtime)?;
            return Ok(());
        };
        let result = provider
            .apply_retention_with_context(
                context.clone(),
                ApplyRetentionRequest {
                    action_id: format!("privacy-erasure-{}", request.request_id),
                    scope_kind: "organization".to_owned(),
                    scope_id: request.organization_id.clone(),
                    subject: request.requester_subject.clone(),
                    mode: ApplyRetentionRequestMode::Delete,
                    reason: "approved privacy erasure workflow".to_owned(),
                },
            )
            .await;
        match result {
            Ok(response)
                if valid_text(&response.receipt, MAX_REFERENCE_BYTES, false)
                    && !response.receipt.contains('\0') =>
            {
                storage::record_step_success(
                    postgres,
                    request.request_id,
                    step.sequence,
                    Some(&response.receipt),
                    None,
                )
                .await
                .map_err(storage_runtime)?;
            }
            Ok(_) => {
                storage::record_step_failure(
                    postgres,
                    request.request_id,
                    step.sequence,
                    "protocol_violation",
                )
                .await
                .map_err(storage_runtime)?;
            }
            Err(RetentionParticipantInvocationError::Domain(_)) => {
                storage::record_step_failure(
                    postgres,
                    request.request_id,
                    step.sequence,
                    "participant_rejected",
                )
                .await
                .map_err(storage_runtime)?;
            }
            Err(RetentionParticipantInvocationError::Runtime(_)) => {
                storage::record_step_failure(
                    postgres,
                    request.request_id,
                    step.sequence,
                    "runtime_failure",
                )
                .await
                .map_err(storage_runtime)?;
            }
        }
        Ok(())
    }

    fn provider_snapshots(&self) -> Vec<storage::ProviderSnapshot> {
        // The request kind is loaded transactionally by storage. Supplying all typed bindings here
        // lets storage choose and freeze only the matching provider set in the same transaction.
        let mut snapshots = self
            .sources
            .iter()
            .map(|provider| storage::ProviderSnapshot {
                kind: "export",
                instance: provider.provider_instance().to_owned(),
            })
            .collect::<Vec<_>>();
        snapshots.extend(
            self.participants
                .iter()
                .map(|provider| storage::ProviderSnapshot {
                    kind: "retention",
                    instance: provider.provider_instance().to_owned(),
                }),
        );
        snapshots.push(storage::ProviderSnapshot {
            kind: "manual",
            instance: "privacy-manual-review".to_owned(),
        });
        snapshots.sort_by(|left, right| {
            (left.kind, left.instance.as_str()).cmp(&(right.kind, right.instance.as_str()))
        });
        snapshots
    }

    fn prepared(&self) -> Result<PreparedPrivacyRequest, RuntimeFailure> {
        self.prepared
            .borrow()
            .clone()
            .ok_or_else(|| RuntimeFailure::PluginFailure {
                detail: "Privacy Request Plugin is not prepared".to_owned(),
            })
    }

    fn allowed_caller(context: &Ctx, allowed: &[String]) -> Option<String> {
        context.caller_instance().and_then(|caller| {
            allowed
                .iter()
                .any(|entry| entry == caller)
                .then(|| caller.to_owned())
        })
    }

    fn authenticated_subject(
        &self,
        context: &Ctx,
        capability: &str,
        operation: &str,
    ) -> Result<String, ()> {
        let actor = self
            .config
            .verifier()
            .map_err(|_| ())?
            .project_context::<PrivacyActor>(context, capability, operation, &UtcClock)
            .map_err(|_| ())?;
        valid_opaque_id(&actor.subject, MAX_ID_BYTES)
            .then_some(actor.subject)
            .ok_or(())
    }

    async fn require_membership(
        &self,
        context: &Ctx,
        organization_id: &str,
        subject: &str,
    ) -> Result<bool, RuntimeFailure> {
        self.membership
            .check_membership_with_context(
                context.clone(),
                CheckMembershipRequest {
                    organization_id: organization_id.to_owned(),
                    subject: subject.to_owned(),
                },
            )
            .await
            .map(|response| response.active)
            .map_err(|error| match error {
                OrganizationMembershipInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                    detail:
                        "Organization Membership rejected a Privacy Request authorization query"
                            .to_owned(),
                },
                OrganizationMembershipInvocationError::Runtime(error) => error,
            })
    }

    async fn permission(
        &self,
        context: &Ctx,
        organization_id: &str,
        subject: &str,
        permission: &str,
    ) -> Result<bool, RuntimeFailure> {
        self.access
            .check_permission_with_context(
                context.clone(),
                CheckPermissionRequest {
                    subject: subject.to_owned(),
                    scope: CheckPermissionRequestScope {
                        kind: "organization".to_owned(),
                        id: organization_id.to_owned(),
                    },
                    permission: permission.to_owned(),
                },
            )
            .await
            .map(|response| response.allowed)
            .map_err(|error| match error {
                AccessControlInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                    detail: "Access Control rejected a Privacy Request authorization query"
                        .to_owned(),
                },
                AccessControlInvocationError::Runtime(error) => error,
            })
    }
}

impl Lifecycle for PostgresPrivacyRequestPlugin {
    async fn activate(&self, context: ActivateContext) -> Result<(), RuntimeFailure> {
        validate_provider_instances(&self.sources, self.config.max_sources, "Data Export Source")?;
        validate_provider_instances(
            &self.participants,
            self.config.max_participants,
            "Retention Participant",
        )?;
        let database_url = resolve_secret(
            &self.secrets,
            context.dependencies(),
            context.cancellation(),
            &self.config.database_url_secret,
        )
        .await?;
        let postgres = OwnedPostgres::prepare(
            &database_url,
            schema::schema_plan(self.config.schema.clone()).map_err(|error| {
                RuntimeFailure::InvalidResolvedPlan {
                    detail: error.to_string(),
                }
            })?,
        )
        .await
        .map_err(|error| RuntimeFailure::PluginFailure {
            detail: error.to_string(),
        })?;
        self.prepared
            .borrow_mut()
            .replace(PreparedPrivacyRequest { postgres });
        Ok(())
    }

    async fn deactivate(&self, _context: DeactivateContext) -> Result<(), RuntimeFailure> {
        let prepared = self.prepared.borrow_mut().take();
        if let Some(prepared) = prepared {
            prepared.postgres.pool().close().await;
        }
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct PrivacyActor {
    subject: String,
}

impl TypedActor for PrivacyActor {
    fn from_assertion(assertion: &ActorAssertion) -> Result<Self, ActorProjectionError> {
        Ok(Self {
            subject: assertion.subject().to_owned(),
        })
    }
}

#[derive(Clone, Copy, Debug)]
struct UtcClock;

impl AssertionClock for UtcClock {
    fn now(&self) -> OffsetDateTime {
        OffsetDateTime::now_utc()
    }
}

async fn resolve_secret(
    secrets: &SecretsClient,
    dependencies: &PluginDependencies,
    cancellation: lenso_kernel::CancellationToken,
    reference: &str,
) -> Result<Zeroizing<String>, RuntimeFailure> {
    let context = dependencies.invocation_context_after(DEPENDENCY_TIMEOUT, cancellation)?;
    secrets
        .resolve_with_context(
            context,
            ResolveRequest {
                reference: reference.to_owned(),
            },
        )
        .await
        .map(|response| Zeroizing::new(response.value))
        .map_err(|error| match error {
            SecretsInvocationError::Domain(_) => RuntimeFailure::PluginFailure {
                detail: format!("database URL secret `{reference}` was rejected"),
            },
            SecretsInvocationError::Runtime(error) => error,
        })
}

trait RoleError: Sized {
    fn unauthenticated() -> Self;
    fn forbidden() -> Self;
    fn invalid_request() -> Self;
    fn from_failure(failure: storage::DomainFailure) -> Self;
}

macro_rules! impl_role_error {
    ($($error:path),+ $(,)?) => {
        $(impl RoleError for $error {
            fn unauthenticated() -> Self { Self::Unauthenticated }
            fn forbidden() -> Self { Self::Forbidden }
            fn invalid_request() -> Self { Self::InvalidRequest }
            fn from_failure(failure: storage::DomainFailure) -> Self {
                match failure {
                    storage::DomainFailure::RequestNotFound => Self::RequestNotFound,
                    storage::DomainFailure::RevisionConflict => Self::RevisionConflict,
                    storage::DomainFailure::IdempotencyConflict => Self::IdempotencyConflict,
                    storage::DomainFailure::InvalidTransition => Self::InvalidTransition,
                    storage::DomainFailure::Forbidden => Self::Forbidden,
                    storage::DomainFailure::OperationInProgress => Self::IdempotencyConflict,
                }
            }
        })+
    };
}

impl_role_error!(
    public::CreateRequestError,
    public::GetRequestError,
    public::ListRequestsError,
    public::WithdrawRequestError,
    admin::VerifyIdentityError,
    admin::ListAdminRequestsError,
    admin::SetLegalHoldError,
    admin::PauseRequestError,
    admin::ResumeRequestError,
    admin::RejectRequestError,
    admin::ListActivityError,
    worker::ClaimRequestError,
    worker::ClaimNextError,
    worker::CompleteRequestError,
    worker::FailRequestError,
    worker::RetryRequestError,
);

impl RoleError for worker::ProcessRequestError {
    fn unauthenticated() -> Self {
        Self::Unauthenticated
    }
    fn forbidden() -> Self {
        Self::Forbidden
    }
    fn invalid_request() -> Self {
        Self::InvalidRequest
    }
    fn from_failure(failure: storage::DomainFailure) -> Self {
        match failure {
            storage::DomainFailure::RequestNotFound => Self::RequestNotFound,
            storage::DomainFailure::RevisionConflict => Self::RevisionConflict,
            storage::DomainFailure::IdempotencyConflict => Self::IdempotencyConflict,
            storage::DomainFailure::InvalidTransition => Self::InvalidTransition,
            storage::DomainFailure::Forbidden => Self::Forbidden,
            storage::DomainFailure::OperationInProgress => Self::OperationInProgress,
        }
    }
}

fn request_hash<T: Serialize, E>(request: &T) -> Result<Vec<u8>, PluginError<E>> {
    serde_json::to_vec(request)
        .map(|wire| Sha256::digest(wire).to_vec())
        .map_err(serialization_runtime)
}

fn wire_cast<T: DeserializeOwned, E>(value: &impl Serialize) -> Result<T, PluginError<E>> {
    serde_json::to_value(value)
        .and_then(serde_json::from_value)
        .map_err(serialization_runtime)
}

#[allow(clippy::needless_pass_by_value)]
fn serialization_runtime<E>(error: serde_json::Error) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::Internal {
        detail: format!("Privacy Request wire serialization failed: {error}"),
    })
}

#[allow(clippy::needless_pass_by_value)]
fn storage_runtime<E>(error: storage::StorageError) -> PluginError<E> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: error.to_string(),
    })
}

fn public_kind(value: &public::CreateRequestRequestKind) -> &'static str {
    match value {
        public::CreateRequestRequestKind::Access => "access",
        public::CreateRequestRequestKind::Export => "export",
        public::CreateRequestRequestKind::Erasure => "erasure",
        public::CreateRequestRequestKind::Correction => "correction",
        public::CreateRequestRequestKind::Restriction => "restriction",
    }
}

fn public_list_state(value: &public::ListRequestsRequestState) -> &'static str {
    match value {
        public::ListRequestsRequestState::PendingVerification => "pending_verification",
        public::ListRequestsRequestState::Ready => "ready",
        public::ListRequestsRequestState::Claimed => "claimed",
        public::ListRequestsRequestState::Processing => "processing",
        public::ListRequestsRequestState::AwaitingCompletion => "awaiting_completion",
        public::ListRequestsRequestState::Paused => "paused",
        public::ListRequestsRequestState::Completed => "completed",
        public::ListRequestsRequestState::Rejected => "rejected",
        public::ListRequestsRequestState::Withdrawn => "withdrawn",
        public::ListRequestsRequestState::Failed => "failed",
    }
}

fn admin_list_state(value: &admin::ListAdminRequestsRequestState) -> &'static str {
    match value {
        admin::ListAdminRequestsRequestState::PendingVerification => "pending_verification",
        admin::ListAdminRequestsRequestState::Ready => "ready",
        admin::ListAdminRequestsRequestState::Claimed => "claimed",
        admin::ListAdminRequestsRequestState::Processing => "processing",
        admin::ListAdminRequestsRequestState::AwaitingCompletion => "awaiting_completion",
        admin::ListAdminRequestsRequestState::Paused => "paused",
        admin::ListAdminRequestsRequestState::Completed => "completed",
        admin::ListAdminRequestsRequestState::Rejected => "rejected",
        admin::ListAdminRequestsRequestState::Withdrawn => "withdrawn",
        admin::ListAdminRequestsRequestState::Failed => "failed",
    }
}

fn admin_list_kind(value: &admin::ListAdminRequestsRequestKind) -> &'static str {
    match value {
        admin::ListAdminRequestsRequestKind::Access => "access",
        admin::ListAdminRequestsRequestKind::Export => "export",
        admin::ListAdminRequestsRequestKind::Erasure => "erasure",
        admin::ListAdminRequestsRequestKind::Correction => "correction",
        admin::ListAdminRequestsRequestKind::Restriction => "restriction",
    }
}

fn worker_claim_kind(value: &worker::ClaimNextRequestKind) -> &'static str {
    match value {
        worker::ClaimNextRequestKind::Access => "access",
        worker::ClaimNextRequestKind::Export => "export",
        worker::ClaimNextRequestKind::Erasure => "erasure",
        worker::ClaimNextRequestKind::Correction => "correction",
        worker::ClaimNextRequestKind::Restriction => "restriction",
    }
}

fn parse_mutation_request(
    organization_id: &str,
    request_id: &str,
    revision: &str,
    key: &str,
) -> Option<(Uuid, i64)> {
    if !valid_opaque_id(organization_id, MAX_ID_BYTES) || !valid_idempotency_key(key) {
        return None;
    }
    Some((
        Uuid::parse_str(request_id).ok()?,
        revision.parse::<i64>().ok().filter(|value| *value > 0)?,
    ))
}

fn parse_read_request(organization_id: &str, request_id: &str, limit: i64) -> Option<Uuid> {
    valid_opaque_id(organization_id, MAX_ID_BYTES)
        .then(|| Uuid::parse_str(request_id).ok())
        .flatten()
        .filter(|_| (1..=200).contains(&limit))
}

fn valid_mutation_payload(mutation: &storage::Mutation<'_>) -> bool {
    match mutation {
        storage::Mutation::Withdraw { reason }
        | storage::Mutation::Pause { reason }
        | storage::Mutation::Reject { reason }
        | storage::Mutation::Fail { reason, .. }
        | storage::Mutation::LegalHold { reason, .. } => {
            valid_text(reason, MAX_REASON_BYTES, false)
        }
        storage::Mutation::VerifyIdentity {
            evidence_reference, ..
        } => valid_text(evidence_reference, MAX_REFERENCE_BYTES, false),
        storage::Mutation::Complete {
            completion_reference,
        } => valid_text(completion_reference, MAX_REFERENCE_BYTES, false),
        storage::Mutation::Resume | storage::Mutation::Claim | storage::Mutation::Retry => true,
    }
}

fn valid_request_ref(value: &str) -> bool {
    Uuid::parse_str(value).is_ok()
        || value.strip_prefix("PRV-").is_some_and(|number| {
            !number.is_empty()
                && number.bytes().all(|byte| byte.is_ascii_digit())
                && !number.starts_with('0')
        })
}

fn valid_text(value: &str, maximum: usize, allow_empty: bool) -> bool {
    let trimmed = value.trim();
    (allow_empty || !trimmed.is_empty())
        && value.len() <= maximum
        && !value
            .chars()
            .any(|character| character.is_control() && !matches!(character, '\n' | '\r' | '\t'))
}

fn valid_idempotency_key(value: &str) -> bool {
    valid_opaque_id(value, MAX_IDEMPOTENCY_BYTES)
}

fn valid_opaque_id(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':' | b'/')
        })
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    valid_opaque_id(value, maximum) && !value.contains('/')
}

fn valid_item_name(value: &str) -> bool {
    valid_identifier(value, 256)
}

fn valid_media_type(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.contains('/')
        && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_secret_reference(reference: &str) -> bool {
    !reference.is_empty()
        && reference.len() <= 256
        && !reference.starts_with('/')
        && !reference.ends_with('/')
        && !reference.contains("//")
        && reference
            .split('/')
            .all(|segment| segment != "." && segment != "..")
        && valid_opaque_id(reference, 256)
}

fn validate_callers(callers: &[String]) -> Result<(), ()> {
    if callers.is_empty()
        || callers.len() > MAX_CALLERS
        || callers.iter().any(|caller| !valid_identifier(caller, 256))
        || callers.iter().collect::<BTreeSet<_>>().len() != callers.len()
    {
        Err(())
    } else {
        Ok(())
    }
}

fn validate_provider_instances<T>(
    providers: &ManyPort<T>,
    maximum: usize,
    label: &str,
) -> Result<(), RuntimeFailure>
where
    T: lenso::CapabilityClientMany,
{
    if providers.is_empty() || providers.len() > maximum {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: format!("{label} cardinality is outside configured bounds"),
        });
    }
    let instances = providers
        .iter()
        .map(lenso::BoundCapabilityClient::provider_instance)
        .collect::<Vec<_>>();
    if instances.iter().any(|value| !valid_identifier(value, 256))
        || instances.iter().collect::<BTreeSet<_>>().len() != instances.len()
    {
        return Err(RuntimeFailure::InvalidResolvedPlan {
            detail: format!("{label} Instance keys are invalid or duplicated"),
        });
    }
    Ok(())
}

fn parse_optional_cursor<T>(
    value: Option<&str>,
    parser: impl FnOnce(&str) -> Option<T>,
) -> Result<Option<T>, ()> {
    match value {
        Some(value) => parser(value).map(Some).ok_or(()),
        None => Ok(None),
    }
}

const fn default_deadline_seconds() -> i64 {
    DEFAULT_DEADLINE_SECONDS
}
const fn default_max_sources() -> usize {
    DEFAULT_MAX_SOURCES
}
const fn default_max_participants() -> usize {
    DEFAULT_MAX_PARTICIPANTS
}
const fn default_max_process_steps() -> usize {
    DEFAULT_MAX_PROCESS_STEPS
}
const fn default_max_items_per_provider() -> usize {
    DEFAULT_MAX_ITEMS_PER_PROVIDER
}
const fn default_max_total_items() -> usize {
    DEFAULT_MAX_TOTAL_ITEMS
}
const fn default_max_item_bytes() -> usize {
    DEFAULT_MAX_ITEM_BYTES
}
const fn default_max_total_export_bytes() -> usize {
    DEFAULT_MAX_TOTAL_EXPORT_BYTES
}
const fn default_process_lease_seconds() -> i64 {
    DEFAULT_PROCESS_LEASE_SECONDS
}

#[cfg(test)]
mod tests {
    use super::*;
    use lenso_auth_sdk::{ActorAssertionIssuer, Validity, audience};
    use lenso_kernel::{CancellationToken, InvocationContext};
    use lenso_native_adapter::NativePluginRegistry;
    use time::Duration as TimeDuration;

    fn config() -> PrivacyRequestConfig {
        let issuer = ActorAssertionIssuer::new("auth.users", b"privacy-request-test-key");
        PrivacyRequestConfig::new(
            "privacy_request",
            "privacy-request/database-url",
            "auth.users",
            issuer.public_key_base64(),
            vec!["privacy-api".to_owned()],
            vec!["privacy-admin".to_owned()],
            vec!["privacy-worker".to_owned()],
        )
        .unwrap()
    }

    fn plugin() -> PostgresPrivacyRequestPlugin {
        PostgresPrivacyRequestPlugin {
            config: config(),
            secrets: Port::default(),
            membership: Port::default(),
            access: Port::default(),
            sources: ManyPort::default(),
            participants: ManyPort::default(),
            prepared: Rc::new(RefCell::new(None)),
        }
    }

    fn context(caller: &str) -> InvocationContext {
        InvocationContext::new(1, None, CancellationToken::new()).with_caller_instance(caller)
    }

    #[test]
    fn descriptor_has_separate_roles_and_many_provider_dependencies() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        let provided = descriptor["provided_capabilities"]
            .as_array()
            .unwrap()
            .iter()
            .map(|value| value["capability_id"].as_str().unwrap())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            provided,
            BTreeSet::from([
                public::CAPABILITY_ID,
                admin::CAPABILITY_ID,
                worker::CAPABILITY_ID
            ])
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(
            required
                .iter()
                .map(|value| value["capability_id"].as_str().unwrap())
                .collect::<BTreeSet<_>>(),
            BTreeSet::from([
                secrets::CAPABILITY_ID,
                membership::CAPABILITY_ID,
                access::CAPABILITY_ID,
                export_source::CAPABILITY_ID,
                retention::CAPABILITY_ID,
            ])
        );
        assert_eq!(
            required
                .iter()
                .filter(|value| value["cardinality"] == "many")
                .count(),
            2
        );
        assert_eq!(
            NativePluginRegistry::new()
                .with_linked_factories()
                .factories()
                .filter(|factory| factory.package_id() == PACKAGE_ID)
                .count(),
            1
        );
    }

    #[test]
    fn config_bounds_keep_inline_exports_below_runtime_envelope() {
        let mut invalid = config();
        invalid.max_total_export_bytes = 8 * 1024 * 1024 + 1;
        assert_eq!(
            invalid.validate(),
            Err(PrivacyRequestConfigError::InvalidBounds)
        );
        let mut invalid = config();
        invalid.max_item_bytes = invalid.max_total_export_bytes + 1;
        assert_eq!(
            invalid.validate(),
            Err(PrivacyRequestConfigError::InvalidBounds)
        );
    }

    #[test]
    fn actor_assertions_are_bound_to_role_and_exact_operation() {
        let issuer = ActorAssertionIssuer::new("auth.users", b"privacy-request-test-key");
        let now = OffsetDateTime::now_utc();
        let assertion = issuer.issue(
            "usr_1",
            "user",
            "strong",
            [audience(
                public::CAPABILITY_ID,
                public::CREATE_REQUEST_OPERATION,
            )],
            Validity::new(
                now - TimeDuration::seconds(1),
                now + TimeDuration::minutes(1),
            )
            .unwrap(),
            std::collections::BTreeMap::default(),
        );
        let context = assertion.attach(context("privacy-api")).unwrap();
        assert_eq!(
            plugin().authenticated_subject(
                &context,
                public::CAPABILITY_ID,
                public::CREATE_REQUEST_OPERATION
            ),
            Ok("usr_1".to_owned())
        );
        assert_eq!(
            plugin().authenticated_subject(
                &context,
                admin::CAPABILITY_ID,
                admin::VERIFY_IDENTITY_OPERATION
            ),
            Err(())
        );
    }

    #[test]
    fn exact_callers_do_not_overlap_ambient_authority() {
        assert!(
            PostgresPrivacyRequestPlugin::allowed_caller(
                &context("privacy-api"),
                &config().public_callers
            )
            .is_some()
        );
        assert!(
            PostgresPrivacyRequestPlugin::allowed_caller(
                &context("privacy-admin"),
                &config().public_callers
            )
            .is_none()
        );
    }

    #[test]
    fn all_five_request_kinds_are_wire_stable() {
        assert_eq!(
            public_kind(&public::CreateRequestRequestKind::Access),
            "access"
        );
        assert_eq!(
            public_kind(&public::CreateRequestRequestKind::Export),
            "export"
        );
        assert_eq!(
            public_kind(&public::CreateRequestRequestKind::Erasure),
            "erasure"
        );
        assert_eq!(
            public_kind(&public::CreateRequestRequestKind::Correction),
            "correction"
        );
        assert_eq!(
            public_kind(&public::CreateRequestRequestKind::Restriction),
            "restriction"
        );
    }
}
