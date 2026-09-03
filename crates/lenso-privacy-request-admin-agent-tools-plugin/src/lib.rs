//! Agent-facing administrative Tools over an explicitly bound Privacy Request Admin capability.

use lenso::prelude::*;
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_capability_privacy_request_admin::{
    self as admin, ListActivityRequest, ListAdminRequestsRequest, PauseRequestRequest,
    RejectRequestRequest, ResumeRequestRequest, SetLegalHoldRequest, VerifyIdentityRequest,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const LIST_REQUESTS_TOOL: &str = "privacy_request_admin_list";
pub const LIST_ACTIVITY_TOOL: &str = "privacy_request_admin_list_activity";
pub const VERIFY_IDENTITY_TOOL: &str = "privacy_request_admin_verify_identity";
pub const SET_LEGAL_HOLD_TOOL: &str = "privacy_request_admin_set_legal_hold";
pub const PAUSE_TOOL: &str = "privacy_request_admin_pause";
pub const RESUME_TOOL: &str = "privacy_request_admin_resume";
pub const REJECT_TOOL: &str = "privacy_request_admin_reject";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct PrivacyRequestAdminAgentToolsPlugin {
    admin: Port<admin::PrivacyRequestAdminClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl PrivacyRequestAdminAgentToolsPlugin {
    fn catalog(
        &self,
        _context: Ctx,
        _request: CatalogRequest,
    ) -> impl std::future::Future<Output = PluginResult<CatalogResponse, tool_contract::CatalogError>>
    {
        let _ = self;
        futures::future::ready(Ok(CatalogResponse {
            tools: tool_definitions(),
        }))
    }

    async fn execute(
        &self,
        context: Ctx,
        request: ExecuteRequest,
    ) -> PluginResult<ExecuteResponse, ExecuteError> {
        macro_rules! invoke {
            ($future:expr, $tool:expr, $domain:path, $runtime:path) => {
                match $future.await {
                    Ok(response) => success($tool, &response),
                    Err($domain(error)) => Err(PluginError::domain(map_domain_error(&error))),
                    Err($runtime(error)) => Err(PluginError::runtime(error)),
                }
            };
        }

        match request.name.as_str() {
            LIST_REQUESTS_TOOL => {
                let arguments = decode::<ListAdminRequestsRequest>(&request)?;
                invoke!(
                    self.admin
                        .list_admin_requests_with_context(context, arguments),
                    LIST_REQUESTS_TOOL,
                    admin::PrivacyRequestAdminListAdminRequestsInvocationError::Domain,
                    admin::PrivacyRequestAdminListAdminRequestsInvocationError::Runtime
                )
            }
            LIST_ACTIVITY_TOOL => {
                let arguments = decode::<ListActivityRequest>(&request)?;
                invoke!(
                    self.admin.list_activity_with_context(context, arguments),
                    LIST_ACTIVITY_TOOL,
                    admin::PrivacyRequestAdminListActivityInvocationError::Domain,
                    admin::PrivacyRequestAdminListActivityInvocationError::Runtime
                )
            }
            VERIFY_IDENTITY_TOOL => {
                let arguments = decode::<VerifyIdentityRequest>(&request)?;
                invoke!(
                    self.admin.verify_identity_with_context(context, arguments),
                    VERIFY_IDENTITY_TOOL,
                    admin::PrivacyRequestAdminVerifyIdentityInvocationError::Domain,
                    admin::PrivacyRequestAdminVerifyIdentityInvocationError::Runtime
                )
            }
            SET_LEGAL_HOLD_TOOL => {
                let arguments = decode::<SetLegalHoldRequest>(&request)?;
                invoke!(
                    self.admin.set_legal_hold_with_context(context, arguments),
                    SET_LEGAL_HOLD_TOOL,
                    admin::PrivacyRequestAdminSetLegalHoldInvocationError::Domain,
                    admin::PrivacyRequestAdminSetLegalHoldInvocationError::Runtime
                )
            }
            PAUSE_TOOL => {
                let arguments = decode::<PauseRequestRequest>(&request)?;
                invoke!(
                    self.admin.pause_request_with_context(context, arguments),
                    PAUSE_TOOL,
                    admin::PrivacyRequestAdminPauseRequestInvocationError::Domain,
                    admin::PrivacyRequestAdminPauseRequestInvocationError::Runtime
                )
            }
            RESUME_TOOL => {
                let arguments = decode::<ResumeRequestRequest>(&request)?;
                invoke!(
                    self.admin.resume_request_with_context(context, arguments),
                    RESUME_TOOL,
                    admin::PrivacyRequestAdminResumeRequestInvocationError::Domain,
                    admin::PrivacyRequestAdminResumeRequestInvocationError::Runtime
                )
            }
            REJECT_TOOL => {
                let arguments = decode::<RejectRequestRequest>(&request)?;
                invoke!(
                    self.admin.reject_request_with_context(context, arguments),
                    REJECT_TOOL,
                    admin::PrivacyRequestAdminRejectRequestInvocationError::Domain,
                    admin::PrivacyRequestAdminRejectRequestInvocationError::Runtime
                )
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            LIST_REQUESTS_TOOL,
            "List the bounded privacy-request administration queue for an authorized organization administrator.",
            include_str!(
                "../../lenso-capability-privacy-request-admin/schemas/list-requests.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_ACTIVITY_TOOL,
            "List bounded activity evidence for one privacy request without executing worker operations.",
            include_str!(
                "../../lenso-capability-privacy-request-admin/schemas/list-activity.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            VERIFY_IDENTITY_TOOL,
            "Record an explicit identity-verification outcome using the current expected_revision and an evidence reference.",
            include_str!(
                "../../lenso-capability-privacy-request-admin/schemas/verify-identity.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            SET_LEGAL_HOLD_TOOL,
            "Set or clear a legal hold using the current expected_revision. Clearing a hold does not resume processing.",
            include_str!(
                "../../lenso-capability-privacy-request-admin/schemas/set-legal-hold.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            PAUSE_TOOL,
            "Pause an eligible privacy request with a reason, current expected_revision, and caller-scoped idempotency_key.",
            include_str!(
                "../../lenso-capability-privacy-request-admin/schemas/reason-mutation.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            RESUME_TOOL,
            "Resume an eligible paused privacy request using its current expected_revision and a caller-scoped idempotency_key.",
            include_str!(
                "../../lenso-capability-privacy-request-admin/schemas/base-mutation.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            REJECT_TOOL,
            "Reject an eligible privacy request with a reason, current expected_revision, and caller-scoped idempotency_key.",
            include_str!(
                "../../lenso-capability-privacy-request-admin/schemas/reason-mutation.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
    ]
}

fn tool(
    name: &str,
    description: &str,
    schema: &str,
    execution: ToolExecutionClass,
) -> ToolDefinition {
    let schema: serde_json::Value =
        serde_json::from_str(schema).expect("Privacy Request admin Tool schema must be valid JSON");
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Privacy Request admin Tool schema must remain valid JSON"),
        execution,
    }
}

fn decode<T: DeserializeOwned>(request: &ExecuteRequest) -> PluginResult<T, ExecuteError> {
    serde_json::from_str(request.arguments_json.as_str())
        .map_err(|_| PluginError::domain(ExecuteError::InvalidArguments))
}

fn success<T: Serialize>(
    tool_name: &str,
    response: &T,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content = serde_json::to_string_pretty(response).map_err(|error| {
        PluginError::runtime(RuntimeFailure::PluginFailure {
            detail: format!(
                "Privacy Request admin Tool could not serialize its typed response: {error}"
            ),
        })
    })?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name })
            .to_string()
            .try_into()
            .expect("Privacy Request admin Tool metadata must be valid JSON"),
    })
}

trait DomainToolError {
    fn to_tool_error(&self) -> ExecuteError;
}

fn map_domain_error(error: &impl DomainToolError) -> ExecuteError {
    error.to_tool_error()
}

fn rejected(reason_code: &str) -> ExecuteError {
    ExecuteError::ExecutionFailed {
        payload: ExecutionFailedPayload {
            reason_code: reason_code.to_owned(),
            message: "Privacy Request rejected the administrator operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Privacy Request admin Tool error metadata must be valid JSON"),
        },
    }
}

macro_rules! impl_admin_error {
    ($($error:ty),+ $(,)?) => {
        $(
            impl DomainToolError for $error {
                fn to_tool_error(&self) -> ExecuteError {
                    match self {
                        Self::InvalidRequest => ExecuteError::InvalidArguments,
                        Self::RequestNotFound => ExecuteError::NotFound,
                        Self::Forbidden | Self::Unauthenticated => ExecuteError::PermissionDenied,
                        Self::IdempotencyConflict => rejected("idempotency_conflict"),
                        Self::InvalidTransition => rejected("invalid_transition"),
                        Self::RevisionConflict => rejected("revision_conflict"),
                        Self::Unknown(_) => rejected("unknown_domain_error"),
                    }
                }
            }
        )+
    };
}

impl_admin_error!(
    admin::ListActivityError,
    admin::ListAdminRequestsError,
    admin::PauseRequestError,
    admin::RejectRequestError,
    admin::ResumeRequestError,
    admin::SetLegalHoldError,
    admin::VerifyIdentityError,
);

#[cfg(test)]
mod tests {
    use super::*;

    fn request(name: &str, arguments: &str) -> ExecuteRequest {
        ExecuteRequest {
            name: name.to_owned(),
            arguments_json: arguments.try_into().unwrap(),
        }
    }

    #[test]
    fn descriptor_requires_only_the_admin_capability() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.privacy-request.admin.agent-tools"
        );
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(
            required[0]["capability_id"],
            "lenso.privacy-request-admin@1"
        );
    }

    #[test]
    fn catalog_has_two_reads_and_five_mutations_without_worker_tools() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 7);
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::ParallelSafe)
                .count(),
            2
        );
        assert_eq!(
            tools
                .iter()
                .filter(|tool| tool.execution == ToolExecutionClass::Exclusive)
                .count(),
            5
        );
        assert!(tools.iter().all(|tool| !tool.name.contains("worker")));
    }

    #[test]
    fn exact_request_decodes_and_domain_failures_stay_distinct() {
        let list = decode::<ListAdminRequestsRequest>(&request(
            LIST_REQUESTS_TOOL,
            r#"{"organization_id":"org-1","limit":25}"#,
        ))
        .unwrap();
        assert_eq!(list.limit, 25);
        assert!(
            decode::<ListAdminRequestsRequest>(&request(
                LIST_REQUESTS_TOOL,
                r#"{"organization_id":"org-1","limit":"25"}"#
            ))
            .is_err()
        );

        assert_eq!(
            map_domain_error(&admin::ListAdminRequestsError::Unauthenticated),
            ExecuteError::PermissionDenied
        );
        assert_eq!(
            map_domain_error(&admin::ListActivityError::RequestNotFound),
            ExecuteError::NotFound
        );
        let ExecuteError::ExecutionFailed { payload } =
            map_domain_error(&admin::ResumeRequestError::RevisionConflict)
        else {
            panic!("revision conflict must remain an execution failure");
        };
        assert_eq!(payload.reason_code, "revision_conflict");
    }
}
