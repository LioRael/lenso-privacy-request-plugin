//! Agent-facing requester Tools over an explicitly bound Privacy Request capability.

use lenso::prelude::*;
use lenso_capability_agent_tool_provider::{
    self as tool_contract, CatalogRequest, CatalogResponse, ContentType, ExecuteError,
    ExecuteRequest, ExecuteResponse, ExecutionFailedPayload, ToolDefinition, ToolExecutionClass,
};
use lenso_capability_privacy_request::{
    self as requester, CreateRequestRequest, GetRequestRequest, GetRequestResponse,
    ListRequestsRequest, WithdrawRequestRequest,
};
use lenso_kernel::RuntimeFailure;
use serde::{Serialize, de::DeserializeOwned};

pub const CREATE_TOOL: &str = "privacy_request_create";
pub const GET_METADATA_TOOL: &str = "privacy_request_get_metadata";
pub const LIST_TOOL: &str = "privacy_request_list";
pub const WITHDRAW_TOOL: &str = "privacy_request_withdraw";

#[lenso::plugin]
#[derive(Clone, Debug)]
struct PrivacyRequestRequesterAgentToolsPlugin {
    requester: Port<requester::PrivacyRequestClient>,
}

#[lenso::provides(tool_contract::ToolProvider)]
impl PrivacyRequestRequesterAgentToolsPlugin {
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
            GET_METADATA_TOOL => {
                let arguments = decode::<GetRequestRequest>(&request)?;
                match self
                    .requester
                    .get_request_with_context(context, arguments)
                    .await
                {
                    Ok(response) => metadata_success(GET_METADATA_TOOL, &response),
                    Err(requester::PrivacyRequestGetRequestInvocationError::Domain(error)) => {
                        Err(PluginError::domain(map_domain_error(&error)))
                    }
                    Err(requester::PrivacyRequestGetRequestInvocationError::Runtime(error)) => {
                        Err(PluginError::runtime(error))
                    }
                }
            }
            LIST_TOOL => {
                let arguments = decode::<ListRequestsRequest>(&request)?;
                invoke!(
                    self.requester
                        .list_requests_with_context(context, arguments),
                    LIST_TOOL,
                    requester::PrivacyRequestListRequestsInvocationError::Domain,
                    requester::PrivacyRequestListRequestsInvocationError::Runtime
                )
            }
            CREATE_TOOL => {
                let arguments = decode::<CreateRequestRequest>(&request)?;
                invoke!(
                    self.requester
                        .create_request_with_context(context, arguments),
                    CREATE_TOOL,
                    requester::PrivacyRequestCreateRequestInvocationError::Domain,
                    requester::PrivacyRequestCreateRequestInvocationError::Runtime
                )
            }
            WITHDRAW_TOOL => {
                let arguments = decode::<WithdrawRequestRequest>(&request)?;
                invoke!(
                    self.requester
                        .withdraw_request_with_context(context, arguments),
                    WITHDRAW_TOOL,
                    requester::PrivacyRequestWithdrawRequestInvocationError::Domain,
                    requester::PrivacyRequestWithdrawRequestInvocationError::Runtime
                )
            }
            _ => Err(PluginError::domain(ExecuteError::NotFound)),
        }
    }
}

fn tool_definitions() -> Vec<ToolDefinition> {
    vec![
        tool(
            GET_METADATA_TOOL,
            "Get metadata for one privacy request owned by the authenticated requester. Export payloads are omitted from Agent context.",
            include_str!("../../lenso-capability-privacy-request/schemas/get-request.schema.json"),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            LIST_TOOL,
            "List privacy requests owned by the authenticated requester with bounded cursor pagination.",
            include_str!(
                "../../lenso-capability-privacy-request/schemas/list-requests.schema.json"
            ),
            ToolExecutionClass::ParallelSafe,
        ),
        tool(
            CREATE_TOOL,
            "Create one privacy request. Reuse the same idempotency_key when retrying the same intent.",
            include_str!(
                "../../lenso-capability-privacy-request/schemas/create-request.schema.json"
            ),
            ToolExecutionClass::Exclusive,
        ),
        tool(
            WITHDRAW_TOOL,
            "Withdraw an eligible owned privacy request using its current expected_revision and a caller-scoped idempotency_key.",
            include_str!(
                "../../lenso-capability-privacy-request/schemas/withdraw-request.schema.json"
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
    let schema: serde_json::Value = serde_json::from_str(schema)
        .expect("Privacy Request requester Tool schema must be valid JSON");
    ToolDefinition {
        name: name.to_owned(),
        description: description.to_owned(),
        input_schema_json: schema
            .to_string()
            .try_into()
            .expect("Privacy Request requester Tool schema must remain valid JSON"),
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
    let value = serde_json::to_value(response).map_err(|error| serialization_failure(&error))?;
    success_value(tool_name, &value)
}

fn metadata_success(
    tool_name: &str,
    response: &GetRequestResponse,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let mut value =
        serde_json::to_value(response).map_err(|error| serialization_failure(&error))?;
    omit_result_payloads(&mut value);
    success_value(tool_name, &value)
}

fn omit_result_payloads(value: &mut serde_json::Value) {
    let Some(items) = value
        .get_mut("result_items")
        .and_then(|items| items.as_array_mut())
    else {
        return;
    };
    for item in items {
        if let Some(item) = item.as_object_mut() {
            item.remove("payload");
            item.insert("payload_omitted".to_owned(), serde_json::Value::Bool(true));
        }
    }
}

fn success_value(
    tool_name: &str,
    value: &serde_json::Value,
) -> PluginResult<ExecuteResponse, ExecuteError> {
    let content =
        serde_json::to_string_pretty(value).map_err(|error| serialization_failure(&error))?;
    Ok(ExecuteResponse {
        content_blocks: None,
        content,
        content_type: ContentType::Text,
        metadata_json: serde_json::json!({ "tool": tool_name, "result_payloads_omitted": tool_name == GET_METADATA_TOOL })
            .to_string()
            .try_into()
            .expect("Privacy Request requester Tool metadata must be valid JSON"),
    })
}

fn serialization_failure(error: &serde_json::Error) -> PluginError<ExecuteError> {
    PluginError::runtime(RuntimeFailure::PluginFailure {
        detail: format!(
            "Privacy Request requester Tool could not serialize its typed response: {error}"
        ),
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
            message: "Privacy Request rejected the requester operation.".to_owned(),
            details_json: serde_json::json!({ "domain_error": reason_code })
                .to_string()
                .try_into()
                .expect("Privacy Request requester Tool error metadata must be valid JSON"),
        },
    }
}

macro_rules! impl_requester_error {
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

impl_requester_error!(
    requester::CreateRequestError,
    requester::GetRequestError,
    requester::ListRequestsError,
    requester::WithdrawRequestError,
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
    fn descriptor_requires_only_the_requester_capability() {
        let descriptor: serde_json::Value = serde_json::from_str(PLUGIN_DESCRIPTOR_JSON).unwrap();
        assert_eq!(
            descriptor["plugin_id"],
            "lenso.privacy-request.requester.agent-tools"
        );
        assert_eq!(
            descriptor["provided_capabilities"][0]["capability_id"],
            "lenso.agent.tool-provider@2"
        );
        let required = descriptor["required_capabilities"].as_array().unwrap();
        assert_eq!(required.len(), 1);
        assert_eq!(required[0]["capability_id"], "lenso.privacy-request@1");
    }

    #[test]
    fn catalog_has_two_reads_and_two_mutations_without_worker_tools() {
        let tools = tool_definitions();
        assert_eq!(tools.len(), 4);
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
            2
        );
        assert!(tools.iter().all(|tool| !tool.name.contains("worker")));
    }

    #[test]
    fn exact_request_decodes_and_domain_failures_stay_distinct() {
        let get = decode::<GetRequestRequest>(&request(
            GET_METADATA_TOOL,
            r#"{"organization_id":"org-1","request_ref":"PRV-1"}"#,
        ))
        .unwrap();
        assert_eq!(get.request_ref, "PRV-1");
        assert!(
            decode::<GetRequestRequest>(&request(
                GET_METADATA_TOOL,
                r#"{"organization_id":"org-1","request_ref":42}"#
            ))
            .is_err()
        );

        assert_eq!(
            map_domain_error(&requester::GetRequestError::Forbidden),
            ExecuteError::PermissionDenied
        );
        assert_eq!(
            map_domain_error(&requester::GetRequestError::RequestNotFound),
            ExecuteError::NotFound
        );
        let ExecuteError::ExecutionFailed { payload } =
            map_domain_error(&requester::WithdrawRequestError::RevisionConflict)
        else {
            panic!("revision conflict must remain an execution failure");
        };
        assert_eq!(payload.reason_code, "revision_conflict");
    }

    #[test]
    fn metadata_projection_never_exposes_export_payloads() {
        let mut value = serde_json::json!({
            "request_id": "request-1",
            "result_items": [{
                "provider_instance": "profile-store",
                "item_name": "profile.json",
                "media_type": "application/json",
                "payload": "private export contents"
            }]
        });
        omit_result_payloads(&mut value);
        let encoded = serde_json::to_string(&value).unwrap();
        assert!(!encoded.contains("private export contents"));
        assert_eq!(value["result_items"][0]["payload_omitted"], true);
    }
}
