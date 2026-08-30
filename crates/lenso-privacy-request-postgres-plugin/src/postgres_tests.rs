use lenso_postgres_kit::OwnedPostgres;
use sqlx::{AssertSqlSafe, Executor as _};
use uuid::Uuid;

use crate::{PrivacyRequestOperator, schema, storage};

async fn mutate(
    postgres: &OwnedPostgres,
    key: &str,
    request: &storage::RequestRecord,
    actor: &str,
    mutation: storage::Mutation<'_>,
) -> Result<storage::RequestRecord, storage::DomainFailure> {
    storage::mutate_request(
        postgres,
        "acceptance-caller",
        key,
        key,
        key.as_bytes(),
        &request.organization_id,
        request.request_id,
        actor,
        request.revision,
        &mutation,
    )
    .await
    .unwrap()
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn durable_workflow_covers_restart_cas_holds_leases_paging_and_partial_retry() {
    let Ok(database_url) = std::env::var("LENSO_PRIVACY_REQUEST_TEST_DATABASE_URL") else {
        return;
    };
    let schema_name = format!("privacy_request_test_{}", Uuid::new_v4().simple());
    PrivacyRequestOperator::setup(&database_url, &schema_name)
        .await
        .unwrap();
    PrivacyRequestOperator::upgrade(&database_url, &schema_name)
        .await
        .unwrap();
    let postgres = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();

    let created = storage::create_request(
        &postgres,
        "privacy-api",
        "create-correction",
        &[1],
        "org_acceptance",
        "usr_requester",
        "correction",
        "Correct an inaccurate profile attribute.",
        3_600,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(created.identifier, "PRV-1");
    assert!(created.deadline_at > created.created_at);
    postgres.pool().close().await;

    let restarted = OwnedPostgres::prepare(
        &database_url,
        schema::schema_plan(schema_name.clone()).unwrap(),
    )
    .await
    .unwrap();
    let replay = storage::create_request(
        &restarted,
        "privacy-api",
        "create-correction",
        &[1],
        "org_acceptance",
        "usr_requester",
        "correction",
        "Correct an inaccurate profile attribute.",
        3_600,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(replay, created);
    let other_caller = storage::create_request(
        &restarted,
        "another-privacy-api",
        "create-correction",
        &[10],
        "org_other",
        "usr_other",
        "correction",
        "A caller-scoped idempotency key may repeat in another caller scope.",
        3_600,
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(other_caller.identifier, "PRV-1");

    let first = storage::mutate_request(
        &restarted,
        "privacy-admin",
        "verify-a",
        "verify_identity",
        &[2],
        "org_acceptance",
        created.request_id,
        "usr_admin",
        created.revision,
        &storage::Mutation::VerifyIdentity {
            outcome: "verified",
            evidence_reference: "proof/a",
        },
    );
    let second = storage::mutate_request(
        &restarted,
        "privacy-admin",
        "verify-b",
        "verify_identity",
        &[3],
        "org_acceptance",
        created.request_id,
        "usr_admin",
        created.revision,
        &storage::Mutation::VerifyIdentity {
            outcome: "verified",
            evidence_reference: "proof/b",
        },
    );
    let (first, second) = tokio::join!(first, second);
    let outcomes = [first.unwrap(), second.unwrap()];
    assert_eq!(outcomes.iter().filter(|value| value.is_ok()).count(), 1);
    assert_eq!(
        outcomes
            .iter()
            .filter(|value| matches!(value, Err(storage::DomainFailure::RevisionConflict)))
            .count(),
        1
    );
    let verified = outcomes.into_iter().find_map(Result::ok).unwrap();
    let claimed = mutate(
        &restarted,
        "claim-correction",
        &verified,
        "usr_worker",
        storage::Mutation::Claim,
    )
    .await
    .unwrap();
    let snapshots = [storage::ProviderSnapshot {
        kind: "manual",
        instance: "manual-review".to_owned(),
    }];
    let start = storage::begin_process(
        &restarted,
        "privacy-worker",
        "process-correction",
        &[4],
        "org_acceptance",
        claimed.request_id,
        "usr_worker",
        claimed.revision,
        &snapshots,
        None,
        10,
        60,
    )
    .await
    .unwrap()
    .unwrap();
    let storage::ProcessStart::Execute { steps, .. } = start else {
        panic!("first process call cannot be a replay")
    };
    assert_eq!(steps.len(), 1);
    assert_eq!(steps[0].provider_kind, "manual");
    assert_eq!(
        storage::begin_process(
            &restarted,
            "privacy-worker",
            "process-correction",
            &[4],
            "org_acceptance",
            claimed.request_id,
            "usr_worker",
            claimed.revision,
            &snapshots,
            None,
            10,
            60,
        )
        .await
        .unwrap(),
        Err(storage::DomainFailure::OperationInProgress)
    );
    sqlx::query("UPDATE privacy_request_commands SET lease_until=CURRENT_TIMESTAMP-INTERVAL '1 second' WHERE caller_instance='privacy-worker' AND idempotency_key='process-correction'")
        .execute(restarted.pool()).await.unwrap();
    assert!(matches!(
        storage::begin_process(
            &restarted,
            "privacy-worker",
            "process-correction",
            &[4],
            "org_acceptance",
            claimed.request_id,
            "usr_worker",
            claimed.revision,
            &snapshots,
            None,
            10,
            60,
        )
        .await
        .unwrap()
        .unwrap(),
        storage::ProcessStart::Execute { .. }
    ));
    storage::record_step_success(
        &restarted,
        claimed.request_id,
        1,
        None,
        Some("manual-proof/1"),
    )
    .await
    .unwrap();
    let processed = storage::finish_process(
        &restarted,
        "privacy-worker",
        "process-correction",
        &[4],
        "org_acceptance",
        claimed.request_id,
        "usr_worker",
        Some(1),
    )
    .await
    .unwrap();
    assert!(processed.all_steps_completed);
    assert_eq!(processed.request.state, "awaiting_completion");

    let held = storage::create_request(
        &restarted,
        "privacy-api",
        "create-erasure",
        &[5],
        "org_acceptance",
        "usr_requester",
        "erasure",
        "Erase personal data.",
        3_600,
    )
    .await
    .unwrap()
    .unwrap();
    let verified = mutate(
        &restarted,
        "verify-erasure",
        &held,
        "usr_admin",
        storage::Mutation::VerifyIdentity {
            outcome: "verified",
            evidence_reference: "proof/erasure",
        },
    )
    .await
    .unwrap();
    let claimed = mutate(
        &restarted,
        "claim-erasure",
        &verified,
        "usr_worker",
        storage::Mutation::Claim,
    )
    .await
    .unwrap();
    let held = mutate(
        &restarted,
        "hold-erasure",
        &claimed,
        "usr_admin",
        storage::Mutation::LegalHold {
            active: true,
            reason: "Preserve while an independent review is active.",
        },
    )
    .await
    .unwrap();
    assert!(held.legal_hold);
    assert_eq!(held.state, "paused");
    let cleared = mutate(
        &restarted,
        "clear-hold-erasure",
        &held,
        "usr_admin",
        storage::Mutation::LegalHold {
            active: false,
            reason: "Independent review ended.",
        },
    )
    .await
    .unwrap();
    assert!(!cleared.legal_hold);
    assert_eq!(cleared.state, "paused");
    let resumed = mutate(
        &restarted,
        "resume-erasure",
        &cleared,
        "usr_admin",
        storage::Mutation::Resume,
    )
    .await
    .unwrap();
    assert_eq!(resumed.state, "claimed");
    let erasure_snapshots = [storage::ProviderSnapshot {
        kind: "retention",
        instance: "account-participant".to_owned(),
    }];
    let start = storage::begin_process(
        &restarted,
        "privacy-worker",
        "process-erasure",
        &[11],
        "org_acceptance",
        resumed.request_id,
        "usr_worker",
        resumed.revision,
        &erasure_snapshots,
        None,
        1,
        60,
    )
    .await
    .unwrap()
    .unwrap();
    let storage::ProcessStart::Execute {
        request: processing,
        steps,
    } = start
    else {
        panic!("erasure start cannot replay")
    };
    let held_in_flight = mutate(
        &restarted,
        "hold-erasure-in-flight",
        &processing,
        "usr_admin",
        storage::Mutation::LegalHold {
            active: true,
            reason: "A new review started after provider dispatch.",
        },
    )
    .await
    .unwrap();
    storage::record_step_success(
        &restarted,
        resumed.request_id,
        steps[0].sequence,
        Some("retention-receipt/1"),
        None,
    )
    .await
    .unwrap();
    let held_result = storage::finish_process(
        &restarted,
        "privacy-worker",
        "process-erasure",
        &[11],
        "org_acceptance",
        resumed.request_id,
        "usr_worker",
        Some(steps[0].sequence),
    )
    .await
    .unwrap();
    assert!(held_result.all_steps_completed);
    assert_eq!(held_result.request.state, "paused");
    assert!(held_result.request.legal_hold);
    assert!(held_result.request.revision > held_in_flight.revision);

    let export = storage::create_request(
        &restarted,
        "privacy-api",
        "create-export",
        &[6],
        "org_acceptance",
        "usr_exporter",
        "export",
        "Export my personal data.",
        3_600,
    )
    .await
    .unwrap()
    .unwrap();
    let verified = mutate(
        &restarted,
        "verify-export",
        &export,
        "usr_admin",
        storage::Mutation::VerifyIdentity {
            outcome: "verified",
            evidence_reference: "proof/export",
        },
    )
    .await
    .unwrap();
    let claimed = mutate(
        &restarted,
        "claim-export",
        &verified,
        "usr_worker",
        storage::Mutation::Claim,
    )
    .await
    .unwrap();
    let export_snapshots = [
        storage::ProviderSnapshot {
            kind: "export",
            instance: "account-source".to_owned(),
        },
        storage::ProviderSnapshot {
            kind: "export",
            instance: "profile-source".to_owned(),
        },
    ];
    let start = storage::begin_process(
        &restarted,
        "privacy-worker",
        "process-export-fail",
        &[7],
        "org_acceptance",
        claimed.request_id,
        "usr_worker",
        claimed.revision,
        &export_snapshots,
        None,
        1,
        60,
    )
    .await
    .unwrap()
    .unwrap();
    let storage::ProcessStart::Execute { steps, .. } = start else {
        panic!("export start cannot replay")
    };
    storage::record_step_failure(
        &restarted,
        claimed.request_id,
        steps[0].sequence,
        "runtime_failure",
    )
    .await
    .unwrap();
    let partial = storage::finish_process(
        &restarted,
        "privacy-worker",
        "process-export-fail",
        &[7],
        "org_acceptance",
        claimed.request_id,
        "usr_worker",
        Some(steps[0].sequence),
    )
    .await
    .unwrap();
    assert!(!partial.all_steps_completed);
    assert_eq!(partial.failed_steps, 1);
    assert_eq!(partial.pending_steps, 1);
    assert!(partial.next_cursor.is_some());
    assert_eq!(partial.request.state, "processing");
    assert_eq!(
        mutate(
            &restarted,
            "complete-too-early",
            &partial.request,
            "usr_worker",
            storage::Mutation::Complete {
                completion_reference: "delivery/too-early",
            },
        )
        .await,
        Err(storage::DomainFailure::InvalidTransition)
    );
    let cursor =
        storage::decode_process_cursor(partial.next_cursor.as_deref().unwrap(), claimed.request_id)
            .unwrap();
    let continuation = storage::begin_process(
        &restarted,
        "privacy-worker",
        "process-export-continuation",
        &[8],
        "org_acceptance",
        claimed.request_id,
        "usr_worker",
        partial.request.revision,
        &export_snapshots,
        Some(cursor),
        1,
        60,
    )
    .await
    .unwrap()
    .unwrap();
    let storage::ProcessStart::Execute { steps, .. } = continuation else {
        panic!("continuation cannot replay")
    };
    assert!(
        storage::record_export_success(
            &restarted,
            claimed.request_id,
            steps[0].sequence,
            "profile-source",
            &[(
                "profile.json".to_owned(),
                "application/json".to_owned(),
                "{\"name\":\"Ada\"}".to_owned(),
            )],
            100,
            1024,
        )
        .await
        .unwrap()
    );
    let continued = storage::finish_process(
        &restarted,
        "privacy-worker",
        "process-export-continuation",
        &[8],
        "org_acceptance",
        claimed.request_id,
        "usr_worker",
        Some(steps[0].sequence),
    )
    .await
    .unwrap();
    assert!(!continued.all_steps_completed);
    assert_eq!(continued.completed_steps, 1);
    assert_eq!(continued.failed_steps, 1);

    let retry = storage::begin_process(
        &restarted,
        "privacy-worker",
        "process-export-retry",
        &[9],
        "org_acceptance",
        claimed.request_id,
        "usr_worker",
        continued.request.revision,
        &export_snapshots,
        None,
        1,
        60,
    )
    .await
    .unwrap()
    .unwrap();
    let storage::ProcessStart::Execute { steps, .. } = retry else {
        panic!("retry cannot replay")
    };
    assert_eq!(steps[0].provider_instance, "account-source");
    assert!(
        storage::record_export_success(
            &restarted,
            claimed.request_id,
            steps[0].sequence,
            "account-source",
            &[(
                "account.json".to_owned(),
                "application/json".to_owned(),
                "{\"email\":\"ada@example.test\"}".to_owned(),
            )],
            100,
            1024,
        )
        .await
        .unwrap()
    );
    let retried = storage::finish_process(
        &restarted,
        "privacy-worker",
        "process-export-retry",
        &[9],
        "org_acceptance",
        claimed.request_id,
        "usr_worker",
        Some(steps[0].sequence),
    )
    .await
    .unwrap();
    assert!(retried.all_steps_completed);
    assert_eq!(
        storage::get_export_items(&restarted, claimed.request_id)
            .await
            .unwrap()
            .len(),
        2
    );

    let mut first_page = storage::list_owned_requests(
        &restarted,
        &storage::RequestFilters {
            organization_id: "org_acceptance",
            requester_subject: "usr_requester",
            state: None,
            cursor: None,
            limit: 2,
        },
    )
    .await
    .unwrap();
    assert_eq!(first_page.len(), 2);
    let cursor = storage::decode_request_cursor(
        &storage::encode_request_cursor(first_page.last().unwrap()).unwrap(),
    )
    .unwrap();
    first_page = storage::list_owned_requests(
        &restarted,
        &storage::RequestFilters {
            organization_id: "org_acceptance",
            requester_subject: "usr_requester",
            state: None,
            cursor: Some(&cursor),
            limit: 2,
        },
    )
    .await
    .unwrap();
    assert!(first_page.is_empty());
    assert!(
        storage::get_owned_request(
            &restarted,
            "org_acceptance",
            &created.request_id.to_string(),
            "usr_someone_else",
        )
        .await
        .unwrap()
        .is_none()
    );

    let activity_page =
        storage::list_activity(&restarted, "org_acceptance", created.request_id, None, 2)
            .await
            .unwrap()
            .unwrap();
    assert_eq!(activity_page.len(), 2);
    let activity_cursor = storage::decode_activity_cursor(
        &storage::encode_activity_cursor(activity_page.last().unwrap()).unwrap(),
    )
    .unwrap();
    assert!(
        !storage::list_activity(
            &restarted,
            "org_acceptance",
            created.request_id,
            Some(&activity_cursor),
            20,
        )
        .await
        .unwrap()
        .unwrap()
        .is_empty()
    );

    let queue_a = storage::create_request(
        &restarted,
        "privacy-api",
        "queue-a",
        &[12],
        "org_queue_test",
        "usr_queue_a",
        "correction",
        "Queue request A.",
        3_600,
    )
    .await
    .unwrap()
    .unwrap();
    let queue_b = storage::create_request(
        &restarted,
        "privacy-api",
        "queue-b",
        &[13],
        "org_queue_test",
        "usr_queue_b",
        "restriction",
        "Queue request B.",
        3_600,
    )
    .await
    .unwrap()
    .unwrap();
    let queue_a = mutate(
        &restarted,
        "queue-verify-a",
        &queue_a,
        "usr_admin",
        storage::Mutation::VerifyIdentity {
            outcome: "verified",
            evidence_reference: "proof/queue-a",
        },
    )
    .await
    .unwrap();
    let queue_b = mutate(
        &restarted,
        "queue-verify-b",
        &queue_b,
        "usr_admin",
        storage::Mutation::VerifyIdentity {
            outcome: "verified",
            evidence_reference: "proof/queue-b",
        },
    )
    .await
    .unwrap();
    let admin_page = storage::list_admin_requests(
        &restarted,
        &storage::AdminRequestFilters {
            organization_id: "org_queue_test",
            state: Some("ready"),
            kind: None,
            requester_subject: None,
            cursor: None,
            limit: 1,
        },
    )
    .await
    .unwrap();
    assert_eq!(admin_page.len(), 1);
    let admin_cursor = storage::decode_admin_request_cursor(
        &storage::encode_admin_request_cursor(&admin_page[0]).unwrap(),
    )
    .unwrap();
    assert_eq!(
        storage::list_admin_requests(
            &restarted,
            &storage::AdminRequestFilters {
                organization_id: "org_queue_test",
                state: Some("ready"),
                kind: None,
                requester_subject: None,
                cursor: Some(&admin_cursor),
                limit: 1,
            },
        )
        .await
        .unwrap()
        .len(),
        1
    );
    let claim_a = storage::claim_next_request(
        &restarted,
        "worker-api-a",
        "claim-next-a",
        &[14],
        "org_queue_test",
        None,
        "usr_worker_a",
    );
    let claim_b = storage::claim_next_request(
        &restarted,
        "worker-api-b",
        "claim-next-b",
        &[15],
        "org_queue_test",
        None,
        "usr_worker_b",
    );
    let (claimed_a, claimed_b) = tokio::join!(claim_a, claim_b);
    let claimed_a = claimed_a.unwrap().unwrap();
    let claimed_b = claimed_b.unwrap().unwrap();
    assert_ne!(claimed_a.request_id, claimed_b.request_id);
    assert_eq!(
        [claimed_a.request_id, claimed_b.request_id]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [queue_a.request_id, queue_b.request_id]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    );
    assert_eq!(
        storage::claim_next_request(
            &restarted,
            "worker-api-a",
            "claim-next-a",
            &[14],
            "org_queue_test",
            None,
            "usr_worker_a",
        )
        .await
        .unwrap()
        .unwrap(),
        claimed_a
    );
    assert_eq!(
        storage::claim_next_request(
            &restarted,
            "worker-api-c",
            "claim-next-empty",
            &[16],
            "org_queue_test",
            None,
            "usr_worker_c",
        )
        .await
        .unwrap(),
        Err(storage::DomainFailure::RequestNotFound)
    );
    assert_eq!(
        storage::mutate_request(
            &restarted,
            "worker-api-stale",
            "stale-fence",
            "fail_request",
            &[17],
            "org_queue_test",
            claimed_a.request_id,
            "usr_not_assignee",
            claimed_a.revision,
            &storage::Mutation::Fail {
                reason: "A stale worker must not cross the assignment fence.",
                retryable: true,
            },
        )
        .await
        .unwrap(),
        Err(storage::DomainFailure::Forbidden)
    );

    restarted.pool().close().await;
    let cleanup = sqlx::PgPool::connect(&database_url).await.unwrap();
    cleanup
        .execute(AssertSqlSafe(format!(
            "DROP SCHEMA \"{schema_name}\" CASCADE"
        )))
        .await
        .unwrap();
    cleanup.close().await;
}
