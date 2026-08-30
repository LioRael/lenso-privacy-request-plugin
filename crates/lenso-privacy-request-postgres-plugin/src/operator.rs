use lenso_postgres_kit::{PostgresKitError, SchemaOperator, SetupOutcome, UpgradeOutcome};
use thiserror::Error;

use crate::schema::schema_plan;

/// Explicit, operator-owned schema administration for Privacy Request storage.
#[derive(Clone, Copy, Debug, Default)]
pub struct PrivacyRequestOperator;

impl PrivacyRequestOperator {
    /// Creates the owned schema and installs the authored migration plan.
    pub async fn setup(
        database_url: &str,
        schema: &str,
    ) -> Result<SetupOutcome, PrivacyRequestOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .setup()
            .await?)
    }

    /// Applies pending authored migrations without performing DDL during activation.
    pub async fn upgrade(
        database_url: &str,
        schema: &str,
    ) -> Result<UpgradeOutcome, PrivacyRequestOperatorError> {
        Ok(SchemaOperator::connect(database_url, schema_plan(schema)?)
            .await?
            .upgrade()
            .await?)
    }
}

/// Failure from an explicit Privacy Request schema workflow.
#[derive(Debug, Error)]
pub enum PrivacyRequestOperatorError {
    #[error(transparent)]
    Plan(#[from] lenso_postgres_kit::PlanError),
    #[error(transparent)]
    Postgres(#[from] PostgresKitError),
}
