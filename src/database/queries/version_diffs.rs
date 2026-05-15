use anyhow::Result;
use sqlx::PgPool;
use uuid::Uuid;

use crate::database::models::VersionDiff;

pub async fn upsert_version_diff(pool: &PgPool, diff: &VersionDiff) -> Result<()> {
	sqlx::query(
		r#"
		INSERT INTO version_diffs (id, package_id, from_version, to_version, change_type, description, severity, detected_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (package_id, from_version, to_version, change_type) DO NOTHING
		"#,
	)
	.bind(diff.id)
	.bind(diff.package_id)
	.bind(&diff.from_version)
	.bind(&diff.to_version)
	.bind(&diff.change_type)
	.bind(&diff.description)
	.bind(&diff.severity)
	.bind(diff.detected_at)
	.execute(pool)
	.await?;

	Ok(())
}

#[allow(dead_code)]
pub async fn get_diffs_for_package(pool: &PgPool, package_id: Uuid) -> Result<Vec<VersionDiff>> {
	let diffs = sqlx::query_as::<_, VersionDiff>(
		r#"
		SELECT id, package_id, from_version, to_version, change_type, description, severity, detected_at
		FROM version_diffs
		WHERE package_id = $1
		ORDER BY detected_at DESC
		"#,
	)
	.bind(package_id)
	.fetch_all(pool)
	.await?;

	Ok(diffs)
}
