#![allow(dead_code)]
use anyhow::Result;
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::database::models::{Advisory, AdvisorySource};

pub struct AdvisoryQueries;

impl AdvisoryQueries {
	pub async fn upsert(pool: &PgPool, advisory: &Advisory) -> Result<Advisory> {
		let row = sqlx::query_as::<Postgres, Advisory>(
			r#"
			INSERT INTO advisories (
				id, package_id, source, external_id, title, description,
				severity, cvss_score, affected_versions, patched_versions,
				published_at, fetched_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
			ON CONFLICT (package_id, source, external_id)
			DO UPDATE SET
				title = EXCLUDED.title,
				description = EXCLUDED.description,
				severity = EXCLUDED.severity,
				cvss_score = EXCLUDED.cvss_score,
				patched_versions = EXCLUDED.patched_versions,
				fetched_at = EXCLUDED.fetched_at
			RETURNING
				id, package_id,
				source AS "source: AdvisorySource",
				external_id, title, description,
				severity AS "severity: SeverityLevel",
				cvss_score, affected_versions, patched_versions,
				published_at, fetched_at
			"#,
		)
		.bind(advisory.id)
		.bind(advisory.package_id)
		.bind(&advisory.source)
		.bind(&advisory.external_id)
		.bind(&advisory.title)
		.bind(&advisory.description)
		.bind(&advisory.severity)
		.bind(advisory.cvss_score)
		.bind(&advisory.affected_versions)
		.bind(&advisory.patched_versions)
		.bind(advisory.published_at)
		.bind(advisory.fetched_at)
		.fetch_one(pool)
		.await?;

		Ok(row)
	}

	pub async fn find_by_package(pool: &PgPool, package_id: Uuid) -> Result<Vec<Advisory>> {
		let rows = sqlx::query_as::<Postgres, Advisory>(
			r#"
			SELECT
				id, package_id,
				source AS "source: AdvisorySource",
				external_id, title, description,
				severity AS "severity: SeverityLevel",
				cvss_score, affected_versions, patched_versions,
				published_at, fetched_at
			FROM advisories
			WHERE package_id = $1
			ORDER BY severity DESC, cvss_score DESC NULLS LAST
			"#,
		)
		.bind(package_id)
		.fetch_all(pool)
		.await?;

		Ok(rows)
	}

	pub async fn find_by_external_id(
		pool: &PgPool,
		source: &AdvisorySource,
		external_id: &str,
	) -> Result<Option<Advisory>> {
		let row = sqlx::query_as::<Postgres, Advisory>(
			r#"
			SELECT
				id, package_id,
				source AS "source: AdvisorySource",
				external_id, title, description,
				severity AS "severity: SeverityLevel",
				cvss_score, affected_versions, patched_versions,
				published_at, fetched_at
			FROM advisories
			WHERE source = $1 AND external_id = $2
			"#,
		)
		.bind(source)
		.bind(external_id)
		.fetch_optional(pool)
		.await?;

		Ok(row)
	}

	pub async fn delete_stale(pool: &PgPool, package_id: Uuid, ttl_seconds: i64) -> Result<u64> {
		let result = sqlx::query(
			r#"
			DELETE FROM advisories
			WHERE package_id = $1
				AND fetched_at < NOW() - ($2 || ' seconds')::interval
			"#,
		)
		.bind(package_id)
		.bind(ttl_seconds.to_string())
		.execute(pool)
		.await?;

		Ok(result.rows_affected())
	}
}
