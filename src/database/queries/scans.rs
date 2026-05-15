#![allow(dead_code)]
use anyhow::Result;
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::database::models::ScanResult;

pub struct ScanQueries;

impl ScanQueries {
	pub async fn create(pool: &PgPool, scan: &ScanResult) -> Result<ScanResult> {
		let row = sqlx::query_as::<Postgres, ScanResult>(
			r#"
			INSERT INTO scan_results (
				id, project_path, ecosystem, total_packages,
				critical_count, high_count, medium_count, low_count, safe_count, scanned_at
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
			RETURNING *
			"#,
		)
		.bind(scan.id)
		.bind(&scan.project_path)
		.bind(&scan.ecosystem)
		.bind(scan.total_packages)
		.bind(scan.critical_count)
		.bind(scan.high_count)
		.bind(scan.medium_count)
		.bind(scan.low_count)
		.bind(scan.safe_count)
		.bind(scan.scanned_at)
		.fetch_one(pool)
		.await?;

		Ok(row)
	}

	pub async fn attach_package(pool: &PgPool, scan_id: Uuid, package_id: Uuid) -> Result<()> {
		sqlx::query(
			r#"
			INSERT INTO scan_packages (scan_id, package_id)
			VALUES ($1, $2)
			ON CONFLICT DO NOTHING
			"#,
		)
		.bind(scan_id)
		.bind(package_id)
		.execute(pool)
		.await?;

		Ok(())
	}

	pub async fn find_latest_by_path(
		pool: &PgPool,
		project_path: &str,
	) -> Result<Option<ScanResult>> {
		let row = sqlx::query_as::<Postgres, ScanResult>(
			r#"
			SELECT * FROM scan_results
			WHERE project_path = $1
			ORDER BY scanned_at DESC
			LIMIT 1
			"#,
		)
		.bind(project_path)
		.fetch_optional(pool)
		.await?;

		Ok(row)
	}

	pub async fn list_all(pool: &PgPool, limit: i64) -> Result<Vec<ScanResult>> {
		let rows = sqlx::query_as::<Postgres, ScanResult>(
			r#"
			SELECT * FROM scan_results
			ORDER BY scanned_at DESC
			LIMIT $1
			"#,
		)
		.bind(limit)
		.fetch_all(pool)
		.await?;

		Ok(rows)
	}
}
