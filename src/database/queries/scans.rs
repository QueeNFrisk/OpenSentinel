#![allow(dead_code)]
use anyhow::Result;
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::database::models::{ScanResult, SeverityLevel};
use crate::scoring::models::PackageRisk;

pub struct ScanQueries;

impl ScanQueries {
	pub async fn save_full(
		pool: &PgPool,
		project_path: &str,
		risks: &[PackageRisk],
	) -> Result<ScanResult> {
		let critical = risks.iter().filter(|r| r.overall_severity == SeverityLevel::Critical).count() as i32;
		let high     = risks.iter().filter(|r| r.overall_severity == SeverityLevel::High).count() as i32;
		let medium   = risks.iter().filter(|r| r.overall_severity == SeverityLevel::Medium).count() as i32;
		let low      = risks.iter().filter(|r| r.overall_severity == SeverityLevel::Low).count() as i32;
		let safe     = risks.iter().filter(|r| r.overall_severity == SeverityLevel::Safe).count() as i32;

		let ecosystems: Vec<String> = {
			let mut seen = std::collections::HashSet::new();
			risks.iter().map(|r| r.ecosystem.clone()).filter(|e| seen.insert(e.clone())).collect()
		};
		let ecosystem = ecosystems.join(",");

		let results_json = serde_json::to_value(risks)?;

		let row = sqlx::query_as::<Postgres, ScanResult>(
			r#"
			INSERT INTO scan_results (
				project_path, ecosystem, total_packages,
				critical_count, high_count, medium_count, low_count, safe_count,
				results_json
			)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			RETURNING *
			"#,
		)
		.bind(project_path)
		.bind(&ecosystem)
		.bind(risks.len() as i32)
		.bind(critical)
		.bind(high)
		.bind(medium)
		.bind(low)
		.bind(safe)
		.bind(&results_json)
		.fetch_one(pool)
		.await?;

		Ok(row)
	}

	pub async fn load_by_id(pool: &PgPool, scan_id: Uuid) -> Result<Option<ScanResult>> {
		let row = sqlx::query_as::<Postgres, ScanResult>(
			r#"SELECT * FROM scan_results WHERE id = $1"#,
		)
		.bind(scan_id)
		.fetch_optional(pool)
		.await?;

		Ok(row)
	}

	pub async fn list_recent(pool: &PgPool, project_path: Option<&str>, limit: i64) -> Result<Vec<ScanResult>> {
		let rows = if let Some(path) = project_path {
			sqlx::query_as::<Postgres, ScanResult>(
				r#"
				SELECT * FROM scan_results
				WHERE project_path = $1
				ORDER BY scanned_at DESC
				LIMIT $2
				"#,
			)
			.bind(path)
			.bind(limit)
			.fetch_all(pool)
			.await?
		} else {
			sqlx::query_as::<Postgres, ScanResult>(
				r#"SELECT * FROM scan_results ORDER BY scanned_at DESC LIMIT $1"#,
			)
			.bind(limit)
			.fetch_all(pool)
			.await?
		};

		Ok(rows)
	}
}
