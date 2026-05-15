#![allow(dead_code)]
use anyhow::Result;
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::database::models::Package;

pub struct PackageQueries;

impl PackageQueries {
	pub async fn upsert(pool: &PgPool, package: &Package) -> Result<Package> {
		let row = sqlx::query_as::<Postgres, Package>(
			r#"
			INSERT INTO packages (id, name, version, ecosystem, registry_url, checksum, is_direct, depth, created_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
			ON CONFLICT (name, version, ecosystem)
			DO UPDATE SET
					registry_url = EXCLUDED.registry_url,
					checksum = EXCLUDED.checksum
			RETURNING *
			"#,
		)
		.bind(package.id)
		.bind(&package.name)
		.bind(&package.version)
		.bind(&package.ecosystem)
		.bind(&package.registry_url)
		.bind(&package.checksum)
		.bind(package.is_direct)
		.bind(package.depth)
		.bind(package.created_at)
		.fetch_one(pool)
		.await?;

		Ok(row)
	}

	pub async fn find_by_name_version(
		pool: &PgPool,
		name: &str,
		version: &str,
		ecosystem: &str,
	) -> Result<Option<Package>> {
		let row = sqlx::query_as::<Postgres, Package>(
			r#"
			SELECT * FROM packages
			WHERE name = $1 AND version = $2 AND ecosystem = $3
			"#,
		)
		.bind(name)
		.bind(version)
		.bind(ecosystem)
		.fetch_optional(pool)
		.await?;

		Ok(row)
	}

	pub async fn find_by_scan(pool: &PgPool, scan_id: Uuid) -> Result<Vec<Package>> {
		let rows = sqlx::query_as::<Postgres, Package>(
			r#"
			SELECT p.* FROM packages p
			INNER JOIN scan_packages sp ON p.id = sp.package_id
			WHERE sp.scan_id = $1
			ORDER BY p.name ASC
			"#,
		)
		.bind(scan_id)
		.fetch_all(pool)
		.await?;

		Ok(rows)
	}

	pub async fn delete_by_id(pool: &PgPool, id: Uuid) -> Result<()> {
		sqlx::query("DELETE FROM packages WHERE id = $1")
			.bind(id)
			.execute(pool)
			.await?;

		Ok(())
	}
}
