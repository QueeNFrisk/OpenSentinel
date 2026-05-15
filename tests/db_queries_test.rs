use chrono::Utc;
use sqlx::postgres::PgPoolOptions;
use uuid::Uuid;

use opensentinel::database::models::{
    Advisory, AdvisorySource, Package, SeverityLevel,
};
use opensentinel::database::queries::advisories::AdvisoryQueries;
use opensentinel::database::queries::packages::PackageQueries;

async fn connect() -> Option<sqlx::PgPool> {
	dotenvy::dotenv().ok();
	let url = match std::env::var("DATABASE_URL") {
		Ok(u) => u,
		Err(_) => {
			eprintln!("[skip] DATABASE_URL not set");
			return None;
		}
	};
	match PgPoolOptions::new()
		.max_connections(2)
		.acquire_timeout(std::time::Duration::from_secs(10))
		.connect(&url)
		.await
	{
		Ok(pool) => Some(pool),
		Err(e) => {
			eprintln!("[skip] DB unreachable: {e}");
			None
		}
	}
}

fn test_package(suffix: &str) -> Package {
	Package {
		id: Uuid::new_v4(),
		name: format!("test-pkg-{suffix}"),
		version: "1.0.0".to_string(),
		ecosystem: "nodejs".to_string(),
		registry_url: None,
		checksum: None,
		is_direct: true,
		depth: 0,
		created_at: Utc::now(),
	}
}

fn test_advisory(package_id: Uuid, suffix: &str) -> Advisory {
	Advisory {
		id: Uuid::new_v4(),
		package_id,
		source: AdvisorySource::Osv,
		external_id: format!("TEST-{suffix}"),
		title: format!("Test advisory {suffix}"),
		description: "test".to_string(),
		severity: SeverityLevel::High,
		cvss_score: Some(7.5),
		affected_versions: "<2.0.0".to_string(),
		patched_versions: Some("2.0.0".to_string()),
		published_at: None,
		fetched_at: Utc::now(),
	}
}

#[tokio::test]
async fn upsert_package_and_fetch_by_name_version() {
	let Some(pool) = connect().await else { return };
	let pkg = test_package(&Uuid::new_v4().to_string()[..8]);

	let inserted = PackageQueries::upsert(&pool, &pkg)
		.await
		.expect("upsert failed");

	assert_eq!(inserted.name, pkg.name);
	assert_eq!(inserted.version, pkg.version);

	let found = PackageQueries::find_by_name_version(&pool, &pkg.name, &pkg.version, &pkg.ecosystem)
		.await
		.expect("fetch failed");

	assert!(found.is_some());
	let found = found.unwrap();
	assert_eq!(found.name, pkg.name);
	assert_eq!(found.ecosystem, "nodejs");

	PackageQueries::delete_by_id(&pool, inserted.id)
		.await
		.expect("cleanup failed");
}

#[tokio::test]
async fn upsert_package_is_idempotent() {
	let Some(pool) = connect().await else { return };
	let pkg = test_package(&Uuid::new_v4().to_string()[..8]);

	let first = PackageQueries::upsert(&pool, &pkg).await.expect("first upsert failed");
	let second = PackageQueries::upsert(&pool, &pkg).await.expect("second upsert failed");

	assert_eq!(first.id, second.id);
	assert_eq!(first.name, second.name);

	PackageQueries::delete_by_id(&pool, first.id).await.expect("cleanup failed");
}

#[tokio::test]
async fn find_by_name_version_returns_none_for_missing() {
	let Some(pool) = connect().await else { return };

	let result = PackageQueries::find_by_name_version(
		&pool,
		"nonexistent-pkg-xyz-abc",
		"99.99.99",
		"nodejs",
	)
	.await
	.expect("query failed");

	assert!(result.is_none());
}

#[tokio::test]
async fn insert_advisory_and_fetch_by_package() {
	let Some(pool) = connect().await else { return };
	let pkg = test_package(&Uuid::new_v4().to_string()[..8]);
	let pkg = PackageQueries::upsert(&pool, &pkg).await.expect("package upsert failed");

	let adv = test_advisory(pkg.id, &Uuid::new_v4().to_string()[..8]);
	let inserted_adv = AdvisoryQueries::upsert(&pool, &adv)
		.await
		.expect("advisory upsert failed");

	assert_eq!(inserted_adv.package_id, pkg.id);
	assert_eq!(inserted_adv.severity, SeverityLevel::High);

	let advisories = AdvisoryQueries::find_by_package(&pool, pkg.id)
		.await
		.expect("fetch advisories failed");

	assert_eq!(advisories.len(), 1);
	assert_eq!(advisories[0].external_id, adv.external_id);
	assert_eq!(advisories[0].cvss_score, Some(7.5));

	PackageQueries::delete_by_id(&pool, pkg.id).await.expect("cleanup failed");
}

#[tokio::test]
async fn advisory_upsert_updates_existing() {
	let Some(pool) = connect().await else { return };
	let pkg = test_package(&Uuid::new_v4().to_string()[..8]);
	let pkg = PackageQueries::upsert(&pool, &pkg).await.expect("package upsert failed");

	let suffix = &Uuid::new_v4().to_string()[..8];
	let adv = test_advisory(pkg.id, suffix);
	AdvisoryQueries::upsert(&pool, &adv).await.expect("first advisory upsert failed");

	let mut updated = adv.clone();
	updated.id = Uuid::new_v4();
	updated.severity = SeverityLevel::Critical;
	updated.cvss_score = Some(9.8);
	AdvisoryQueries::upsert(&pool, &updated).await.expect("second advisory upsert failed");

	let advisories = AdvisoryQueries::find_by_package(&pool, pkg.id)
		.await
		.expect("fetch failed");

	assert_eq!(advisories.len(), 1);
	assert_eq!(advisories[0].severity, SeverityLevel::Critical);
	assert_eq!(advisories[0].cvss_score, Some(9.8));

	PackageQueries::delete_by_id(&pool, pkg.id).await.expect("cleanup failed");
}
