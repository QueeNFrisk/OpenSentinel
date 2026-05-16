use anyhow::Result;
use sqlx::PgPool;

use crate::database::models::MaintainerMetrics;

pub async fn upsert_maintainer_metrics(pool: &PgPool, metrics: &MaintainerMetrics) -> Result<()> {
	sqlx::query(
		r#"
		INSERT INTO maintainer_metrics (
			id, package_name, ecosystem, repo_url,
			days_since_push, releases_last_year, open_issues,
			stars, forks, contributor_count, reputation_score, fetched_at
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		ON CONFLICT (package_name, ecosystem) DO UPDATE SET
			repo_url = EXCLUDED.repo_url,
			days_since_push = EXCLUDED.days_since_push,
			releases_last_year = EXCLUDED.releases_last_year,
			open_issues = EXCLUDED.open_issues,
			stars = EXCLUDED.stars,
			forks = EXCLUDED.forks,
			contributor_count = EXCLUDED.contributor_count,
			reputation_score = EXCLUDED.reputation_score,
			fetched_at = EXCLUDED.fetched_at
		"#,
	)
	.bind(metrics.id)
	.bind(&metrics.package_name)
	.bind(&metrics.ecosystem)
	.bind(&metrics.repo_url)
	.bind(metrics.days_since_push)
	.bind(metrics.releases_last_year)
	.bind(metrics.open_issues)
	.bind(metrics.stars)
	.bind(metrics.forks)
	.bind(metrics.contributor_count)
	.bind(metrics.reputation_score)
	.bind(metrics.fetched_at)
	.execute(pool)
	.await?;

	Ok(())
}

pub async fn delete_stale_maintainer_metrics(pool: &PgPool, ttl_seconds: i64) -> Result<u64> {
	let result = sqlx::query(
		r#"
		DELETE FROM maintainer_metrics
		WHERE fetched_at < NOW() - ($1 || ' seconds')::interval
		"#,
	)
	.bind(ttl_seconds.to_string())
	.execute(pool)
	.await?;

	Ok(result.rows_affected())
}

#[allow(dead_code)]
pub async fn get_maintainer_metrics(
	pool: &PgPool,
	package_name: &str,
	ecosystem: &str,
) -> Result<Option<MaintainerMetrics>> {
	let metrics = sqlx::query_as::<_, MaintainerMetrics>(
		r#"
		SELECT id, package_name, ecosystem, repo_url,
			   days_since_push, releases_last_year, open_issues,
			   stars, forks, contributor_count, reputation_score, fetched_at
		FROM maintainer_metrics
		WHERE package_name = $1 AND ecosystem = $2
		"#,
	)
	.bind(package_name)
	.bind(ecosystem)
	.fetch_optional(pool)
	.await?;

	Ok(metrics)
}
