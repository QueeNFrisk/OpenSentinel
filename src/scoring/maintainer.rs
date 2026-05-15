use crate::database::models::MaintainerMetrics;

pub struct MaintainerScorer;

impl MaintainerScorer {
	/// Returns a risk score from 0.0 (healthy) to 1.0 (abandoned/risky)
	pub fn score(metrics: &MaintainerMetrics) -> f32 {
		let freshness = freshness_score(metrics.days_since_push);
		let cadence = cadence_score(metrics.releases_last_year);
		let issues = issues_score(metrics.open_issues, metrics.releases_last_year);
		let adoption = adoption_score(metrics.stars);
		let contributors = contributor_score(metrics.contributor_count);

		let health = freshness * 0.30
			+ cadence * 0.25
			+ issues * 0.20
			+ adoption * 0.15
			+ contributors * 0.10;

		// reputation_score stored in DB is health (0=bad, 1=good)
		// for risk scoring we invert: 0=low risk, 1=high risk
		1.0 - health.clamp(0.0, 1.0)
	}

	pub fn health_score(metrics: &MaintainerMetrics) -> f32 {
		1.0 - Self::score(metrics)
	}
}

fn freshness_score(days_since_push: i32) -> f32 {
	match days_since_push {
		d if d <= 30 => 1.0,
		d if d <= 90 => 0.9,
		d if d <= 180 => 0.75,
		d if d <= 365 => 0.55,
		d if d <= 730 => 0.30,
		d if d <= 1095 => 0.10,
		_ => 0.0,
	}
}

fn cadence_score(releases_last_year: i32) -> f32 {
	match releases_last_year {
		r if r >= 12 => 1.0,
		r if r >= 6 => 0.85,
		r if r >= 3 => 0.65,
		r if r >= 1 => 0.40,
		_ => 0.10,
	}
}

fn issues_score(open_issues: i32, releases_last_year: i32) -> f32 {
	if releases_last_year == 0 && open_issues > 50 {
		return 0.10;
	}
	match open_issues {
		i if i == 0 => 0.80,
		i if i <= 10 => 1.0,
		i if i <= 50 => 0.75,
		i if i <= 200 => 0.55,
		i if i <= 500 => 0.35,
		_ => 0.15,
	}
}

fn adoption_score(stars: i32) -> f32 {
	match stars {
		s if s >= 10_000 => 1.0,
		s if s >= 1_000 => 0.80,
		s if s >= 100 => 0.55,
		s if s >= 10 => 0.30,
		_ => 0.10,
	}
}

fn contributor_score(count: i32) -> f32 {
	match count {
		c if c >= 50 => 1.0,
		c if c >= 10 => 0.80,
		c if c >= 3 => 0.55,
		c if c >= 1 => 0.30,
		_ => 0.05,
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use chrono::Utc;
	use uuid::Uuid;

	fn make_metrics(
		days_since_push: i32,
		releases_last_year: i32,
		open_issues: i32,
		stars: i32,
		contributor_count: i32,
	) -> MaintainerMetrics {
		MaintainerMetrics {
			id: Uuid::new_v4(),
			package_name: "test-pkg".to_string(),
			ecosystem: "nodejs".to_string(),
			repo_url: None,
			days_since_push,
			releases_last_year,
			open_issues,
			stars,
			forks: 0,
			contributor_count,
			reputation_score: 0.5,
			fetched_at: Utc::now(),
		}
	}

	#[test]
	fn healthy_package_has_low_risk_score() {
		let metrics = make_metrics(10, 12, 5, 5000, 20);
		let score = MaintainerScorer::score(&metrics);
		assert!(score < 0.3, "healthy package score should be < 0.3, got {score}");
	}

	#[test]
	fn abandoned_package_has_high_risk_score() {
		let metrics = make_metrics(2000, 0, 500, 1, 0);
		let score = MaintainerScorer::score(&metrics);
		assert!(score > 0.7, "abandoned package score should be > 0.7, got {score}");
	}

	#[test]
	fn score_clamped_between_zero_and_one() {
		let healthy = make_metrics(1, 24, 2, 50_000, 200);
		let abandoned = make_metrics(9999, 0, 9999, 0, 0);
		assert!(MaintainerScorer::score(&healthy) >= 0.0);
		assert!(MaintainerScorer::score(&healthy) <= 1.0);
		assert!(MaintainerScorer::score(&abandoned) >= 0.0);
		assert!(MaintainerScorer::score(&abandoned) <= 1.0);
	}

	#[test]
	fn freshness_recent_push_scores_high() {
		assert!((freshness_score(7) - 1.0).abs() < 0.001);
	}

	#[test]
	fn freshness_ancient_push_scores_zero() {
		assert!((freshness_score(9999) - 0.0).abs() < 0.001);
	}

	#[test]
	fn cadence_no_releases_scores_low() {
		assert!((cadence_score(0) - 0.10).abs() < 0.001);
	}

	#[test]
	fn cadence_monthly_releases_scores_high() {
		assert!((cadence_score(12) - 1.0).abs() < 0.001);
	}

	#[test]
	fn health_score_is_inverse_of_risk_score() {
		let metrics = make_metrics(30, 6, 15, 500, 8);
		let risk = MaintainerScorer::score(&metrics);
		let health = MaintainerScorer::health_score(&metrics);
		assert!((risk + health - 1.0).abs() < 0.001);
	}

	#[test]
	fn issues_score_small_tracker_scores_high() {
		assert!((issues_score(5, 4) - 1.0).abs() < 0.001);
	}

	#[test]
	fn issues_score_large_stale_tracker_scores_low() {
		assert!(issues_score(600, 0) < 0.20);
	}
}
