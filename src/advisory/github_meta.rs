use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use reqwest::Client;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct GithubRepoMeta {
	pub pushed_at: Option<DateTime<Utc>>,
	pub stargazers_count: u32,
	pub forks_count: u32,
	pub open_issues_count: u32,
}

#[derive(Deserialize)]
struct GithubRelease {
	published_at: Option<DateTime<Utc>>,
}

#[derive(Deserialize)]
struct GithubContributor {
	#[allow(dead_code)]
	login: String,
}

#[derive(Debug)]
pub struct RepoMetrics {
	pub days_since_push: i32,
	pub releases_last_year: i32,
	pub open_issues: i32,
	pub stars: i32,
	pub forks: i32,
	pub contributor_count: i32,
}

pub struct GithubMetaClient {
	client: Client,
	token: Option<String>,
}

impl GithubMetaClient {
	pub fn new(token: Option<String>) -> Self {
		Self {
			client: Client::builder()
				.user_agent("opensentinel/0.1.0")
				.timeout(std::time::Duration::from_secs(15))
				.build()
				.expect("failed to build HTTP client"),
			token,
		}
	}

	pub async fn fetch_repo_url_from_npm(&self, package_name: &str) -> Option<String> {
		let url = if package_name.starts_with('@') {
			let encoded = package_name.replace('/', "%2F");
			format!("https://registry.npmjs.org/{encoded}/latest")
		} else {
			format!("https://registry.npmjs.org/{package_name}/latest")
		};

		let resp: serde_json::Value = self
			.client
			.get(&url)
			.send()
			.await
			.ok()?
			.json()
			.await
			.ok()?;

		let repo_url = resp
			.get("repository")
			.and_then(|r| {
				if let Some(url) = r.get("url").and_then(|u| u.as_str()) {
					Some(url.to_string())
				} else if r.is_string() {
					r.as_str().map(|s| s.to_string())
				} else {
					None
				}
			})?;

		normalize_github_url(&repo_url)
	}

	pub async fn fetch_repo_metrics(&self, owner: &str, repo: &str) -> Result<RepoMetrics> {
		let meta = self.fetch_repo_meta(owner, repo).await?;

		let days_since_push = meta
			.pushed_at
			.map(|t| (Utc::now() - t).num_days() as i32)
			.unwrap_or(9999);

		let releases = self.fetch_releases_last_year(owner, repo).await.unwrap_or(0);
		let contributors = self.fetch_contributor_count(owner, repo).await.unwrap_or(0);

		Ok(RepoMetrics {
			days_since_push,
			releases_last_year: releases,
			open_issues: meta.open_issues_count as i32,
			stars: meta.stargazers_count as i32,
			forks: meta.forks_count as i32,
			contributor_count: contributors,
		})
	}

	async fn fetch_repo_meta(&self, owner: &str, repo: &str) -> Result<GithubRepoMeta> {
		let url = format!("https://api.github.com/repos/{owner}/{repo}");
		let mut req = self.client.get(&url);
		if let Some(token) = &self.token {
			req = req.bearer_auth(token);
		}
		req.send()
			.await
			.with_context(|| format!("failed to reach GitHub API for {owner}/{repo}"))?
			.json::<GithubRepoMeta>()
			.await
			.with_context(|| format!("failed to parse GitHub repo meta for {owner}/{repo}"))
	}

	async fn fetch_releases_last_year(&self, owner: &str, repo: &str) -> Result<i32> {
		let cutoff = Utc::now() - chrono::Duration::days(365);

		let url = format!(
			"https://api.github.com/repos/{owner}/{repo}/releases?per_page=100"
		);

		let mut req = self.client.get(&url);
		if let Some(token) = &self.token {
			req = req.bearer_auth(token);
		}

		let releases: Vec<GithubRelease> = req
			.send()
			.await?
			.json()
			.await
			.unwrap_or_default();

		let count = releases
			.into_iter()
			.filter(|r| r.published_at.map(|d| d >= cutoff).unwrap_or(false))
			.count() as i32;

		Ok(count)
	}

	async fn fetch_contributor_count(&self, owner: &str, repo: &str) -> Result<i32> {
		let url = format!(
			"https://api.github.com/repos/{owner}/{repo}/contributors?per_page=100&anon=0"
		);

		let mut req = self.client.get(&url);
		if let Some(token) = &self.token {
			req = req.bearer_auth(token);
		}

		let contributors: Vec<GithubContributor> = req
			.send()
			.await?
			.json()
			.await
			.unwrap_or_default();

		Ok(contributors.len() as i32)
	}
}

pub fn parse_github_owner_repo(url: &str) -> Option<(String, String)> {
	let normalized = normalize_github_url(url)?;
	let path = normalized
		.trim_start_matches("https://github.com/")
		.trim_end_matches(".git");
	let mut parts = path.splitn(2, '/');
	let owner = parts.next()?.to_string();
	let repo = parts.next()?.to_string();
	if owner.is_empty() || repo.is_empty() {
		return None;
	}
	Some((owner, repo))
}

fn normalize_github_url(raw: &str) -> Option<String> {
	let cleaned = raw
		.trim()
		.trim_start_matches("git+")
		.trim_start_matches("git://")
		.trim_end_matches(".git");

	if cleaned.contains("github.com") {
		let path = cleaned
			.trim_start_matches("https://")
			.trim_start_matches("http://")
			.trim_start_matches("github.com/");
		return Some(format!("https://github.com/{path}"));
	}
	None
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn parses_https_github_url() {
		let result = parse_github_owner_repo("https://github.com/lodash/lodash");
		assert_eq!(result, Some(("lodash".to_string(), "lodash".to_string())));
	}

	#[test]
	fn parses_git_plus_https_url() {
		let result = parse_github_owner_repo("git+https://github.com/expressjs/express.git");
		assert_eq!(result, Some(("expressjs".to_string(), "express".to_string())));
	}

	#[test]
	fn parses_git_protocol_url() {
		let result = parse_github_owner_repo("git://github.com/facebook/react.git");
		assert_eq!(result, Some(("facebook".to_string(), "react".to_string())));
	}

	#[test]
	fn returns_none_for_non_github_url() {
		let result = parse_github_owner_repo("https://gitlab.com/user/repo");
		assert_eq!(result, None);
	}

	#[test]
	fn returns_none_for_incomplete_url() {
		let result = parse_github_owner_repo("https://github.com/onlyowner");
		assert_eq!(result, None);
	}

	#[test]
	fn normalizes_git_plus_url() {
		let result = normalize_github_url("git+https://github.com/sindresorhus/got.git");
		assert_eq!(result, Some("https://github.com/sindresorhus/got".to_string()));
	}
}
