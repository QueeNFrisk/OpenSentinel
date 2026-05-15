use anyhow::{Context, Result};
use flate2::read::GzDecoder;
use reqwest::Client;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tar::Archive;

pub struct CacheManager {
	cache_dir: PathBuf,
	ttl_seconds: u64,
	http: Client,
}

impl CacheManager {
	pub fn new(cache_dir: PathBuf, ttl_seconds: u64) -> Self {
		Self {
			cache_dir,
			ttl_seconds,
			http: Client::new(),
		}
	}

	pub fn clear(&self) -> Result<()> {
		if self.cache_dir.exists() {
			std::fs::remove_dir_all(&self.cache_dir)?;
		}
		Ok(())
	}

	pub fn package_dir(&self, name: &str, version: &str) -> PathBuf {
		let safe_name = name.replace('/', "+");
		self.cache_dir.join(format!("{safe_name}@{version}"))
	}

	pub fn is_cached(&self, name: &str, version: &str) -> bool {
		let dir = self.package_dir(name, version);
		dir.exists() && !self.is_expired(&dir)
	}

	pub async fn ensure_source(&self, name: &str, version: &str) -> Result<PathBuf> {
		let dir = self.package_dir(name, version);

		if self.is_cached(name, version) {
			return Ok(dir);
		}

		self.download_and_extract(name, version, &dir).await?;
		Ok(dir)
	}

	async fn download_and_extract(&self, name: &str, version: &str, dest: &Path) -> Result<()> {
		let url = Self::tarball_url(name, version);

		let bytes = self.http
			.get(&url)
			.send()
			.await
			.with_context(|| format!("failed to fetch {url}"))?
			.error_for_status()
			.with_context(|| format!("npm registry returned error for {name}@{version}"))?
			.bytes()
			.await
			.with_context(|| format!("failed to read tarball bytes for {name}@{version}"))?;

		std::fs::create_dir_all(dest)
			.with_context(|| format!("failed to create cache dir {}", dest.display()))?;

		let cursor = Cursor::new(bytes);
		let gz = GzDecoder::new(cursor);
		let mut archive = Archive::new(gz);

		for entry in archive.entries().context("failed to read tarball entries")? {
			let mut entry = entry.context("invalid tarball entry")?;
			let entry_path = entry.path().context("invalid entry path")?;

			let stripped = entry_path
				.components()
				.skip(1)
				.collect::<PathBuf>();

			if stripped.as_os_str().is_empty() {
				continue;
			}

			let target = dest.join(&stripped);

			if let Some(parent) = target.parent() {
				std::fs::create_dir_all(parent)?;
			}

			entry.unpack(&target)
				.with_context(|| format!("failed to extract {}", stripped.display()))?;
		}

		Ok(())
	}

	fn tarball_url(name: &str, version: &str) -> String {
		if let Some(rest) = name.strip_prefix('@') {
			let slash_pos = rest.find('/').unwrap_or(rest.len());
			let scope = &rest[..slash_pos];
			let pkg = &rest[slash_pos + 1..];
			format!("https://registry.npmjs.org/@{scope}/{pkg}/-/{pkg}-{version}.tgz")
		} else {
			format!("https://registry.npmjs.org/{name}/-/{name}-{version}.tgz")
		}
	}

	fn is_expired(&self, path: &Path) -> bool {
		path.metadata()
			.and_then(|m| m.modified())
			.map(|modified| {
				modified
					.elapsed()
					.map(|elapsed| elapsed.as_secs() > self.ttl_seconds)
					.unwrap_or(true)
			})
			.unwrap_or(true)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn tarball_url_regular_package() {
		let url = CacheManager::tarball_url("lodash", "4.17.21");
		assert_eq!(url, "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz");
	}

	#[test]
	fn tarball_url_scoped_package() {
		let url = CacheManager::tarball_url("@babel/core", "7.24.0");
		assert_eq!(url, "https://registry.npmjs.org/@babel/core/-/core-7.24.0.tgz");
	}

	#[test]
	fn package_dir_regular() {
		let mgr = CacheManager::new(PathBuf::from("/tmp/cache"), 3600);
		let dir = mgr.package_dir("lodash", "4.17.21");
		assert_eq!(dir, PathBuf::from("/tmp/cache/lodash@4.17.21"));
	}

	#[test]
	fn package_dir_scoped_replaces_slash() {
		let mgr = CacheManager::new(PathBuf::from("/tmp/cache"), 3600);
		let dir = mgr.package_dir("@babel/core", "7.24.0");
		assert_eq!(dir, PathBuf::from("/tmp/cache/@babel+core@7.24.0"));
	}

	#[test]
	fn is_cached_returns_false_for_nonexistent() {
		let mgr = CacheManager::new(PathBuf::from("/tmp/nonexistent_cache_xyz"), 3600);
		assert!(!mgr.is_cached("lodash", "4.17.21"));
	}
}
