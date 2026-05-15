use anyhow::{Context, Result};
use std::env;
use keyring::Entry;

use super::models::{CredentialStorage, EnvOrValue, CredentialsConfig};

pub struct CredentialResolver;

impl CredentialResolver {
	pub fn resolve(value: &EnvOrValue) -> Result<String> {
		match value {
			EnvOrValue::EnvVar(raw) => {
				if let Some(var_name) = raw.strip_prefix("${").and_then(|s| s.strip_suffix('}')) {
					env::var(var_name)
						.with_context(|| format!("environment variable '{var_name}' is not set"))
				} else {
					Ok(raw.clone())
				}
			}
			EnvOrValue::Literal(val) => Ok(val.clone()),
		}
	}

	pub fn resolve_credentials(config: &CredentialsConfig) -> Result<ResolvedCredentials> {
		match &config.storage {
			CredentialStorage::Keyring => Self::resolve_from_keyring(config),
			_ => Self::resolve_from_env_or_value(config),
		}
	}

	fn resolve_from_env_or_value(config: &CredentialsConfig) -> Result<ResolvedCredentials> {
		Ok(ResolvedCredentials {
			github_token: Self::resolve(&config.github_token).ok(),
			nvd_api_key: Self::resolve(&config.nvd_api_key).ok(),
		})
	}

	fn resolve_from_keyring(config: &CredentialsConfig) -> Result<ResolvedCredentials> {
		let github_token = Entry::new("opensentinel", "github_token")
			.and_then(|e| e.get_password())
			.ok()
			.or_else(|| Self::resolve(&config.github_token).ok());

		let nvd_api_key = Entry::new("opensentinel", "nvd_api_key")
			.and_then(|e| e.get_password())
			.ok()
			.or_else(|| Self::resolve(&config.nvd_api_key).ok());

		Ok(ResolvedCredentials { github_token, nvd_api_key })
	}
}

#[derive(Debug, Clone)]
pub struct ResolvedCredentials {
	pub github_token: Option<String>,
	pub nvd_api_key: Option<String>,
}
