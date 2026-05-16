#![allow(dead_code)]
use anyhow::{bail, Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::config::{DatabaseConfig, DatabaseEngine};

pub struct DatabasePool {
	inner: PgPool,
}

impl DatabasePool {
	pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
		match config.engine {
			DatabaseEngine::SQLite => {
				bail!(
					"SQLite support is not yet available — \
					 configure a PostgreSQL database or run without one"
				);
			}
			DatabaseEngine::MySQL => {
				bail!(
					"MySQL support is not yet available — \
					 configure a PostgreSQL database or run without one"
				);
			}
			DatabaseEngine::PostgreSQL => {}
		}

		let connection_string = Self::build_pg_connection_string(config)?;

		let pool = PgPoolOptions::new()
			.max_connections(config.pool_size)
			.connect(&connection_string)
			.await
			.with_context(|| format!(
				"failed to connect to PostgreSQL at {}",
				Self::sanitized_url(config),
			))?;

		let db = Self { inner: pool };
		db.run_migrations().await?;
		Ok(db)
	}

	pub fn inner(&self) -> &PgPool {
		&self.inner
	}

	async fn run_migrations(&self) -> Result<()> {
		sqlx::migrate!("./migrations")
			.run(&self.inner)
			.await
			.context("failed to run database migrations")
	}

	fn build_pg_connection_string(config: &DatabaseConfig) -> Result<String> {
		if let Some(url_val) = &config.url {
			let resolved = crate::config::CredentialResolver::resolve(url_val)
				.context("failed to resolve database URL")?;
			if !resolved.is_empty() {
				return Ok(resolved);
			}
		}

		let password = config.password_value();
		if password.is_empty() {
			bail!(
				"no database password found — set DB_PASSWORD or use a connection URL via DATABASE_URL"
			);
		}

		let ssl_mode = if config.ssl || Self::requires_ssl(&config.host) {
			"require"
		} else {
			"disable"
		};
		Ok(format!(
			"postgresql://{}:{}@{}:{}/{}?sslmode={}",
			config.user,
			password,
			config.host,
			config.port,
			config.database,
			ssl_mode,
		))
	}

	fn requires_ssl(host: &str) -> bool {
		!matches!(host, "localhost" | "127.0.0.1" | "::1")
	}

	pub fn sanitized_url(config: &DatabaseConfig) -> String {
		match config.engine {
			DatabaseEngine::SQLite => {
				let path = config.sqlite_path.as_deref().unwrap_or("opensentinel.db");
				return format!("sqlite://{path}");
			}
			DatabaseEngine::MySQL => {
				return format!(
					"mysql://{}@{}:{}/{}",
					config.user, config.host, config.port, config.database
				);
			}
			DatabaseEngine::PostgreSQL => {}
		}

		if let Some(url_val) = &config.url {
			if let Ok(resolved) = crate::config::CredentialResolver::resolve(url_val) {
				if !resolved.is_empty() {
					return Self::redact_password(&resolved);
				}
			}
		}
		format!(
			"postgresql://{}@{}:{}/{}",
			config.user, config.host, config.port, config.database
		)
	}

	fn redact_password(url: &str) -> String {
		if let Some(at) = url.find('@') {
			if let Some(scheme_end) = url.find("://") {
				let after_scheme = &url[scheme_end + 3..at];
				if let Some(colon) = after_scheme.find(':') {
					let user = &after_scheme[..colon];
					let rest = &url[at..];
					let prefix = &url[..scheme_end + 3];
					return format!("{prefix}{user}:***{rest}");
				}
			}
		}
		url.to_string()
	}
}

impl crate::config::DatabaseConfig {
	pub fn password_value(&self) -> String {
		crate::config::CredentialResolver::resolve(&self.password)
			.unwrap_or_default()
	}
}
