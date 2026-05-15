#![allow(dead_code)]
use anyhow::{Context, Result};
use sqlx::{postgres::PgPoolOptions, PgPool};

use crate::config::DatabaseConfig;

pub struct DatabasePool {
	inner: PgPool,
}

impl DatabasePool {
	pub async fn connect(config: &DatabaseConfig) -> Result<Self> {
		let connection_string = Self::build_connection_string(config);

		let pool = PgPoolOptions::new()
			.max_connections(config.pool_size)
			.connect(&connection_string)
			.await
			.with_context(|| format!(
				"failed to connect to PostgreSQL at {}:{}",
				config.host, config.port
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

	fn build_connection_string(config: &DatabaseConfig) -> String {
		let ssl_mode = if config.ssl { "require" } else { "disable" };
		format!(
			"postgresql://{}:{}@{}:{}/{}?sslmode={}",
			config.user,
			config.password_value(),
			config.host,
			config.port,
			config.database,
			ssl_mode
		)
	}
}

impl crate::config::DatabaseConfig {
	pub fn password_value(&self) -> String {
		crate::config::CredentialResolver::resolve(&self.password)
			.unwrap_or_default()
	}
}
