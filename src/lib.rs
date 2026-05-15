pub mod cli;
pub mod community;
pub mod config;
pub mod parser;
pub mod analyzer;
pub mod advisory;
pub mod scoring;
pub mod report;
pub mod tui;
pub mod database;
pub mod cache;
pub mod pipeline;

pub mod error {
	use thiserror::Error;

	#[derive(Debug, Error)]
	pub enum OpenSentinelError {
		#[error("configuration error: {0}")]
		Config(String),

		#[error("parser error: {0}")]
		Parser(String),

		#[error("database error: {0}")]
		Database(String),

		#[error("api error: {0}")]
		Api(String),

		#[error("io error: {0}")]
		Io(#[from] std::io::Error),
	}

	pub type Result<T> = std::result::Result<T, OpenSentinelError>;
}
