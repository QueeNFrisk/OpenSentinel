use anyhow::Result;
use clap::Parser;

mod cli;
mod community;
mod config;
mod parser;
mod analyzer;
mod advisory;
mod scoring;
mod report;
mod tui;
mod database;
mod cache;
mod pipeline;

use cli::Commands;

#[tokio::main]
async fn main() -> Result<()> {
	tracing_subscriber::fmt()
		.with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
		.init();

	let args = cli::Cli::parse();

	match args.command {
		Commands::Scan(opts) => cli::handlers::handle_scan(opts).await?,
		Commands::Analyze(opts) => cli::handlers::handle_analyze(opts).await?,
		Commands::Report(opts) => cli::handlers::handle_report(opts).await?,
		Commands::CacheClear => cli::handlers::handle_cache_clear().await?,
		Commands::Init(opts) => cli::handlers::handle_init(opts).await?,
		Commands::Community(opts) => cli::handlers::handle_community(opts).await?,
		Commands::History(opts)   => cli::handlers::handle_history(opts).await?,
		Commands::View(opts)      => cli::handlers::handle_view(opts).await?,
	}

	Ok(())
}
