use indicatif::{MultiProgress, ProgressBar, ProgressStyle};
use std::time::Duration;
use tokio::sync::mpsc;

pub trait ScanReporter: Send + Sync {
	fn set_total(&self, total: u64);
	fn tick_package(&self, name: &str);
	fn tick_advisory(&self);
	fn tick_analysis(&self);
	fn finish(&self);
	fn log(&self, _msg: &str) {}
}

#[derive(Debug)]
pub enum ScanEvent {
	Total(u64),
	Package(String),
	Log(String),
	DbConnecting,
	DbConnected(String),
	DbFailed(String),
	Done(Vec<crate::scoring::models::PackageRisk>),
	Error(String),
}

pub struct ScanProgress {
	#[allow(dead_code)]
	multi: MultiProgress,
	pub main_bar: ProgressBar,
	pub advisory_bar: ProgressBar,
	pub analysis_bar: ProgressBar,
}

impl ScanProgress {
	pub fn new() -> Self {
		let multi = MultiProgress::new();

		let main_style = ProgressStyle::with_template(
			" {spinner:.cyan} {msg:<40} [{bar:30.cyan/blue}] {pos}/{len}",
		)
		.unwrap()
		.tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

		let sub_style = ProgressStyle::with_template(
			"   {spinner:.blue} {msg:<38} {pos}/{len}",
		)
		.unwrap()
		.tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]);

		let main_bar = multi.add(ProgressBar::new(0));
		main_bar.set_style(main_style);
		main_bar.enable_steady_tick(Duration::from_millis(80));

		let advisory_bar = multi.add(ProgressBar::new(0));
		advisory_bar.set_style(sub_style.clone());
		advisory_bar.enable_steady_tick(Duration::from_millis(80));

		let analysis_bar = multi.add(ProgressBar::new(0));
		analysis_bar.set_style(sub_style);
		analysis_bar.enable_steady_tick(Duration::from_millis(80));

		Self { multi, main_bar, advisory_bar, analysis_bar }
	}
}

impl ScanReporter for ScanProgress {
	fn set_total(&self, total: u64) {
		self.main_bar.set_length(total);
		self.main_bar.set_message("Resolving dependency tree");
		self.advisory_bar.set_length(total);
		self.advisory_bar.set_message("Fetching advisories");
		self.analysis_bar.set_length(total);
		self.analysis_bar.set_message("Analyzing patterns");
	}

	fn tick_package(&self, name: &str) {
		self.main_bar.set_message(format!("Scanning {name}"));
		self.main_bar.inc(1);
	}

	fn tick_advisory(&self) {
		self.advisory_bar.inc(1);
	}

	fn tick_analysis(&self) {
		self.analysis_bar.inc(1);
	}

	fn finish(&self) {
		self.main_bar.finish_with_message("Scan complete");
		self.advisory_bar.finish_and_clear();
		self.analysis_bar.finish_and_clear();
	}
}

pub struct ChannelReporter {
	tx: mpsc::UnboundedSender<ScanEvent>,
}

impl ChannelReporter {
	pub fn new(tx: mpsc::UnboundedSender<ScanEvent>) -> Self {
		Self { tx }
	}
}

impl ScanReporter for ChannelReporter {
	fn set_total(&self, total: u64) {
		self.tx.send(ScanEvent::Total(total)).ok();
	}

	fn tick_package(&self, name: &str) {
		self.tx.send(ScanEvent::Package(name.to_string())).ok();
	}

	fn log(&self, msg: &str) {
		self.tx.send(ScanEvent::Log(msg.to_string())).ok();
	}

	fn tick_advisory(&self) {}
	fn tick_analysis(&self) {}
	fn finish(&self) {}
}
