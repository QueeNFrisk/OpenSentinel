use std::path::PathBuf;
use tokio::sync::mpsc;

use crate::config::{KeybindingsMode, OpenSentinelConfig};
use crate::pipeline::{ChannelReporter, ScanEvent, ScanOrchestrator};
use crate::scoring::models::PackageRisk;

#[derive(Debug, Clone, PartialEq)]
pub enum ActivePanel {
	Left,
	Right,
	Bottom,
}

#[derive(Debug)]
pub struct ScanningState {
	pub current_package: String,
	pub scanned: u64,
	pub total: u64,
	pub spinner_tick: u8,
	last_spinner_tick: std::time::Instant,
}

impl Default for ScanningState {
	fn default() -> Self {
		Self {
			current_package: String::new(),
			scanned: 0,
			total: 0,
			spinner_tick: 0,
			last_spinner_tick: std::time::Instant::now(),
		}
	}
}

impl ScanningState {
	pub fn progress_pct(&self) -> u16 {
		if self.total == 0 { return 0; }
		((self.scanned * 100) / self.total) as u16
	}

	pub fn tick_spinner(&mut self) {
		let now = std::time::Instant::now();
		if now.duration_since(self.last_spinner_tick).as_millis() >= 80 {
			self.spinner_tick = self.spinner_tick.wrapping_add(1);
			self.last_spinner_tick = now;
		}
	}
}

pub enum AppState {
	Scanning(ScanningState),
	Results(ResultsState),
	Error(String),
}

#[derive(Debug)]
pub struct ResultsState {
	pub risks: Vec<PackageRisk>,
	pub selected_index: usize,
	pub active_panel: ActivePanel,
	pub search_query: String,
	pub search_mode: bool,
	pub show_direct_only: bool,
	pub group_by_severity: bool,
	pub selected_vuln: usize,
	pub detail_scroll: usize,
	pub status_message: Option<String>,
	pub status_clear_at: Option<std::time::Instant>,
}

impl ResultsState {
	fn new(risks: Vec<PackageRisk>) -> Self {
		Self {
			risks,
			selected_index: 0,
			active_panel: ActivePanel::Left,
			search_query: String::new(),
			search_mode: false,
			show_direct_only: false,
			group_by_severity: false,
			selected_vuln: 0,
			detail_scroll: 0,
			status_message: None,
			status_clear_at: None,
		}
	}

	pub fn set_status(&mut self, msg: impl Into<String>) {
		self.status_message = Some(msg.into());
		self.status_clear_at = Some(
			std::time::Instant::now() + std::time::Duration::from_secs(3),
		);
	}

	pub fn vuln_count(&self) -> usize {
		self.selected_risk()
			.map(|r| r.advisories.len() + r.detections.len())
			.unwrap_or(0)
	}

	pub fn filtered_risks(&self) -> Vec<&PackageRisk> {
		let mut filtered: Vec<&PackageRisk> = self
			.risks
			.iter()
			.filter(|r| {
				if self.show_direct_only && !r.is_direct { return false; }
				if !self.search_query.is_empty() {
					return r.package_name.to_lowercase().contains(&self.search_query.to_lowercase());
				}
				true
			})
			.collect();

		if self.group_by_severity {
			filtered.sort_by(|a, b| {
				b.final_score.partial_cmp(&a.final_score).unwrap_or(std::cmp::Ordering::Equal)
			});
		}
		filtered
	}

	pub fn selected_risk(&self) -> Option<&PackageRisk> {
		self.filtered_risks().into_iter().nth(self.selected_index)
	}

	pub fn move_up(&mut self) {
		match self.active_panel {
			ActivePanel::Left => {
				if self.selected_index > 0 {
					self.selected_index -= 1;
					self.selected_vuln = 0;
					self.detail_scroll = 0;
				}
			}
			ActivePanel::Right => {
				if self.selected_vuln > 0 {
					self.selected_vuln -= 1;
					self.detail_scroll = 0;
				}
			}
			ActivePanel::Bottom => {
				if self.detail_scroll > 0 { self.detail_scroll -= 1; }
			}
		}
	}

	pub fn move_down(&mut self) {
		match self.active_panel {
			ActivePanel::Left => {
				let count = self.filtered_risks().len();
				if self.selected_index + 1 < count {
					self.selected_index += 1;
					self.selected_vuln = 0;
					self.detail_scroll = 0;
				}
			}
			ActivePanel::Right => {
				let count = self.vuln_count();
				if self.selected_vuln + 1 < count {
					self.selected_vuln += 1;
					self.detail_scroll = 0;
				}
			}
			ActivePanel::Bottom => {
				self.detail_scroll += 1;
			}
		}
	}

	pub fn toggle_panel(&mut self) {
		self.active_panel = match self.active_panel {
			ActivePanel::Left   => ActivePanel::Right,
			ActivePanel::Right  => ActivePanel::Bottom,
			ActivePanel::Bottom => ActivePanel::Left,
		};
	}

	pub fn enter_search(&mut self) {
		self.search_mode = true;
		self.search_query.clear();
	}

	pub fn exit_search(&mut self) { self.search_mode = false; }

	pub fn push_search_char(&mut self, c: char) {
		self.search_query.push(c);
		self.selected_index = 0;
	}

	pub fn pop_search_char(&mut self) {
		self.search_query.pop();
		self.selected_index = 0;
	}

	pub fn stats(&self) -> ScanStats {
		ScanStats {
			total:    self.risks.len(),
			critical: self.risks.iter().filter(|r| r.severity_label() == "CRITICAL").count(),
			high:     self.risks.iter().filter(|r| r.severity_label() == "HIGH").count(),
			medium:   self.risks.iter().filter(|r| r.severity_label() == "MEDIUM").count(),
			low:      self.risks.iter().filter(|r| r.severity_label() == "LOW").count(),
			safe:     self.risks.iter().filter(|r| r.severity_label() == "SAFE").count(),
		}
	}
}

pub struct TuiApp {
	pub state: AppState,
	pub keybindings: KeybindingsMode,
	pub should_quit: bool,
	pub rx: mpsc::UnboundedReceiver<ScanEvent>,
}

impl TuiApp {
	pub fn new_scanning(
		config: &OpenSentinelConfig,
		project_path: PathBuf,
		keybindings: KeybindingsMode,
	) -> (Self, tokio::task::JoinHandle<()>) {
		let (tx, rx) = mpsc::unbounded_channel::<ScanEvent>();

		let config = config.clone();
		let handle = tokio::spawn(async move {
			let reporter = ChannelReporter::new(tx.clone());
			let orchestrator = ScanOrchestrator::new(&config, &project_path);
			match orchestrator.run(&reporter).await {
				Ok(risks) => { tx.send(ScanEvent::Done(risks)).ok(); }
				Err(e)    => { tx.send(ScanEvent::Error(e.to_string())).ok(); }
			}
		});

		let app = Self {
			state: AppState::Scanning(ScanningState::default()),
			keybindings,
			should_quit: false,
			rx,
		};

		(app, handle)
	}

	pub fn poll_scan_events(&mut self) {
		if let AppState::Scanning(ref mut s) = self.state {
			s.tick_spinner();
		}

		if let AppState::Results(ref mut s) = self.state {
			if let Some(clear_at) = s.status_clear_at {
				if std::time::Instant::now() >= clear_at {
					s.status_message = None;
					s.status_clear_at = None;
				}
			}
		}

		loop {
			match self.rx.try_recv() {
				Ok(ScanEvent::Total(n)) => {
					if let AppState::Scanning(s) = &mut self.state {
						s.total = n;
					}
				}
				Ok(ScanEvent::Package(name)) => {
					if let AppState::Scanning(s) = &mut self.state {
						s.scanned += 1;
						s.current_package = name;
					}
				}
				Ok(ScanEvent::Done(risks)) => {
					self.state = AppState::Results(ResultsState::new(risks));
				}
				Ok(ScanEvent::Error(msg)) => {
					self.state = AppState::Error(msg);
				}
				Err(_) => break,
			}
		}
	}
}

#[derive(Debug)]
pub struct ScanStats {
	pub total: usize,
	pub critical: usize,
	pub high: usize,
	pub medium: usize,
	pub low: usize,
	pub safe: usize,
}
