use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use anyhow::Result;

use crate::config::KeybindingsMode;
use super::app::{ActivePanel, AppState, ResultsState, TuiApp};

pub struct EventHandler;

impl EventHandler {
	pub fn handle(app: &mut TuiApp) -> Result<()> {
		if event::poll(std::time::Duration::from_millis(16))? {
			if let Event::Key(key) = event::read()? {
				match &app.state {
					AppState::Scanning(_) => Self::handle_scanning(app, key),
					AppState::Results(_)  => Self::handle_results(app, key),
					AppState::Error(_)    => { app.should_quit = true; }
				}
			}
		}
		Ok(())
	}

	fn handle_scanning(app: &mut TuiApp, key: KeyEvent) {
		match key.code {
			KeyCode::Char('q') | KeyCode::Char('Q') | KeyCode::Esc => app.should_quit = true,
			KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => app.should_quit = true,
			_ => {}
		}
	}

	fn handle_results(app: &mut TuiApp, key: KeyEvent) {
		let AppState::Results(ref mut state) = app.state else { return };

		if state.show_help {
			state.show_help = false;
			return;
		}

		if state.search_mode {
			match key.code {
				KeyCode::Esc | KeyCode::Enter => state.exit_search(),
				KeyCode::Backspace => state.pop_search_char(),
				KeyCode::Char(c)   => state.push_search_char(c),
				_ => {}
			}
			return;
		}

		if key.code == KeyCode::Char('?') {
			state.show_help = true;
			return;
		}

		match &app.keybindings {
			KeybindingsMode::Arrows => Self::arrows(app, key),
			KeybindingsMode::Vim    => Self::vim(app, key),
		}
	}

	fn arrows(app: &mut TuiApp, key: KeyEvent) {
		let AppState::Results(ref mut state) = app.state else { return };
		match key.code {
			KeyCode::Up    => state.move_up(),
			KeyCode::Down  => state.move_down(),
			KeyCode::Tab   => state.toggle_panel(),
			KeyCode::Enter => {
				match state.active_panel {
					ActivePanel::Left => {
						state.active_panel = ActivePanel::Right;
						state.selected_vuln = 0;
						state.detail_scroll = 0;
					}
					ActivePanel::Right => {
						state.active_panel = ActivePanel::Bottom;
						state.detail_scroll = 0;
					}
					ActivePanel::Bottom => {}
				}
			}
			KeyCode::Char('/') => state.enter_search(),
			KeyCode::Char('e') | KeyCode::Char('E') => Self::export(state),
			KeyCode::Char('c') | KeyCode::Char('C') if key.modifiers != KeyModifiers::CONTROL => {
				Self::copy(state);
			}
			KeyCode::Char('d') | KeyCode::Char('D') => {
				state.show_direct_only = !state.show_direct_only;
				state.selected_index = 0;
			}
			KeyCode::Char('g') | KeyCode::Char('G') => {
				state.group_by_severity = !state.group_by_severity;
				state.selected_index = 0;
			}
			KeyCode::Char('i') | KeyCode::Char('I') => {
				state.toggle_ignored();
				if let Some(ref path) = app.project_path {
					let list: Vec<String> = state.ignored.iter().cloned().collect();
					let _ = crate::config::ConfigLoader::save_ignored(path, &list);
				}
			}
			KeyCode::Char('q') | KeyCode::Char('Q') => app.should_quit = true,
			KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => app.should_quit = true,
			KeyCode::Esc => {
				let AppState::Results(ref mut s) = app.state else { return };
				match s.active_panel {
					ActivePanel::Bottom => {
						s.active_panel = ActivePanel::Right;
						s.detail_scroll = 0;
					}
					ActivePanel::Right => {
						s.active_panel = ActivePanel::Left;
					}
					ActivePanel::Left => {}
				}
			}
			_ => {}
		}
	}

	fn vim(app: &mut TuiApp, key: KeyEvent) {
		let AppState::Results(ref mut state) = app.state else { return };
		match key.code {
			KeyCode::Char('k') => state.move_up(),
			KeyCode::Char('j') => state.move_down(),
			KeyCode::Char('l') | KeyCode::Enter => {
				match state.active_panel {
					ActivePanel::Left => {
						state.active_panel = ActivePanel::Right;
						state.selected_vuln = 0;
						state.detail_scroll = 0;
					}
					ActivePanel::Right => {
						state.active_panel = ActivePanel::Bottom;
						state.detail_scroll = 0;
					}
					ActivePanel::Bottom => {}
				}
			}
			KeyCode::Char('h') | KeyCode::Esc => {
				match state.active_panel {
					ActivePanel::Bottom => {
						state.active_panel = ActivePanel::Right;
						state.detail_scroll = 0;
					}
					ActivePanel::Right => {
						state.active_panel = ActivePanel::Left;
					}
					ActivePanel::Left => {}
				}
			}
			KeyCode::Char('/') => state.enter_search(),
			KeyCode::Char('e') => Self::export(state),
			KeyCode::Char('c') => Self::copy(state),
			KeyCode::Char('q') => app.should_quit = true,
			KeyCode::Char('d') => {
				state.show_direct_only = !state.show_direct_only;
				state.selected_index = 0;
			}
			KeyCode::Char('g') => {
				state.group_by_severity = !state.group_by_severity;
				state.selected_index = 0;
			}
			KeyCode::Char('i') => {
				state.toggle_ignored();
				if let Some(ref path) = app.project_path {
					let list: Vec<String> = state.ignored.iter().cloned().collect();
					let _ = crate::config::ConfigLoader::save_ignored(path, &list);
				}
			}
			_ => {}
		}
	}

	// ── E: Export filtered results to JSON ────────────────────────────────────

	fn export(state: &mut ResultsState) {
		let risks: Vec<_> = state.filtered_risks().into_iter().cloned().collect();
		let count = risks.len();

		let json = match serde_json::to_string_pretty(&risks) {
			Ok(j) => j,
			Err(e) => {
				state.set_status(format!("Export failed: {e}"));
				return;
			}
		};

		let filename = {
			use std::time::{SystemTime, UNIX_EPOCH};
			let ts = SystemTime::now()
				.duration_since(UNIX_EPOCH)
				.map(|d| d.as_secs())
				.unwrap_or(0);
			format!("opensentinel-{ts}.json")
		};

		match std::fs::write(&filename, json) {
			Ok(_) => state.set_status(format!("Exported {count} packages → {filename}")),
			Err(e) => state.set_status(format!("Export failed: {e}")),
		}
	}

	// ── C: Copy selected vulnerability to clipboard ───────────────────────────

	fn copy(state: &mut ResultsState) {
		let text = Self::clipboard_text(state);
		if text.is_empty() {
			state.set_status("Nothing selected to copy".to_string());
			return;
		}

		match Self::write_clipboard(&text) {
			Ok(_)  => state.set_status(format!("Copied: {text}")),
			Err(e) => state.set_status(format!("Clipboard error: {e}")),
		}
	}

	fn clipboard_text(state: &ResultsState) -> String {
		let Some(risk) = state.selected_risk() else { return String::new() };
		let n_adv = risk.advisories.len();
		let total = n_adv + risk.detections.len();
		if total == 0 { return String::new(); }

		let sel = state.selected_vuln.min(total.saturating_sub(1));

		if sel < n_adv {
			let adv = &risk.advisories[sel];
			let fix = adv.patched_versions.as_deref().unwrap_or("unknown");
			format!(
				"{} ({}) — {}@{} — fix: {}",
				adv.external_id,
				adv.severity_text(),
				risk.package_name,
				risk.package_version,
				fix,
			)
		} else {
			let det = &risk.detections[sel - n_adv];
			let loc = match (&det.file_path, det.line_number) {
				(Some(p), Some(l)) => format!(" @ {p}:{l}"),
				(Some(p), None)    => format!(" @ {p}"),
				_                  => String::new(),
			};
			format!(
				"{}{} — {}@{}",
				det.description, loc,
				risk.package_name, risk.package_version,
			)
		}
	}

	fn write_clipboard(text: &str) -> Result<()> {
		use std::io::Write;
		use std::process::{Command, Stdio};

		let cmd = if cfg!(target_os = "macos") {
			"pbcopy"
		} else {
			"xclip"
		};

		let args: &[&str] = if cfg!(target_os = "macos") {
			&[]
		} else {
			&["-selection", "clipboard"]
		};

		let mut child = Command::new(cmd)
			.args(args)
			.stdin(Stdio::piped())
			.spawn()
			.map_err(|e| anyhow::anyhow!("{cmd} not available: {e}"))?;

		if let Some(stdin) = child.stdin.as_mut() {
			stdin.write_all(text.as_bytes())?;
		}
		child.wait()?;
		Ok(())
	}
}

// ── Local helpers ─────────────────────────────────────────────────────────────

trait AdvisoryText {
	fn severity_text(&self) -> &str;
}

impl AdvisoryText for crate::advisory::models::AdvisoryData {
	fn severity_text(&self) -> &str {
		match self.severity {
			crate::database::models::SeverityLevel::Critical => "CRITICAL",
			crate::database::models::SeverityLevel::High     => "HIGH",
			crate::database::models::SeverityLevel::Medium   => "MEDIUM",
			crate::database::models::SeverityLevel::Low      => "LOW",
			crate::database::models::SeverityLevel::Safe     => "SAFE",
		}
	}
}
