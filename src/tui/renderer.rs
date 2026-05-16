use anyhow::Result;
use crossterm::{
	execute,
	terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
	backend::CrosstermBackend,
	layout::{Alignment, Constraint, Direction, Layout, Margin, Rect},
	style::{Modifier, Style},
	text::{Line, Span},
	widgets::{Block, BorderType, Borders, Gauge, Paragraph},
	Frame, Terminal,
};
use std::io::{self, Stdout};

use super::app::{AppState, TuiApp};
use super::events::EventHandler;
use super::panels::{LeftPanel, VulnDetailPanel, VulnListPanel};
use super::theme::Theme;

const SPINNER: &[&str] = &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];

pub struct Renderer {
	terminal: Terminal<CrosstermBackend<Stdout>>,
}

impl Renderer {
	pub fn new() -> Result<Self> {
		enable_raw_mode()?;
		let mut stdout = io::stdout();
		execute!(stdout, EnterAlternateScreen)?;
		let backend = CrosstermBackend::new(stdout);
		let terminal = Terminal::new(backend)?;
		Ok(Self { terminal })
	}

	pub fn run(&mut self, app: &mut TuiApp) -> Result<()> {
		loop {
			app.poll_scan_events();
			self.terminal.draw(|f| Self::draw(f, app))?;
			EventHandler::handle(app)?;
			if app.should_quit {
				break;
			}
		}
		Ok(())
	}

	fn draw(f: &mut Frame, app: &TuiApp) {
		match &app.state {
			AppState::Scanning(s) => Self::draw_scanning(f, s),
			AppState::Results(s)  => {
				Self::draw_results(f, app, s);
				if s.show_help { Self::draw_help_overlay(f); }
			}
			AppState::Error(msg)  => Self::draw_error(f, msg),
		}
	}

	fn draw_scanning(f: &mut Frame, state: &super::app::ScanningState) {
		use super::app::DbStatus;

		let area = f.size();
		f.render_widget(Block::default().style(Style::default().bg(Theme::BG)), area);

		let log_lines = state.log.len() as u16;
		let box_height = 8 + 1 + log_lines.max(1) + 2; // header + progress + log + padding

		let vchunks = Layout::default()
			.direction(Direction::Vertical)
			.constraints([
				Constraint::Percentage(20),
				Constraint::Length(box_height),
				Constraint::Min(0),
			])
			.split(area);

		let hchunks = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([
				Constraint::Percentage(10),
				Constraint::Percentage(80),
				Constraint::Percentage(10),
			])
			.split(vchunks[1]);

		let box_area = hchunks[1];
		let spinner = SPINNER[(state.spinner_tick as usize) % SPINNER.len()];

		let outer = Block::default()
			.title(" OpenSentinel ")
			.title_alignment(Alignment::Center)
			.borders(Borders::ALL)
			.border_type(BorderType::Rounded)
			.border_style(Theme::border_active())
			.style(Style::default().bg(Theme::BG_PANEL));

		let inner = outer.inner(box_area);
		f.render_widget(outer, box_area);

		let rows = Layout::default()
			.direction(Direction::Vertical)
			.margin(1)
			.constraints([
				Constraint::Length(1), // spinner + current package
				Constraint::Length(1), // blank
				Constraint::Length(1), // gauge label (N/M packages)
				Constraint::Length(1), // gauge bar
				Constraint::Length(1), // blank
				Constraint::Length(1), // db status
				Constraint::Length(1), // separator
				Constraint::Min(0),    // log lines
				Constraint::Length(1), // cancel hint
			])
			.split(inner);

		// ── Spinner + current package ──────────────────────────────────
		let pkg = if state.current_package.is_empty() {
			"Resolving dependency tree…".to_string()
		} else {
			format!("Scanning  {}", state.current_package)
		};
		f.render_widget(
			Paragraph::new(Line::from(vec![
				Span::styled(format!("{spinner} "), Theme::accent()),
				Span::styled(pkg, Theme::base()),
			])),
			rows[0],
		);

		// ── Progress label ─────────────────────────────────────────────
		let label = if state.total > 0 {
			format!("{} / {} packages", state.scanned, state.total)
		} else {
			"Waiting…".to_string()
		};
		f.render_widget(Paragraph::new(label).style(Theme::secondary()), rows[2]);

		// ── Gauge ──────────────────────────────────────────────────────
		let gauge = Gauge::default()
			.gauge_style(Style::default().fg(Theme::ACCENT).bg(Theme::BG_SELECTED))
			.percent(state.progress_pct())
			.label("");
		f.render_widget(gauge, rows[3]);

		// ── Database status ────────────────────────────────────────────
		let db_line = match &state.db_status {
			DbStatus::Pending => Line::from(vec![
				Span::styled("  ○ ", Theme::dim()),
				Span::styled("Database", Theme::dim()),
				Span::styled("  pending", Theme::dim()),
			]),
			DbStatus::Connecting => Line::from(vec![
				Span::styled(format!("  {spinner} "), Theme::accent()),
				Span::styled("Database", Theme::secondary()),
				Span::styled("  connecting…", Theme::dim()),
			]),
			DbStatus::Connected(addr) => Line::from(vec![
				Span::styled("  ✓ ", Style::default().fg(Theme::SEVERITY_SAFE)),
				Span::styled("Database", Theme::secondary()),
				Span::styled(format!("  {addr}"), Theme::dim()),
			]),
			DbStatus::Failed(reason) => Line::from(vec![
				Span::styled("  ✗ ", Theme::dim()),
				Span::styled("Database", Theme::dim()),
				Span::styled(format!("  offline  ·  {reason}"), Theme::dim()),
			]),
		};
		f.render_widget(Paragraph::new(db_line), rows[5]);

		// ── Separator ──────────────────────────────────────────────────
		f.render_widget(
			Paragraph::new(Span::styled(
				"─".repeat(box_area.width.saturating_sub(4) as usize),
				Theme::dim(),
			)),
			rows[6],
		);

		// ── Log lines ──────────────────────────────────────────────────
		let log_text: Vec<Line> = state.log
			.iter()
			.map(|msg| Line::from(vec![
				Span::styled("  → ", Theme::dim()),
				Span::styled(msg.clone(), Theme::secondary()),
			]))
			.collect();
		f.render_widget(
			Paragraph::new(log_text).style(Theme::base()),
			rows[7],
		);

		// ── Cancel hint ────────────────────────────────────────────────
		f.render_widget(
			Paragraph::new(Span::styled("  Q / Esc  Cancel", Theme::dim())),
			rows[8],
		);
	}

	fn draw_results(f: &mut Frame, app: &TuiApp, state: &super::app::ResultsState) {
		let area = f.size();

		let vertical = Layout::default()
			.direction(Direction::Vertical)
			.constraints([
				Constraint::Length(1),
				Constraint::Min(0),
				Constraint::Length(2),
			])
			.split(area);

		Self::render_header(f, vertical[0]);
		Self::render_body(f, app, state, vertical[1]);
		Self::render_footer(f, state, vertical[2]);
	}

	fn render_header(f: &mut Frame, area: Rect) {
		let title = Line::from(vec![
			Span::styled(" OpenSentinel ", Theme::header()),
			Span::styled("v0.1.0", Theme::dim()),
			Span::styled("  |  ", Theme::dim()),
			Span::styled("Supply Chain Security Scanner", Theme::secondary()),
		]);
		f.render_widget(Paragraph::new(title).style(Theme::base()), area);
	}

	fn render_body(f: &mut Frame, app: &TuiApp, state: &super::app::ResultsState, area: Rect) {
		let horizontal = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
			.split(area);

		LeftPanel::render(f, app, state, horizontal[0]);

		let right_chunks = Layout::default()
			.direction(Direction::Vertical)
			.constraints([Constraint::Percentage(30), Constraint::Percentage(70)])
			.split(horizontal[1]);

		VulnListPanel::render(f, app, state, right_chunks[0]);
		VulnDetailPanel::render(f, app, state, right_chunks[1]);
	}

	fn render_footer(f: &mut Frame, state: &super::app::ResultsState, area: Rect) {
		let stats = state.stats();

		let layout = Layout::default()
			.direction(Direction::Vertical)
			.constraints([Constraint::Length(1), Constraint::Length(1)])
			.split(area);

		let sep = Span::styled("  ", Theme::dim());
		let k = |s: &'static str| Span::styled(s, Theme::dim());

		let keybinds = if let Some(msg) = &state.status_message {
			Line::from(Span::styled(format!("  {msg}"), Theme::accent()))
		} else {
			match state.active_panel {
				super::app::ActivePanel::Right => Line::from(vec![
					k("[↑↓] Nav"), sep.clone(), k("[↵] Detail"), sep.clone(),
					k("[C] Copy"), sep.clone(), k("[E] Export"), sep.clone(),
					k("[Tab]"), sep.clone(), k("[Esc] Back"), sep.clone(), k("[Q] Quit"),
				]),
				super::app::ActivePanel::Bottom => Line::from(vec![
					k("[↑↓] Scroll"), sep.clone(), k("[C] Copy"), sep.clone(),
					k("[E] Export"), sep.clone(), k("[Tab]"), sep.clone(),
					k("[Esc] Back"), sep.clone(), k("[Q] Quit"),
				]),
				super::app::ActivePanel::Left => Line::from(vec![
					k("[↑↓] Nav"), sep.clone(), k("[↵] Open"), sep.clone(),
					k("[I] Ignore"), sep.clone(), k("[/] Search"), sep.clone(),
					k("[D] Direct"), sep.clone(), k("[G] Group"), sep.clone(),
					k("[E] Export"), sep.clone(), k("[Q] Quit"),
				]),
			}
		};

		let mut stat_spans = vec![
			Span::styled(format!("Packages: {}", stats.total), Theme::secondary()),
			Span::styled("  |  ", Theme::dim()),
			Span::styled(format!("Critical: {}", stats.critical), Theme::severity_style("CRITICAL")),
			Span::styled("  ", Theme::dim()),
			Span::styled(format!("High: {}", stats.high), Theme::severity_style("HIGH")),
			Span::styled("  ", Theme::dim()),
			Span::styled(format!("Medium: {}", stats.medium), Theme::severity_style("MEDIUM")),
			Span::styled("  ", Theme::dim()),
			Span::styled(format!("Low: {}", stats.low), Theme::severity_style("LOW")),
			Span::styled("  ", Theme::dim()),
			Span::styled(format!("Safe: {}", stats.safe), Theme::severity_style("SAFE")),
		];
		if stats.ignored > 0 {
			stat_spans.push(Span::styled("  ", Theme::dim()));
			stat_spans.push(Span::styled(format!("Ignored: {}", stats.ignored), Theme::dim()));
		}
		let stat_line = Line::from(stat_spans);

		f.render_widget(Paragraph::new(keybinds).style(Theme::base()), layout[0]);
		f.render_widget(Paragraph::new(stat_line).style(Theme::base()), layout[1]);
	}

	fn draw_help_overlay(f: &mut Frame) {
		use ratatui::{layout::Flex, widgets::Clear};

		let rows = [
			("Navigation", ""),
			("↑ / ↓  or  k / j", "Move up / down in active panel"),
			("Tab",              "Cycle panels: List → Vulns → Detail"),
			("Enter",           "Drill into next panel"),
			("Esc",             "Go back one panel"),
			("",                ""),
			("Actions", ""),
			("I",               "Ignore / restore package (saved to config)"),
			("/",               "Search packages by name"),
			("D",               "Toggle direct dependencies only"),
			("G",               "Group by severity"),
			("E",               "Export filtered results to JSON"),
			("C",               "Copy selected vulnerability ID to clipboard"),
			("",                ""),
			("App", ""),
			("Q",               "Quit"),
			("?",               "Toggle this help"),
		];

		let width  = 56u16;
		let height = rows.len() as u16 + 4;
		let area   = f.size();
		let popup  = ratatui::layout::Layout::horizontal([Constraint::Length(width)])
			.flex(Flex::Center)
			.areas::<1>(
				ratatui::layout::Layout::vertical([Constraint::Length(height)])
					.flex(Flex::Center)
					.areas::<1>(area)[0],
			)[0];

		f.render_widget(Clear, popup);
		f.render_widget(
			Block::default()
				.title(" Help  (any key to close) ")
				.borders(Borders::ALL)
				.border_type(BorderType::Rounded)
				.border_style(Theme::border_active())
				.style(Theme::panel()),
			popup,
		);

		let inner = popup.inner(Margin { horizontal: 2, vertical: 1 });
		let mut lines: Vec<Line> = Vec::new();
		for (key, desc) in &rows {
			if key.is_empty() {
				lines.push(Line::from(""));
			} else if desc.is_empty() {
				lines.push(Line::from(Span::styled(
					key.to_string(),
					Style::default().fg(Theme::SEVERITY_HIGH).add_modifier(Modifier::BOLD),
				)));
			} else {
				lines.push(Line::from(vec![
					Span::styled(format!("{:<22}", key), Style::default().fg(Theme::TEXT_DIM)),
					Span::raw(desc.to_string()),
				]));
			}
		}
		f.render_widget(Paragraph::new(lines), inner);
	}

	fn draw_error(f: &mut Frame, msg: &str) {
		let area = f.size();
		f.render_widget(Block::default().style(Style::default().bg(Theme::BG)), area);
		f.render_widget(
			Paragraph::new(format!("Error: {msg}\n\nPress any key to exit."))
				.style(Style::default().fg(Theme::SEVERITY_CRITICAL))
				.alignment(Alignment::Center),
			area,
		);
	}
}

impl Drop for Renderer {
	fn drop(&mut self) {
		let _ = disable_raw_mode();
		let _ = execute!(self.terminal.backend_mut(), LeaveAlternateScreen);
	}
}
