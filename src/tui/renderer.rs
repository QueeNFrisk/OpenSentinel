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
			AppState::Results(s)  => Self::draw_results(f, app, s),
			AppState::Error(msg)  => Self::draw_error(f, msg),
		}
	}

	fn draw_scanning(f: &mut Frame, state: &super::app::ScanningState) {
		let area = f.size();
		f.render_widget(Block::default().style(Style::default().bg(Theme::BG)), area);

		let vchunks = Layout::default()
			.direction(Direction::Vertical)
			.constraints([
				Constraint::Percentage(35),
				Constraint::Length(10),
				Constraint::Min(0),
			])
			.split(area);

		let hchunks = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([
				Constraint::Percentage(20),
				Constraint::Percentage(60),
				Constraint::Percentage(20),
			])
			.split(vchunks[1]);

		let box_area = hchunks[1];

		let spinner = SPINNER[(state.spinner_tick as usize) % SPINNER.len()];

		let outer = Block::default()
			.title(" OpenSentinel — Scanning ")
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
				Constraint::Length(1), // spinner + package name
				Constraint::Length(1), // blank
				Constraint::Length(1), // gauge label
				Constraint::Length(1), // gauge
				Constraint::Length(1), // blank
				Constraint::Length(1), // hint
			])
			.split(inner);

		let pkg = if state.current_package.is_empty() {
			"Resolving dependencies…".to_string()
		} else {
			format!("Scanning  {}", state.current_package)
		};
		f.render_widget(
			Paragraph::new(Line::from(vec![
				Span::styled(format!("{spinner} "), Style::default().fg(Theme::ACCENT)),
				Span::styled(pkg, Style::default().fg(Theme::TEXT_PRIMARY)),
			])),
			rows[0],
		);

		let label = if state.total > 0 {
			format!("{} / {} packages", state.scanned, state.total)
		} else {
			String::new()
		};
		f.render_widget(
			Paragraph::new(label).style(Theme::secondary()),
			rows[2],
		);

		let gauge = Gauge::default()
			.gauge_style(Style::default().fg(Theme::ACCENT).bg(Theme::BG_SELECTED))
			.percent(state.progress_pct())
			.label("");
		f.render_widget(gauge, rows[3]);

		f.render_widget(
			Paragraph::new("  Q / Esc  Cancel").style(Theme::dim()),
			rows[5],
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

		let keybinds = if let Some(msg) = &state.status_message {
			Line::from(Span::styled(format!("  {msg}"), Theme::accent()))
		} else {
			match state.active_panel {
				super::app::ActivePanel::Right => Line::from(vec![
					Span::styled("[↑↓] Navigate vulns", Theme::dim()),
					Span::styled("  [Enter] Detail", Theme::dim()),
					Span::styled("  [C] Copy", Theme::dim()),
					Span::styled("  [E] Export", Theme::dim()),
					Span::styled("  [Tab] Switch", Theme::dim()),
					Span::styled("  [Esc] Back", Theme::dim()),
					Span::styled("  [Q] Quit", Theme::dim()),
				]),
				super::app::ActivePanel::Bottom => Line::from(vec![
					Span::styled("[↑↓] Scroll", Theme::dim()),
					Span::styled("  [C] Copy", Theme::dim()),
					Span::styled("  [E] Export", Theme::dim()),
					Span::styled("  [Tab] Switch", Theme::dim()),
					Span::styled("  [Esc] Back", Theme::dim()),
					Span::styled("  [Q] Quit", Theme::dim()),
				]),
				super::app::ActivePanel::Left => Line::from(vec![
					Span::styled("[↑↓] Navigate", Theme::dim()),
					Span::styled("  [Enter] View vulns", Theme::dim()),
					Span::styled("  [I] Ignore", Theme::dim()),
					Span::styled("  [/] Search", Theme::dim()),
					Span::styled("  [D] Direct only", Theme::dim()),
					Span::styled("  [G] Group", Theme::dim()),
					Span::styled("  [E] Export", Theme::dim()),
					Span::styled("  [Q] Quit", Theme::dim()),
				]),
			}
		};

		let stat_line = Line::from(vec![
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
		]);

		f.render_widget(Paragraph::new(keybinds).style(Theme::base()), layout[0]);
		f.render_widget(Paragraph::new(stat_line).style(Theme::base()), layout[1]);
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
