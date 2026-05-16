use anyhow::Result;
use crossterm::{
	event::{self, Event, KeyCode, KeyModifiers},
	execute,
	terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
	backend::CrosstermBackend,
	layout::{Alignment, Constraint, Direction, Layout, Margin},
	style::{Color, Modifier, Style},
	text::{Line, Span},
	widgets::{Block, BorderType, Borders, Paragraph, Wrap},
	Terminal,
};
use std::io;

use super::theme::Theme;

#[derive(Clone)]
struct Opt {
	label: &'static str,
	value: &'static str,
}

impl Opt {
	fn v(label: &'static str, value: &'static str) -> Self { Self { label, value } }
	fn same(v: &'static str) -> Self { Self { label: v, value: v } }
}

#[derive(Clone)]
struct Field {
	label: &'static str,
	hint:  &'static str,
	opts:  Vec<Opt>,
	selected: usize,
	custom:   String,
	secret:   bool,
}

impl Field {
	fn new(label: &'static str, hint: &'static str, opts: Vec<Opt>) -> Self {
		Self { label, hint, opts, selected: 0, custom: String::new(), secret: false }
	}

	fn secret(label: &'static str, hint: &'static str) -> Self {
		Self { label, hint, opts: vec![], selected: 0, custom: String::new(), secret: true }
	}

	fn is_custom_active(&self) -> bool { self.selected == self.opts.len() }

	fn value(&self) -> String {
		if self.is_custom_active() {
			self.custom.clone()
		} else {
			self.opts[self.selected].value.to_string()
		}
	}

	fn display_value(&self) -> String {
		let v = self.value();
		if self.secret && !v.is_empty() && !v.starts_with('$') {
			"*".repeat(v.len().min(16))
		} else {
			v
		}
	}

	fn total_options(&self) -> usize { self.opts.len() + 1 }
}

enum Row {
	Header(&'static str),
	Done(usize),
	ActiveLabel(usize),
	Opt(usize, usize),
	Custom(usize),
	Pending(usize),
}

// ── Field index layout ────────────────────────────────────────────────────────
//  0   DB Engine
//  --- PostgreSQL / MySQL -------------------------------------------------------
//  1   Connection URL  (skip if SQLite)
//  2   Host            (skip if SQLite, or if URL is set)
//  3   Port            (skip if SQLite, or if URL is set)
//  4   Database name   (skip if SQLite, or if URL is set)
//  5   User            (skip if SQLite, or if URL is set)
//  6   Password        (skip if SQLite, or if URL is set)
//  7   SSL             (skip if not PostgreSQL, or if URL is set)
//  8   Pool size       (skip if SQLite)
//  --- SQLite -------------------------------------------------------------------
//  9   SQLite file path (skip if not SQLite)
//  --- Source Analysis ----------------------------------------------------------
// 10   Enable source scan
// 11   Download source
// 12   AST analysis
// 13   Cache TTL
// 14   Max source size
//  --- Parallelism --------------------------------------------------------------
// 15   Package concurrency
// 16   API concurrency
// 17   OSV limit
// 18   OSV delay
// 19   GitHub limit
// 20   GitHub delay
// 21   NVD limit
// 22   NVD delay
//  --- Credentials -------------------------------------------------------------
// 23   GitHub Token
// 24   NVD API Key
// 25   Credential storage
// 26   Keyring support
//  --- Output & Behavior -------------------------------------------------------
// 27   Ecosystems
// 28   Severity filter
// 29   Exclude dev deps
// 30   Keybindings
// 31   Output format

const SECTIONS: &[(&str, &[usize])] = &[
	("Database",          &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9]),
	("Source Analysis",   &[10, 11, 12, 13, 14]),
	("Parallelism",       &[15, 16, 17, 18, 19, 20, 21, 22]),
	("Credentials",       &[23, 24, 25, 26]),
	("Output & Behavior", &[27, 28, 29, 30, 31]),
];

pub struct InitWizard {
	fields:     Vec<Field>,
	field_cur:  usize,
	opt_cur:    usize,
	scroll_row: usize,
	confirmed:  bool,
	cancelled:  bool,
}

impl InitWizard {
	pub fn new() -> Self {
		let fields = vec![
			// 0 ── DB Engine
			Field::new("DB Engine", "Database backend to connect to",
				vec![
					Opt::v("PostgreSQL", "postgresql"),
					Opt::v("SQLite",     "sqlite"),
					Opt::v("MySQL",      "mysql"),
				]),
			// 1 ── Connection URL (PostgreSQL / MySQL)
			Field::new("Connection URL",
				"Full connection string for this database.\n\
				 Cloud providers (Neon, Vercel, Railway, PlanetScale):\n\
				 paste the URL they give you here.\n\
				 Supports ${ENV_VAR} syntax — recommended:\n\
				 ${DATABASE_URL}\n\
				 Leave on '(none)' to configure fields individually below.",
				vec![Opt::v("(none) — configure fields below", "")]),
			// 2 ── Host
			Field::new("Host", "Hostname or IP of your database server",
				vec![
					Opt::same("localhost"),
					Opt::same("127.0.0.1"),
					Opt::v("Cloud / Remote", "db.example.com"),
				]),
			// 3 ── Port
			Field::new("Port", "Database port",
				vec![
					Opt::v("5432  (PostgreSQL default)", "5432"),
					Opt::v("3306  (MySQL default)",      "3306"),
					Opt::v("5433  (alt)",                "5433"),
				]),
			// 4 ── Database name
			Field::new("Database name", "Name of the database to use",
				vec![
					Opt::same("opensentinel"),
					Opt::same("opensentinel_dev"),
					Opt::same("security"),
				]),
			// 5 ── User
			Field::new("User", "Database user",
				vec![
					Opt::same("postgres"),
					Opt::same("root"),
					Opt::same("opensentinel"),
					Opt::same("admin"),
				]),
			// 6 ── Password
			Field::secret("Password",
				"Database password.\n\
				 Leave as ${DB_PASSWORD} to read from the environment variable.\n\
				 This field is skipped when a Connection URL is set above."),
			// 7 ── SSL
			Field::new("SSL", "Require SSL for database connection",
				vec![
					Opt::v("No  — local / internal network", "false"),
					Opt::v("Yes — production / cloud",       "true"),
				]),
			// 8 ── Pool size
			Field::new("Pool size", "Max simultaneous database connections",
				vec![Opt::same("5"), Opt::same("10"), Opt::same("20"), Opt::same("50")]),
			// 9 ── SQLite file path
			Field::new("SQLite file path",
				"Path to the SQLite database file.\n\
				 The file will be created if it does not exist.\n\
				 Use a relative path (./opensentinel.db) or absolute.",
				vec![
					Opt::v("opensentinel.db  (current directory)",  "opensentinel.db"),
					Opt::v("~/.opensentinel/data.db  (user home)",  "~/.opensentinel/data.db"),
				]),
			// 10 ── Enable source scan
			Field::new("Enable source scan", "Scan actual source code of packages",
				vec![Opt::v("Yes", "true"), Opt::v("No", "false")]),
			// 11 ── Download source
			Field::new("Download source",
				"Fetch package tarballs to scan for malicious code.\nRequired to see Code Snippets in the TUI.",
				vec![
					Opt::v("Yes — full analysis (slower)",    "true"),
					Opt::v("No — advisories only (faster)", "false"),
				]),
			// 12 ── AST analysis
			Field::new("AST analysis", "Deep Tree-sitter analysis of JS/TS code",
				vec![
					Opt::v("Yes — detect obfuscation and hidden patterns", "true"),
					Opt::v("No — regex patterns only",                     "false"),
				]),
			// 13 ── Cache TTL
			Field::new("Cache TTL", "How long to keep cached source tarballs",
				vec![
					Opt::v("1 day   (86400)",    "86400"),
					Opt::v("7 days  (604800)",   "604800"),
					Opt::v("30 days (2592000)", "2592000"),
				]),
			// 14 ── Max source size
			Field::new("Max source size", "Maximum tarball size to download (MB)",
				vec![Opt::same("50"), Opt::same("100"), Opt::same("250"), Opt::same("500")]),
			// 15 ── Package concurrency
			Field::new("Package concurrency", "Packages analyzed in parallel",
				vec![Opt::same("2"), Opt::same("4"), Opt::same("8"), Opt::same("16")]),
			// 16 ── API concurrency
			Field::new("API concurrency", "Simultaneous advisory API requests",
				vec![Opt::same("2"), Opt::same("3"), Opt::same("5")]),
			// 17 ── OSV limit
			Field::new("OSV limit", "Max requests per OSV batch",
				vec![Opt::same("5"), Opt::same("10"), Opt::same("20")]),
			// 18 ── OSV delay
			Field::new("OSV delay (ms)", "Pause between OSV batches",
				vec![Opt::same("50"), Opt::same("100"), Opt::same("250")]),
			// 19 ── GitHub limit
			Field::new("GitHub limit", "Max requests per GitHub Advisory batch",
				vec![Opt::same("3"), Opt::same("5"), Opt::same("10")]),
			// 20 ── GitHub delay
			Field::new("GitHub delay (ms)", "Pause between GitHub batches",
				vec![Opt::same("100"), Opt::same("200"), Opt::same("500")]),
			// 21 ── NVD limit
			Field::new("NVD limit", "Max requests per NVD batch",
				vec![Opt::same("3"), Opt::same("5"), Opt::same("10")]),
			// 22 ── NVD delay
			Field::new("NVD delay (ms)", "Pause between NVD batches",
				vec![Opt::same("100"), Opt::same("200"), Opt::same("500")]),
			// 23 ── GitHub Token
			Field::secret("GitHub Token",
				"Personal access token for GitHub Advisory API.\nUse ${GITHUB_TOKEN} to read from environment."),
			// 24 ── NVD API Key
			Field::secret("NVD API Key",
				"API key for NVD CVE database (optional but recommended).\nUse ${NVD_API_KEY} to read from environment."),
			// 25 ── Credential storage
			Field::new("Credential storage", "Where to read credential values from",
				vec![
					Opt::v("env      — environment variables (recommended)", "env"),
					Opt::v("file     — plain config file",                   "file"),
					Opt::v("keyring  — OS keyring",                          "keyring"),
				]),
			// 26 ── Keyring support
			Field::new("Keyring support", "Use OS keyring for secure credential storage",
				vec![Opt::v("No", "false"), Opt::v("Yes", "true")]),
			// 27 ── Ecosystems
			Field::new("Ecosystems", "Which package managers to scan",
				vec![
					Opt::v("Node.js + Bun", "nodejs,bun"),
					Opt::v("Node.js only",  "nodejs"),
					Opt::v("Bun only",      "bun"),
				]),
			// 28 ── Severity filter
			Field::new("Severity filter", "Only report packages at or above this level",
				vec![
					Opt::v("high + critical only",        "high,critical"),
					Opt::v("medium, high, critical",      "medium,high,critical"),
					Opt::v("all severities",              "low,medium,high,critical"),
					Opt::v("critical only",               "critical"),
				]),
			// 29 ── Exclude dev deps
			Field::new("Exclude dev deps", "Skip devDependencies during scan",
				vec![
					Opt::v("No  — scan everything",           "false"),
					Opt::v("Yes — production deps only",      "true"),
				]),
			// 30 ── Keybindings
			Field::new("Keybindings", "TUI navigation style",
				vec![Opt::v("Arrow keys", "arrows"), Opt::v("Vim  (hjkl)", "vim")]),
			// 31 ── Output format
			Field::new("Output format", "Default format for non-interactive (opse analyze)",
				vec![
					Opt::v("SBOM  — CycloneDX", "sbom"),
					Opt::v("JSON",               "json"),
					Opt::v("Table",              "table"),
					Opt::v("HTML",               "html"),
				]),
		];

		let mut w = Self {
			fields,
			field_cur: 0,
			opt_cur: 0,
			scroll_row: 0,
			confirmed: false,
			cancelled: false,
		};
		w.fields[6].custom   = "${DB_PASSWORD}".to_string();
		w.fields[6].selected = 0; // custom active
		w.fields[23].custom  = "${GITHUB_TOKEN}".to_string();
		w.fields[23].selected = 0;
		w.fields[24].custom  = "${NVD_API_KEY}".to_string();
		w.fields[24].selected = 0;
		w
	}

	// Returns true if this field should be hidden based on previous answers.
	fn should_skip(&self, fi: usize) -> bool {
		let engine    = self.fields[0].value();
		let is_sqlite = engine == "sqlite";
		let url_set   = !self.fields[1].value().is_empty();

		match fi {
			// URL field: only for PostgreSQL / MySQL
			1 => is_sqlite,
			// Individual connection fields: skip for SQLite, or if URL is provided
			2..=6 => is_sqlite || url_set,
			// SSL: only relevant for PostgreSQL without a URL
			7 => engine != "postgresql" || url_set,
			// Pool size: skip for SQLite
			8 => is_sqlite,
			// SQLite file path: only for SQLite
			9 => !is_sqlite,
			_ => false,
		}
	}

	fn next_visible_field(&self, from: usize) -> Option<usize> {
		let mut next = from + 1;
		while next < self.fields.len() {
			if !self.should_skip(next) { return Some(next); }
			next += 1;
		}
		None
	}

	fn build_rows(&self) -> Vec<Row> {
		let mut rows = Vec::new();
		for &(section, indices) in SECTIONS {
			let visible_in_section: Vec<usize> = indices.iter()
				.copied()
				.filter(|&fi| !self.should_skip(fi))
				.collect();
			if visible_in_section.is_empty() { continue; }

			rows.push(Row::Header(section));
			for &fi in &visible_in_section {
				if fi < self.field_cur {
					rows.push(Row::Done(fi));
				} else if fi == self.field_cur {
					rows.push(Row::ActiveLabel(fi));
					let n = self.fields[fi].opts.len();
					for oi in 0..n { rows.push(Row::Opt(fi, oi)); }
					rows.push(Row::Custom(fi));
				} else {
					rows.push(Row::Pending(fi));
				}
			}
		}
		rows
	}

	fn active_opt_row_index(&self) -> usize {
		let rows = self.build_rows();
		let target_opt = self.opt_cur;
		let n_opts = self.fields[self.field_cur].opts.len();
		rows.iter().enumerate().find(|(_, r)| match r {
			Row::Opt(fi, oi)     => *fi == self.field_cur && *oi == target_opt && target_opt < n_opts,
			Row::Custom(fi)      => *fi == self.field_cur && target_opt == n_opts,
			Row::ActiveLabel(fi) => *fi == self.field_cur && target_opt == 0 && n_opts == 0,
			_ => false,
		}).map(|(i, _)| i).unwrap_or(0)
	}

	fn ensure_visible(&mut self, viewport: usize) {
		if viewport == 0 { return; }
		let row = self.active_opt_row_index();
		if row < self.scroll_row { self.scroll_row = row; }
		else if row >= self.scroll_row + viewport { self.scroll_row = row + 1 - viewport; }
	}

	pub fn run(mut self) -> Result<Option<serde_json::Value>> {
		enable_raw_mode()?;
		let mut stdout = io::stdout();
		execute!(stdout, EnterAlternateScreen)?;
		let backend = CrosstermBackend::new(stdout);
		let mut terminal = Terminal::new(backend)?;

		let result = self.event_loop(&mut terminal);

		disable_raw_mode()?;
		execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
		terminal.show_cursor()?;
		result?;

		if self.cancelled { return Ok(None); }
		Ok(Some(self.build_config()))
	}

	fn confirm_current_and_advance(&mut self) {
		match self.next_visible_field(self.field_cur) {
			Some(next) => {
				self.field_cur = next;
				self.opt_cur = 0;
			}
			None => {
				self.confirmed = true;
			}
		}
	}

	fn event_loop(&mut self, terminal: &mut Terminal<CrosstermBackend<io::Stdout>>) -> Result<()> {
		loop {
			terminal.draw(|f| self.render(f))?;

			if event::poll(std::time::Duration::from_millis(16))? {
				if let Event::Key(key) = event::read()? {
					let field = &self.fields[self.field_cur];
					let n_opts = field.opts.len();
					let in_custom = self.opt_cur == n_opts;
					let is_secret_only = field.opts.is_empty();

					match key.code {
						KeyCode::Esc => { self.cancelled = true; break; }
						KeyCode::Char('c') if key.modifiers == KeyModifiers::CONTROL => {
							self.cancelled = true;
							break;
						}

						KeyCode::Up | KeyCode::BackTab if !in_custom || is_secret_only => {
							if self.opt_cur > 0 {
								self.opt_cur -= 1;
							} else if self.field_cur > 0 {
								// go back to the previous visible field
								let mut prev = self.field_cur - 1;
								while prev > 0 && self.should_skip(prev) { prev -= 1; }
								if !self.should_skip(prev) {
									self.field_cur = prev;
									self.opt_cur = self.fields[prev].opts.len();
								}
							}
						}
						KeyCode::Down | KeyCode::Tab if !in_custom || is_secret_only => {
							let max = self.fields[self.field_cur].total_options() - 1;
							if self.opt_cur < max {
								self.opt_cur += 1;
							} else {
								self.fields[self.field_cur].selected = self.opt_cur;
								self.confirm_current_and_advance();
							}
						}

						KeyCode::Tab if in_custom && !is_secret_only => {
							self.fields[self.field_cur].selected = self.opt_cur;
							self.confirm_current_and_advance();
						}
						KeyCode::Up | KeyCode::BackTab if in_custom && !is_secret_only => {
							if self.opt_cur > 0 { self.opt_cur -= 1; }
						}

						KeyCode::Enter => {
							self.fields[self.field_cur].selected = self.opt_cur;
							self.confirm_current_and_advance();
							if self.confirmed { break; }
						}

						KeyCode::Backspace if in_custom || is_secret_only => {
							self.fields[self.field_cur].custom.pop();
						}
						KeyCode::Char(c) if in_custom || is_secret_only => {
							self.fields[self.field_cur].custom.push(c);
						}

						_ => {}
					}
				}
			}
		}
		Ok(())
	}

	fn render(&mut self, f: &mut ratatui::Frame) {
		let area = f.size();
		f.render_widget(Block::default().style(Style::default().bg(Theme::BG)), area);

		let outer = Block::default()
			.title(" OpenSentinel — Project Setup ")
			.title_alignment(Alignment::Center)
			.borders(Borders::ALL)
			.border_type(BorderType::Rounded)
			.border_style(Theme::border_active())
			.style(Style::default().bg(Theme::BG));

		let inner = outer.inner(area);
		f.render_widget(outer, area);

		let cols = Layout::default()
			.direction(Direction::Horizontal)
			.constraints([Constraint::Min(54), Constraint::Length(36)])
			.split(inner);

		let viewport = cols[0].height.saturating_sub(4) as usize;
		self.ensure_visible(viewport);

		self.render_form(f, cols[0]);
		self.render_hint(f, cols[1]);
	}

	fn render_form(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
		let rows = self.build_rows();
		let viewport = area.height.saturating_sub(4) as usize;

		let visible: Vec<_> = rows.iter().skip(self.scroll_row).take(viewport).collect();

		let constraints: Vec<Constraint> = visible.iter()
			.map(|_| Constraint::Length(1))
			.chain(std::iter::once(Constraint::Min(0)))
			.collect();

		let chunks = Layout::default()
			.direction(Direction::Vertical)
			.margin(1)
			.constraints(constraints)
			.split(area);

		for (i, row) in visible.iter().enumerate() {
			let chunk = chunks[i];
			match row {
				Row::Header(title) => {
					f.render_widget(
						Paragraph::new(Line::from(Span::styled(
							*title,
							Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD),
						))),
						chunk,
					);
				}
				Row::Done(fi) => {
					let field = &self.fields[*fi];
					let label_padded = format!("{:<22}", field.label);
					f.render_widget(
						Paragraph::new(Line::from(vec![
							Span::styled("    ✓ ", Style::default().fg(Theme::SEVERITY_SAFE)),
							Span::styled(label_padded, Theme::secondary()),
							Span::styled(field.display_value(), Style::default().fg(Theme::TEXT_PRIMARY)),
						])),
						chunk,
					);
				}
				Row::Pending(fi) => {
					let field = &self.fields[*fi];
					f.render_widget(
						Paragraph::new(Line::from(vec![
							Span::styled("    ○ ", Theme::dim()),
							Span::styled(field.label, Theme::dim()),
						])),
						chunk,
					);
				}
				Row::ActiveLabel(fi) => {
					let field = &self.fields[*fi];
					let visible_total = self.fields.iter().enumerate()
						.filter(|(i, _)| !self.should_skip(*i))
						.count();
					let visible_done = self.fields.iter().enumerate()
						.filter(|(i, _)| !self.should_skip(*i) && *i < self.field_cur)
						.count();
					let progress = format!("  {}/{}", visible_done + 1, visible_total);
					f.render_widget(
						Paragraph::new(Line::from(vec![
							Span::styled("  ▸ ", Style::default().fg(Theme::ACCENT)),
							Span::styled(
								field.label,
								Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
							),
							Span::styled(progress, Theme::dim()),
						])),
						chunk,
					);
				}
				Row::Opt(fi, oi) => {
					let field = &self.fields[*fi];
					let opt = &field.opts[*oi];
					let is_sel = field.selected == *oi;
					let is_focused = self.field_cur == *fi && self.opt_cur == *oi;

					let bullet = if is_sel { "  ●" } else { "  ○" };
					let bullet_style = if is_sel || is_focused {
						Style::default().fg(Theme::ACCENT)
					} else {
						Theme::dim()
					};
					let label_style = if is_focused {
						Style::default().fg(Color::White).bg(Theme::BG_SELECTED)
					} else if is_sel {
						Style::default().fg(Theme::TEXT_PRIMARY)
					} else {
						Theme::dim()
					};
					let bg = if is_focused { Theme::BG_SELECTED } else { Theme::BG };

					f.render_widget(
						Paragraph::new(Line::from(vec![
							Span::styled(format!("    {bullet} "), bullet_style),
							Span::styled(opt.label, label_style),
						]))
						.style(Style::default().bg(bg)),
						chunk,
					);
				}
				Row::Custom(fi) => {
					let field = &self.fields[*fi];
					let n_opts = field.opts.len();
					let is_sel = field.selected == n_opts || field.opts.is_empty();
					let is_focused = self.field_cur == *fi
						&& (self.opt_cur == n_opts || field.opts.is_empty());

					let bullet = if is_sel { "  ●" } else { "  ○" };
					let bullet_style = if is_sel || is_focused {
						Style::default().fg(Theme::ACCENT)
					} else {
						Theme::dim()
					};
					let bg = if is_focused { Theme::BG_SELECTED } else { Theme::BG };
					let display = field.display_value();
					let cursor = if is_focused { "█" } else { "" };
					let custom_label = if field.opts.is_empty() { "" } else { "Custom...  " };

					f.render_widget(
						Paragraph::new(Line::from(vec![
							Span::styled(format!("    {bullet} "), bullet_style),
							Span::styled(
								custom_label,
								if is_focused { Style::default().fg(Theme::ACCENT) } else { Theme::dim() },
							),
							Span::styled(
								format!("{}{}", display, cursor),
								if is_focused { Style::default().fg(Color::White) } else { Theme::secondary() },
							),
						]))
						.style(Style::default().bg(bg)),
						chunk,
					);
				}
			}
		}

		// Progress bar
		let visible_total = self.fields.iter().enumerate()
			.filter(|(i, _)| !self.should_skip(*i))
			.count();
		let visible_done = self.fields.iter().enumerate()
			.filter(|(i, _)| !self.should_skip(*i) && *i < self.field_cur)
			.count();
		let pct = (visible_done * 100 / visible_total.max(1)) as u16;
		let filled = (pct / 5) as usize;
		let bar = format!(
			"  [{}{}] {}/{}",
			"█".repeat(filled),
			"░".repeat(20usize.saturating_sub(filled)),
			visible_done, visible_total,
		);

		let last_fi = self.fields.iter().enumerate()
			.rev()
			.find(|(i, _)| !self.should_skip(*i))
			.map(|(i, _)| i)
			.unwrap_or(0);
		let at_last = self.field_cur == last_fi
			&& self.opt_cur == self.fields[last_fi].total_options() - 1;

		let footer_text = if self.confirmed || at_last {
			format!("{}   Enter Confirm   Esc Cancel", bar)
		} else {
			format!("{}   ↑↓ Select   Enter Confirm   Esc Cancel", bar)
		};

		let footer_area = ratatui::layout::Rect {
			x: area.x,
			y: area.y + area.height.saturating_sub(2),
			width: area.width,
			height: 1,
		};
		f.render_widget(Paragraph::new(footer_text).style(Theme::dim()), footer_area);
	}

	fn render_hint(&self, f: &mut ratatui::Frame, area: ratatui::layout::Rect) {
		let block = Block::default()
			.title(" Hint ")
			.borders(Borders::ALL)
			.border_type(BorderType::Rounded)
			.border_style(Theme::border_inactive())
			.style(Style::default().bg(Theme::BG_PANEL));

		let inner = block.inner(area);
		f.render_widget(block, area);

		let field = &self.fields[self.field_cur];
		let section = Self::section_name(self.field_cur);

		let mut lines = vec![
			Line::from(Span::styled(
				field.label,
				Style::default().fg(Theme::ACCENT).add_modifier(Modifier::BOLD),
			)),
			Line::from(Span::styled(section, Theme::secondary())),
			Line::from(""),
		];

		for part in field.hint.split('\n') {
			lines.push(Line::from(Span::styled(part, Style::default().fg(Theme::TEXT_PRIMARY))));
		}

		lines.push(Line::from(""));
		lines.push(Line::from(Span::styled("${VAR} reads from env.", Theme::secondary())));

		f.render_widget(
			Paragraph::new(lines).wrap(Wrap { trim: true }),
			inner.inner(Margin { horizontal: 1, vertical: 1 }),
		);
	}

	fn section_name(cursor: usize) -> &'static str {
		match cursor {
			0..=9  => "Database",
			10..=14 => "Source Analysis",
			15..=22 => "Parallelism",
			23..=26 => "Credentials",
			_      => "Output & Behavior",
		}
	}

	fn build_config(&self) -> serde_json::Value {
		use crate::config::loader::DEFAULT_CONFIG;
		let mut cfg: serde_json::Value =
			serde_json::from_str(DEFAULT_CONFIG).expect("invalid default config");

		let v = |i: usize| self.fields[i].value();
		let b = |i: usize| v(i) == "true";
		let n = |i: usize, d: u64|   v(i).parse::<u64>().unwrap_or(d);
		let u = |i: usize, d: usize| v(i).parse::<usize>().unwrap_or(d);

		let engine = v(0);
		cfg["database"]["engine"] = engine.clone().into();

		// Remove all individual-field defaults first so the config is clean
		let db = cfg["database"].as_object_mut().unwrap();
		for key in &["url", "sqlitePath", "host", "port", "database", "user", "password", "ssl", "poolSize"] {
			db.remove(*key);
		}

		match engine.as_str() {
			"sqlite" => {
				let path = v(9);
				cfg["database"]["sqlitePath"] = if path.is_empty() {
					"opensentinel.db".into()
				} else {
					path.into()
				};
			}
			_ => {
				let url = v(1);
				if !url.is_empty() {
					// URL mode: only store url and poolSize
					cfg["database"]["url"]      = url.into();
					cfg["database"]["poolSize"] = n(8, 10).into();
				} else {
					// Individual fields mode
					cfg["database"]["host"]     = v(2).into();
					cfg["database"]["port"]     = n(3, 5432).into();
					cfg["database"]["database"] = v(4).into();
					cfg["database"]["user"]     = v(5).into();
					cfg["database"]["password"] = v(6).into();
					cfg["database"]["ssl"]      = b(7).into();
					cfg["database"]["poolSize"] = n(8, 10).into();
				}
			}
		}

		cfg["sourceAnalysis"]["enabled"]         = b(10).into();
		cfg["sourceAnalysis"]["downloadSource"]  = b(11).into();
		cfg["sourceAnalysis"]["analyzeAst"]      = b(12).into();
		cfg["sourceAnalysis"]["cacheTtl"]        = n(13, 604800).into();
		cfg["sourceAnalysis"]["maxSourceSizeMb"] = n(14, 100).into();

		cfg["parallelism"]["packageConcurrency"] = u(15, 4).into();
		cfg["parallelism"]["apiConcurrency"]     = u(16, 3).into();
		cfg["parallelism"]["osv"]["limit"]       = u(17, 10).into();
		cfg["parallelism"]["osv"]["delayMs"]     = n(18, 100).into();
		cfg["parallelism"]["github"]["limit"]    = u(19, 5).into();
		cfg["parallelism"]["github"]["delayMs"]  = n(20, 200).into();
		cfg["parallelism"]["nvd"]["limit"]       = u(21, 5).into();
		cfg["parallelism"]["nvd"]["delayMs"]     = n(22, 200).into();

		cfg["credentials"]["githubToken"]    = v(23).into();
		cfg["credentials"]["nvdApiKey"]      = v(24).into();
		cfg["credentials"]["storage"]        = v(25).into();
		cfg["credentials"]["keyringSupport"] = b(26).into();

		let eco: Vec<serde_json::Value> = v(27).split(',')
			.map(|s| serde_json::Value::String(s.trim().to_string())).collect();
		cfg["ecosystems"] = serde_json::Value::Array(eco);

		let sev: Vec<serde_json::Value> = v(28).split(',')
			.map(|s| serde_json::Value::String(s.trim().to_string())).collect();
		cfg["severity"] = serde_json::Value::Array(sev);

		cfg["excludeDevDeps"] = b(29).into();
		cfg["keybindings"]    = v(30).into();
		cfg["outputFormat"]   = v(31).into();

		cfg
	}
}
