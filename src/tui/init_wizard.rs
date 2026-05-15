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

	fn total_options(&self) -> usize { self.opts.len() + 1 } // +1 for Custom
}


enum Row {
	Header(&'static str),
	Done(usize),         // completed field — one line with ✓
	ActiveLabel(usize),  // field currently being edited — header line
	Opt(usize, usize),   // field_idx, opt_idx — radio option
	Custom(usize),       // Custom... option
	Pending(usize),      // not-yet-reached field — dimmed one line
}

const SECTIONS: &[(&str, &[usize])] = &[
	("Database",         &[0, 1, 2, 3, 4, 5, 6, 7]),
	("Source Analysis",  &[8, 9, 10, 11, 12]),
	("Parallelism",      &[13, 14, 15, 16, 17, 18, 19, 20]),
	("Credentials",      &[21, 22, 23, 24]),
	("Output & Behavior",&[25, 26, 27, 28, 29]),
];

pub struct InitWizard {
	fields:      Vec<Field>,
	field_cur:   usize,   
	opt_cur:     usize,   
	scroll_row:  usize,
	confirmed:   bool,
	cancelled:   bool,
}

impl InitWizard {
	pub fn new() -> Self {
		let fields = vec![
			Field::new("DB Engine", "Database backend to connect to",
				vec![Opt::v("PostgreSQL","postgresql"), Opt::v("SQLite","sqlite"), Opt::v("MySQL","mysql")]),
			Field::new("Host", "Hostname or IP of your database server",
				vec![Opt::same("localhost"), Opt::same("127.0.0.1"), Opt::v("Cloud / Remote","db.example.com")]),
			Field::new("Port", "Database port",
				vec![Opt::v("5432  (PostgreSQL default)","5432"), Opt::v("3306  (MySQL default)","3306"), Opt::v("5433  (alt)","5433")]),
			Field::new("Database name", "Name of the database to use",
				vec![Opt::same("opensentinel"), Opt::same("opensentinel_dev"), Opt::same("security")]),
			Field::new("User", "Database user",
				vec![Opt::same("postgres"), Opt::same("root"), Opt::same("opensentinel"), Opt::same("admin")]),
			Field::secret("Password", "Leave as ${DB_PASSWORD} to read from environment variable"),
			Field::new("SSL", "Require SSL for database connection",
				vec![Opt::v("No  — local / internal network","false"), Opt::v("Yes — production / cloud","true")]),
			Field::new("Pool size", "Max simultaneous database connections",
				vec![Opt::same("5"), Opt::same("10"), Opt::same("20"), Opt::same("50")]),
			Field::new("Enable source scan", "Scan actual source code of packages",
				vec![Opt::v("Yes","true"), Opt::v("No","false")]),
			Field::new("Download source", "Fetch package tarballs to scan for malicious code.\nRequired to see Code Snippets in the TUI.",
				vec![Opt::v("Yes — full analysis (slower)","true"), Opt::v("No — advisories only (faster)","false")]),
			Field::new("AST analysis", "Deep Tree-sitter analysis of JS/TS code",
				vec![Opt::v("Yes — detect obfuscation and hidden patterns","true"), Opt::v("No — regex patterns only","false")]),
			Field::new("Cache TTL", "How long to keep cached source tarballs",
				vec![Opt::v("1 day   (86400)","86400"), Opt::v("7 days  (604800)","604800"), Opt::v("30 days (2592000)","2592000")]),
			Field::new("Max source size", "Maximum tarball size to download (MB)",
				vec![Opt::same("50"), Opt::same("100"), Opt::same("250"), Opt::same("500")]),
			Field::new("Package concurrency", "Packages analyzed in parallel",
				vec![Opt::same("2"), Opt::same("4"), Opt::same("8"), Opt::same("16")]),
			Field::new("API concurrency", "Simultaneous advisory API requests",
				vec![Opt::same("2"), Opt::same("3"), Opt::same("5")]),
			Field::new("OSV limit", "Max requests per OSV batch",
				vec![Opt::same("5"), Opt::same("10"), Opt::same("20")]),
			Field::new("OSV delay (ms)", "Pause between OSV batches",
				vec![Opt::same("50"), Opt::same("100"), Opt::same("250")]),
			Field::new("GitHub limit", "Max requests per GitHub Advisory batch",
				vec![Opt::same("3"), Opt::same("5"), Opt::same("10")]),
			Field::new("GitHub delay (ms)", "Pause between GitHub batches",
				vec![Opt::same("100"), Opt::same("200"), Opt::same("500")]),
			Field::new("NVD limit", "Max requests per NVD batch",
				vec![Opt::same("3"), Opt::same("5"), Opt::same("10")]),
			Field::new("NVD delay (ms)", "Pause between NVD batches",
				vec![Opt::same("100"), Opt::same("200"), Opt::same("500")]),
			Field::secret("GitHub Token", "Personal access token for GitHub Advisory API.\nUse ${GITHUB_TOKEN} to read from environment."),
			Field::secret("NVD API Key", "API key for NVD CVE database (optional but recommended).\nUse ${NVD_API_KEY} to read from environment."),
			Field::new("Credential storage", "Where to read credential values from",
				vec![Opt::v("env      — environment variables (recommended)","env"),
				     Opt::v("file     — plain config file","file"),
				     Opt::v("keyring  — OS keyring","keyring")]),
			Field::new("Keyring support", "Use OS keyring for secure credential storage",
				vec![Opt::v("No","false"), Opt::v("Yes","true")]),
			Field::new("Ecosystems", "Which package managers to scan",
				vec![Opt::v("Node.js + Bun","nodejs,bun"), Opt::v("Node.js only","nodejs"), Opt::v("Bun only","bun")]),
			Field::new("Severity filter", "Only report packages at or above this level",
				vec![Opt::v("high + critical only","high,critical"),
				     Opt::v("medium, high, critical","medium,high,critical"),
				     Opt::v("all severities","low,medium,high,critical"),
				     Opt::v("critical only","critical")]),
			Field::new("Exclude dev deps", "Skip devDependencies during scan",
				vec![Opt::v("No  — scan everything","false"), Opt::v("Yes — production deps only","true")]),
			Field::new("Keybindings", "TUI navigation style",
				vec![Opt::v("Arrow keys","arrows"), Opt::v("Vim  (hjkl)","vim")]),
			Field::new("Output format", "Default format for non-interactive (opse analyze)",
				vec![Opt::v("SBOM  — CycloneDX","sbom"), Opt::v("JSON","json"), Opt::v("Table","table"), Opt::v("HTML","html")]),
		];

		let mut w = Self { fields, field_cur: 0, opt_cur: 0, scroll_row: 0, confirmed: false, cancelled: false };
		w.fields[5].custom  = "${DB_PASSWORD}".to_string();
		w.fields[5].selected = 0; // custom
		w.fields[21].custom = "${GITHUB_TOKEN}".to_string();
		w.fields[21].selected = 0;
		w.fields[22].custom = "${NVD_API_KEY}".to_string();
		w.fields[22].selected = 0;
		w
	}

	fn build_rows(&self) -> Vec<Row> {
		let mut rows = Vec::new();
		for &(section, indices) in SECTIONS {
			rows.push(Row::Header(section));
			for &fi in indices {
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
			Row::Opt(fi, oi)  => *fi == self.field_cur && *oi == target_opt && target_opt < n_opts,
			Row::Custom(fi)   => *fi == self.field_cur && target_opt == n_opts,
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
		if self.field_cur < self.fields.len() - 1 {
			self.field_cur += 1;
			self.opt_cur = 0;
		} else {
			self.confirmed = true;
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
								self.field_cur -= 1;
								self.opt_cur = self.fields[self.field_cur].opts.len();
							}
						}
						KeyCode::Down | KeyCode::Tab if !in_custom || is_secret_only => {
							let max = self.fields[self.field_cur].total_options() - 1;
							if self.opt_cur < max {
								self.opt_cur += 1;
							} else {
								// at Custom, Tab moves to next field
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
					let progress = format!("  {}/{}", self.field_cur + 1, self.fields.len());
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

					let bullet = if is_sel    { "  ●" } else { "  ○" };
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
								if is_focused {
									Style::default().fg(Theme::ACCENT)
								} else {
									Theme::dim()
								},
							),
							Span::styled(
								format!("{}{}", display, cursor),
								if is_focused {
									Style::default().fg(Color::White)
								} else {
									Theme::secondary()
								},
							),
						]))
						.style(Style::default().bg(bg)),
						chunk,
					);
				}
			}
		}

		let total = self.fields.len();
		let done  = self.field_cur;
		let pct   = (done * 100 / total) as u16;
		let filled = (pct / 5) as usize;
		let bar = format!(
			"  [{}{}] {}/{}",
			"█".repeat(filled),
			"░".repeat(20usize.saturating_sub(filled)),
			done, total,
		);

		let footer_text = if self.confirmed || (self.field_cur == total - 1
			&& self.opt_cur == self.fields[total - 1].total_options() - 1)
		{
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
			0..=7  => "Database",
			8..=12 => "Source Analysis",
			13..=20 => "Parallelism",
			21..=24 => "Credentials",
			_      => "Output & Behavior",
		}
	}

	fn build_config(&self) -> serde_json::Value {
		use crate::config::loader::DEFAULT_CONFIG;
		let mut cfg: serde_json::Value =
			serde_json::from_str(DEFAULT_CONFIG).expect("invalid default config");

		let v  = |i: usize| self.fields[i].value();
		let b  = |i: usize| v(i) == "true";
		let n  = |i: usize, d: u64|    v(i).parse::<u64>().unwrap_or(d);
		let u  = |i: usize, d: usize|  v(i).parse::<usize>().unwrap_or(d);

		cfg["database"]["engine"]   = v(0).into();
		cfg["database"]["host"]     = v(1).into();
		cfg["database"]["port"]     = n(2, 5432).into();
		cfg["database"]["database"] = v(3).into();
		cfg["database"]["user"]     = v(4).into();
		cfg["database"]["password"] = v(5).into();
		cfg["database"]["ssl"]      = b(6).into();
		cfg["database"]["poolSize"] = n(7, 10).into();

		cfg["sourceAnalysis"]["enabled"]         = b(8).into();
		cfg["sourceAnalysis"]["downloadSource"]  = b(9).into();
		cfg["sourceAnalysis"]["analyzeAst"]      = b(10).into();
		cfg["sourceAnalysis"]["cacheTtl"]        = n(11, 604800).into();
		cfg["sourceAnalysis"]["maxSourceSizeMb"] = n(12, 100).into();

		cfg["parallelism"]["packageConcurrency"] = u(13, 4).into();
		cfg["parallelism"]["apiConcurrency"]     = u(14, 3).into();
		cfg["parallelism"]["osv"]["limit"]       = u(15, 10).into();
		cfg["parallelism"]["osv"]["delayMs"]     = n(16, 100).into();
		cfg["parallelism"]["github"]["limit"]    = u(17, 5).into();
		cfg["parallelism"]["github"]["delayMs"]  = n(18, 200).into();
		cfg["parallelism"]["nvd"]["limit"]       = u(19, 5).into();
		cfg["parallelism"]["nvd"]["delayMs"]     = n(20, 200).into();

		cfg["credentials"]["githubToken"]    = v(21).into();
		cfg["credentials"]["nvdApiKey"]      = v(22).into();
		cfg["credentials"]["storage"]        = v(23).into();
		cfg["credentials"]["keyringSupport"] = b(24).into();

		let eco: Vec<serde_json::Value> = v(25).split(',')
			.map(|s| serde_json::Value::String(s.trim().to_string())).collect();
		cfg["ecosystems"] = serde_json::Value::Array(eco);

		let sev: Vec<serde_json::Value> = v(26).split(',')
			.map(|s| serde_json::Value::String(s.trim().to_string())).collect();
		cfg["severity"] = serde_json::Value::Array(sev);

		cfg["excludeDevDeps"] = b(27).into();
		cfg["keybindings"]    = v(28).into();
		cfg["outputFormat"]   = v(29).into();

		cfg
	}
}
