use ratatui::{
	layout::Rect,
	style::Style,
	text::{Line, Span},
	widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
	Frame,
};

use super::app::{ActivePanel, ResultsState, TuiApp};
use super::theme::Theme;

pub struct LeftPanel;
pub struct VulnListPanel;
pub struct VulnDetailPanel;

impl LeftPanel {
	pub fn render(f: &mut Frame, _app: &TuiApp, state: &ResultsState, area: Rect) {
		let is_active = state.active_panel == ActivePanel::Left;

		let title = if state.search_mode {
			format!(" Search: {} ", state.search_query)
		} else {
			" Dependencies ".to_string()
		};

		let block = Block::default()
			.title(title)
			.borders(Borders::ALL)
			.border_style(if is_active { Theme::border_active() } else { Theme::border_inactive() })
			.style(Theme::panel());

		let filtered = state.filtered_risks();

		let items: Vec<ListItem> = filtered
			.iter()
			.map(|risk| {
				let label = format!("{}: {}@{}", risk.severity_label(), risk.package_name, risk.package_version);
				let style = Theme::severity_style(risk.severity_label());
				ListItem::new(Line::from(Span::styled(label, style)))
			})
			.collect();

		let mut list_state = ListState::default();
		list_state.select(Some(state.selected_index));

		let list = List::new(items)
			.block(block)
			.highlight_style(Theme::selected())
			.highlight_symbol("  ");

		f.render_stateful_widget(list, area, &mut list_state);
	}
}

impl VulnListPanel {
	pub fn render(f: &mut Frame, _app: &TuiApp, state: &ResultsState, area: Rect) {
		let is_active = state.active_panel == ActivePanel::Right;

		let Some(risk) = state.selected_risk() else {
			let block = Block::default()
				.title(" Vulnerabilities ")
				.borders(Borders::ALL)
				.border_style(if is_active { Theme::border_active() } else { Theme::border_inactive() })
				.style(Theme::panel());
			f.render_widget(
				Paragraph::new(Line::from(Span::styled(
					"  Select a package to view vulnerabilities",
					Theme::dim(),
				)))
				.block(block),
				area,
			);
			return;
		};

		let title = format!(
			" {}@{}  —  {} ({:.1}) ",
			risk.package_name, risk.package_version,
			risk.severity_label(), risk.final_score
		);
		let block = Block::default()
			.title(title)
			.borders(Borders::ALL)
			.border_style(if is_active { Theme::border_active() } else { Theme::border_inactive() })
			.style(Theme::panel());

		let n_adv = risk.advisories.len();
		let total = n_adv + risk.detections.len();

		if total == 0 {
			f.render_widget(
				Paragraph::new(vec![
					Line::from(""),
					Line::from(Span::styled("  No vulnerabilities detected", Theme::dim())),
				])
				.block(block),
				area,
			);
			return;
		}

		let items: Vec<ListItem> = (0..total)
			.map(|i| {
				if i < n_adv {
					let adv = &risk.advisories[i];
					let sev = adv.severity_label();
					let cvss = adv
						.cvss_score
						.map(|s| format!("  CVSS {s:.1}"))
						.unwrap_or_default();
					let subtitle = if !adv.title.is_empty() && adv.title != adv.external_id {
						let t: String = adv.title.chars().take(55).collect();
						if adv.title.len() > 55 { format!("  {t}…") } else { format!("  {t}") }
					} else {
						"  Advisory".to_string()
					};
					ListItem::new(vec![
						Line::from(vec![
							Span::styled(format!(" [{}] ", adv.source_label()), Theme::secondary()),
							Span::styled(adv.external_id.clone(), Theme::severity_style(&sev)),
							Span::styled(format!("  {sev}{cvss}"), Theme::severity_style(&sev)),
						]),
						Line::from(Span::styled(subtitle, Theme::dim())),
					])
				} else {
					let det = &risk.detections[i - n_adv];
					let sev = if det.confidence >= 0.8 {
						"HIGH"
					} else if det.confidence >= 0.5 {
						"MEDIUM"
					} else {
						"LOW"
					};
					let location = match (&det.file_path, det.line_number) {
						(Some(p), Some(l)) => {
							let fname = p.split('/').last().unwrap_or(p.as_str());
							format!("  {fname}:{l}")
						}
						(Some(p), None) => {
							let fname = p.split('/').last().unwrap_or(p.as_str());
							format!("  {fname}")
						}
						_ => "  Metadata pattern".to_string(),
					};
					let desc: String = det.description.chars().take(45).collect();
					let desc = if det.description.len() > 45 { format!("{desc}…") } else { desc };
					ListItem::new(vec![
						Line::from(vec![
							Span::styled(" [CODE] ", Theme::secondary()),
							Span::styled(desc, Theme::severity_style(sev)),
							Span::styled(
								format!("  {:.0}% conf.", det.confidence * 100.0),
								Theme::dim(),
							),
						]),
						Line::from(Span::styled(location, Theme::dim())),
					])
				}
			})
			.collect();

		let clamped = state.selected_vuln.min(total.saturating_sub(1));
		let mut list_state = ListState::default();
		list_state.select(Some(clamped));

		let list = List::new(items)
			.block(block)
			.highlight_style(Theme::selected())
			.highlight_symbol("");

		f.render_stateful_widget(list, area, &mut list_state);
	}
}

impl VulnDetailPanel {
	pub fn render(f: &mut Frame, _app: &TuiApp, state: &ResultsState, area: Rect) {
		let is_active = state.active_panel == ActivePanel::Bottom;

		let block = Block::default()
			.title(" Vulnerability Detail ")
			.borders(Borders::ALL)
			.border_style(if is_active { Theme::border_active() } else { Theme::border_inactive() })
			.style(Theme::panel());

		let Some(risk) = state.selected_risk() else {
			f.render_widget(
				Paragraph::new(Line::from(Span::styled("  Select a package", Theme::dim())))
					.block(block),
				area,
			);
			return;
		};

		let n_adv = risk.advisories.len();
		let total = n_adv + risk.detections.len();

		if total == 0 {
			f.render_widget(
				Paragraph::new(vec![
					Line::from(""),
					Line::from(Span::styled("  No vulnerabilities to display", Theme::dim())),
				])
				.block(block),
				area,
			);
			return;
		}

		let sel = state.selected_vuln.min(total.saturating_sub(1));
		let lines = if sel < n_adv {
			Self::advisory_lines(&risk.advisories[sel], risk)
		} else {
			Self::detection_lines(&risk.detections[sel - n_adv], risk)
		};

		f.render_widget(
			Paragraph::new(lines)
				.block(block)
				.wrap(Wrap { trim: true })
				.scroll((state.detail_scroll as u16, 0)),
			area,
		);
	}

	fn advisory_lines(
		advisory: &crate::advisory::models::AdvisoryData,
		risk: &crate::scoring::models::PackageRisk,
	) -> Vec<Line<'static>> {
		let mut lines = Vec::new();

		let sev = advisory.severity_label();
		let mut header = vec![
			Span::styled(format!("  [{}] ", advisory.source_label()), Theme::secondary()),
			Span::styled(advisory.external_id.clone(), Theme::severity_style(&sev)),
			Span::styled(format!("  {sev}"), Theme::severity_style(&sev)),
		];
		if let Some(score) = advisory.cvss_score {
			header.push(Span::styled(format!("  CVSS {score:.1}"), Theme::dim()));
		}
		lines.push(Line::from(header));

		if !advisory.title.is_empty() && advisory.title != advisory.external_id {
			lines.push(Line::from(Span::styled(
				format!("  {}", advisory.title),
				Theme::base(),
			)));
		}

		lines.push(Line::from(""));

		if !advisory.description.is_empty() {
			lines.push(Line::from(Span::styled("  Description:", Theme::accent())));
			for desc_line in advisory.description.lines() {
				lines.push(Line::from(Span::styled(
					format!("    {desc_line}"),
					Theme::dim(),
				)));
			}
			lines.push(Line::from(""));
		}

		if !advisory.affected_versions.is_empty() {
			lines.push(Line::from(vec![
				Span::styled("  Affected:  ", Theme::secondary()),
				Span::styled(advisory.affected_versions.clone(), Theme::base()),
			]));
		}
		if let Some(fixed) = &advisory.patched_versions {
			if !fixed.is_empty() {
				lines.push(Line::from(vec![
					Span::styled("  Fixed in:  ", Theme::secondary()),
					Span::styled(fixed.clone(), Theme::severity_style("SAFE")),
				]));
			}
		}
		if let Some(published) = advisory.published_at {
			lines.push(Line::from(vec![
				Span::styled("  Published: ", Theme::secondary()),
				Span::styled(published.format("%Y-%m-%d").to_string(), Theme::dim()),
			]));
		}

		if !advisory.references.is_empty() {
			lines.push(Line::from(""));
			lines.push(Line::from(Span::styled("  References:", Theme::secondary())));
			for url in &advisory.references {
				lines.push(Line::from(Span::styled(format!("    • {url}"), Theme::dim())));
			}
		}

		lines.push(Line::from(""));
		Self::append_package_context(&mut lines, risk);
		lines
	}

	fn detection_lines(
		detection: &crate::analyzer::models::DetectionMatch,
		risk: &crate::scoring::models::PackageRisk,
	) -> Vec<Line<'static>> {
		let mut lines = Vec::new();

		let sev = if detection.confidence >= 0.8 {
			"HIGH"
		} else if detection.confidence >= 0.5 {
			"MEDIUM"
		} else {
			"LOW"
		};

		lines.push(Line::from(vec![
			Span::styled("  [CODE] ", Theme::secondary()),
			Span::styled(detection.description.clone(), Theme::severity_style(sev)),
			Span::styled(
				format!("  {:.0}% confidence", detection.confidence * 100.0),
				Theme::dim(),
			),
		]));
		lines.push(Line::from(""));

		match (&detection.file_path, detection.line_number) {
			(Some(path), Some(line_num)) => {
				lines.push(Line::from(vec![
					Span::styled("  File: ", Theme::secondary()),
					Span::styled(format!("{path}:{line_num}"), Theme::base()),
				]));
			}
			(Some(path), None) => {
				lines.push(Line::from(vec![
					Span::styled("  File: ", Theme::secondary()),
					Span::styled(path.clone(), Theme::base()),
				]));
			}
			_ => {}
		}

		if let Some(snippet) = &detection.code_snippet {
			lines.push(Line::from(""));
			lines.push(Line::from(Span::styled("  Code snippet:", Theme::accent())));
			lines.push(Line::from(""));
			for code_line in snippet.lines() {
				lines.push(Line::from(vec![
					Span::styled("    > ", Style::default().fg(Theme::ACCENT)),
					Span::styled(
						code_line.to_string(),
						Style::default().fg(Theme::TEXT_PRIMARY),
					),
				]));
			}
		} else {
			lines.push(Line::from(""));
			lines.push(Line::from(Span::styled(
				"  No code snippet available.",
				Theme::dim(),
			)));
			lines.push(Line::from(Span::styled(
				"  Enable sourceAnalysis.downloadSource in config to view code.",
				Theme::dim(),
			)));
		}

		lines.push(Line::from(""));
		Self::append_package_context(&mut lines, risk);
		lines
	}

	fn append_package_context(
		lines: &mut Vec<Line<'static>>,
		risk: &crate::scoring::models::PackageRisk,
	) {
		if !risk.mitre_mappings.is_empty() {
			lines.push(Line::from(Span::styled("  MITRE ATT&CK:", Theme::accent())));
			for mapping in &risk.mitre_mappings {
				lines.push(Line::from(vec![
					Span::styled(format!("    {} ", mapping.technique_id), Theme::accent()),
					Span::styled(mapping.technique_name.clone(), Theme::base()),
				]));
				lines.push(Line::from(Span::styled(
					format!("    Tactic: {}", mapping.tactic),
					Theme::secondary(),
				)));
				if !mapping.description.is_empty() {
					lines.push(Line::from(Span::styled(
						format!("    {}", mapping.description),
						Theme::dim(),
					)));
				}
			}
			lines.push(Line::from(""));
		}

		if !risk.recommendations.is_empty() {
			lines.push(Line::from(Span::styled("  Recommendations:", Theme::accent())));
			for rec in &risk.recommendations {
				lines.push(Line::from(vec![
					Span::styled("    -> ", Theme::dim()),
					Span::styled(rec.clone(), Theme::base()),
				]));
			}
		}
	}
}

trait AdvisoryExt {
	fn source_label(&self) -> &str;
	fn severity_label(&self) -> String;
}

impl AdvisoryExt for crate::advisory::models::AdvisoryData {
	fn source_label(&self) -> &str {
		match self.source {
			crate::database::models::AdvisorySource::Osv    => "OSV",
			crate::database::models::AdvisorySource::Github => "GitHub",
			crate::database::models::AdvisorySource::Nvd    => "NVD",
			crate::database::models::AdvisorySource::Mitre  => "MITRE",
		}
	}

	fn severity_label(&self) -> String {
		match self.severity {
			crate::database::models::SeverityLevel::Critical => "CRITICAL".to_string(),
			crate::database::models::SeverityLevel::High     => "HIGH".to_string(),
			crate::database::models::SeverityLevel::Medium   => "MEDIUM".to_string(),
			crate::database::models::SeverityLevel::Low      => "LOW".to_string(),
			crate::database::models::SeverityLevel::Safe     => "SAFE".to_string(),
		}
	}
}
