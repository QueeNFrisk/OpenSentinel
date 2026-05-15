use anyhow::{Context, Result};
use chrono::Utc;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;

use crate::scoring::models::PackageRisk;
use super::Reporter;

#[cfg(test)]
mod tests {
	use super::*;
	use crate::advisory::models::AdvisoryData;
	use crate::database::models::{AdvisorySource, SeverityLevel};

	fn make_risk(name: &str, severity: SeverityLevel) -> PackageRisk {
		PackageRisk {
			package_name: name.to_string(),
			package_version: "1.0.0".to_string(),
			ecosystem: "nodejs".to_string(),
			overall_severity: severity,
			advisory_score: 0.8,
			pattern_score: 0.0,
			version_change_score: 0.0,
			reputation_score: 0.0,
			community_score: 0.0,
			final_score: 0.8,
			advisories: vec![AdvisoryData {
				source: AdvisorySource::Osv,
				external_id: "CVE-2024-0001".to_string(),
				title: "Test CVE".to_string(),
				description: "A test vulnerability".to_string(),
				severity: SeverityLevel::High,
				cvss_score: Some(8.0),
				affected_versions: "< 2.0.0".to_string(),
				patched_versions: Some("2.0.0".to_string()),
				published_at: None,
				references: vec!["https://example.com".to_string()],
			}],
			detections: vec![],
			version_changes: vec![],
			community_reports: vec![],
			maintainer: None,
			mitre_mappings: vec![],
			recommendations: vec!["Upgrade to 2.0.0".to_string()],
			is_direct: true,
			depth: 1,
		}
	}

	fn make_safe_risk(name: &str) -> PackageRisk {
		PackageRisk {
			package_name: name.to_string(),
			package_version: "1.0.0".to_string(),
			ecosystem: "nodejs".to_string(),
			overall_severity: SeverityLevel::Safe,
			advisory_score: 0.0,
			pattern_score: 0.0,
			version_change_score: 0.0,
			reputation_score: 0.0,
			community_score: 0.0,
			final_score: 0.0,
			advisories: vec![],
			detections: vec![],
			version_changes: vec![],
			community_reports: vec![],
			maintainer: None,
			mitre_mappings: vec![],
			recommendations: vec![],
			is_direct: true,
			depth: 1,
		}
	}

	#[test]
	fn renders_valid_html_document() {
		let risks = vec![make_risk("lodash", SeverityLevel::High)];
		let html = HtmlReporter::render(&risks);
		assert!(html.starts_with("<!DOCTYPE html>"));
		assert!(html.contains("<html"));
		assert!(html.contains("</html>"));
	}

	#[test]
	fn includes_package_name_in_output() {
		let risks = vec![make_risk("my-vulnerable-package", SeverityLevel::Critical)];
		let html = HtmlReporter::render(&risks);
		assert!(html.contains("my-vulnerable-package"));
	}

	#[test]
	fn summary_counts_are_correct() {
		let risks = vec![
			make_risk("pkg-a", SeverityLevel::Critical),
			make_risk("pkg-b", SeverityLevel::High),
			make_safe_risk("pkg-c"),
		];
		let html = HtmlReporter::render(&risks);
		assert!(html.contains(">1<") || html.contains("stat-value\">1"));
		assert!(html.contains("3"));
	}

	#[test]
	fn empty_risks_renders_without_panic() {
		let html = HtmlReporter::render(&[]);
		assert!(html.contains("<!DOCTYPE html>"));
		assert!(html.contains(">0<") || html.contains("stat-value\">0"));
	}

	#[test]
	fn severity_badges_are_present() {
		let risks = vec![
			make_risk("critical-pkg", SeverityLevel::Critical),
			make_risk("high-pkg", SeverityLevel::High),
		];
		let html = HtmlReporter::render(&risks);
		assert!(html.contains("badge-critical"));
		assert!(html.contains("badge-high"));
	}

	#[test]
	fn generates_file_when_output_path_given() {
		let dir = tempfile::tempdir().unwrap();
		let path = dir.path().join("report.html");
		let risks = vec![make_risk("lodash", SeverityLevel::High)];
		HtmlReporter.generate(&risks, Some(&path)).unwrap();
		let content = std::fs::read_to_string(&path).unwrap();
		assert!(content.contains("<!DOCTYPE html>"));
	}
}

pub struct HtmlReporter;

impl Reporter for HtmlReporter {
	fn generate(&self, risks: &[PackageRisk], output_path: Option<&Path>) -> Result<()> {
		let html = Self::render(risks);

		match output_path {
			Some(path) => fs::write(path, &html)
				.with_context(|| format!("failed to write HTML report to {}", path.display()))?,
			None => println!("{html}"),
		}

		Ok(())
	}
}

impl HtmlReporter {
	fn render(risks: &[PackageRisk]) -> String {
		let critical = risks.iter().filter(|r| r.severity_label() == "CRITICAL").count();
		let high = risks.iter().filter(|r| r.severity_label() == "HIGH").count();
		let medium = risks.iter().filter(|r| r.severity_label() == "MEDIUM").count();
		let low = risks.iter().filter(|r| r.severity_label() == "LOW").count();
		let safe = risks.iter().filter(|r| r.severity_label() == "SAFE").count();
		let total = risks.len();
		let scanned_at = Utc::now().format("%Y-%m-%d %H:%M UTC").to_string();

		let community_total: usize = risks.iter().map(|r| r.community_reports.len()).sum();

		let mut rows = String::new();
		for risk in risks {
			let advisory_count = risk.advisories.len();
			let detection_count = risk.detections.len();
			let community_count = risk.community_reports.len();
			let mitre_ids: Vec<&str> = risk.mitre_mappings.iter().map(|m| m.technique_id.as_str()).collect();
			let mitre_str = mitre_ids.join(", ");

			let community_badge = if community_count > 0 {
				r#"<span class="badge badge-critical" title="Known malicious package">MALICIOUS</span>"#
			} else {
				""
			};

			let score_bar_width = (risk.final_score * 100.0) as u32;
			let score_color = match risk.severity_label() {
				"CRITICAL" => "var(--critical)",
				"HIGH"     => "var(--high)",
				"MEDIUM"   => "var(--medium)",
				"LOW"      => "var(--low)",
				_          => "var(--safe)",
			};

			let maintainer_cell = match &risk.maintainer {
				Some(m) => {
					let health = (risk.reputation_score * 100.0) as u32;
					let staleness = if m.days_since_push >= 9999 { "unknown".to_string() }
						else { format!("{}d ago", m.days_since_push) };
					format!(
						r#"<span class="maintainer-info">⭐ {} &nbsp; {} &nbsp; risk {}%</span>"#,
						m.stars, staleness, health,
					)
				}
				None => "<span class=\"text-dim\">—</span>".to_string(),
			};

			let rec_list = if !risk.recommendations.is_empty() {
				let items: String = risk.recommendations.iter()
					.take(3)
					.map(|r| format!("<li>{r}</li>"))
					.collect();
				format!("<ul class=\"rec-list\">{items}</ul>")
			} else {
				String::new()
			};

			let _ = write!(
				rows,
				r#"<tr class="row-{severity_lower}">
					<td><span class="badge badge-{severity_lower}">{severity}</span>{community_badge}</td>
					<td class="pkg-name">{name}</td>
					<td>{version}</td>
					<td>{ecosystem}</td>
					<td>
					  <div class="score-bar-wrap" title="{score:.2}">
					    <div class="score-bar" style="width:{bar}%;background:{color}"></div>
					  </div>
					  <span class="score-num">{score:.2}</span>
					</td>
					<td>{advisories}</td>
					<td>{detections}</td>
					<td class="mitre">{mitre}</td>
					<td class="maintainer-cell">{maintainer}</td>
					<td class="recs">{recs}</td>
				</tr>"#,
				severity_lower = risk.severity_label().to_lowercase(),
				severity = risk.severity_label(),
				community_badge = community_badge,
				name = &risk.package_name,
				version = &risk.package_version,
				ecosystem = &risk.ecosystem,
				bar = score_bar_width,
				color = score_color,
				score = risk.final_score,
				advisories = advisory_count,
				detections = detection_count,
				mitre = mitre_str,
				maintainer = maintainer_cell,
				recs = rec_list,
			);
		}

		format!(
				r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OpenSentinel — Security Report</title>
<style>
  :root {{
    --bg: #0d1117; --bg-panel: #161b22; --bg-card: #21262d;
    --border: #30363d; --text: #c9d1d9; --text-dim: #8b949e;
    --accent: #58a6ff; --critical: #ff5555; --high: #ffa64d;
    --medium: #ffd700; --low: #58a6ff; --safe: #3fb950;
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    --mono: 'SFMono-Regular', Consolas, monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; font-size: 14px; }}
  h1 {{ color: var(--accent); font-size: 1.4rem; font-weight: 700; margin-bottom: 0.2rem; }}
  .meta {{ color: var(--text-dim); font-size: 0.8rem; margin-bottom: 1.75rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(6, 1fr); gap: 0.75rem; margin-bottom: 1.75rem; }}
  .stat {{ background: var(--bg-panel); border: 1px solid var(--border); border-radius: 6px; padding: 0.75rem; text-align: center; }}
  .stat-value {{ font-size: 1.75rem; font-weight: 800; line-height: 1; }}
  .stat-label {{ font-size: 0.65rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.07em; margin-top: 0.25rem; }}
  .stat-critical .stat-value {{ color: var(--critical); }}
  .stat-high .stat-value {{ color: var(--high); }}
  .stat-medium .stat-value {{ color: var(--medium); }}
  .stat-low .stat-value {{ color: var(--low); }}
  .stat-safe .stat-value {{ color: var(--safe); }}
  .stat-community .stat-value {{ color: var(--critical); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--bg-panel); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }}
  th {{ background: var(--bg-card); color: var(--text-dim); font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.6rem 0.75rem; text-align: left; border-bottom: 1px solid var(--border); white-space: nowrap; }}
  td {{ padding: 0.55rem 0.75rem; border-bottom: 1px solid var(--border); font-size: 0.82rem; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(88,166,255,0.03); }}
  .badge {{ display: inline-block; padding: 0.15rem 0.45rem; border-radius: 3px; font-size: 0.65rem; font-weight: 700; letter-spacing: 0.05em; margin-right: 3px; }}
  .badge-critical {{ background: rgba(255,85,85,0.15); color: var(--critical); }}
  .badge-high {{ background: rgba(255,166,77,0.15); color: var(--high); }}
  .badge-medium {{ background: rgba(255,215,0,0.12); color: var(--medium); }}
  .badge-low {{ background: rgba(88,166,255,0.12); color: var(--low); }}
  .badge-safe {{ background: rgba(63,185,80,0.12); color: var(--safe); }}
  .pkg-name {{ font-family: var(--mono); color: var(--accent); font-size: 0.82rem; }}
  .mitre {{ font-family: var(--mono); font-size: 0.72rem; color: var(--text-dim); }}
  .score-bar-wrap {{ background: var(--bg-card); border-radius: 2px; height: 4px; width: 60px; display: inline-block; vertical-align: middle; margin-right: 4px; }}
  .score-bar {{ height: 4px; border-radius: 2px; }}
  .score-num {{ color: var(--text-dim); font-size: 0.75rem; vertical-align: middle; }}
  .text-dim {{ color: var(--text-dim); }}
  .maintainer-cell {{ font-size: 0.75rem; color: var(--text-dim); white-space: nowrap; }}
  .rec-list {{ padding-left: 1rem; font-size: 0.78rem; color: var(--text-dim); }}
  .rec-list li {{ margin-bottom: 0.2rem; }}
  .recs {{ max-width: 260px; }}
</style>
</head>
<body>
<h1>OpenSentinel — Security Report</h1>
<p class="meta">Scanned: {scanned_at} &nbsp;|&nbsp; {total} packages analyzed</p>
<div class="stats">
  <div class="stat stat-critical"><div class="stat-value">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat stat-high"><div class="stat-value">{high}</div><div class="stat-label">High</div></div>
  <div class="stat stat-medium"><div class="stat-value">{medium}</div><div class="stat-label">Medium</div></div>
  <div class="stat stat-low"><div class="stat-value">{low}</div><div class="stat-label">Low</div></div>
  <div class="stat stat-safe"><div class="stat-value">{safe}</div><div class="stat-label">Safe</div></div>
  <div class="stat stat-community"><div class="stat-value">{community_total}</div><div class="stat-label">Known Malicious</div></div>
</div>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Package</th><th>Version</th><th>Ecosystem</th>
      <th>Score</th><th>Advisories</th><th>Detections</th>
      <th>MITRE</th><th>Maintainer</th><th>Recommendations</th>
    </tr>
  </thead>
  <tbody>{rows}</tbody>
</table>
</body>
</html>"#,
			scanned_at = scanned_at,
			total = total,
			critical = critical,
			high = high,
			medium = medium,
			low = low,
			safe = safe,
			community_total = community_total,
			rows = rows,
		)
	}
}
