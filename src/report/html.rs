use anyhow::{Context, Result};
use chrono::Utc;
use std::fmt::Write as FmtWrite;
use std::fs;
use std::path::Path;

use crate::scoring::models::PackageRisk;
use super::Reporter;

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

		let mut rows = String::new();
		for risk in risks {
			let advisory_count = risk.advisories.len();
			let detection_count = risk.detections.len();
			let mitre_ids: Vec<&str> = risk.mitre_mappings.iter().map(|m| m.technique_id.as_str()).collect();
			let mitre_str = mitre_ids.join(", ");

			let _ = write!(
				rows,
				r#"<tr class="row-{severity_lower}">
					<td><span class="badge badge-{severity_lower}">{severity}</span></td>
					<td class="pkg-name">{name}</td>
					<td>{version}</td>
					<td>{ecosystem}</td>
					<td>{advisories}</td>
					<td>{detections}</td>
					<td class="mitre">{mitre}</td>
				</tr>"#,
				severity_lower = risk.severity_label().to_lowercase(),
				severity = risk.severity_label(),
				name = risk.package_name,
				version = risk.package_version,
				ecosystem = risk.ecosystem,
				advisories = advisory_count,
				detections = detection_count,
				mitre = mitre_str,
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
    --font: -apple-system, BlinkMacSystemFont, 'Segoe UI', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  h1 {{ color: var(--accent); font-size: 1.5rem; margin-bottom: 0.25rem; }}
  .meta {{ color: var(--text-dim); font-size: 0.85rem; margin-bottom: 2rem; }}
  .stats {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 1rem; margin-bottom: 2rem; }}
  .stat {{ background: var(--bg-panel); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }}
  .stat-value {{ font-size: 2rem; font-weight: bold; }}
  .stat-label {{ font-size: 0.75rem; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.05em; }}
  .stat-critical .stat-value {{ color: var(--critical); }}
  .stat-high .stat-value {{ color: var(--high); }}
  .stat-medium .stat-value {{ color: var(--medium); }}
  .stat-low .stat-value {{ color: var(--low); }}
  .stat-safe .stat-value {{ color: var(--safe); }}
  table {{ width: 100%; border-collapse: collapse; background: var(--bg-panel); border-radius: 8px; overflow: hidden; border: 1px solid var(--border); }}
  th {{ background: var(--bg-card); color: var(--text-dim); font-size: 0.75rem; text-transform: uppercase; letter-spacing: 0.05em; padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
  td {{ padding: 0.65rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.875rem; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: rgba(88,166,255,0.04); }}
  .badge {{ display: inline-block; padding: 0.2rem 0.5rem; border-radius: 4px; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.05em; }}
  .badge-critical {{ background: rgba(255,85,85,0.15); color: var(--critical); }}
  .badge-high {{ background: rgba(255,166,77,0.15); color: var(--high); }}
  .badge-medium {{ background: rgba(255,215,0,0.15); color: var(--medium); }}
  .badge-low {{ background: rgba(88,166,255,0.15); color: var(--low); }}
  .badge-safe {{ background: rgba(63,185,80,0.15); color: var(--safe); }}
  .pkg-name {{ font-family: monospace; color: var(--accent); }}
  .mitre {{ font-family: monospace; font-size: 0.75rem; color: var(--text-dim); }}
</style>
</head>
<body>
<h1>OpenSentinel — Security Report</h1>
<p class="meta">Scanned: {scanned_at} &nbsp;|&nbsp; Total packages: {total}</p>
<div class="stats">
  <div class="stat stat-critical"><div class="stat-value">{critical}</div><div class="stat-label">Critical</div></div>
  <div class="stat stat-high"><div class="stat-value">{high}</div><div class="stat-label">High</div></div>
  <div class="stat stat-medium"><div class="stat-value">{medium}</div><div class="stat-label">Medium</div></div>
  <div class="stat stat-low"><div class="stat-value">{low}</div><div class="stat-label">Low</div></div>
  <div class="stat stat-safe"><div class="stat-value">{safe}</div><div class="stat-label">Safe</div></div>
</div>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Package</th><th>Version</th>
      <th>Ecosystem</th><th>Advisories</th><th>Detections</th><th>MITRE</th>
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
			rows = rows,
		)
	}
}
