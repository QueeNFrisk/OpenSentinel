use opensentinel::advisory::osv::OsvClient;
use opensentinel::database::models::SeverityLevel;

#[tokio::test]
async fn returns_empty_vec_when_no_vulnerabilities_found() {
	let mut server = mockito::Server::new_async().await;

	let _mock = server
		.mock("POST", "/v1/query")
		.with_status(200)
		.with_header("content-type", "application/json")
		.with_body(r#"{}"#)
		.create_async()
		.await;

	let client = OsvClient::with_base_url(&server.url());
	let result = client.query("safe-package", "1.0.0", "nodejs").await.unwrap();

	assert!(result.is_empty());
}

#[tokio::test]
async fn parses_single_vulnerability_with_cvss_score() {
	let mut server = mockito::Server::new_async().await;

	let body = r#"{
		"vulns": [
			{
				"id": "GHSA-xxxx-yyyy-zzzz",
				"summary": "Prototype Pollution in lodash",
				"details": "Versions before 4.17.21 are vulnerable.",
				"published": "2021-05-19T00:00:00Z",
				"severity": [{"score": "7.4"}],
				"affected": [],
				"references": [{"url": "https://github.com/advisories/GHSA-xxxx"}]
			}
		]
	}"#;

	let _mock = server
		.mock("POST", "/v1/query")
		.with_status(200)
		.with_header("content-type", "application/json")
		.with_body(body)
		.create_async()
		.await;

	let client = OsvClient::with_base_url(&server.url());
	let result = client.query("lodash", "4.17.20", "nodejs").await.unwrap();

	assert_eq!(result.len(), 1);
	let advisory = &result[0];
	assert_eq!(advisory.external_id, "GHSA-xxxx-yyyy-zzzz");
	assert_eq!(advisory.severity, SeverityLevel::High);
	assert!((advisory.cvss_score.unwrap() - 7.4).abs() < 0.01);
	assert_eq!(advisory.references.len(), 1);
}

#[tokio::test]
async fn maps_nodejs_ecosystem_to_npm() {
	let mut server = mockito::Server::new_async().await;

	let _mock = server
		.mock("POST", "/v1/query")
		.match_body(mockito::Matcher::PartialJsonString(
			r#"{"package":{"ecosystem":"npm"}}"#.to_string(),
		))
		.with_status(200)
		.with_header("content-type", "application/json")
		.with_body(r#"{}"#)
		.create_async()
		.await;

	let client = OsvClient::with_base_url(&server.url());
	let _ = client.query("express", "4.18.0", "nodejs").await;

	_mock.assert_async().await;
}

#[tokio::test]
async fn maps_bun_ecosystem_to_npm() {
	let mut server = mockito::Server::new_async().await;

	let _mock = server
		.mock("POST", "/v1/query")
		.match_body(mockito::Matcher::PartialJsonString(
			r#"{"package":{"ecosystem":"npm"}}"#.to_string(),
		))
		.with_status(200)
		.with_header("content-type", "application/json")
		.with_body(r#"{}"#)
		.create_async()
		.await;

	let client = OsvClient::with_base_url(&server.url());
	let _ = client.query("hono", "4.0.0", "bun").await;

	_mock.assert_async().await;
}

#[tokio::test]
async fn critical_cvss_score_above_nine_maps_to_critical() {
	let mut server = mockito::Server::new_async().await;

	let body = r#"{
		"vulns": [{
			"id": "CVE-2024-1234",
			"summary": "Critical vuln",
			"details": "details",
			"published": "2024-01-01T00:00:00Z",
			"severity": [{"score": "9.8"}],
			"affected": [],
			"references": []
		}]
	}"#;

	let _mock = server
		.mock("POST", "/v1/query")
		.with_status(200)
		.with_header("content-type", "application/json")
		.with_body(body)
		.create_async()
		.await;

	let client = OsvClient::with_base_url(&server.url());
	let result = client.query("pkg", "1.0.0", "npm").await.unwrap();

	assert_eq!(result[0].severity, SeverityLevel::Critical);
}
