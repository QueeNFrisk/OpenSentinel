use crate::database::models::PatternType;
use super::models::DetectionMatch;

const POPULAR_PACKAGES: &[&str] = &[
	"react", "lodash", "express", "axios", "webpack", "babel", "typescript",
	"eslint", "prettier", "jest", "mocha", "chai", "sinon", "moment", "dayjs",
	"underscore", "jquery", "vue", "angular", "next", "nuxt", "gatsby",
	"tailwindcss", "bootstrap", "styled-components", "emotion", "sass",
	"dotenv", "cors", "helmet", "morgan", "passport", "bcrypt", "jsonwebtoken",
	"mongoose", "sequelize", "prisma", "knex", "typeorm", "redis", "bull",
	"socket.io", "ws", "nodemailer", "multer", "sharp", "jimp", "pdf-lib",
	"zod", "yup", "joi", "ajv", "uuid", "nanoid", "crypto-js", "node-fetch",
];

pub struct TyposquattingDetector;

impl TyposquattingDetector {
	pub fn check(package_name: &str) -> Option<DetectionMatch> {
		for popular in POPULAR_PACKAGES {
			if package_name == *popular {
				return None;
			}

			let distance = Self::levenshtein(package_name, popular);
			if distance > 0 && distance <= 2 {
				return Some(DetectionMatch {
					pattern_type: PatternType::Typosquatting,
					description: format!(
							"package '{package_name}' is similar to popular package '{popular}' (edit distance: {distance})"
					),
					file_path: None,
					line_number: None,
					code_snippet: None,
					confidence: if distance == 1 { 0.75 } else { 0.5 },
				});
			}
		}

		None
	}

	fn levenshtein(a: &str, b: &str) -> usize {
		let a: Vec<char> = a.chars().collect();
		let b: Vec<char> = b.chars().collect();
		let m = a.len();
		let n = b.len();

		if m == 0 { return n; }
		if n == 0 { return m; }

		let mut dp = vec![vec![0usize; n + 1]; m + 1];

		for i in 0..=m { dp[i][0] = i; }
		for j in 0..=n { dp[0][j] = j; }

		for i in 1..=m {
			for j in 1..=n {
				dp[i][j] = if a[i - 1] == b[j - 1] {
					dp[i - 1][j - 1]
				} else {
					1 + dp[i - 1][j].min(dp[i][j - 1]).min(dp[i - 1][j - 1])
				};
			}
		}

		dp[m][n]
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn levenshtein_identical_strings_returns_zero() {
		assert_eq!(TyposquattingDetector::levenshtein("react", "react"), 0);
	}

	#[test]
	fn levenshtein_single_substitution() {
		assert_eq!(TyposquattingDetector::levenshtein("reakt", "react"), 1);
	}

	#[test]
	fn levenshtein_empty_strings() {
		assert_eq!(TyposquattingDetector::levenshtein("", ""), 0);
		assert_eq!(TyposquattingDetector::levenshtein("abc", ""), 3);
		assert_eq!(TyposquattingDetector::levenshtein("", "abc"), 3);
	}

	#[test]
	fn exact_popular_package_name_not_flagged() {
		assert!(TyposquattingDetector::check("react").is_none());
		assert!(TyposquattingDetector::check("lodash").is_none());
		assert!(TyposquattingDetector::check("express").is_none());
	}

	#[test]
	fn one_char_typo_flagged_with_high_confidence() {
		let result = TyposquattingDetector::check("reakt");
		assert!(result.is_some());
		let detection = result.unwrap();
		assert!((detection.confidence - 0.75).abs() < 0.001);
		assert!(detection.description.contains("react"));
	}

	#[test]
	fn two_char_typo_flagged_with_lower_confidence() {
		let result = TyposquattingDetector::check("xxdash");
		assert!(result.is_some());
		let detection = result.unwrap();
		assert!((detection.confidence - 0.5).abs() < 0.001);
	}

	#[test]
	fn unrelated_package_not_flagged() {
		assert!(TyposquattingDetector::check("my-totally-unique-package-xyz123").is_none());
	}

	#[test]
	fn three_char_difference_not_flagged() {
		assert!(TyposquattingDetector::check("xreactyy").is_none());
	}
}
