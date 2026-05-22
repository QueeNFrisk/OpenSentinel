#![allow(unused_imports)]
pub mod ast;
pub mod credential;
pub mod install_hook;
pub mod typosquatting;
pub mod patterns;
pub mod models;
pub mod version_behavior;
pub mod version_resolver;
pub mod behavioral;
pub mod behavioral_ast;

pub use models::{AnalysisResult, DetectionMatch};
pub use behavioral::BehavioralAnalyzer;
