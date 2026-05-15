#![allow(unused_imports)]
pub mod ast;
pub mod credential;
pub mod install_hook;
pub mod typosquatting;
pub mod patterns;
pub mod models;

pub use models::{AnalysisResult, DetectionMatch};
