use crate::{
    edit_packet_by_pattern,
    lexer::{pattern_lexer, PatternToken},
};

use anyhow::{anyhow, Result};
use std::sync::OnceLock;

static PATTERNS: OnceLock<Vec<(Vec<PatternToken>, Vec<PatternToken>)>> = OnceLock::new();

pub async fn compile_patterns(patterns: Vec<(String, String)>) {
    let mut compiled_patterns = Vec::new();

    for (pattern, replacement) in patterns {
        compiled_patterns.push((pattern_lexer(pattern), pattern_lexer(replacement)));
    }

    PATTERNS
        .set(compiled_patterns)
        .expect("Failed to set PATTERNS global");
}

pub async fn process_packet(packet: &mut Vec<u8>) -> Result<()> {
    let patterns = PATTERNS.get().ok_or(anyhow!("Failed to read PATTERNS."))?;

    patterns.iter().for_each(|(pattern, replacement)| {
        edit_packet_by_pattern(pattern.clone(), replacement.clone(), packet);
    });

    Ok(())
}
