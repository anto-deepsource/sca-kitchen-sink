use regex::Regex;
use std::error::Error;
use tempfile::NamedTempFile;
use time::Duration;
use url::Url;
use base64;

fn demonstrate_vulnerabilities() -> Result<(), Box<dyn Error>> {
    let pattern = Regex::new(r"^(\w+)+$")?;
    let malicious_input = "a".repeat(100) + "!";
    let _ = pattern.is_match(&malicious_input);

    let _ = Duration::weeks(i64::MAX);

    let file = NamedTempFile::new()?;
    println!("Temp file: {:?}", file.path());

    let invalid_base64 = "====";
    let _ = base64::decode(invalid_base64);

    let malicious_url = "http://example.com/".to_string() + &"a".repeat(65535);
    let _ = Url::parse(&malicious_url)?;

    Ok(())
}

fn main() {
    if let Err(e) = demonstrate_vulnerabilities() {
        eprintln!("Error: {}", e);
    }
} 