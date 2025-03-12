use regex::Regex;
use std::error::Error;
use tempfile::NamedTempFile;
use time::Duration;
use url::Url;
use base64;

fn demonstrate_vulnerabilities() -> Result<(), Box<dyn Error>> {
    // Regex ReDoS (CVE-2017-18589)
    let pattern = Regex::new(r"^(\w+)+$")?;
    let malicious_input = "a".repeat(100) + "!";
    let _ = pattern.is_match(&malicious_input);

    // Time Duration overflow (CVE-2020-26235)
    let _ = Duration::weeks(i64::MAX);

    // Tempfile TOCTOU (CVE-2018-20997)
    let file = NamedTempFile::new()?;
    println!("Temp file: {:?}", file.path());

    // Base64 panic (CVE-2017-1000430)
    let invalid_base64 = "====";
    let _ = base64::decode(invalid_base64);

    // URL parsing vulnerability (CVE-2019-16144)
    let malicious_url = "http://example.com/".to_string() + &"a".repeat(65535);
    let _ = Url::parse(&malicious_url)?;

    Ok(())
}

fn main() {
    if let Err(e) = demonstrate_vulnerabilities() {
        eprintln!("Error: {}", e);
    }
} 