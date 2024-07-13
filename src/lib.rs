mod header_analyzer;

use regex::Regex;
use reqwest::blocking::ClientBuilder;
use reqwest::header::HeaderMap;
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead};
use std::time::Duration;
use rand::seq::SliceRandom;
use rand::Rng;
use header_analyzer::HeaderAnalyzer;

pub fn read_urls_from_file(filename: &str) -> io::Result<Vec<String>> {
    let file = File::open(filename)?;
    let reader = io::BufReader::new(file);
    reader.lines().collect()
}

fn get_random_user_agent() -> &'static str {
    let user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Mobile/15E148 Safari/604.1",
    ];
    user_agents.choose(&mut rand::thread_rng()).unwrap()
}

pub fn check_headers(url: &str) -> Result<(String, HeaderMap), String> {
    let mut rng = rand::thread_rng();
    
    let client = ClientBuilder::new()
        .timeout(Duration::from_secs(10))
        .user_agent(get_random_user_agent())
        .build()
        .map_err(|e| e.to_string())?;

    // Random delay between 1 and 5 seconds
    std::thread::sleep(Duration::from_millis(rng.gen_range(1000..5000)));

    let response = client.head(url).send().map_err(|e| e.to_string())?;
    Ok((url.to_string(), response.headers().clone()))
}

pub fn search_headers(
    urls: &[String],
    search_params: &[&str],
    exploit_patterns: &[&str],
) -> HashMap<String, Vec<(String, u32, String)>> {
    let analyzer = HeaderAnalyzer::new();
    let regex_patterns: Vec<Regex> = exploit_patterns
        .iter()
        .map(|&pattern| Regex::new(pattern).unwrap())
        .collect();

    urls.iter()
        .filter_map(|url| {
            match check_headers(url) {
                Ok((url, headers)) => {
                    let mut matches = Vec::new();

                    for &param in search_params {
                        if let Some(value) = headers.get(param) {
                            if let Some((header, score, suggestion)) = analyzer.analyze_header(param, value.to_str().unwrap_or("")) {
                                matches.push((header, score, suggestion));
                            }
                        }
                    }

                    for (key, value) in headers.iter() {
                        let key_str = key.as_str();
                        let value_str = value.to_str().unwrap_or("");

                        if let Some((header, score, suggestion)) = analyzer.analyze_header(key_str, value_str) {
                            matches.push((header, score, suggestion));
                        } else {
                            for pattern in &regex_patterns {
                                if pattern.is_match(key_str) || pattern.is_match(value_str) {
                                    matches.push((format!("Pattern match - {}: {:?}", key, value), 1, "Matched a known exploit pattern.".to_string()));
                                    break;
                                }
                            }
                        }
                    }

                    if !matches.is_empty() {
                        Some((url, matches))
                    } else {
                        None
                    }
                }
                Err(e) => {
                    println!("{} generated an exception: {}", url, e);
                    None
                }
            }
        })
        .collect()
}
