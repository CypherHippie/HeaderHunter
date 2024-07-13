use header_checker::{read_urls_from_file, search_headers};

fn main() {
    let url_file = "wayback_urls.txt"; // change the name of the file for the one that u want to test

    let urls = match read_urls_from_file(url_file) {
        Ok(urls) => urls,
        Err(e) => {
            eprintln!("Error reading URLs file: {}", e);
            return;
        }
    };

    let search_params = vec!["Server", "X-Powered-By", "Content-Type"];

    let exploit_patterns = vec![
        r"session", r"cookie", r"auth", r"token", r"jwt", r"key", r"api[-_]?key", r"secret",
        r"password", r"credentials", r"oauth", r"admin", r"root", r"user", r"username", r"email",
        r"x-frame-options", r"content-security-policy", r"strict-transport-security",
        r"x-xss-protection", r"x-content-type-options", r"referrer-policy", r"feature-policy",
        r"permissions-policy", r"x-powered-by", r"server", r"x-aspnet-version", r"x-runtime",
        r"x-version", r"x-debug", r"debug", r"trace", r"internal", r"cache-control", r"etag",
        r"if-none-match", r"access-control-allow-origin", r"access-control-allow-credentials",
        r"access-control-expose-headers", r"location", r"origin", r"referer", r"x-forwarded-for",
        r"x-real-ip", r"x-requested-with", r"x-", r"vulnerable", r"cvss", r"cve",
    ];

    let results = search_headers(&urls, &search_params, &exploit_patterns);

    for (url, matches) in results {
        println!("\nURL: {}", url);
        for (header, score, suggestion) in matches {
            println!("  {} (Severity: {}): {}", header, score, suggestion);
        }
    }
}
