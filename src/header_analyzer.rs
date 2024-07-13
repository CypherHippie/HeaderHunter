use std::collections::HashMap;

pub struct HeaderAnalyzer {
    whitelist: Vec<String>,
    severity_scores: HashMap<String, u32>,
    version_vulnerabilities: HashMap<String, Vec<String>>,
    suggestions: HashMap<String, String>,
}

impl HeaderAnalyzer {
    pub fn new() -> Self {
        let mut analyzer = HeaderAnalyzer {
            whitelist: vec!["User-Agent".to_string(), "Accept".to_string()],
            severity_scores: HashMap::new(),
            version_vulnerabilities: HashMap::new(),
            suggestions: HashMap::new(),
        };

        // Populate data
        analyzer.severity_scores.insert("Server".to_string(), 3);
        analyzer.severity_scores.insert("X-Powered-By".to_string(), 5);
        analyzer.severity_scores.insert("Content-Type".to_string(), 2);
        analyzer.severity_scores.insert("Set-Cookie".to_string(), 4);
        analyzer.severity_scores.insert("X-AspNet-Version".to_string(), 5);
        analyzer.severity_scores.insert("X-AspNetMvc-Version".to_string(), 5);
        analyzer.severity_scores.insert("X-Frame-Options".to_string(), 3);
        analyzer.severity_scores.insert("X-XSS-Protection".to_string(), 3);
        analyzer.severity_scores.insert("Strict-Transport-Security".to_string(), 3);
        analyzer.severity_scores.insert("X-Content-Type-Options".to_string(), 3);
        analyzer.severity_scores.insert("Referrer-Policy".to_string(), 3);
        analyzer.severity_scores.insert("Feature-Policy".to_string(), 3);
        analyzer.severity_scores.insert("Permissions-Policy".to_string(), 3);
        analyzer.severity_scores.insert("Access-Control-Allow-Origin".to_string(), 3);
        analyzer.severity_scores.insert("Access-Control-Allow-Credentials".to_string(), 3);

        analyzer.version_vulnerabilities.insert(
            "Server".to_string(), 
            vec!["Apache/2.4.49".to_string(), "nginx/1.18.0".to_string(), "IIS/10.0".to_string()]
        );

        analyzer.version_vulnerabilities.insert(
            "X-Powered-By".to_string(),
            vec!["PHP/5.6".to_string(), "ASP.NET".to_string()]
        );

        analyzer.suggestions.insert("Server".to_string(), "Consider hiding the server version to avoid revealing potential vulnerabilities.".to_string());
        analyzer.suggestions.insert("X-Powered-By".to_string(), "Remove the X-Powered-By header to prevent disclosing the technology stack.".to_string());
        analyzer.suggestions.insert("Content-Type".to_string(), "Ensure Content-Type headers specify a charset (e.g., charset=UTF-8) to prevent charset-related attacks.".to_string());
        analyzer.suggestions.insert("Set-Cookie".to_string(), "Ensure cookies are set with HttpOnly, Secure, and SameSite attributes for better security.".to_string());
        analyzer.suggestions.insert("X-AspNet-Version".to_string(), "Remove the X-AspNet-Version header to prevent disclosing the framework version.".to_string());
        analyzer.suggestions.insert("X-AspNetMvc-Version".to_string(), "Remove the X-AspNetMvc-Version header to prevent disclosing the framework version.".to_string());
        analyzer.suggestions.insert("X-Frame-Options".to_string(), "Set X-Frame-Options to DENY or SAMEORIGIN to protect against clickjacking attacks.".to_string());
        analyzer.suggestions.insert("X-XSS-Protection".to_string(), "Ensure X-XSS-Protection is set to '1; mode=block' to enable XSS filtering.".to_string());
        analyzer.suggestions.insert("Strict-Transport-Security".to_string(), "Ensure HSTS is properly configured to enforce HTTPS connections.".to_string());
        analyzer.suggestions.insert("X-Content-Type-Options".to_string(), "Set X-Content-Type-Options to 'nosniff' to prevent MIME type sniffing.".to_string());
        analyzer.suggestions.insert("Referrer-Policy".to_string(), "Set a Referrer-Policy to control the amount of referrer information sent with requests.".to_string());
        analyzer.suggestions.insert("Feature-Policy".to_string(), "Implement a Feature-Policy to control which features can be used in the browser.".to_string());
        analyzer.suggestions.insert("Permissions-Policy".to_string(), "Implement a Permissions-Policy to control which permissions can be used in the browser.".to_string());
        analyzer.suggestions.insert("Access-Control-Allow-Origin".to_string(), "Ensure Access-Control-Allow-Origin is properly configured to prevent unauthorized cross-origin requests.".to_string());
        analyzer.suggestions.insert("Access-Control-Allow-Credentials".to_string(), "Ensure Access-Control-Allow-Credentials is properly configured to prevent unauthorized cross-origin credentials sharing.".to_string());

        analyzer
    }

    pub fn analyze_header(&self, key: &str, value: &str) -> Option<(String, u32, String)> {
        if self.whitelist.contains(&key.to_string()) {
            return None;
        }

        let score = self.calculate_severity(key, value);
        if score > 0 {
            let suggestion = self.suggestions.get(key).unwrap_or(&"No suggestion available.".to_string()).clone();
            Some((format!("{}: {}", key, value), score, suggestion))
        } else {
            None
        }
    }

    fn calculate_severity(&self, key: &str, value: &str) -> u32 {
        let base_score = *self.severity_scores.get(key).unwrap_or(&0);
        
        let additional_score = match key {
            "Server" => self.check_server_version(value),
            "X-Powered-By" => 5, //: always consider this header interesting
            "Content-Type" => self.check_content_type(value),
            "Set-Cookie" => self.check_set_cookie(value),
            _ => 0,
        };

        base_score + additional_score
    }

    fn check_server_version(&self, version: &str) -> u32 {
        if let Some(vulnerabilities) = self.version_vulnerabilities.get("Server") {
            if vulnerabilities.iter().any(|v| version.contains(v)) {
                return 10; // High severity for known vulnerable versions
            }
        }
        0
    }

    fn check_content_type(&self, content_type: &str) -> u32 {
        if content_type.contains("text/html") && !content_type.contains("charset=UTF-8") {
            return 2; //  missing charset in HTML content
        }
        0
    }

    fn check_set_cookie(&self, cookie: &str) -> u32 {
        let mut score = 0;
        if !cookie.contains("HttpOnly") {
            score += 2;
        }
        if !cookie.contains("Secure") {
            score += 2;
        }
        if !cookie.contains("SameSite") {
            score += 1;
        }
        score
    }
}
