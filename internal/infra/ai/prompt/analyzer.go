package prompt

import (
    "encoding/json"
    "regexp"
    "strings"
)

// AnalyzeFileContent inspects file content for secrets/risks and returns a JSON string
// matching the required schema. It never prints; it only returns the JSON string.
func AnalyzeFileContent(fileURL string, fileContent string) string {
    type Finding struct {
        Title          string `json:"title"`
        Severity       string `json:"severity"`
        Summary        string `json:"summary"`
        Recommendation string `json:"recommendation"`
    }

    type Counts struct {
        Critical int `json:"critical"`
        High     int `json:"high"`
        Medium   int `json:"medium"`
        Low      int `json:"low"`
        Total    int `json:"total"`
    }

    type Output struct {
        FileURL  string    `json:"file_url"`
        Counts   Counts    `json:"counts"`
        Findings []Finding `json:"findings"`
        Advice   string    `json:"advice"`
    }

    // Normalize for easier checks
    content := fileContent
    lower := strings.ToLower(content)

    // Helper to keep summaries concise
    trim := func(s string, n int) string {
        if len(s) <= n {
            return s
        }
        return s[:n] + "..."
    }

    out := Output{FileURL: fileURL}
    findings := make([]Finding, 0, 16)

    // Add a finding and increment counts appropriately (info not counted)
    addFinding := func(sev, title, summary, rec string) {
        sev = strings.ToLower(sev)
        f := Finding{
            Title:          title,
            Severity:       sev,
            Summary:        summary,
            Recommendation: rec,
        }
        findings = append(findings, f)
        switch sev {
        case "critical":
            out.Counts.Critical++
        case "high":
            out.Counts.High++
        case "medium":
            out.Counts.Medium++
        case "low":
            out.Counts.Low++
        }
    }

    // Secret and credential detectors (critical)
    detectors := []struct {
        re          *regexp.Regexp
        title       string
        recommendation string
    }{
        // Private keys
        {regexp.MustCompile(`-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`), "Private key material committed", "Remove private keys from repos; use a secure secrets manager and rotate affected keys immediately."},
        // AWS
        {regexp.MustCompile(`AKIA[0-9A-Z]{16}`), "AWS access key exposed", "Revoke the access key, create a new one with least privilege, and configure credentials via IAM roles/secret manager."},
        {regexp.MustCompile(`(?i)aws_secret_access_key\s*[:=]\s*["']?[A-Za-z0-9/+=]{20,}`), "AWS secret access key exposed", "Rotate the secret, audit usage, and move to role-based access or secret manager."},
        // GitHub
        {regexp.MustCompile(`gh[pousr]_[A-Za-z0-9_]{20,}`), "GitHub token exposed", "Revoke the token, create a new token with minimal scopes, and store in CI/CD secrets."},
        {regexp.MustCompile(`github_pat_[A-Za-z0-9_]{20,}`), "GitHub PAT exposed", "Revoke the PAT and rotate; use repository/org secrets to inject at runtime."},
        // Google
        {regexp.MustCompile(`AIza[0-9A-Za-z\-_]{35}`), "Google API key exposed", "Restrict the API key by IP/referrer/service, rotate it, and move to secret management."},
        // Slack
        {regexp.MustCompile(`xox[baprs]-[A-Za-z0-9\-]{10,}`), "Slack token exposed", "Revoke the token in Slack admin, rotate, and scope minimally."},
        // Stripe
        {regexp.MustCompile(`sk_(?:live|test)_[0-9A-Za-z]{10,}`), "Stripe secret key exposed", "Rotate the key in Stripe dashboard and move to server-side secret storage."},
        // Twilio
        {regexp.MustCompile(`AC[0-9a-fA-F]{32}`), "Twilio Account SID found", "Treat alongside Auth Token; rotate as needed and store securely."},
        {regexp.MustCompile(`SK[0-9a-fA-F]{32}`), "Twilio API key exposed", "Rotate the key in Twilio console; avoid committing credentials."},
        // OpenAI
        {regexp.MustCompile(`(?i)sk-[a-z0-9\-_]{20,}`), "OpenAI API key exposed", "Revoke and rotate the key in OpenAI dashboard; keep keys in environment or secret manager."},
        // JWT/Bearer-like
        {regexp.MustCompile(`[A-Za-z0-9-_]{8,}\.eyJ[A-Za-z0-9-_]{5,}\.[A-Za-z0-9-_]{10,}`), "JWT token present", "Avoid committing tokens; rotate, invalidate sessions, and prefer short-lived tokens from an identity provider."},
        {regexp.MustCompile(`(?i)authorization\s*[:=]\s*["']?bearer\s+[A-Za-z0-9\-\._~\+\/]+=*`), "Bearer token exposed", "Remove bearer tokens from code; rotate credentials and use secure configs."},
        // Generic key hints
        {regexp.MustCompile(`(?i)(api[_-]?key|client[_-]?secret|secret|token)\s*[:=]\s*["']?[^\s"']{12,}`), "Sensitive credential literal detected", "Do not hardcode secrets. Use environment variables or a secret manager (Vault, AWS Secrets Manager, etc.)."},
        // URL with basic auth
        {regexp.MustCompile(`://[^\s/:@]+:[^\s/@]+@`), "Credentials embedded in URL", "Strip credentials from URLs; pass via configuration or secret store."},
        // Database style credentials
        {regexp.MustCompile(`(?i)(user(name)?|db_user)\s*[:=]\s*["']?[^\s"']+\s*\n\s*(password|db_pass|db_password)\s*[:=]\s*["']?[^\s"']+`), "Database credentials in config", "Move DB credentials to secure storage and rotate immediately."},
        // MinIO style keys
        {regexp.MustCompile(`(?i)minio[\s\S]{0,100}?secret\s*key\s*[:=]\s*["']?[^\s"']+`), "MinIO secret key exposed", "Rotate MinIO keys and use server-side environment/secret store."},
    }

    // Track which detector triggered to avoid duplicate titles
    seenTitles := map[string]bool{}

    for _, d := range detectors {
        if d.re.FindStringIndex(content) != nil {
            if !seenTitles[d.title] {
                match := d.re.FindString(content)
                sample := trim(match, 64)
                addFinding("critical", d.title, "Example: "+sample, d.recommendation)
                seenTitles[d.title] = true
            }
        }
    }

    // Heuristic lower-severity checks
    // Insecure protocol usage (if content references http URLs for APIs)
    if strings.Contains(lower, "http://") && strings.Contains(lower, "api") {
        addFinding("medium", "Insecure HTTP reference", "Found potential API calls over HTTP. This may expose data in transit.", "Prefer HTTPS for all API and configuration endpoints; enforce HSTS where applicable.")
    }

    // YAML/JSON config hints
    if strings.HasSuffix(strings.ToLower(fileURL), ".yml") || strings.HasSuffix(strings.ToLower(fileURL), ".yaml") || strings.HasSuffix(strings.ToLower(fileURL), ".json") {
        if strings.Contains(lower, "use_ssl: false") || strings.Contains(lower, "usessl: false") {
            addFinding("high", "SSL/TLS disabled in config", "Configuration suggests TLS is disabled.", "Enable TLS and verify certificate validation in all environments.")
        }
        // Keys mentioning password but without obvious value may still be risky
        if regexp.MustCompile(`(?i)password\s*:`).FindStringIndex(content) != nil && out.Counts.Critical == 0 {
            addFinding("low", "Password field present", "A password field exists in config; verify it is sourced from a secret store, not committed.", "Load passwords from environment variables or secret manager; never commit values.")
        }
    }

    // If nothing detected, add conservative baseline findings (low/info)
    if len(findings) == 0 {
        addFinding("low", "Enable secret scanning", "No explicit secrets detected, but false negatives are possible.", "Enable pre-commit hooks and CI/CD secret scanners (e.g., gitleaks, trufflehog).")
        addFinding("info", "Use least privilege", "Review access scopes for any tokens used by this project.", "Scope tokens narrowly and rotate regularly with audit logs enabled.")
        addFinding("info", "Centralize secret management", "Adopt a standard secret manager across environments.", "Use solutions like AWS Secrets Manager, Vault, or Azure Key Vault.")
    }

    // Cap findings to a reasonable number to keep output compact
    if len(findings) > 20 {
        findings = findings[:20]
    }

    out.Findings = findings
    // Ensure counts.total equals the sum of counted severities (info not counted)
    out.Counts.Total = out.Counts.Critical + out.Counts.High + out.Counts.Medium + out.Counts.Low

    // Compose advice
    if out.Counts.Critical > 0 {
        out.Advice = "Immediate action required: rotate exposed credentials, revoke tokens, and remove secrets from the repository. Add automated secret scanning to CI/CD and migrate to a managed secret store."
    } else if out.Counts.High+out.Counts.Medium > 0 {
        out.Advice = "Address configuration risks, enforce TLS everywhere, and review credentials handling. Add secret scanning and least-privilege policies."
    } else {
        out.Advice = "Maintain good hygiene: enable secret scanning, store credentials centrally, and periodically rotate tokens."
    }

    // Marshal to JSON and return as string. If marshal fails, return a minimal fallback.
    b, err := json.Marshal(out)
    if err != nil {
        // Fallback minimal JSON to satisfy schema
        fb := Output{
            FileURL: fileURL,
            Advice:  "Analysis error; ensure content is accessible and try again.",
        }
        fb.Counts.Total = 0
        data, _ := json.Marshal(fb)
        return string(data)
    }
    return string(b)
}

