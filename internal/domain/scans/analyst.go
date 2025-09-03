package scans

import (
    "bufio"
    "encoding/json"
    "os"
    "regexp"
    "strings"
)

func ParseSeverityCounts(tool Tool, artifactPath string) (SeverityCounts, error) {
    switch tool {
    case ToolNuclei:
        return parseNucleiJSONL(artifactPath)
    case ToolTrivy:
        return parseTrivySARIF(artifactPath)
    case ToolGitleaks:
        return parseGitleaksJSON(artifactPath)
    case ToolSQLMap:
        return parseSQLMapJSON(artifactPath)
    case ToolZAP:
        return parseZAPHTML(artifactPath)
    default:
        return SeverityCounts{}, nil
    }
}

func parseNucleiJSONL(path string) (SeverityCounts, error) {
    f, err := os.Open(path)
    if err != nil {
        return SeverityCounts{}, err
    }
    defer f.Close()

    var c SeverityCounts
    s := bufio.NewScanner(f)
    for s.Scan() {
        line := strings.TrimSpace(s.Text())
        if line == "" {
            continue
        }
        var obj struct {
            Info struct {
                Severity string `json:"severity"`
            } `json:"info"`
        }
        if err := json.Unmarshal([]byte(line), &obj); err != nil {
            continue
        }
        sev := strings.ToLower(obj.Info.Severity)
        switch sev {
        case "critical":
            c.Critical++
        case "high":
            c.High++
        case "medium":
            c.Medium++
        case "low":
            c.Low++
        case "info", "informational":
            c.Low++
        }
        c.Total++
    }
    if err := s.Err(); err != nil {
        return SeverityCounts{}, err
    }
    return c, nil
}

func parseTrivySARIF(path string) (SeverityCounts, error) {
    f, err := os.ReadFile(path)
    if err != nil {
        return SeverityCounts{}, err
    }
    var doc struct {
        Runs []struct {
            Results []struct {
                Level      string                 `json:"level"`
                Properties map[string]any        `json:"properties"`
            } `json:"results"`
        } `json:"runs"`
    }
    if err := json.Unmarshal(f, &doc); err != nil {
        return SeverityCounts{}, err
    }
    var c SeverityCounts
    for _, run := range doc.Runs {
        for _, r := range run.Results {
            var sev string
            if r.Properties != nil {
                if v, ok := r.Properties["severity"]; ok {
                    if s, ok := v.(string); ok {
                        sev = strings.ToLower(s)
                    }
                } else if v, ok := r.Properties["Severity"]; ok {
                    if s, ok := v.(string); ok {
                        sev = strings.ToLower(s)
                    }
                }
            }
            if sev == "" {
                switch strings.ToLower(r.Level) {
                case "error":
                    sev = "high"
                case "warning":
                    sev = "medium"
                case "note":
                    sev = "low"
                }
            }
            switch sev {
            case "critical":
                c.Critical++
            case "high":
                c.High++
            case "medium":
                c.Medium++
            case "low":
                c.Low++
            }
            c.Total++
        }
    }
    return c, nil
}

func parseGitleaksJSON(path string) (SeverityCounts, error) {
    f, err := os.ReadFile(path)
    if err != nil {
        return SeverityCounts{}, err
    }
    var arr []map[string]any
    if err := json.Unmarshal(f, &arr); err != nil {
        return SeverityCounts{}, err
    }
    return SeverityCounts{Total: len(arr)}, nil
}

func parseSQLMapJSON(path string) (SeverityCounts, error) {
    f, err := os.ReadFile(path)
    if err != nil {
        return SeverityCounts{}, err
    }
    var anyjson map[string]any
    if err := json.Unmarshal(f, &anyjson); err != nil {
        return SeverityCounts{}, err
    }
    // Try to extract vulnerabilities with best effort.
    var c SeverityCounts
    // Top-level vulnerabilities array
    if v, ok := anyjson["vulnerabilities"]; ok {
        if arr, ok := v.([]any); ok {
            c.High += len(arr)
            c.Total += len(arr)
        }
    }
    // Some outputs may nest results with vulnerabilities
    if res, ok := anyjson["results"]; ok {
        if arr, ok := res.([]any); ok {
            for _, it := range arr {
                if m, ok := it.(map[string]any); ok {
                    if v, ok := m["vulnerabilities"]; ok {
                        if vs, ok := v.([]any); ok {
                            c.High += len(vs)
                            c.Total += len(vs)
                            continue
                        }
                    }
                    // Heuristic: status string indicates injection possible
                    if st, ok := m["status"].(string); ok {
                        s := strings.ToLower(st)
                        if strings.Contains(s, "possible") || strings.Contains(s, "vulnerable") {
                            c.High++
                            c.Total++
                        }
                    }
                }
            }
        }
    }
    return c, nil
}

func parseZAPHTML(path string) (SeverityCounts, error) {
    b, err := os.ReadFile(path)
    if err != nil {
        return SeverityCounts{}, err
    }
    s := strings.ToLower(string(b))

    // Use regex to count risk labels; this is heuristic and may slightly over/undercount
    // depending on the HTML template.
    var c SeverityCounts
    rxHigh := regexp.MustCompile(`risk\s*:?\s*high`)
    rxMed := regexp.MustCompile(`risk\s*:?\s*medium`)
    rxLow := regexp.MustCompile(`risk\s*:?\s*low`)
    rxInfo := regexp.MustCompile(`risk\s*:?\s*(informational|info)`) // map to Low

    // Primary heuristic based on "Risk: High/Medium/Low" labels in classic ZAP report
    c.High = len(rxHigh.FindAllStringIndex(s, -1))
    c.Medium = len(rxMed.FindAllStringIndex(s, -1))
    low := len(rxLow.FindAllStringIndex(s, -1))
    info := len(rxInfo.FindAllStringIndex(s, -1))
    c.Low = low + info
    c.Total = c.High + c.Medium + c.Low

    // Fallback: newer templates may use classes like severity-high or risk-high, or "Risk Level: High"
    if c.Total == 0 {
        var f SeverityCounts
        // class-based matches
        rxClass := regexp.MustCompile(`class\s*=\s*\"(?:risk|severity)-(high|medium|low|informational|info)\"`)
        for _, m := range rxClass.FindAllStringSubmatch(s, -1) {
            switch m[1] {
            case "high":
                f.High++
            case "medium":
                f.Medium++
            case "low", "informational", "info":
                f.Low++
            }
        }
        // textual "risk level: x"
        rxLevel := regexp.MustCompile(`risk\s*level\s*:?\s*(high|medium|low|informational|info)`)
        for _, m := range rxLevel.FindAllStringSubmatch(s, -1) {
            switch m[1] {
            case "high":
                f.High++
            case "medium":
                f.Medium++
            case "low", "informational", "info":
                f.Low++
            }
        }
        f.Total = f.High + f.Medium + f.Low
        if f.Total > 0 {
            return f, nil
        }
    }

    return c, nil
}
