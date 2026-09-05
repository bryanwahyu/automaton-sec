package scans

import (
	"bufio"
	"encoding/json"
	"os"
	"regexp"
	"strconv"
	"strings"
)

func ParseSeverityCounts(tool Tool, artifactPath string) (SeverityCounts, error) {
	switch tool {
	case ToolNuclei:
		return parseNucleiJSONL(artifactPath)
	case ToolTrivy:
		return parseTrivyJSON(artifactPath)
	case ToolGitleaks:
		return parseGitleaksJSON(artifactPath)
	case ToolSQLMap:
		return parseSQLMapJSON(artifactPath)
	case ToolZAP:
		return parseZAPHTML(artifactPath)
	case ToolSemgrep:
		return parseSemgrepJSON(artifactPath)
	case ToolOSVScanner:
		return parseOSVScannerJSON(artifactPath)
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

func parseTrivyJSON(path string) (SeverityCounts, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return SeverityCounts{}, err
	}

	var report struct {
		Results []struct {
			Vulnerabilities []struct {
				Severity string `json:"Severity"`
			} `json:"Vulnerabilities"`
			Misconfigurations []struct {
				Severity string `json:"Severity"`
			} `json:"Misconfigurations"`
			Secrets []struct {
				Severity string `json:"Severity"`
			} `json:"Secrets"`
		} `json:"Results"`
	}

	if err := json.Unmarshal(f, &report); err != nil {
		return SeverityCounts{}, err
	}

	var c SeverityCounts
	for _, result := range report.Results {
		// Count vulnerabilities
		for _, vuln := range result.Vulnerabilities {
			countSeverity(&c, vuln.Severity)
		}
		// Count misconfigurations
		for _, misconf := range result.Misconfigurations {
			countSeverity(&c, misconf.Severity)
		}
		// Count secrets
		for _, secret := range result.Secrets {
			countSeverity(&c, secret.Severity)
		}
	}

	return c, nil
}

func countSeverity(c *SeverityCounts, severity string) {
	sev := strings.ToLower(severity)
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

func parseTrivySARIF(path string) (SeverityCounts, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return SeverityCounts{}, err
	}
	var doc struct {
		Runs []struct {
			Results []struct {
				Level      string         `json:"level"`
				Properties map[string]any `json:"properties"`
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

// parseSemgrepJSON reads `semgrep scan --json` output.
//
// Semgrep grades a finding twice: extra.severity is the rule's own
// ERROR/WARNING/INFO level, while extra.metadata.severity carries a
// CRITICAL/HIGH/MEDIUM/LOW rating on the rules that have been triaged. The
// metadata rating is the more useful of the two, so it wins when present.
func parseSemgrepJSON(path string) (SeverityCounts, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return SeverityCounts{}, err
	}

	var report struct {
		Results []struct {
			Extra struct {
				Severity string `json:"severity"`
				Metadata struct {
					Severity string `json:"severity"`
				} `json:"metadata"`
			} `json:"extra"`
		} `json:"results"`
	}
	if err := json.Unmarshal(f, &report); err != nil {
		return SeverityCounts{}, err
	}

	var c SeverityCounts
	for _, r := range report.Results {
		sev := strings.ToLower(strings.TrimSpace(r.Extra.Metadata.Severity))
		switch sev {
		case "critical":
			c.Critical++
		case "high":
			c.High++
		case "medium":
			c.Medium++
		case "low":
			c.Low++
		default:
			// Fall back to the rule level: ERROR is the highest semgrep
			// reports without a triaged rating.
			switch strings.ToLower(strings.TrimSpace(r.Extra.Severity)) {
			case "error":
				c.High++
			case "warning":
				c.Medium++
			default:
				// INFO and anything unrecognised. Folded into Low for now,
				// like the other parsers, until SeverityCounts grows an Info
				// field.
				c.Low++
			}
		}
		c.Total++
	}
	return c, nil
}

// parseOSVScannerJSON reads `osv-scanner scan --format json` output.
//
// Counting is done over groups rather than over vulnerabilities: OSV lists the
// same issue once per identifier, so a single Go advisory shows up as both
// GO-2026-4503 and GHSA-fw7p-63qq-7hpr. A group is one finding.
//
// Severity is taken from the group's max_severity, a CVSS base score. Where
// that is absent the worst GitHub-advisory rating among the group's members is
// used instead. Many Go advisories carry neither; those are counted as Low so
// the buckets still sum to Total, which understates them — see the open issue
// about giving SeverityCounts a dedicated bucket for unrated findings.
func parseOSVScannerJSON(path string) (SeverityCounts, error) {
	f, err := os.ReadFile(path)
	if err != nil {
		return SeverityCounts{}, err
	}

	var report struct {
		Results []struct {
			Packages []struct {
				Vulnerabilities []struct {
					ID               string `json:"id"`
					DatabaseSpecific struct {
						Severity string `json:"severity"`
					} `json:"database_specific"`
				} `json:"vulnerabilities"`
				Groups []struct {
					IDs         []string `json:"ids"`
					MaxSeverity string   `json:"max_severity"`
				} `json:"groups"`
			} `json:"packages"`
		} `json:"results"`
	}
	if err := json.Unmarshal(f, &report); err != nil {
		return SeverityCounts{}, err
	}

	var c SeverityCounts
	for _, res := range report.Results {
		for _, pkg := range res.Packages {
			ratings := make(map[string]string, len(pkg.Vulnerabilities))
			for _, v := range pkg.Vulnerabilities {
				ratings[v.ID] = v.DatabaseSpecific.Severity
			}

			groups := pkg.Groups
			if len(groups) == 0 && len(pkg.Vulnerabilities) > 0 {
				// Older output, or a package whose groups were omitted: fall
				// back to counting each vulnerability once.
				for _, v := range pkg.Vulnerabilities {
					addOSVSeverity(&c, "", map[string]string{v.ID: v.DatabaseSpecific.Severity}, []string{v.ID})
				}
				continue
			}
			for _, g := range groups {
				addOSVSeverity(&c, g.MaxSeverity, ratings, g.IDs)
			}
		}
	}
	return c, nil
}

// addOSVSeverity buckets one OSV group.
func addOSVSeverity(c *SeverityCounts, maxSeverity string, ratings map[string]string, ids []string) {
	c.Total++

	if score, err := strconv.ParseFloat(strings.TrimSpace(maxSeverity), 64); err == nil && score > 0 {
		// CVSS v3 qualitative bands.
		switch {
		case score >= 9.0:
			c.Critical++
		case score >= 7.0:
			c.High++
		case score >= 4.0:
			c.Medium++
		default:
			c.Low++
		}
		return
	}

	// No CVSS score: take the worst advisory rating among the group's members.
	worst := 0
	for _, id := range ids {
		switch strings.ToLower(strings.TrimSpace(ratings[id])) {
		case "critical":
			if worst < 4 {
				worst = 4
			}
		case "high":
			if worst < 3 {
				worst = 3
			}
		// GitHub advisories say MODERATE where everything else says MEDIUM.
		case "moderate", "medium":
			if worst < 2 {
				worst = 2
			}
		case "low":
			if worst < 1 {
				worst = 1
			}
		}
	}

	switch worst {
	case 4:
		c.Critical++
	case 3:
		c.High++
	case 2:
		c.Medium++
	default:
		// Rated Low, or carrying no rating at all.
		c.Low++
	}
}
