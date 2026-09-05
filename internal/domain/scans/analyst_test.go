package scans

import (
	"os"
	"path/filepath"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture: %v", err)
	}
	return path
}

func TestParseNucleiJSONL(t *testing.T) {
	// One finding per line, plus a blank line and an unparseable line that must
	// both be skipped rather than aborting the parse.
	const jsonl = `{"info":{"severity":"critical"}}
{"info":{"severity":"HIGH"}}
{"info":{"severity":"info"}}

not json at all
{"info":{"severity":"low"}}
`
	got, err := ParseSeverityCounts(ToolNuclei, writeTemp(t, "n.jsonl", jsonl))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}

	// info currently folds into Low — see the Info-field issue.
	want := SeverityCounts{Critical: 1, High: 1, Low: 2, Total: 4}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseTrivyJSONCountsEverySection(t *testing.T) {
	const report = `{"Results":[
	  {"Vulnerabilities":[{"Severity":"CRITICAL"},{"Severity":"HIGH"}],
	   "Misconfigurations":[{"Severity":"MEDIUM"}],
	   "Secrets":[{"Severity":"HIGH"}]},
	  {"Vulnerabilities":[{"Severity":"LOW"}]}
	]}`
	got, err := ParseSeverityCounts(ToolTrivy, writeTemp(t, "t.json", report))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}

	want := SeverityCounts{Critical: 1, High: 2, Medium: 1, Low: 1, Total: 5}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseGitleaksJSON(t *testing.T) {
	got, err := ParseSeverityCounts(ToolGitleaks, writeTemp(t, "g.json", `[{"RuleID":"a"},{"RuleID":"b"}]`))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}
	if got.Total != 2 {
		t.Fatalf("Total = %d, want 2", got.Total)
	}
}

func TestParseSeverityCountsUnknownTool(t *testing.T) {
	got, err := ParseSeverityCounts(Tool("nmap"), "does-not-exist")
	if err != nil {
		t.Fatalf("unknown tool should not error: %v", err)
	}
	if got != (SeverityCounts{}) {
		t.Fatalf("counts = %+v, want zero", got)
	}
}

func TestParseZAPHTMLFallsBackToClassMarkup(t *testing.T) {
	// No "Risk: High" labels, so the parser must fall back to class markup.
	const html = `<html><body>
	  <div class="risk-high">x</div>
	  <div class="risk-medium">y</div>
	  <div class="severity-informational">z</div>
	</body></html>`
	got, err := ParseSeverityCounts(ToolZAP, writeTemp(t, "z.html", html))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}
	want := SeverityCounts{High: 1, Medium: 1, Low: 1, Total: 3}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseSemgrepJSON(t *testing.T) {
	// The first result carries a triaged metadata rating, which wins over the
	// rule level; the rest fall back to ERROR/WARNING/INFO.
	const report = `{"results":[
	  {"extra":{"severity":"WARNING","metadata":{"severity":"CRITICAL"}}},
	  {"extra":{"severity":"ERROR","metadata":{}}},
	  {"extra":{"severity":"WARNING","metadata":{}}},
	  {"extra":{"severity":"INFO","metadata":{}}}
	],"errors":[]}`

	got, err := ParseSeverityCounts(ToolSemgrep, writeTemp(t, "s.json", report))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}

	want := SeverityCounts{Critical: 1, High: 1, Medium: 1, Low: 1, Total: 4}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseSemgrepJSONEmptyRun(t *testing.T) {
	got, err := ParseSeverityCounts(ToolSemgrep, writeTemp(t, "s.json", `{"results":[],"errors":[]}`))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}
	if got != (SeverityCounts{}) {
		t.Fatalf("counts = %+v, want zero", got)
	}
}

func TestParseOSVScannerJSONCountsGroupsNotAliases(t *testing.T) {
	// GO-1 and GHSA-1 are the same vulnerability under two identifiers, so the
	// group is one finding, not two. Severity comes from the CVSS band.
	const report = `{"results":[
	  {"packages":[
	    {"vulnerabilities":[
	      {"id":"GO-1","database_specific":{}},
	      {"id":"GHSA-1","database_specific":{"severity":"CRITICAL"}},
	      {"id":"GHSA-2","database_specific":{"severity":"MODERATE"}}
	    ],
	     "groups":[
	      {"ids":["GO-1","GHSA-1"],"max_severity":"9.8"},
	      {"ids":["GHSA-2"],"max_severity":"5.3"}
	    ]}
	  ]}
	]}`

	got, err := ParseSeverityCounts(ToolOSVScanner, writeTemp(t, "o.json", report))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}

	want := SeverityCounts{Critical: 1, Medium: 1, Total: 2}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
}

func TestParseOSVScannerJSONSeverityFallbacks(t *testing.T) {
	// Go advisories routinely carry neither a CVSS score nor a GitHub rating.
	// Where a score is missing the worst member rating is used; where both are
	// missing the finding still has to land in a bucket.
	const report = `{"results":[
	  {"packages":[
	    {"vulnerabilities":[
	      {"id":"GO-2","database_specific":{}},
	      {"id":"GHSA-3","database_specific":{"severity":"HIGH"}},
	      {"id":"GO-4","database_specific":{}}
	    ],
	     "groups":[
	      {"ids":["GO-2","GHSA-3"],"max_severity":""},
	      {"ids":["GO-4"],"max_severity":""}
	    ]}
	  ]}
	]}`

	got, err := ParseSeverityCounts(ToolOSVScanner, writeTemp(t, "o.json", report))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}

	want := SeverityCounts{High: 1, Low: 1, Total: 2}
	if got != want {
		t.Fatalf("counts = %+v, want %+v", got, want)
	}
	if got.Critical+got.High+got.Medium+got.Low != got.Total {
		t.Fatal("severity buckets should sum to Total")
	}
}

func TestParseOSVScannerJSONWithoutGroups(t *testing.T) {
	// Output that omits groups falls back to one finding per vulnerability.
	const report = `{"results":[{"packages":[{"vulnerabilities":[
	  {"id":"GHSA-9","database_specific":{"severity":"MODERATE"}}
	]}]}]}`

	got, err := ParseSeverityCounts(ToolOSVScanner, writeTemp(t, "o.json", report))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}
	if (got != SeverityCounts{Medium: 1, Total: 1}) {
		t.Fatalf("counts = %+v, want 1 medium", got)
	}
}

func TestParseOSVScannerJSONAgainstRealOutput(t *testing.T) {
	// Fixture captured from osv-scanner v1.9.2 scanning this repository.
	path := "testdata/osv-scanner.json"
	if _, err := os.Stat(path); err != nil {
		t.Skip("fixture not present")
	}
	got, err := ParseSeverityCounts(ToolOSVScanner, path)
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}
	if got.Total == 0 {
		t.Fatal("the fixture contains findings; got none")
	}
	if got.Critical+got.High+got.Medium+got.Low != got.Total {
		t.Fatalf("buckets %+v do not sum to Total", got)
	}
}

func TestParseOSVScannerJSONNoVulnerabilities(t *testing.T) {
	got, err := ParseSeverityCounts(ToolOSVScanner, writeTemp(t, "o.json", `{"results":[]}`))
	if err != nil {
		t.Fatalf("ParseSeverityCounts: %v", err)
	}
	if got.Total != 0 {
		t.Fatalf("Total = %d, want 0", got.Total)
	}
}
