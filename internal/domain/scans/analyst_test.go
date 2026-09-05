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
