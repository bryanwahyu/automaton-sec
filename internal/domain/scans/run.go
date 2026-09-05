package scans

// RunRequest untuk Runner
type RunRequest struct {
	Tool   Tool
	Mode   string // image | repo | url
	Image  string
	Path   string
	Target string
}

// RunResult hasil dari Runner
type RunResult struct {
	Counts            SeverityCounts
	LocalArtifactPath string
	RawFormat         string
	// ExitCode is the scanner process exit code, preserved for troubleshooting.
	// It is NOT a success signal: several scanners exit non-zero purely to report
	// that they found something. Use HasFindings/Failed instead.
	ExitCode int
	// HasFindings is true when the scanner exited non-zero only to signal findings.
	HasFindings bool
	DurationMS  int64
}
