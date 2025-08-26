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
	ExitCode          int
	DurationMS        int64
}
