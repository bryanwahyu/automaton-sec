package runner

import (
	"context"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// versionCommand is how each tool is asked what version it is.
var versionCommand = map[domain.Tool][]string{
	domain.ToolTrivy:      {"trivy", "--version"},
	domain.ToolNuclei:     {"nuclei", "-version"},
	domain.ToolGitleaks:   {"gitleaks", "version"},
	domain.ToolSemgrep:    {"semgrep", "--version"},
	domain.ToolOSVScanner: {"osv-scanner", "--version"},
	domain.ToolZAP:        {"zap.sh", "-version"},
	domain.ToolSQLMap:     {"sqlmap", "--version"},
}

// ToolVersion is what the API reports for one scanner.
type ToolVersion struct {
	// Version is the reported version string, empty when the tool is missing.
	Version string `json:"version,omitempty"`
	// Available is false when the binary is not installed in this image.
	Available bool `json:"available"`
	// Error explains why a version could not be read.
	Error string `json:"error,omitempty"`
}

// Versions reports the scanners actually present in the running image.
//
// It probes the binaries rather than echoing the Dockerfile's build arguments,
// so the answer cannot drift from what is installed — including a tool that is
// referenced by the runner but absent from the image.
//
// The result is cached: versions cannot change without the process restarting.
func (r *Runner) Versions(ctx context.Context) map[string]ToolVersion {
	r.versionsOnce.Do(func() {
		r.versions = probeVersions(ctx)
	})
	return r.versions
}

func probeVersions(ctx context.Context) map[string]ToolVersion {
	tools := make([]domain.Tool, 0, len(versionCommand))
	for t := range versionCommand {
		tools = append(tools, t)
	}
	sort.Slice(tools, func(i, j int) bool { return tools[i] < tools[j] })

	out := make(map[string]ToolVersion, len(tools))
	var mu sync.Mutex
	var wg sync.WaitGroup

	for _, tool := range tools {
		wg.Add(1)
		go func(tool domain.Tool) {
			defer wg.Done()
			v := probeOne(ctx, versionCommand[tool])
			mu.Lock()
			out[string(tool)] = v
			mu.Unlock()
		}(tool)
	}
	wg.Wait()
	return out
}

func probeOne(ctx context.Context, argv []string) ToolVersion {
	if _, err := exec.LookPath(argv[0]); err != nil {
		return ToolVersion{Available: false, Error: "not installed"}
	}

	// A scanner that hangs on --version must not hang the endpoint.
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(ctx, argv[0], argv[1:]...).CombinedOutput()
	text := firstMeaningfulLine(string(out))
	if err != nil && text == "" {
		return ToolVersion{Available: true, Error: err.Error()}
	}
	return ToolVersion{Version: text, Available: true}
}

// firstMeaningfulLine picks the first non-empty line, which is where every one
// of these tools puts its version.
func firstMeaningfulLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if l := strings.TrimSpace(line); l != "" {
			return l
		}
	}
	return ""
}
