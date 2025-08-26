package runner

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

type Runner struct{}

func NewRunner() *Runner { return &Runner{} }

func (r *Runner) Run(ctx context.Context, req domain.RunRequest) (domain.RunResult, error) {
	start := time.Now()

	artifactPath := filepath.Join("./temp", fmt.Sprintf("%s-%d", req.Tool, time.Now().UnixNano()))
	var cmd *exec.Cmd
	rawFormat := "json"

	switch req.Tool {
	case domain.ToolTrivy:
		artifactPath += ".sarif"
		rawFormat = "sarif"
		cmd = exec.CommandContext(ctx,
			"trivy", "image",
			"--scanners", "vuln",
			"--severity", "HIGH,CRITICAL",
			"--format", "sarif",
			"-o", artifactPath,
			req.Image,
		)

	case domain.ToolGitleaks:
		artifactPath += ".json"
		cmd = exec.CommandContext(ctx,
			"gitleaks", "detect",
			"--source", req.Path,
			"--report-format", "json",
			"--report-path", artifactPath,
		)

	case domain.ToolZAP:
		artifactPath += ".html"
		rawFormat = "html"
		cmd = exec.CommandContext(ctx,
			"zap-baseline.py",
			"-t", req.Target,
			"-r", artifactPath,
			"-I", "-m", "5", "-d",
		)

	case domain.ToolNuclei:
		artifactPath += ".json"
		cmd = exec.CommandContext(ctx,
			"nuclei",
			"-u", req.Target,
			"-severity", "critical,high,medium",
			"-json", "-o", artifactPath,
			"-rl", "50", "-c", "50", "-irr",
		)

	default:
		return domain.RunResult{}, fmt.Errorf("unsupported tool: %s", req.Tool)
	}

	out, err := cmd.CombinedOutput()
	duration := time.Since(start).Milliseconds()

	if err != nil {
		return domain.RunResult{}, fmt.Errorf("run error: %v, output=%s", err, string(out))
	}

	return domain.RunResult{
		Counts:            domain.SeverityCounts{}, // TODO: parse output
		LocalArtifactPath: artifactPath,
		RawFormat:         rawFormat,
		ExitCode:          0,
		DurationMS:        duration,
	}, nil
}
