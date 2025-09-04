package runner

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

type Runner struct{}

func NewRunner() *Runner {
	return &Runner{}
}

func (r *Runner) Run(ctx context.Context, req domain.RunRequest) (domain.RunResult, error) {
	start := time.Now()

	// Pastikan temp dir ada
	if err := os.MkdirAll("./temp", 0755); err != nil {
		return domain.RunResult{}, fmt.Errorf("failed to create temp dir: %w", err)
	}

	artifactPath := filepath.Join("./temp", fmt.Sprintf("%s-%d", req.Tool, time.Now().UnixNano()))
	var cmd *exec.Cmd
	rawFormat := "json"

	switch req.Tool {
	case domain.ToolSQLMap:
		artifactPath += ".json"
		cmd = exec.CommandContext(ctx,
			"sqlmap", "-u", req.Target,
			"--batch", "--json", "-o", artifactPath,
		)
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
		// Convert to absolute path untuk ZAP
		absArtifactPath, err := filepath.Abs(artifactPath)
		if err != nil {
			return domain.RunResult{}, fmt.Errorf("failed to get absolute path: %w", err)
		}
		// Use a subdirectory in the artifact path's parent directory for ZAP home
		zapHome := filepath.Join(filepath.Dir(absArtifactPath), fmt.Sprintf("zap-%d", time.Now().UnixNano()))
		
		// Create ZAP home directory with world-writable permissions
		if err := os.MkdirAll(zapHome, 0777); err != nil {
			return domain.RunResult{}, fmt.Errorf("failed to create ZAP home dir: %w", err)
		}
		
		// Clean up after scan completes
		defer func() {
			_ = os.RemoveAll(zapHome)
		}()

		cmd = exec.CommandContext(ctx,
			"zap.sh", "-cmd",
			"-quickurl", req.Target,
			"-quickout", absArtifactPath,
			"-quickprogress",
			"-config", "database.recoverylog=false", // Disable recovery log to prevent permission issues
			"-dir", zapHome,
		)
	case domain.ToolNuclei:
		artifactPath += ".jsonl"
		cmd = exec.CommandContext(ctx,
			"nuclei",
			"-u", req.Target,
			"-severity", "critical,high,medium,info,low",
			"-jsonl", "-o", artifactPath,
			"-rl", "50", "-c", "50", "-irr", "-silent",
		)

	default:
		return domain.RunResult{}, fmt.Errorf("unsupported tool: %s", req.Tool)
	}

	out, err := cmd.CombinedOutput()
	duration := time.Since(start).Milliseconds()

	exitCode := 0
	if err != nil {
		// Ambil exit code
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		// Trivy (1), ZAP (2), atau Nuclei (1) artinya ada finding, bukan gagal
		if (req.Tool == domain.ToolTrivy && exitCode == 1) ||
			(req.Tool == domain.ToolZAP && exitCode == 2) ||
			(req.Tool == domain.ToolNuclei && exitCode == 1) {
			// treat as success with findings
		} else {
			return domain.RunResult{}, fmt.Errorf("run error: tool=%s exit=%d, err=%v, output=%s",
				req.Tool, exitCode, err, string(out))
		}
	}

	// Verifikasi file output ada sebelum return
	if _, err := os.Stat(artifactPath); os.IsNotExist(err) {
		return domain.RunResult{}, fmt.Errorf("output file not created: %s, command output: %s", artifactPath, string(out))
	}

	counts, _ := domain.ParseSeverityCounts(req.Tool, artifactPath)

	return domain.RunResult{
		Counts:            counts,
		LocalArtifactPath: artifactPath,
		RawFormat:         rawFormat,
		ExitCode:          exitCode,
		DurationMS:        duration,
	}, nil
}
