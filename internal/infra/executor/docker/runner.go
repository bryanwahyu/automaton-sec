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

// findingsExitCode maps a tool to the exit code it uses to mean "ran fine, and
// I found something". Any other non-zero code is a real failure.
var findingsExitCode = map[domain.Tool]int{
	domain.ToolTrivy:  1,
	domain.ToolZAP:    2,
	domain.ToolNuclei: 1,
}

type Runner struct {
	policy  domain.TargetPolicy
	tempDir string
}

func NewRunner(policy domain.TargetPolicy) *Runner {
	return &Runner{policy: policy, tempDir: "./temp"}
}

func (r *Runner) Run(ctx context.Context, req domain.RunRequest) (domain.RunResult, error) {
	// Reject anything we would not want to hand to a scanner's argv before we
	// build a command line out of it.
	if err := r.policy.ValidateRunRequest(req); err != nil {
		return domain.RunResult{}, fmt.Errorf("invalid scan request: %w", err)
	}

	start := time.Now()

	// Pastikan temp dir ada
	if err := os.MkdirAll(r.tempDir, 0o755); err != nil {
		return domain.RunResult{}, fmt.Errorf("failed to create temp dir: %w", err)
	}

	artifactPath := filepath.Join(r.tempDir, fmt.Sprintf("%s-%d", req.Tool, time.Now().UnixNano()))
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
		artifactPath += ".json"
		rawFormat = "json"
		cmd = exec.CommandContext(ctx,
			"trivy", "image",
			"--scanners", "vuln,secret,misconfig",
			"--severity", "CRITICAL,HIGH,MEDIUM,LOW",
			"--format", "json",
			"--timeout", "15m",
			"--quiet",
			"-o", artifactPath,
			req.Image,
		)

	case domain.ToolGitleaks:
		artifactPath += ".json"
		// ValidateRunRequest already confirmed the path resolves inside the
		// workspace root; use the cleaned absolute form it returns.
		source, err := r.policy.ValidatePath(req.Path)
		if err != nil {
			return domain.RunResult{}, err
		}
		cmd = exec.CommandContext(ctx,
			"gitleaks", "detect",
			"--source", source,
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

		// Use unique session and config settings to avoid conflicts

		// Use ZAP's working directory for the session
		sessionPath := filepath.Join("/zap/wrk", fmt.Sprintf("session-%d", time.Now().UnixNano()))

		cmd = exec.CommandContext(ctx,
			"zap.sh",
			"-cmd",      // Run in command line mode
			"-silent",   // Prevent unsolicited requests
			"-nostdout", // Disable standard output logging
			"-config", "database.recoverylog=false",
			"-config", "api.disablekey=true",
			"-quickurl", req.Target,
			"-quickout", absArtifactPath,
			"-quickprogress",
			"-newsession", sessionPath,
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
	hasFindings := false
	if err != nil {
		// A cancelled or timed-out context is always a failure, whatever exit
		// code the killed process happened to report.
		if ctxErr := ctx.Err(); ctxErr != nil {
			return domain.RunResult{}, fmt.Errorf("run aborted: tool=%s: %w", req.Tool, ctxErr)
		}
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		// Trivy (1), ZAP (2), dan Nuclei (1) artinya ada finding, bukan gagal.
		if want, ok := findingsExitCode[req.Tool]; ok && exitCode == want {
			hasFindings = true
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
		HasFindings:       hasFindings,
		DurationMS:        duration,
	}, nil
}
