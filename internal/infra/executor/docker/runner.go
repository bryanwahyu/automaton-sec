package docker

import (
	"context"
	"fmt"
	"math/rand"
	"os/exec"
	"path/filepath"
	"time"

	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

type Runner struct{
	randSource *rand.Rand
}

func NewRunner() *Runner {
	// Create a dedicated random source to avoid contention
	src := rand.NewSource(time.Now().UnixNano())
	return &Runner{
		randSource: rand.New(src),
	}
}

func (r *Runner) Run(ctx context.Context, req domain.RunRequest) (domain.RunResult, error) {
	start := time.Now()

	var cmd *exec.Cmd
	// Use ./temp directory instead of system temp
	tempDir := filepath.Join(".", "temp")
	artifactPath := filepath.Join(tempDir, fmt.Sprintf("%s-%d", req.Tool, r.randSource.Int()))
	rawFormat := "json"

	switch req.Tool {
	case domain.ToolTrivy:
		artifactPath += ".sarif"
		rawFormat = "sarif"
		cmd = exec.CommandContext(ctx, "docker", "run", "--rm",
			"-v", "/var/run/docker.sock:/var/run/docker.sock",
			"-v", fmt.Sprintf("%s:/out", filepath.Dir(artifactPath)),
			"aquasec/trivy:latest",
			"image", "--scanners", "vuln",
			"--severity", "HIGH,CRITICAL",
			"--format", "sarif",
			"-o", "/out/"+filepath.Base(artifactPath),
			req.Image,
		)

	case domain.ToolGitleaks:
		artifactPath += ".json"
		rawFormat = "json"
		cmd = exec.CommandContext(ctx, "docker", "run", "--rm",
			"-v", fmt.Sprintf("%s:/repo", req.Path),
			"zricethezav/gitleaks:latest",
			"detect", "--source=/repo",
			"--report-format=json", "--report-path=/repo/"+filepath.Base(artifactPath),
		)

	case domain.ToolZAP:
		artifactPath += ".html"
		rawFormat = "html"
		cmd = exec.CommandContext(ctx, "docker", "run", "--rm", "-t",
			"-v", fmt.Sprintf("%s:/zap/wrk", filepath.Dir(artifactPath)),
			"owasp/zap2docker-stable",
			"zap-baseline.py",
			"-t", req.Target,
			"-r", filepath.Base(artifactPath),
			"-I", "-m", "5", "-d",
		)

	case domain.ToolNuclei:
		artifactPath += ".json"
		rawFormat = "json"
		cmd = exec.CommandContext(ctx, "docker", "run", "--rm",
			"-v", fmt.Sprintf("%s:/tmp", filepath.Dir(artifactPath)),
			"projectdiscovery/nuclei:latest",
			"-u", req.Target,
			"-severity", "critical,high,medium",
			"-json", "-o", "/tmp/"+filepath.Base(artifactPath),
			"-rl", "50", "-c", "50", "-irr",
		)

	default:
		return domain.RunResult{}, fmt.Errorf("unsupported tool: %s", req.Tool)
	}

	// jalankan docker command
	out, err := cmd.CombinedOutput()
	duration := time.Since(start).Milliseconds()

	exitCode := 0
	if err != nil {
		// ambil exit code
		if ee, ok := err.(*exec.ExitError); ok {
			exitCode = ee.ExitCode()
		} else {
			return domain.RunResult{}, fmt.Errorf("run error: %v, output=%s", err, string(out))
		}
	}

	// counts parsing minimal (misal dari exit code, detail parse bisa ditambahkan)
	counts := domain.SeverityCounts{}
	if exitCode != 0 {
		counts.High = 1
		counts.Total = 1
	}

	return domain.RunResult{
		Counts:           counts,
		LocalArtifactPath: artifactPath,
		RawFormat:        rawFormat,
		ExitCode:         exitCode,
		DurationMS:       duration,
	}, nil
}
