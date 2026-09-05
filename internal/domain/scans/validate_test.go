package scans

import "testing"

func TestValidateTargetRejectsUnsafeInput(t *testing.T) {
	p := TargetPolicy{}

	cases := []struct {
		name   string
		target string
	}{
		{"empty", ""},
		{"flag-like", "-oJ/etc/cron.d/pwn"},
		{"non-http scheme", "file:///etc/passwd"},
		{"no host", "https://"},
		{"whitespace", "https://example.com /etc"},
		{"loopback", "http://127.0.0.1:8080/"},
		{"cloud metadata", "http://169.254.169.254/latest/meta-data/"},
		{"rfc1918", "http://10.0.0.5/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := p.ValidateTarget(tc.target); err == nil {
				t.Fatalf("ValidateTarget(%q) = nil, want an error", tc.target)
			}
		})
	}
}

func TestValidateTargetAllowsPrivateWhenOptedIn(t *testing.T) {
	p := TargetPolicy{AllowPrivateTargets: true}
	if err := p.ValidateTarget("http://127.0.0.1:8080/"); err != nil {
		t.Fatalf("ValidateTarget with AllowPrivateTargets: %v", err)
	}
}

func TestValidateTargetHostAllowlist(t *testing.T) {
	p := TargetPolicy{AllowPrivateTargets: true, AllowedHosts: []string{"example.com", ".internal.test"}}

	if err := p.ValidateTarget("https://example.com/x"); err != nil {
		t.Fatalf("exact host should be allowed: %v", err)
	}
	if err := p.ValidateTarget("https://api.internal.test/x"); err != nil {
		t.Fatalf("suffix host should be allowed: %v", err)
	}
	if err := p.ValidateTarget("https://evil.test/x"); err == nil {
		t.Fatal("host outside the allowlist should be rejected")
	}
}

func TestValidateImage(t *testing.T) {
	p := TargetPolicy{}

	ok := []string{
		"nginx",
		"nginx:latest",
		"library/nginx:1.27-alpine",
		"ghcr.io/bryanwahyu/automaton-sec:v1.2.3",
		"registry.local:5000/team/app:dev",
		"nginx@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
	for _, img := range ok {
		if err := p.ValidateImage(img); err != nil {
			t.Errorf("ValidateImage(%q) = %v, want nil", img, err)
		}
	}

	bad := []string{"", "-v", "nginx latest", "nginx;rm -rf /", "nginx:tag$(id)"}
	for _, img := range bad {
		if err := p.ValidateImage(img); err == nil {
			t.Errorf("ValidateImage(%q) = nil, want an error", img)
		}
	}
}

func TestValidatePathConfinesToWorkspace(t *testing.T) {
	root := t.TempDir()
	p := TargetPolicy{WorkspaceRoot: root}

	abs, err := p.ValidatePath("repo")
	if err != nil {
		t.Fatalf("relative path inside the root should be accepted: %v", err)
	}
	if abs != root+"/repo" {
		t.Fatalf("ValidatePath = %q, want %q", abs, root+"/repo")
	}

	for _, bad := range []string{"../../etc", "/etc/passwd", "-config"} {
		if _, err := p.ValidatePath(bad); err == nil {
			t.Errorf("ValidatePath(%q) = nil, want an error", bad)
		}
	}
}

func TestValidatePathDisabledWithoutWorkspaceRoot(t *testing.T) {
	if _, err := (TargetPolicy{}).ValidatePath("/srv/repo"); err == nil {
		t.Fatal("filesystem scans should be refused when no workspace root is set")
	}
}

func TestValidateRunRequestChecksTheFieldTheToolUses(t *testing.T) {
	root := t.TempDir()
	p := TargetPolicy{WorkspaceRoot: root}

	// trivy reads Image, so a missing Target must not matter.
	if err := p.ValidateRunRequest(RunRequest{Tool: ToolTrivy, Image: "nginx:latest"}); err != nil {
		t.Errorf("trivy with a valid image: %v", err)
	}
	// gitleaks reads Path.
	if err := p.ValidateRunRequest(RunRequest{Tool: ToolGitleaks, Path: "repo"}); err != nil {
		t.Errorf("gitleaks with a path inside the root: %v", err)
	}
	// An unknown tool is rejected before anything else is looked at.
	if err := p.ValidateRunRequest(RunRequest{Tool: Tool("nmap"), Target: "https://example.com"}); err == nil {
		t.Error("unknown tool should be rejected")
	}
}

func TestToolValid(t *testing.T) {
	for _, tool := range KnownTools {
		if !tool.Valid() {
			t.Errorf("%q should be a known tool", tool)
		}
	}
	if Tool("nmap").Valid() {
		t.Error("nmap is not a supported tool")
	}
}
