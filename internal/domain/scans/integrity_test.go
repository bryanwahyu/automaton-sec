package scans

import (
	"strings"
	"testing"
)

const (
	digestA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func issueChecks(i ImageIntegrity) []string {
	out := make([]string, 0, len(i.Issues))
	for _, is := range i.Issues {
		out = append(out, is.Check)
	}
	return out
}

func assess(t *testing.T, ref, report string) ImageIntegrity {
	t.Helper()
	got, err := AssessTrivyImage(ref, writeTemp(t, "trivy.json", report))
	if err != nil {
		t.Fatalf("AssessTrivyImage: %v", err)
	}
	return got
}

func TestAssessTrivyImageHealthyTaggedImage(t *testing.T) {
	got := assess(t, "nginx:1.27", `{
	  "Metadata": {"OS": {"Family": "debian", "Name": "12.7"},
	               "ImageID": "sha256:img",
	               "RepoDigests": ["nginx@`+digestA+`"]},
	  "Results": [{"Class": "os-pkgs", "Packages": [{"Name":"libc6"},{"Name":"openssl"}]}]
	}`)

	if got.Verdict != IntegrityVerified {
		t.Fatalf("verdict = %q, want verified; issues %v", got.Verdict, issueChecks(got))
	}
	if got.OSPackages != 2 || got.Digest != digestA {
		t.Fatalf("os packages = %d, digest = %q", got.OSPackages, got.Digest)
	}
	// A tag can be re-pointed after the scan; the advice must name the exact
	// digest to deploy instead.
	if got.PinnedRef != "nginx@"+digestA {
		t.Fatalf("pinned ref = %q", got.PinnedRef)
	}
	if checks := issueChecks(got); len(checks) != 1 || checks[0] != CheckTagNotPinned {
		t.Fatalf("issues = %v, want only %s", checks, CheckTagNotPinned)
	}

	var c SeverityCounts
	got.AddTo(&c)
	if c.Total != 0 {
		t.Fatalf("an info-only issue must not be counted, got %+v", c)
	}
}

func TestAssessTrivyImageStrippedPackageDatabase(t *testing.T) {
	// The classic way to get a clean report: keep the OS, delete dpkg's status
	// file. Trivy still identifies Debian but sees zero packages, so it can
	// report zero CVEs. That must come back unverified and counted.
	got := assess(t, "evil/app@"+digestA, `{
	  "Metadata": {"OS": {"Family": "debian", "Name": "12.7"},
	               "RepoDigests": ["evil/app@`+digestA+`"]},
	  "Results": []
	}`)

	if got.Verdict != IntegrityUnverified {
		t.Fatalf("verdict = %q, want unverified", got.Verdict)
	}
	if checks := issueChecks(got); len(checks) != 1 || checks[0] != CheckOSPackagesMissing {
		t.Fatalf("issues = %v, want only %s", checks, CheckOSPackagesMissing)
	}

	var c SeverityCounts
	got.AddTo(&c)
	if c != (SeverityCounts{High: 1, Total: 1}) {
		t.Fatalf("counts = %+v, want one high", c)
	}
}

func TestAssessTrivyImageEmptyInventory(t *testing.T) {
	got := assess(t, "evil/app@"+digestA, `{"Metadata": {}, "Results": []}`)

	if got.Verdict != IntegrityUnverified {
		t.Fatalf("verdict = %q, want unverified", got.Verdict)
	}
	if checks := issueChecks(got); len(checks) != 1 || checks[0] != CheckInventoryEmpty {
		t.Fatalf("issues = %v, want only %s", checks, CheckInventoryEmpty)
	}
}

func TestAssessTrivyImageStaticBinaryOnScratch(t *testing.T) {
	// FROM scratch with a Go binary has no OS, but Trivy reads the binary's
	// embedded module list. That is a real inventory, not a hidden one.
	got := assess(t, "app@"+digestA, `{
	  "Metadata": {"RepoDigests": ["app@`+digestA+`"]},
	  "Results": [{"Class": "lang-pkgs", "Packages": [{"Name":"golang.org/x/net"}]}]
	}`)

	if got.Verdict != IntegrityVerified || len(got.Issues) != 0 {
		t.Fatalf("verdict = %q, issues = %v; want verified with none", got.Verdict, issueChecks(got))
	}
}

func TestAssessTrivyImageEndOfLifeOS(t *testing.T) {
	got := assess(t, "old@"+digestA, `{
	  "Metadata": {"OS": {"Family": "debian", "Name": "9.13", "EOSL": true},
	               "RepoDigests": ["old@`+digestA+`"]},
	  "Results": [{"Class": "os-pkgs", "Packages": [{"Name":"libc6"}]}]
	}`)

	if got.Verdict != IntegrityUnverified || !got.EOSL {
		t.Fatalf("verdict = %q, eosl = %v; want unverified, true", got.Verdict, got.EOSL)
	}
	if checks := issueChecks(got); len(checks) != 1 || checks[0] != CheckEOSL {
		t.Fatalf("issues = %v, want only %s", checks, CheckEOSL)
	}
}

func TestAssessTrivyImageDigestMismatch(t *testing.T) {
	got := assess(t, "app@"+digestA, `{
	  "Metadata": {"OS": {"Family": "alpine", "Name": "3.20.3"},
	               "RepoDigests": ["app@`+digestB+`"]},
	  "Results": [{"Class": "os-pkgs", "Packages": [{"Name":"musl"}]}]
	}`)

	if got.Verdict != IntegrityUnverified {
		t.Fatalf("verdict = %q, want unverified", got.Verdict)
	}
	if checks := issueChecks(got); len(checks) != 1 || checks[0] != CheckDigestMismatch {
		t.Fatalf("issues = %v, want only %s", checks, CheckDigestMismatch)
	}
	var c SeverityCounts
	got.AddTo(&c)
	if c.Critical != 1 {
		t.Fatalf("counts = %+v, want one critical", c)
	}
}

func TestAssessTrivyImageRejectsUnreadableReport(t *testing.T) {
	if _, err := AssessTrivyImage("nginx", writeTemp(t, "t.json", "not json")); err == nil {
		t.Fatal("want an error for an unreadable report")
	}
}

func TestSplitImageRef(t *testing.T) {
	cases := []struct{ ref, name, digest string }{
		{"nginx", "nginx", ""},
		{"nginx:1.27", "nginx", ""},
		{"localhost:5000/team/app", "localhost:5000/team/app", ""},
		{"localhost:5000/team/app:v2@" + digestA, "localhost:5000/team/app", digestA},
	}
	for _, tc := range cases {
		name, digest := splitImageRef(tc.ref)
		if name != tc.name || digest != tc.digest {
			t.Errorf("splitImageRef(%q) = %q, %q; want %q, %q", tc.ref, name, digest, tc.name, tc.digest)
		}
	}
}

func TestIntegrityDetailsAreSpecific(t *testing.T) {
	got := assess(t, "evil/app", `{"Metadata": {"OS": {"Family": "ubuntu", "Name": "22.04"}}}`)
	for _, is := range got.Issues {
		if is.Check == CheckOSPackagesMissing && !strings.Contains(is.Detail, "ubuntu 22.04") {
			t.Fatalf("detail should name the detected OS: %q", is.Detail)
		}
	}
}
