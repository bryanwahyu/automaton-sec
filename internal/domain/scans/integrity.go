package scans

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// A vulnerability scanner can only report CVEs for packages it can see. An
// image built to pass a scan exploits exactly that: delete the package
// manager's database, ship on an end-of-life base the feed no longer covers,
// or swap the tag after the scan ran, and Trivy honestly reports zero CVEs.
//
// ImageIntegrity records the evidence a "clean" result rests on, so zero
// findings is only trusted when Trivy actually had something to look at.

// Integrity check identifiers, stable for clients that filter on them.
const (
	CheckOSPackagesMissing = "os_packages_missing"
	CheckInventoryEmpty    = "inventory_empty"
	CheckEOSL              = "os_end_of_life"
	CheckDigestMismatch    = "digest_mismatch"
	CheckTagNotPinned      = "tag_not_pinned"
)

// Integrity verdicts.
const (
	// IntegrityVerified means nothing undermines the scan result.
	IntegrityVerified = "verified"
	// IntegrityUnverified means the image hides enough from the scanner that
	// its finding count cannot be taken as evidence of safety.
	IntegrityUnverified = "unverified"
)

// IntegrityIssue is one reason a scan result should not be taken at face value.
type IntegrityIssue struct {
	Check string `json:"check"`
	// Severity is critical, high, medium or low (counted into the scan's
	// SeverityCounts), or info (advice only, not counted).
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
}

// ImageIntegrity is the evidence behind a Trivy image scan.
type ImageIntegrity struct {
	Verdict      string `json:"verdict"`
	RequestedRef string `json:"requested_ref"`
	// Pinned is true when the request named an immutable digest.
	Pinned bool `json:"pinned"`
	// Digest is the registry digest of the image that was actually scanned.
	Digest string `json:"digest,omitempty"`
	// PinnedRef is the requested name at the scanned digest: deploy this, not
	// the tag, so the image that ships is the image that was scanned.
	PinnedRef    string           `json:"pinned_ref,omitempty"`
	ImageID      string           `json:"image_id,omitempty"`
	OSFamily     string           `json:"os_family,omitempty"`
	OSName       string           `json:"os_name,omitempty"`
	EOSL         bool             `json:"eosl,omitempty"`
	OSPackages   int              `json:"os_packages"`
	LangPackages int              `json:"lang_packages"`
	Issues       []IntegrityIssue `json:"issues"`
}

// AddTo folds the counted integrity issues into c, so a dashboard or summary
// that only reads severity counts still sees them.
func (i ImageIntegrity) AddTo(c *SeverityCounts) {
	for _, is := range i.Issues {
		switch is.Severity {
		case "critical", "high", "medium", "low":
			countSeverity(c, is.Severity)
		}
	}
}

// trivyImageReport is the subset of Trivy's JSON report (schema v2) the
// integrity checks read. Packages are only present with --list-all-pkgs.
type trivyImageReport struct {
	Metadata struct {
		OS *struct {
			Family string `json:"Family"`
			Name   string `json:"Name"`
			EOSL   bool   `json:"EOSL"`
		} `json:"OS"`
		ImageID     string   `json:"ImageID"`
		RepoDigests []string `json:"RepoDigests"`
	} `json:"Metadata"`
	Results []struct {
		Class    string            `json:"Class"`
		Packages []json.RawMessage `json:"Packages"`
	} `json:"Results"`
}

// AssessTrivyImage reads a Trivy image report and decides whether its result
// can be trusted. requestedRef is the image reference the caller asked for.
func AssessTrivyImage(requestedRef, artifactPath string) (ImageIntegrity, error) {
	b, err := os.ReadFile(artifactPath)
	if err != nil {
		return ImageIntegrity{}, err
	}
	var r trivyImageReport
	if err := json.Unmarshal(b, &r); err != nil {
		return ImageIntegrity{}, fmt.Errorf("parsing trivy report: %w", err)
	}

	name, wantDigest := splitImageRef(requestedRef)
	out := ImageIntegrity{
		RequestedRef: requestedRef,
		Pinned:       wantDigest != "",
		ImageID:      r.Metadata.ImageID,
		Issues:       []IntegrityIssue{},
	}
	if osInfo := r.Metadata.OS; osInfo != nil {
		out.OSFamily, out.OSName, out.EOSL = osInfo.Family, osInfo.Name, osInfo.EOSL
	}
	for _, res := range r.Results {
		switch res.Class {
		case "os-pkgs":
			out.OSPackages += len(res.Packages)
		case "lang-pkgs":
			out.LangPackages += len(res.Packages)
		}
	}

	scanned := repoDigests(r.Metadata.RepoDigests)
	if len(scanned) > 0 {
		out.Digest = scanned[0]
		if wantDigest != "" {
			for _, d := range scanned {
				if d == wantDigest {
					out.Digest = d
					break
				}
			}
		}
		out.PinnedRef = name + "@" + out.Digest
	}

	add := func(check, sev, detail string) {
		out.Issues = append(out.Issues, IntegrityIssue{Check: check, Severity: sev, Detail: detail})
	}

	switch {
	case out.OSFamily != "" && out.OSPackages == 0:
		add(CheckOSPackagesMissing, "high", fmt.Sprintf(
			"base OS detected (%s %s) but no OS packages were found. The package "+
				"database has likely been removed, which hides every OS-level CVE "+
				"from the scanner; a zero count here is not evidence of safety.",
			out.OSFamily, out.OSName))
	case out.OSFamily == "" && out.LangPackages == 0:
		add(CheckInventoryEmpty, "high",
			"no OS and no application packages were found, so the scanner had "+
				"nothing to check. Binaries in this image are unaccounted for; "+
				"inspect its layers or require an SBOM before trusting it.")
	}

	if out.EOSL {
		add(CheckEOSL, "high", fmt.Sprintf(
			"%s %s is end-of-service-life: it no longer receives security fixes and "+
				"vulnerability data for it is incomplete, so missing CVEs are "+
				"expected rather than reassuring.", out.OSFamily, out.OSName))
	}

	if wantDigest != "" && len(scanned) > 0 && !contains(scanned, wantDigest) {
		add(CheckDigestMismatch, "critical", fmt.Sprintf(
			"requested digest %s but the scanned image reports %s. The result "+
				"describes a different image from the one asked for.",
			wantDigest, strings.Join(scanned, ", ")))
	}

	if wantDigest == "" {
		detail := "the image was referenced by tag, which can be re-pointed to " +
			"different content after this scan."
		if out.PinnedRef != "" {
			detail += " Deploy " + out.PinnedRef + " to run exactly what was scanned."
		}
		add(CheckTagNotPinned, "info", detail)
	}

	out.Verdict = IntegrityVerified
	for _, is := range out.Issues {
		if is.Severity == "critical" || is.Severity == "high" {
			out.Verdict = IntegrityUnverified
			break
		}
	}
	return out, nil
}

// splitImageRef separates "name[:tag][@sha256:...]" into the repository name
// (tag dropped) and the digest, if any.
func splitImageRef(ref string) (name, digest string) {
	name = ref
	if at := strings.Index(name, "@"); at >= 0 {
		name, digest = name[:at], name[at+1:]
	}
	// A colon after the last slash is a tag; one before it is a registry port.
	if colon := strings.LastIndex(name, ":"); colon > strings.LastIndex(name, "/") {
		name = name[:colon]
	}
	return name, digest
}

// repoDigests extracts the "sha256:..." part of each "repo@sha256:..." entry.
func repoDigests(entries []string) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if at := strings.LastIndex(e, "@"); at >= 0 && at < len(e)-1 {
			d := e[at+1:]
			if !contains(out, d) {
				out = append(out, d)
			}
		}
	}
	return out
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}
