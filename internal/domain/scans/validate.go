package scans

import (
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// TargetPolicy decides which scan inputs the runner is allowed to accept.
//
// The zero value is the safe default: only http/https targets, only public
// hosts, and filesystem paths confined to WorkspaceRoot when one is set.
type TargetPolicy struct {
	// AllowPrivateTargets permits loopback, link-local and RFC1918 destinations.
	// Off by default: the API accepts targets from callers, so leaving it on
	// turns the service into an SSRF proxy into its own network.
	AllowPrivateTargets bool

	// AllowedHosts, when non-empty, restricts targets to these hosts. Entries
	// may be an exact host ("example.com") or a domain suffix (".example.com").
	AllowedHosts []string

	// WorkspaceRoot confines gitleaks paths. Empty means no filesystem scans
	// are permitted at all.
	WorkspaceRoot string
}

// imageRef matches name[:tag][@digest], with an optional registry host and port.
var imageRef = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]*(?::[0-9]+)?(?:/[a-zA-Z0-9][a-zA-Z0-9._-]*)*(?::[a-zA-Z0-9_][a-zA-Z0-9._-]{0,127})?(?:@sha256:[a-f0-9]{64})?$`)

// ValidateRunRequest checks every field the runner will hand to a scanner's
// argv. It is the single gate between untrusted request bodies and exec.
func (p TargetPolicy) ValidateRunRequest(req RunRequest) error {
	if !req.Tool.Valid() {
		return fmt.Errorf("unsupported tool: %q", req.Tool)
	}

	switch req.Tool {
	case ToolTrivy:
		return p.ValidateImage(req.Image)
	case ToolGitleaks:
		_, err := p.ValidatePath(req.Path)
		return err
	case ToolNuclei, ToolZAP, ToolSQLMap:
		return p.ValidateTarget(req.Target)
	}
	return nil
}

// ValidateTarget accepts only an absolute http/https URL pointing at a host the
// policy allows.
func (p TargetPolicy) ValidateTarget(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("target is required")
	}
	// A value starting with "-" is parsed as a flag by every scanner we shell
	// out to, regardless of the fact that we do not use a shell.
	if err := rejectFlagLike(raw, "target"); err != nil {
		return err
	}
	if strings.ContainsAny(raw, " \t\r\n") {
		return fmt.Errorf("target must not contain whitespace")
	}

	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("target is not a valid URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("target scheme must be http or https, got %q", u.Scheme)
	}
	host := u.Hostname()
	if host == "" {
		return fmt.Errorf("target must include a host")
	}
	if err := p.checkHostAllowed(host); err != nil {
		return err
	}
	return p.checkNotPrivate(host)
}

// ValidateImage accepts a container image reference for trivy.
func (p TargetPolicy) ValidateImage(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fmt.Errorf("image is required")
	}
	if err := rejectFlagLike(raw, "image"); err != nil {
		return err
	}
	if !imageRef.MatchString(raw) {
		return fmt.Errorf("image %q is not a valid name[:tag][@digest] reference", raw)
	}
	return nil
}

// ValidatePath resolves a gitleaks source path and confirms it stays inside the
// configured workspace root. It returns the cleaned absolute path.
func (p TargetPolicy) ValidatePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("path is required")
	}
	if err := rejectFlagLike(raw, "path"); err != nil {
		return "", err
	}
	if p.WorkspaceRoot == "" {
		return "", fmt.Errorf("filesystem scans are disabled: no workspace root configured")
	}

	root, err := filepath.Abs(p.WorkspaceRoot)
	if err != nil {
		return "", fmt.Errorf("invalid workspace root: %w", err)
	}
	abs := raw
	if !filepath.IsAbs(abs) {
		abs = filepath.Join(root, abs)
	}
	abs = filepath.Clean(abs)

	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("path %q escapes the workspace root", raw)
	}
	return abs, nil
}

func (p TargetPolicy) checkHostAllowed(host string) error {
	if len(p.AllowedHosts) == 0 {
		return nil
	}
	h := strings.ToLower(host)
	for _, allowed := range p.AllowedHosts {
		a := strings.ToLower(strings.TrimSpace(allowed))
		if a == "" {
			continue
		}
		if strings.HasPrefix(a, ".") {
			if strings.HasSuffix(h, a) || h == strings.TrimPrefix(a, ".") {
				return nil
			}
			continue
		}
		if h == a {
			return nil
		}
	}
	return fmt.Errorf("host %q is not in the configured target allowlist", host)
}

func (p TargetPolicy) checkNotPrivate(host string) error {
	if p.AllowPrivateTargets {
		return nil
	}

	ips := []net.IP{}
	if ip := net.ParseIP(host); ip != nil {
		ips = append(ips, ip)
	} else {
		resolved, err := net.LookupIP(host)
		if err != nil {
			return fmt.Errorf("cannot resolve target host %q: %w", host, err)
		}
		ips = append(ips, resolved...)
	}

	for _, ip := range ips {
		if isPrivate(ip) {
			return fmt.Errorf("target host %q resolves to non-public address %s; "+
				"set scanner.allowPrivateTargets to scan internal hosts", host, ip)
		}
	}
	return nil
}

// isPrivate reports whether ip is anything other than a routable public
// address. Link-local unicast covers the 169.254.169.254 cloud metadata
// endpoint, which is the address this check exists for.
func isPrivate(ip net.IP) bool {
	return ip.IsLoopback() ||
		ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() ||
		ip.IsUnspecified() ||
		ip.IsMulticast()
}

func rejectFlagLike(v, field string) error {
	if strings.HasPrefix(v, "-") {
		return fmt.Errorf("%s must not start with '-': %q would be read as a scanner flag", field, v)
	}
	return nil
}
