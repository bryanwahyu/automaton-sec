package sdk

import (
	"google.golang.org/protobuf/types/known/structpb"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
)

// Each scanner reads exactly one kind of input: trivy an image, the filesystem
// tools a path, the rest a URL. These constructors put the value in the field
// that tool actually reads, so a caller cannot quietly send an image to nuclei
// and get a validation error back from the server.

// TrivyScan scans a container image.
func TrivyScan(tenant, image string) *secv1.TriggerScanRequest {
	return &secv1.TriggerScanRequest{Tenant: tenant, Tool: secv1.Tool_TOOL_TRIVY, Image: image}
}

// NucleiScan scans a URL for known vulnerabilities.
func NucleiScan(tenant, target string) *secv1.TriggerScanRequest {
	return &secv1.TriggerScanRequest{Tenant: tenant, Tool: secv1.Tool_TOOL_NUCLEI, Target: target}
}

// ZAPScan runs a DAST scan against a URL. mode selects the profile, e.g.
// "baseline" or "full"; empty takes the server's default.
func ZAPScan(tenant, target, mode string) *secv1.TriggerScanRequest {
	return &secv1.TriggerScanRequest{Tenant: tenant, Tool: secv1.Tool_TOOL_ZAP, Target: target, Mode: mode}
}

// SQLMapScan probes a URL for SQL injection.
func SQLMapScan(tenant, target string) *secv1.TriggerScanRequest {
	return &secv1.TriggerScanRequest{Tenant: tenant, Tool: secv1.Tool_TOOL_SQLMAP, Target: target}
}

// GitleaksScan searches a checkout for committed secrets. The path is resolved
// inside the server's configured workspace root; a path outside it is refused.
func GitleaksScan(tenant, path string) *secv1.TriggerScanRequest {
	return &secv1.TriggerScanRequest{Tenant: tenant, Tool: secv1.Tool_TOOL_GITLEAKS, Path: path}
}

// SemgrepScan runs static analysis over a checkout.
func SemgrepScan(tenant, path string) *secv1.TriggerScanRequest {
	return &secv1.TriggerScanRequest{Tenant: tenant, Tool: secv1.Tool_TOOL_SEMGREP, Path: path}
}

// OSVScan resolves a checkout's lockfiles against the OSV database.
func OSVScan(tenant, path string) *secv1.TriggerScanRequest {
	return &secv1.TriggerScanRequest{Tenant: tenant, Tool: secv1.Tool_TOOL_OSV_SCANNER, Path: path}
}

// WithCI stamps the request with the commit it covers, so a stored scan can be
// traced back to what produced it.
func WithCI(req *secv1.TriggerScanRequest, source, branch, commitSHA string) *secv1.TriggerScanRequest {
	req.Source = source
	req.Branch = branch
	req.CommitSha = commitSHA
	return req
}

// WithMetadata attaches free-form context, stored and returned untouched.
// Values must be JSON-representable; anything else is rejected here rather
// than silently dropped by the server.
func WithMetadata(req *secv1.TriggerScanRequest, meta map[string]any) (*secv1.TriggerScanRequest, error) {
	s, err := structpb.NewStruct(meta)
	if err != nil {
		return nil, err
	}
	req.Metadata = s
	return req, nil
}
