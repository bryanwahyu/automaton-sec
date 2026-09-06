package grpcserver

import (
	"encoding/json"
	"time"

	"google.golang.org/protobuf/types/known/structpb"
	"google.golang.org/protobuf/types/known/timestamppb"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
	anldom "github.com/bryanwahyu/automaton-sec/internal/domain/analyst"
	serrdom "github.com/bryanwahyu/automaton-sec/internal/domain/scanerrors"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// The proto enums and the domain's string constants are two spellings of the
// same set. These tables are the only place that knows both, so adding a tool
// is one entry here rather than a switch in every handler.

var toolToProto = map[domain.Tool]secv1.Tool{
	domain.ToolSQLMap:     secv1.Tool_TOOL_SQLMAP,
	domain.ToolTrivy:      secv1.Tool_TOOL_TRIVY,
	domain.ToolGitleaks:   secv1.Tool_TOOL_GITLEAKS,
	domain.ToolZAP:        secv1.Tool_TOOL_ZAP,
	domain.ToolNuclei:     secv1.Tool_TOOL_NUCLEI,
	domain.ToolSemgrep:    secv1.Tool_TOOL_SEMGREP,
	domain.ToolOSVScanner: secv1.Tool_TOOL_OSV_SCANNER,
}

var protoToTool = func() map[secv1.Tool]domain.Tool {
	m := make(map[secv1.Tool]domain.Tool, len(toolToProto))
	for k, v := range toolToProto {
		m[v] = k
	}
	return m
}()

var statusToProto = map[domain.Status]secv1.Status{
	domain.StatusRunning: secv1.Status_STATUS_RUNNING,
	domain.StatusSuccess: secv1.Status_STATUS_SUCCESS,
	domain.StatusFailed:  secv1.Status_STATUS_FAILED,
	domain.StatusError:   secv1.Status_STATUS_ERROR,
}

var protoToStatus = func() map[secv1.Status]domain.Status {
	m := make(map[secv1.Status]domain.Status, len(statusToProto))
	for k, v := range statusToProto {
		m[v] = k
	}
	return m
}()

// toolFromProto returns the domain tool name. TOOL_UNSPECIFIED becomes the
// empty string, which the target policy rejects with a clear message — better
// than inventing a default the caller did not ask for.
func toolFromProto(t secv1.Tool) domain.Tool { return protoToTool[t] }

func toolToProtoEnum(t domain.Tool) secv1.Tool { return toolToProto[t] }

// statusFromProto is used for filters only, where the zero value means "no
// filter" rather than a status to match.
func statusFromProto(s secv1.Status) domain.Status { return protoToStatus[s] }

func statusToProtoEnum(s domain.Status) secv1.Status { return statusToProto[s] }

// scanToProto renders a stored scan on the wire. A nil scan yields nil so a
// caller-visible NotFound is decided by the handler, not here.
func scanToProto(s *domain.Scan) *secv1.Scan {
	if s == nil {
		return nil
	}
	out := &secv1.Scan{
		Id:          string(s.ID),
		Tenant:      s.TenantID,
		Tool:        toolToProtoEnum(s.Tool),
		Target:      s.Target,
		Image:       s.Image,
		Path:        s.Path,
		Status:      statusToProtoEnum(s.Status),
		ArtifactUrl: s.ArtifactURL,
		RawFormat:   s.RawFormat,
		DurationMs:  s.DurationMS,
		Source:      s.Source,
		CommitSha:   s.CommitSHA,
		Branch:      s.Branch,
		Counts: &secv1.SeverityCounts{
			Critical: int32(s.Counts.Critical),
			High:     int32(s.Counts.High),
			Medium:   int32(s.Counts.Medium),
			Low:      int32(s.Counts.Low),
			Total:    int32(s.Counts.Total),
		},
		Metadata: metadataToStruct(s.Metadata),
	}
	if !s.TriggeredAt.IsZero() {
		out.TriggeredAt = timestamppb.New(s.TriggeredAt)
	}
	return out
}

// metadataToStruct converts the free-form metadata the repositories hand back.
//
// It arrives as whatever the JSON decoder produced, so the round trip through
// JSON is the only conversion that handles every shape uniformly. Anything that
// will not convert is dropped rather than failing the request: metadata is
// caller context, never something the server acts on.
func metadataToStruct(meta any) *structpb.Struct {
	if meta == nil {
		return nil
	}
	if m, ok := meta.(map[string]any); ok {
		if s, err := structpb.NewStruct(m); err == nil {
			return s
		}
		return nil
	}
	raw, err := json.Marshal(meta)
	if err != nil {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	s, err := structpb.NewStruct(m)
	if err != nil {
		return nil
	}
	return s
}

// structToMetadata unwraps a request's metadata into the plain Go values the
// application layer stores.
func structToMetadata(s *structpb.Struct) any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

func analysisToProto(a *anldom.Analysis) *secv1.Analysis {
	if a == nil {
		return nil
	}
	out := &secv1.Analysis{
		Id:      string(a.ID),
		Tenant:  a.TenantID,
		ScanId:  a.ScanID,
		FileUrl: a.FileURL,
		Result:  a.Result,
	}
	if !a.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(a.CreatedAt)
	}
	return out
}

func scanErrorToProto(e *serrdom.ScanError) *secv1.ScanError {
	if e == nil {
		return nil
	}
	out := &secv1.ScanError{
		Id:          e.ID,
		Tenant:      e.TenantID,
		ScanId:      e.ScanID,
		Tool:        e.Tool,
		Phase:       e.Phase,
		Message:     e.Message,
		DetailsJson: e.DetailsJSON,
	}
	if !e.CreatedAt.IsZero() {
		out.CreatedAt = timestamppb.New(e.CreatedAt)
	}
	return out
}

// cursorFromProto reads a pagination cursor. Both halves are required together
// because a timestamp alone is not unique; a half-filled cursor is treated as
// no cursor at all, which returns the first page instead of a silent misread.
func cursorFromProto(c *secv1.Cursor) (time.Time, string, bool) {
	if c == nil || c.GetId() == "" || c.GetTriggeredAt() == nil {
		return time.Time{}, "", false
	}
	return c.GetTriggeredAt().AsTime(), c.GetId(), true
}
