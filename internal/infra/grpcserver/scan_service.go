package grpcserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
	"github.com/bryanwahyu/automaton-sec/internal/apierr"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	serrdom "github.com/bryanwahyu/automaton-sec/internal/domain/scanerrors"
	domain "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
)

// defaultWatchInterval is how often WatchScan re-reads a running scan.
//
// Two seconds is a compromise: scans run for minutes, so a tighter interval
// only adds load, and a looser one makes completion feel laggy. It is one
// poller per watched scan rather than one per client, which is the point.
const defaultWatchInterval = 2 * time.Second

// scanService implements ScanService over the shared Server state. Embedding
// the generated Unimplemented type is what keeps adding an RPC to the proto
// from breaking this build before the method exists.
type scanService struct {
	secv1.UnimplementedScanServiceServer
	*Server
}

func (s *scanService) TriggerScan(ctx context.Context, req *secv1.TriggerScanRequest) (*secv1.TriggerScanResponse, error) {
	tool := toolFromProto(req.GetTool())

	// The id is minted here, before the scan is queued, so the response can
	// carry it. Without it a caller has no handle on the scan it just started.
	scanID := appscans.NewScanID(string(tool))

	cmd := appscans.TriggerScanCommand{
		ScanID:    scanID,
		TenantID:  req.GetTenant(),
		Tool:      string(tool),
		Mode:      req.GetMode(),
		Image:     req.GetImage(),
		Path:      req.GetPath(),
		Target:    req.GetTarget(),
		Source:    req.GetSource(),
		CommitSHA: req.GetCommitSha(),
		Branch:    req.GetBranch(),
		Metadata:  structToMetadata(req.GetMetadata()),
	}

	// Reject unusable input up front so the caller sees the reason instead of
	// a scan that fails silently in the background.
	if err := s.policy.ValidateRunRequest(domain.RunRequest{
		Tool:   tool,
		Mode:   cmd.Mode,
		Image:  cmd.Image,
		Path:   cmd.Path,
		Target: cmd.Target,
	}); err != nil {
		return nil, toStatus(apierr.InvalidArgument(err))
	}

	queuedAt := time.Now()
	tenant := req.GetTenant()
	err := s.pool.Submit(func(runCtx context.Context) {
		result, err := s.scansSvc.TriggerScan(runCtx, cmd)
		if err != nil {
			log.Printf("grpc scan failed tenant=%s tool=%s id=%s: %v", tenant, tool, result.ID, err)
			// TriggerScan has already marked the row as error; record the
			// detail so it can be read back through ListScanErrors.
			s.recordScanError(tenant, result.ID, string(tool), "trigger", err)
			return
		}
		log.Printf("grpc scan finished tenant=%s tool=%s id=%s status=%s artifact=%s",
			tenant, tool, result.ID, result.Status, result.ArtifactURL)
	})
	if err != nil {
		return nil, toStatus(err)
	}

	return &secv1.TriggerScanResponse{
		ScanId:    scanID,
		Tenant:    tenant,
		Tool:      req.GetTool(),
		Branch:    req.GetBranch(),
		CommitSha: req.GetCommitSha(),
		QueuedAt:  timestamppb.New(queuedAt),
	}, nil
}

func (s *scanService) GetScan(ctx context.Context, req *secv1.GetScanRequest) (*secv1.Scan, error) {
	scan, err := s.scansSvc.Get(ctx, req.GetTenant(), domain.ScanID(req.GetId()))
	if err != nil {
		return nil, toStatus(err)
	}
	if scan == nil {
		return nil, toStatus(apierr.ErrNotFound)
	}
	return scanToProto(scan), nil
}

func (s *scanService) ListScans(ctx context.Context, req *secv1.ListScansRequest) (*secv1.ListScansResponse, error) {
	filters := map[string]any{}
	if f := req.GetFilters(); f != nil {
		if f.GetTarget() != "" {
			filters["target"] = f.GetTarget()
		}
		if t := toolFromProto(f.GetTool()); t != "" {
			filters["tool"] = string(t)
		}
		if st := statusFromProto(f.GetStatus()); st != "" {
			filters["status"] = string(st)
		}
		if f.GetBranch() != "" {
			filters["branch"] = f.GetBranch()
		}
	}

	page := clampPage(req.GetPage())
	pageSize := clampPageSize(req.GetPageSize())

	result, err := s.scansSvc.Paginate(ctx, req.GetTenant(), page, pageSize, filters)
	if err != nil {
		return nil, toStatus(err)
	}

	out := &secv1.ListScansResponse{
		Scans:      make([]*secv1.Scan, 0, len(result.Data)),
		Page:       int32(result.Page),
		PageSize:   int32(result.PageSize),
		TotalItems: result.Total,
		TotalPages: int32(result.TotalPages),
	}
	for _, sc := range result.Data {
		out.Scans = append(out.Scans, scanToProto(sc))
	}
	return out, nil
}

func (s *scanService) ListLatestScans(ctx context.Context, req *secv1.ListLatestScansRequest) (*secv1.ListLatestScansResponse, error) {
	limit := clampPageSize(req.GetLimit())

	var (
		list []*domain.Scan
		err  error
	)
	if cursorTime, cursorID, ok := cursorFromProto(req.GetCursor()); ok {
		list, err = s.scansSvc.Cursor(ctx, req.GetTenant(), cursorTime, cursorID, limit)
	} else {
		list, err = s.scansSvc.Latest(ctx, req.GetTenant(), limit)
	}
	if err != nil {
		return nil, toStatus(err)
	}

	out := &secv1.ListLatestScansResponse{
		Scans: make([]*secv1.Scan, 0, len(list)),
		// A full page means there is probably another one. This is the same
		// heuristic the HTTP endpoint uses; it can be one page optimistic when
		// the total is an exact multiple of the limit.
		HasMore: len(list) == limit,
	}
	for _, sc := range list {
		out.Scans = append(out.Scans, scanToProto(sc))
	}
	if out.HasMore {
		last := list[len(list)-1]
		out.NextCursor = &secv1.Cursor{
			TriggeredAt: timestamppb.New(last.TriggeredAt),
			Id:          string(last.ID),
		}
	}
	return out, nil
}

func (s *scanService) RetryScan(ctx context.Context, req *secv1.RetryScanRequest) (*secv1.RetryScanResponse, error) {
	tenant := req.GetTenant()
	id := req.GetId()

	// Confirm the scan exists before promising a retry.
	existing, err := s.scansSvc.Get(ctx, tenant, domain.ScanID(id))
	if err != nil {
		return nil, toStatus(err)
	}
	if existing == nil {
		return nil, toStatus(apierr.ErrNotFound)
	}

	err = s.pool.Submit(func(runCtx context.Context) {
		result, err := s.scansSvc.RetryScan(runCtx, tenant, domain.ScanID(id))
		if err != nil {
			log.Printf("grpc retry scan failed tenant=%s id=%s: %v", tenant, id, err)
			s.recordScanError(tenant, id, string(existing.Tool), "retry", err)
			return
		}
		log.Printf("grpc retry scan finished tenant=%s id=%s status=%s artifact=%s",
			tenant, id, result.Status, result.ArtifactURL)
	})
	if err != nil {
		return nil, toStatus(err)
	}

	return &secv1.RetryScanResponse{
		ScanId:   id,
		Tenant:   tenant,
		QueuedAt: timestamppb.New(time.Now()),
	}, nil
}

func (s *scanService) GetSummary(ctx context.Context, req *secv1.GetSummaryRequest) (*secv1.Summary, error) {
	summary, err := s.scansSvc.Summary(ctx, req.GetTenant(), clampDays(req.GetDays()))
	if err != nil {
		return nil, toStatus(err)
	}
	return &secv1.Summary{
		TotalScans: summaryValue(summary, "total_scans"),
		Critical:   summaryValue(summary, "critical"),
		High:       summaryValue(summary, "high"),
		Medium:     summaryValue(summary, "medium"),
	}, nil
}

// summaryValue reads one counter out of the map the application service
// returns. The map is an int per key today; anything else counts as zero
// rather than failing a whole summary over one unreadable field.
func summaryValue(m map[string]any, key string) int64 {
	switch v := m[key].(type) {
	case int:
		return int64(v)
	case int64:
		return v
	case float64:
		return int64(v)
	default:
		return 0
	}
}

func (s *scanService) ListScanErrors(ctx context.Context, req *secv1.ListScanErrorsRequest) (*secv1.ListScanErrorsResponse, error) {
	if s.serrRepo == nil {
		return nil, toStatus(fmt.Errorf("errors repository not configured"))
	}
	list, err := s.serrRepo.ListByScan(ctx, req.GetTenant(), req.GetScanId(), clampPageSize(req.GetLimit()))
	if err != nil {
		return nil, toStatus(err)
	}
	out := &secv1.ListScanErrorsResponse{Errors: make([]*secv1.ScanError, 0, len(list))}
	for _, e := range list {
		out.Errors = append(out.Errors, scanErrorToProto(e))
	}
	return out, nil
}

// WatchScan streams a scan until it reaches a terminal status.
//
// The repository is the only source of truth about progress — nothing in the
// system emits a completion event yet — so this polls it and pushes on change.
// That is still an improvement on every client running its own loop: one
// poller per watched scan, and the client learns of completion as soon as the
// row changes rather than on its next scheduled poll.
//
// Replacing the poll with a real notification path does not change what a
// client sees, so clients written against this keep working.
func (s *scanService) WatchScan(req *secv1.WatchScanRequest, stream secv1.ScanService_WatchScanServer) error {
	ctx := stream.Context()
	tenant := req.GetTenant()
	id := domain.ScanID(req.GetId())

	// The first read doubles as an existence check, so a watch on an unknown
	// id fails immediately instead of polling a row that will never appear.
	scan, err := s.scansSvc.Get(ctx, tenant, id)
	if err != nil {
		return toStatus(err)
	}
	if scan == nil {
		return toStatus(apierr.ErrNotFound)
	}
	if err := stream.Send(scanToProto(scan)); err != nil {
		return err
	}
	if isTerminal(scan.Status) {
		return nil
	}
	last := fingerprint(scan)

	ticker := time.NewTicker(s.watchInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			// The client hung up or its deadline passed. Neither is a server
			// error, so the stream just ends.
			return nil
		case <-ticker.C:
			scan, err := s.scansSvc.Get(ctx, tenant, id)
			if err != nil {
				return toStatus(err)
			}
			if scan == nil {
				return toStatus(apierr.ErrNotFound)
			}
			// Only a change is worth a message; an unchanged running scan
			// would otherwise send one every tick for the length of the scan.
			if fp := fingerprint(scan); fp != last {
				last = fp
				if err := stream.Send(scanToProto(scan)); err != nil {
					return err
				}
			}
			if isTerminal(scan.Status) {
				return nil
			}
		}
	}
}

// isTerminal reports whether a scan will not change again on its own.
func isTerminal(st domain.Status) bool { return st != domain.StatusRunning }

// fingerprint captures the fields a watcher cares about, so an unchanged row
// does not produce a message. The counts move independently of the status
// because AI analysis can update them after the scan itself finished.
func fingerprint(s *domain.Scan) string {
	return fmt.Sprintf("%s|%s|%d|%d|%d|%d|%d|%d",
		s.Status, s.ArtifactURL, s.DurationMS,
		s.Counts.Critical, s.Counts.High, s.Counts.Medium, s.Counts.Low, s.Counts.Total)
}

// recordScanError stores a background failure so it can be read back through
// ListScanErrors. It mirrors the HTTP router's helper because both surfaces
// queue onto the same pool and fail the same way.
func (s *scanService) recordScanError(tenant, scanID, tool, phase string, cause error) {
	if s.serrRepo == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	details, _ := json.Marshal(map[string]any{
		"status": "error",
		"type":   "scan_error_" + phase,
		"time":   time.Now().Format(time.RFC3339Nano),
	})
	if err := s.serrRepo.Save(ctx, &serrdom.ScanError{
		TenantID:    tenant,
		ScanID:      scanID,
		Tool:        tool,
		Phase:       phase,
		Message:     cause.Error(),
		DetailsJSON: string(details),
	}); err != nil {
		log.Printf("could not record scan error tenant=%s scan=%s: %v", tenant, scanID, err)
	}
}
