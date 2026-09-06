package sdk

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	secv1 "github.com/bryanwahyu/automaton-sec/gen/go/automaton/sec/v1"
)

// TriggerScan queues a scan and returns as soon as the server has an id for
// it. The scan itself is still running; pass the id to WaitForScan.
func (c *Client) TriggerScan(ctx context.Context, req *secv1.TriggerScanRequest) (*secv1.TriggerScanResponse, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.TriggerScanResponse, error) {
		return c.scans.TriggerScan(ctx, req)
	})
}

// GetScan reads one scan.
func (c *Client) GetScan(ctx context.Context, tenant, id string) (*secv1.Scan, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.Scan, error) {
		return c.scans.GetScan(ctx, &secv1.GetScanRequest{Tenant: tenant, Id: id})
	})
}

// ListScans pages through a tenant's scans with offset pagination.
func (c *Client) ListScans(ctx context.Context, req *secv1.ListScansRequest) (*secv1.ListScansResponse, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.ListScansResponse, error) {
		return c.scans.ListScans(ctx, req)
	})
}

// ListLatestScans pages through the newest scans first. Pass the previous
// response's NextCursor to continue; a nil cursor starts at the newest.
func (c *Client) ListLatestScans(ctx context.Context, req *secv1.ListLatestScansRequest) (*secv1.ListLatestScansResponse, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.ListLatestScansResponse, error) {
		return c.scans.ListLatestScans(ctx, req)
	})
}

// RetryScan re-runs an existing scan.
func (c *Client) RetryScan(ctx context.Context, tenant, id string) (*secv1.RetryScanResponse, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.RetryScanResponse, error) {
		return c.scans.RetryScan(ctx, &secv1.RetryScanRequest{Tenant: tenant, Id: id})
	})
}

// GetSummary aggregates findings over the last days days.
func (c *Client) GetSummary(ctx context.Context, tenant string, days int32) (*secv1.Summary, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.Summary, error) {
		return c.scans.GetSummary(ctx, &secv1.GetSummaryRequest{Tenant: tenant, Days: days})
	})
}

// ListScanErrors reads the failures recorded for one scan. A scan that ends
// with STATUS_ERROR usually has an entry here explaining why.
func (c *Client) ListScanErrors(ctx context.Context, tenant, scanID string, limit int32) (*secv1.ListScanErrorsResponse, error) {
	return do(ctx, c, func(ctx context.Context) (*secv1.ListScanErrorsResponse, error) {
		return c.scans.ListScanErrors(ctx, &secv1.ListScanErrorsRequest{
			Tenant: tenant, ScanId: scanID, Limit: limit,
		})
	})
}

// WatchScan opens the raw stream. Most callers want WaitForScan instead; this
// is for a caller that wants each intermediate update, a progress bar say.
//
// The stream is not bounded by the client timeout — a scan may legitimately run
// for many minutes — so bound it with the context you pass.
func (c *Client) WatchScan(ctx context.Context, tenant, id string) (secv1.ScanService_WatchScanClient, error) {
	return c.scans.WatchScan(c.authContext(ctx), &secv1.WatchScanRequest{Tenant: tenant, Id: id})
}

// WaitForScan blocks until the scan reaches a terminal status and returns its
// final state.
//
// It streams, and falls back to polling when the server does not support the
// stream or something between here and there will not carry it. Both paths
// return the same thing, so a caller never has to care which one ran.
//
// A scan that finished before the call still returns immediately: the server
// sends the current state as the stream's first message.
func (c *Client) WaitForScan(ctx context.Context, tenant, id string) (*secv1.Scan, error) {
	scan, err := c.waitViaStream(ctx, tenant, id)
	if err == nil {
		return scan, nil
	}
	// Unimplemented means an older server. Unavailable here means the stream
	// itself could not be established — a proxy that drops long-lived
	// connections, typically. Polling still works in both cases; every other
	// failure is real and is returned as-is.
	if code := status.Code(err); code != codes.Unimplemented && code != codes.Unavailable {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	return c.waitViaPolling(ctx, tenant, id)
}

func (c *Client) waitViaStream(ctx context.Context, tenant, id string) (*secv1.Scan, error) {
	stream, err := c.WatchScan(ctx, tenant, id)
	if err != nil {
		return nil, err
	}

	var last *secv1.Scan
	for {
		scan, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			// The server closes the stream once the scan is terminal, so the
			// last message received is the final state. No message at all
			// means the stream never carried one, which is not a result.
			if last == nil {
				return nil, status.Error(codes.Unavailable, "watch stream closed without sending a scan")
			}
			return last, nil
		}
		if err != nil {
			return nil, err
		}
		last = scan
		if isTerminal(scan.GetStatus()) {
			return scan, nil
		}
	}
}

func (c *Client) waitViaPolling(ctx context.Context, tenant, id string) (*secv1.Scan, error) {
	ticker := time.NewTicker(c.watch)
	defer ticker.Stop()

	for {
		scan, err := c.GetScan(ctx, tenant, id)
		if err != nil {
			return nil, err
		}
		if isTerminal(scan.GetStatus()) {
			return scan, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-ticker.C:
		}
	}
}

// isTerminal reports whether a scan will not change again on its own.
// STATUS_UNSPECIFIED counts as non-terminal: it means the server sent a status
// this client does not know, and waiting is safer than reporting a scan
// finished when it has not.
func isTerminal(s secv1.Status) bool {
	switch s {
	case secv1.Status_STATUS_SUCCESS, secv1.Status_STATUS_FAILED, secv1.Status_STATUS_ERROR:
		return true
	default:
		return false
	}
}

// FindingsError reports a scan that completed but found something. Callers
// that want a CI step to fail on findings can use errors.As on it.
type FindingsError struct {
	Scan *secv1.Scan
}

func (e *FindingsError) Error() string {
	c := e.Scan.GetCounts()
	return fmt.Sprintf("scan %s found %d finding(s): %d critical, %d high, %d medium, %d low",
		e.Scan.GetId(), c.GetTotal(), c.GetCritical(), c.GetHigh(), c.GetMedium(), c.GetLow())
}
