package ai

import "context"

type Client interface {
	Analyze(ctx context.Context, fileURL string) (string, error)
}
