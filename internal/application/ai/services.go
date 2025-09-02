package ai

import (
	"context"

	"github.com/bryanwahyu/automaton-sec/internal/domain/ai"
)

type Service struct {
	client ai.Client
}

func NewService(client ai.Client) *Service {
	return &Service{client: client}
}

func (s *Service) Analyze(ctx context.Context, fileURL string) (string, error) {
	return s.client.Analyze(ctx, fileURL)
}
