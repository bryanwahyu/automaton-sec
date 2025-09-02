package openai

import (
	"context"
	"fmt"

	"github.com/bryanwahyu/automaton-sec/internal/infra/ai/prompt"
	"github.com/sashabaranov/go-openai"
)

const maxTokens = 2048

type Client struct {
	*openai.Client
}

func NewClient(apiKey string) *Client {
	return &Client{Client: openai.NewClient(apiKey)}
}

func (c *Client) Analyze(ctx context.Context, fileURL string) (string, error) {
	resp, err := c.CreateChatCompletion(ctx, openai.ChatCompletionRequest{
		Model:     "gpt-4-1106-preview",
		MaxTokens: maxTokens,
		ResponseFormat: &openai.ChatCompletionResponseFormat{
			Type: openai.ChatCompletionResponseFormatTypeJSONObject,
		},
		Messages: []openai.ChatCompletionMessage{
			{
				Role:    openai.ChatMessageRoleSystem,
				Content: prompt.GetSystemPrompt(),
			},
			{
				Role:    openai.ChatMessageRoleUser,
				Content: fileURL,
			},
		},
	})
	if err != nil {
		return "", fmt.Errorf("failed to create chat completion: %w", err)
	}

	return resp.Choices[0].Message.Content, nil
}
