package openai

import (
    "context"
    "fmt"
    "strings"

    "github.com/bryanwahyu/automaton-sec/internal/infra/ai/prompt"
    "github.com/sashabaranov/go-openai"
)

const maxTokens = 2048

type Client struct {
    *openai.Client
    Model string
}

func NewClient(apiKey, model string) *Client {
    return &Client{Client: openai.NewClient(apiKey), Model: model}
}

func (c *Client) Analyze(ctx context.Context, fileURL string) (string, error) {
    model := c.Model
    if model == "" {
        model = "o3-2025-04-16"
    }
    req := openai.ChatCompletionRequest{
        Model: model,
        ResponseFormat: &openai.ChatCompletionResponseFormat{
            Type: openai.ChatCompletionResponseFormatTypeJSONObject,
        },
        Messages: []openai.ChatCompletionMessage{
            {Role: openai.ChatMessageRoleSystem, Content: prompt.GetSystemPrompt()},
            {Role: openai.ChatMessageRoleUser, Content: prompt.GetUserPrompt(fileURL)},
        },
    }
    // For reasoning models (o1/o3/o4/gpt-5*) use MaxCompletionTokens instead of MaxTokens
    if strings.HasPrefix(model, "o1") || strings.HasPrefix(model, "o3") || strings.HasPrefix(model, "o4") || strings.HasPrefix(model, "gpt-5") {
        req.MaxCompletionTokens = maxTokens
    } else {
        req.MaxTokens = maxTokens
    }

    resp, err := c.CreateChatCompletion(ctx, req)
    if err != nil {
        return "", fmt.Errorf("failed to create chat completion: %w", err)
    }

    return resp.Choices[0].Message.Content, nil
}
