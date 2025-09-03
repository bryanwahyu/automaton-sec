package prompt

import (
    "encoding/json"
    "fmt"
)

// GetSystemPrompt provides strict directions and schema for JSON output.
func GetSystemPrompt() string {
    return `You are a senior application security analyst. You must produce one valid JSON object only (no markdown, no commentary) that follows the schema below. Do not include code fences.

Requirements:
- Output must be a single JSON object.
- Use lowercase severity values: critical, high, medium, low, info.
- counts.total must equal counts.critical + counts.high + counts.medium + counts.low.
- findings is an array of objects; include at least a title, severity, and summary. Keep items concise.
- If the actual file content is not provided in the prompt, infer likely risks from the file type and URL safely and conservatively.

Schema (example with empty values):
{
  "file_url": "<string>",
  "counts": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0},
  "findings": [
    {
      "title": "<string>",
      "severity": "<critical|high|medium|low|info>",
      "summary": "<string>",
      "recommendation": "<string>"
    }
  ],
  "advice": "<string>"
}`
}

// GetUserPrompt builds a compact user message around a file URL.
func GetUserPrompt(fileURL string) string {
    return fmt.Sprintf("Analyze the file at this URL and respond with the JSON per schema. URL: %s", fileURL)
}

// Suggestion is a sample structure that matches the schema used by the system prompt.
type Suggestion struct {
    FileURL string `json:"file_url"`
    Counts  struct {
        Critical int `json:"critical"`
        High     int `json:"high"`
        Medium   int `json:"medium"`
        Low      int `json:"low"`
        Total    int `json:"total"`
    } `json:"counts"`
    Findings []struct {
        Title          string `json:"title"`
        Severity       string `json:"severity"`
        Summary        string `json:"summary"`
        Recommendation string `json:"recommendation"`
    } `json:"findings"`
    Advice string `json:"advice"`
}

// AnalyzeFromMinioURL returns a mock JSON following the schema. Replace with real logic as needed.
func AnalyzeFromMinioURL(url string) (string, error) {
    sample := Suggestion{
        FileURL: url,
        Advice:  "Review repository secrets management and enable CI scanning.",
    }
    // Example: one high severity finding
    sample.Counts.High = 1
    sample.Counts.Total = sample.Counts.Critical + sample.Counts.High + sample.Counts.Medium + sample.Counts.Low
    sample.Findings = append(sample.Findings, struct {
        Title          string `json:"title"`
        Severity       string `json:"severity"`
        Summary        string `json:"summary"`
        Recommendation string `json:"recommendation"`
    }{
        Title:          "Potential hardcoded credentials",
        Severity:       "high",
        Summary:        "The file name or path suggests secrets might be embedded.",
        Recommendation: "Use environment variables or secret managers; rotate any exposed keys.",
    })

    b, err := json.Marshal(sample)
    if err != nil {
        return "", fmt.Errorf("failed to marshal suggestion: %w", err)
    }
    return string(b), nil
}
