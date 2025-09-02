package prompt

import (
	"encoding/json"
	"fmt"
)

type Suggestion struct {
	FileURL  string   `json:"file_url"`
	Findings []string `json:"findings"`
	Advice   string   `json:"advice"`
}

func GetSystemPrompt() string {
	return `You are a security analyst. Analyze the provided file and respond with a JSON object containing your findings and advice.`
}

// AnalyzeFromMinioURL analyzes a file from a MinIO URL and returns suggestions in JSON format.
func AnalyzeFromMinioURL(url string) (string, error) {
	// TODO: Replace this mock logic with actual analysis of the file at the given URL.
	suggestion := Suggestion{
		FileURL:  url,
		Findings: []string{"No malware detected", "File is safe to use"},
		Advice:   "No action needed. Continue monitoring for future threats.",
	}
	result, err := json.MarshalIndent(suggestion, "", "  ")
	if err != nil {
		return "", fmt.Errorf("failed to marshal suggestion: %w", err)
	}
	return string(result), nil
}
