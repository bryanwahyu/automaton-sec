package middleware

import (
	"fmt"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
)

// Input validation and sanitization utilities

// ValidateTool checks if the tool name is in the allowed list
func ValidateTool(tool string) error {
	allowed := map[string]bool{
		"trivy":   true,
		"nuclei":  true,
		"gitleaks": true,
		"zap":     true,
		"sqlmap":  true,
	}

	if !allowed[strings.ToLower(tool)] {
		return fmt.Errorf("invalid tool: %s (allowed: trivy, nuclei, gitleaks, zap, sqlmap)", tool)
	}
	return nil
}

// ValidateURL validates and sanitizes URLs
func ValidateURL(rawURL string) error {
	if rawURL == "" {
		return fmt.Errorf("URL cannot be empty")
	}

	// Parse URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("invalid URL format: %w", err)
	}

	// Check scheme
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("invalid URL scheme: %s (allowed: http, https)", u.Scheme)
	}

	// Check for localhost/internal IPs (SSRF protection)
	host := strings.ToLower(u.Hostname())
	blocked := []string{"localhost", "127.0.0.1", "0.0.0.0", "[::]", "::1"}
	for _, b := range blocked {
		if strings.Contains(host, b) {
			return fmt.Errorf("localhost/internal IPs are not allowed")
		}
	}

	// Block private IP ranges (basic check)
	if strings.HasPrefix(host, "10.") ||
	   strings.HasPrefix(host, "192.168.") ||
	   strings.HasPrefix(host, "172.16.") ||
	   strings.HasPrefix(host, "172.31.") {
		return fmt.Errorf("private IP ranges are not allowed")
	}

	return nil
}

// ValidateImageName validates Docker image names
func ValidateImageName(image string) error {
	if image == "" {
		return nil // Optional field
	}

	// Docker image name pattern: [registry/]name[:tag][@digest]
	pattern := `^([a-z0-9]+([._-][a-z0-9]+)*(/[a-z0-9]+([._-][a-z0-9]+)*)*(:[a-zA-Z0-9._-]+)?(@sha256:[a-f0-9]{64})?)$`
	matched, _ := regexp.MatchString(pattern, strings.ToLower(image))
	if !matched {
		return fmt.Errorf("invalid Docker image name format")
	}

	// Block dangerous patterns
	dangerous := []string{"../", "..", "$(", "`", "&", "|", ";", "\n", "\r"}
	for _, d := range dangerous {
		if strings.Contains(image, d) {
			return fmt.Errorf("invalid characters in image name")
		}
	}

	return nil
}

// ValidatePath validates file paths (for security)
func ValidatePath(path string) error {
	if path == "" {
		return nil // Optional field
	}

	// Clean the path
	cleaned := filepath.Clean(path)

	// Block path traversal attempts
	if strings.Contains(cleaned, "..") {
		return fmt.Errorf("path traversal detected")
	}

	// Block absolute paths to sensitive directories
	blocked := []string{"/etc", "/proc", "/sys", "/dev", "/root", "/var", "/boot"}
	for _, b := range blocked {
		if strings.HasPrefix(cleaned, b) {
			return fmt.Errorf("access to %s is not allowed", b)
		}
	}

	// Block dangerous patterns
	dangerous := []string{"$(", "`", "&", "|", ";", "\n", "\r", "&&", "||"}
	for _, d := range dangerous {
		if strings.Contains(path, d) {
			return fmt.Errorf("invalid characters in path")
		}
	}

	return nil
}

// SanitizeString removes dangerous characters from strings
func SanitizeString(input string) string {
	// Remove null bytes
	input = strings.ReplaceAll(input, "\x00", "")

	// Remove control characters
	var result strings.Builder
	for _, r := range input {
		if r >= 32 || r == '\t' || r == '\n' {
			result.WriteRune(r)
		}
	}

	return strings.TrimSpace(result.String())
}

// ValidateTenantID validates tenant ID format
func ValidateTenantID(tenant string) error {
	if tenant == "" {
		return fmt.Errorf("tenant ID cannot be empty")
	}

	// Allow alphanumeric, dash, underscore (max 64 chars)
	pattern := `^[a-zA-Z0-9_-]{1,64}$`
	matched, _ := regexp.MatchString(pattern, tenant)
	if !matched {
		return fmt.Errorf("invalid tenant ID format (alphanumeric, dash, underscore only, max 64 chars)")
	}

	return nil
}

// ValidateScanID validates scan ID format
func ValidateScanID(scanID string) error {
	if scanID == "" {
		return fmt.Errorf("scan ID cannot be empty")
	}

	// UUID pattern with tool suffix: uuid-tool
	pattern := `^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}-.+$`
	matched, _ := regexp.MatchString(pattern, scanID)
	if !matched {
		return fmt.Errorf("invalid scan ID format")
	}

	return nil
}

// ValidateLimit validates pagination limit
func ValidateLimit(limit int) int {
	if limit <= 0 {
		return 20 // default
	}
	if limit > 100 {
		return 100 // max limit
	}
	return limit
}

// ValidateDays validates days parameter
func ValidateDays(days int) int {
	if days <= 0 {
		return 7 // default
	}
	if days > 365 {
		return 365 // max 1 year
	}
	return days
}
