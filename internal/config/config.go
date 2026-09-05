package config

import (
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Server struct {
		Port int `yaml:"port"`
		// ShutdownGrace is how long to wait for in-flight scans on SIGTERM.
		ShutdownGrace Duration `yaml:"shutdownGrace"`
	} `yaml:"server"`

	Database struct {
		Type     string `yaml:"type"`
		Host     string `yaml:"host"`
		Port     int    `yaml:"port"`
		User     string `yaml:"user"`
		Password string `yaml:"password"`
		Name     string `yaml:"name"`
	} `yaml:"database"`

	Minio struct {
		Endpoint   string `yaml:"endpoint"`
		AccessKey  string `yaml:"accessKey"`
		SecretKey  string `yaml:"secretKey"`
		BucketName string `yaml:"bucketName"`
		Region     string `yaml:"region"`
		UseSSL     bool   `yaml:"useSSL"`
	} `yaml:"minio"`

	OpenAI struct {
		APIKey string `yaml:"apiKey"`
		Model  string `yaml:"model"`
	} `yaml:"openai"`

	// Auth guards every route except /health.
	Auth struct {
		// WebhookHMACKey is the shared secret for the X-Signature header on
		// webhook routes (hex-encoded HMAC-SHA256 of the raw request body).
		WebhookHMACKey string `yaml:"webhookHmacKey"`
		// APIKeys are accepted on read routes via Authorization: Bearer <key>.
		APIKeys []string `yaml:"apiKeys"`
		// Disabled turns authentication off entirely. Intended for local
		// development only; the server logs a warning on every startup.
		Disabled bool `yaml:"disabled"`
	} `yaml:"auth"`

	CORS struct {
		// AllowedOrigins defaults to none. "*" is honoured but warned about.
		AllowedOrigins []string `yaml:"allowedOrigins"`
	} `yaml:"cors"`

	Scanner struct {
		// MaxConcurrent caps simultaneously running scanner processes.
		MaxConcurrent int `yaml:"maxConcurrent"`
		// Timeout bounds a single scan run.
		Timeout Duration `yaml:"timeout"`
		// AllowPrivateTargets permits scanning loopback/private/link-local hosts.
		AllowPrivateTargets bool `yaml:"allowPrivateTargets"`
		// AllowedHosts, when set, restricts scan targets to these hosts.
		AllowedHosts []string `yaml:"allowedHosts"`
		// WorkspaceRoot confines gitleaks source paths. Empty disables them.
		WorkspaceRoot string `yaml:"workspaceRoot"`
	} `yaml:"scanner"`
}

// Duration is a time.Duration that unmarshals from a YAML string like "30m".
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err != nil {
		return err
	}
	if strings.TrimSpace(s) == "" {
		return nil
	}
	parsed, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", s, err)
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) Duration() time.Duration { return time.Duration(d) }

// Load reads config.yaml and applies defaults for anything left unset.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

func (c *Config) applyDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = 8000
	}
	if c.Server.ShutdownGrace == 0 {
		c.Server.ShutdownGrace = Duration(30 * time.Second)
	}
	if c.Scanner.MaxConcurrent <= 0 {
		c.Scanner.MaxConcurrent = 2
	}
	if c.Scanner.Timeout == 0 {
		c.Scanner.Timeout = Duration(30 * time.Minute)
	}
}

// Validate rejects a configuration the server cannot safely run with.
func (c *Config) Validate() error {
	if !c.Auth.Disabled && c.Auth.WebhookHMACKey == "" && len(c.Auth.APIKeys) == 0 {
		return fmt.Errorf("auth: set auth.webhookHmacKey and/or auth.apiKeys, " +
			"or set auth.disabled: true to run without authentication")
	}
	switch c.Database.Type {
	case "", "mysql", "postgres", "postgresql", "pg":
	default:
		return fmt.Errorf("database.type %q is not supported (want mysql or postgres)", c.Database.Type)
	}
	return nil
}

// Helper untuk build DSN MySQL
func (c *Config) MySQLDSN() string {
	return fmt.Sprintf("%s:%s@tcp(%s:%d)/%s?parseTime=true&charset=utf8mb4&loc=UTC",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
	)
}

// Helper to build DSN for PostgreSQL (lib/pq style)
// Example: postgres://user:pass@host:5432/dbname?sslmode=disable
func (c *Config) PostgresDSN() string {
	sslmode := "disable"
	// allow override via env if needed
	if v := os.Getenv("PG_SSLMODE"); v != "" {
		sslmode = v
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
		c.Database.User,
		c.Database.Password,
		c.Database.Host,
		c.Database.Port,
		c.Database.Name,
		sslmode,
	)
}
