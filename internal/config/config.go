package config

import (
	"fmt"
	"os"
	"strconv"
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

	// RateLimit bounds how many requests a single tenant+IP may make.
	RateLimit struct {
		// Burst is the token bucket capacity.
		Burst int `yaml:"burst"`
		// PerMinute is the sustained refill rate.
		PerMinute int `yaml:"perMinute"`
	} `yaml:"rateLimit"`

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

// Load reads the config file, overlays environment variables, applies defaults,
// and validates the result.
//
// Environment variables win over the file so that secrets need not be written
// to disk. A missing file is tolerated when the environment supplies enough.
func Load(path string) (*Config, error) {
	var cfg Config

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return nil, err
			}
		} else if err := yaml.Unmarshal(data, &cfg); err != nil {
			return nil, fmt.Errorf("failed to parse config file: %w", err)
		}
	}

	cfg.applyEnv()
	cfg.applyDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// applyEnv overlays environment variables on top of the file.
func (c *Config) applyEnv() {
	envInt("SERVER_PORT", &c.Server.Port)
	envDuration("SERVER_SHUTDOWN_GRACE", &c.Server.ShutdownGrace)

	envString("DB_TYPE", &c.Database.Type)
	envString("DB_HOST", &c.Database.Host)
	envInt("DB_PORT", &c.Database.Port)
	envString("DB_USER", &c.Database.User)
	envString("DB_PASSWORD", &c.Database.Password)
	envString("DB_NAME", &c.Database.Name)

	envString("MINIO_ENDPOINT", &c.Minio.Endpoint)
	envString("MINIO_ACCESS_KEY", &c.Minio.AccessKey)
	envString("MINIO_SECRET_KEY", &c.Minio.SecretKey)
	envString("MINIO_BUCKET", &c.Minio.BucketName)
	envString("MINIO_REGION", &c.Minio.Region)
	envBool("MINIO_USE_SSL", &c.Minio.UseSSL)

	envString("OPENAI_API_KEY", &c.OpenAI.APIKey)
	envString("OPENAI_MODEL", &c.OpenAI.Model)

	envString("AUTH_WEBHOOK_HMAC_KEY", &c.Auth.WebhookHMACKey)
	envList("AUTH_API_KEYS", &c.Auth.APIKeys)
	envBool("AUTH_DISABLED", &c.Auth.Disabled)

	envList("CORS_ALLOWED_ORIGINS", &c.CORS.AllowedOrigins)

	envInt("SCANNER_MAX_CONCURRENT", &c.Scanner.MaxConcurrent)
	envDuration("SCANNER_TIMEOUT", &c.Scanner.Timeout)
	envBool("SCANNER_ALLOW_PRIVATE_TARGETS", &c.Scanner.AllowPrivateTargets)
	envList("SCANNER_ALLOWED_HOSTS", &c.Scanner.AllowedHosts)
	envString("SCANNER_WORKSPACE_ROOT", &c.Scanner.WorkspaceRoot)

	envInt("RATE_LIMIT_BURST", &c.RateLimit.Burst)
	envInt("RATE_LIMIT_PER_MINUTE", &c.RateLimit.PerMinute)
}

func envString(key string, dst *string) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		*dst = v
	}
}

func envInt(key string, dst *int) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}

func envBool(key string, dst *bool) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = b
		}
	}
}

// envList reads a comma-separated list, e.g. AUTH_API_KEYS="k1,k2".
func envList(key string, dst *[]string) {
	v, ok := os.LookupEnv(key)
	if !ok || strings.TrimSpace(v) == "" {
		return
	}
	var out []string
	for _, part := range strings.Split(v, ",") {
		if p := strings.TrimSpace(part); p != "" {
			out = append(out, p)
		}
	}
	*dst = out
}

func envDuration(key string, dst *Duration) {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			*dst = Duration(d)
		}
	}
}

func (c *Config) applyDefaults() {
	if c.Server.Port == 0 {
		c.Server.Port = 5000
	}
	if c.Database.Host == "" {
		c.Database.Host = "localhost"
	}
	if c.Database.Port == 0 {
		switch c.Database.Type {
		case "postgres", "postgresql", "pg":
			c.Database.Port = 5432
		default:
			c.Database.Port = 3306
		}
	}
	if c.RateLimit.Burst <= 0 {
		c.RateLimit.Burst = 20
	}
	if c.RateLimit.PerMinute <= 0 {
		c.RateLimit.PerMinute = 60
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
