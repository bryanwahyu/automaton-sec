package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing config: %v", err)
	}
	return path
}

func TestLoadAppliesDefaults(t *testing.T) {
	cfg, err := Load(write(t, `
auth:
  apiKeys: ["k1"]
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Port != 5000 {
		t.Errorf("port = %d, want 5000", cfg.Server.Port)
	}
	if cfg.Database.Host != "localhost" {
		t.Errorf("db host = %q, want localhost", cfg.Database.Host)
	}
	if cfg.Database.Port != 3306 {
		t.Errorf("db port = %d, want 3306 for mysql", cfg.Database.Port)
	}
	if cfg.RateLimit.Burst != 20 || cfg.RateLimit.PerMinute != 60 {
		t.Errorf("rate limit = %d/%d, want 20/60", cfg.RateLimit.Burst, cfg.RateLimit.PerMinute)
	}
	if cfg.Scanner.MaxConcurrent != 2 {
		t.Errorf("maxConcurrent = %d, want 2", cfg.Scanner.MaxConcurrent)
	}
	if cfg.Scanner.Timeout.Duration() != 30*time.Minute {
		t.Errorf("scanner timeout = %s, want 30m", cfg.Scanner.Timeout.Duration())
	}
	if cfg.Server.ShutdownGrace.Duration() != 30*time.Second {
		t.Errorf("shutdown grace = %s, want 30s", cfg.Server.ShutdownGrace.Duration())
	}
}

func TestLoadParsesDurations(t *testing.T) {
	cfg, err := Load(write(t, `
auth:
  disabled: true
server:
  shutdownGrace: 90s
scanner:
  timeout: 45m
`))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Scanner.Timeout.Duration() != 45*time.Minute {
		t.Errorf("scanner timeout = %s, want 45m", cfg.Scanner.Timeout.Duration())
	}
	if cfg.Server.ShutdownGrace.Duration() != 90*time.Second {
		t.Errorf("shutdown grace = %s, want 90s", cfg.Server.ShutdownGrace.Duration())
	}
}

func TestLoadRejectsAnInvalidDuration(t *testing.T) {
	_, err := Load(write(t, `
auth:
  disabled: true
scanner:
  timeout: "half an hour"
`))
	if err == nil {
		t.Fatal("an unparseable duration should fail the load")
	}
}

func TestLoadRefusesToStartWithNoCredentials(t *testing.T) {
	// Silently serving an unauthenticated security scanner is the failure mode
	// this check exists to prevent.
	_, err := Load(write(t, "server:\n  port: 8000\n"))
	if err == nil {
		t.Fatal("a config with neither auth nor auth.disabled should be rejected")
	}
	if !strings.Contains(err.Error(), "auth") {
		t.Fatalf("error = %v, want it to mention auth", err)
	}
}

func TestLoadAcceptsExplicitlyDisabledAuth(t *testing.T) {
	if _, err := Load(write(t, "auth:\n  disabled: true\n")); err != nil {
		t.Fatalf("Load: %v", err)
	}
}

func TestLoadRejectsAnUnknownDatabaseType(t *testing.T) {
	_, err := Load(write(t, `
auth:
  disabled: true
database:
  type: mongodb
`))
	if err == nil {
		t.Fatal("an unsupported database type should be rejected")
	}
}

func TestDSNs(t *testing.T) {
	cfg := &Config{}
	cfg.Database.Host = "db.internal"
	cfg.Database.Port = 3306
	cfg.Database.User = "app"
	cfg.Database.Password = "pw"
	cfg.Database.Name = "security_db"

	want := "app:pw@tcp(db.internal:3306)/security_db?parseTime=true&charset=utf8mb4&loc=UTC"
	if got := cfg.MySQLDSN(); got != want {
		t.Errorf("MySQLDSN()\n got %q\nwant %q", got, want)
	}

	t.Setenv("PG_SSLMODE", "require")
	if got := cfg.PostgresDSN(); got != "postgres://app:pw@db.internal:3306/security_db?sslmode=require" {
		t.Errorf("PostgresDSN() = %q", got)
	}
}

func TestEnvironmentOverridesTheFile(t *testing.T) {
	path := write(t, `
server:
  port: 5000
database:
  type: mysql
  host: file-host
auth:
  apiKeys: ["from-file"]
`)

	t.Setenv("SERVER_PORT", "9999")
	t.Setenv("DB_HOST", "env-host")
	t.Setenv("AUTH_API_KEYS", "k1, k2 ,")
	t.Setenv("SCANNER_ALLOW_PRIVATE_TARGETS", "true")
	t.Setenv("SCANNER_TIMEOUT", "5m")
	t.Setenv("CORS_ALLOWED_ORIGINS", "https://a.test,https://b.test")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	if cfg.Server.Port != 9999 {
		t.Errorf("port = %d, want the env value 9999", cfg.Server.Port)
	}
	if cfg.Database.Host != "env-host" {
		t.Errorf("db host = %q, want env-host", cfg.Database.Host)
	}
	if len(cfg.Auth.APIKeys) != 2 || cfg.Auth.APIKeys[0] != "k1" || cfg.Auth.APIKeys[1] != "k2" {
		t.Errorf("api keys = %v, want [k1 k2]", cfg.Auth.APIKeys)
	}
	if !cfg.Scanner.AllowPrivateTargets {
		t.Error("SCANNER_ALLOW_PRIVATE_TARGETS should have been applied")
	}
	if cfg.Scanner.Timeout.Duration() != 5*time.Minute {
		t.Errorf("scanner timeout = %s, want 5m", cfg.Scanner.Timeout.Duration())
	}
	if len(cfg.CORS.AllowedOrigins) != 2 {
		t.Errorf("cors origins = %v, want two entries", cfg.CORS.AllowedOrigins)
	}
}

func TestEnvAloneIsEnoughWithoutAConfigFile(t *testing.T) {
	// A missing file is fine when the environment supplies the settings, so
	// secrets never have to be written to disk.
	t.Setenv("AUTH_API_KEYS", "k1")
	t.Setenv("DB_TYPE", "postgres")

	cfg, err := Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Database.Port != 5432 {
		t.Errorf("db port = %d, want the postgres default 5432", cfg.Database.Port)
	}
}
