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

	if cfg.Server.Port != 8000 {
		t.Errorf("port = %d, want 8000", cfg.Server.Port)
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
