# Security API

A comprehensive Go-based security scanning platform with multiple security tools integration including Trivy, Nuclei, Gitleaks, ZAP, and SQLMap.

## 🚀 Features

### Security Scanning Tools

| Tool | Scans | Input |
| --- | --- | --- |
| **Trivy** | Container image vulnerabilities, secrets, misconfiguration | `image` |
| **Nuclei** | Known CVEs, exposed panels, misconfiguration | `target` |
| **Gitleaks** | Secrets in a repository's history | `path` |
| **Semgrep** | Vulnerable patterns in source code (SAST) | `path` |
| **osv-scanner** | Lockfile dependencies against the OSV database | `path` |
| **ZAP (OWASP ZAP)** | Web application security | `target` |
| **SQLMap** | SQL injection | `target` |

The three `path` tools all resolve their input inside `scanner.workspaceRoot`;
filesystem scans are refused outright when that is unset.

### Core Features
- RESTful API with offset and cursor pagination, plus filtering
- HMAC-signed webhooks and bearer-key reads; nothing but `/health` is open
- Target policy that refuses argument-shaped input and private/link-local hosts
- Bounded scanner pool with per-scan timeouts; a full pool answers `429`
- AI-powered vulnerability analysis (OpenAI integration)
- MySQL or PostgreSQL for scan results
- MinIO/S3 object storage for artifacts
- Docker containerized deployment
- Configurable CORS allowlist and per-tenant rate limiting
- Liveness, readiness, detailed health, and metrics endpoints
- Scan failures recorded per scan and readable over the API

## 📋 Requirements

- Docker & Docker Compose
- Go 1.24+ (for local development)
- MySQL 8.0+ or PostgreSQL 15+
- MinIO or S3-compatible storage
- OpenAI API key (optional, for AI analysis)

## 🏗️ Architecture

```
security-api/
├── cmd/api/              # Application entry point
├── internal/
│   ├── application/      # Business logic layer
│   │   ├── ai/          # AI analysis services
│   │   └── scans/       # Scan orchestration
│   ├── domain/          # Domain models and interfaces
│   │   ├── ai/          # AI domain models
│   │   ├── analyst/     # Analyst domain
│   │   └── scans/       # Scan domain models
│   ├── middleware/      # Logging, metrics, health, rate limiting, validators
│   ├── infra/           # Infrastructure layer
│   │   ├── ai/          # OpenAI client
│   │   ├── db/          # Database repositories
│   │   ├── executor/    # Security tool executors
│   │   ├── httpserver/  # HTTP routes and handlers
│   │   └── storage/     # MinIO/S3 storage
│   └── config/          # Configuration management
├── Dockerfile           # Multi-stage build
├── docker-compose.yml   # Service orchestration
└── config.yaml.example  # Template for config.yaml
```

## 🚀 Quick Start

### Option 1: Docker Compose (Recommended)

```bash
# 1. Clone the repository
git clone https://github.com/bryanwahyu/automaton-sec.git
cd automaton-sec

# 2. Create config.yaml
cp config.yaml.example config.yaml
# Edit config.yaml with your credentials

# 3. Start all services
docker compose up --build -d

# 4. Check logs
docker compose logs -f security-api

# 5. Access API
# MySQL variant: http://localhost:5002
# PostgreSQL variant: http://localhost:5001
```

### Option 2: Local Development

```bash
# 1. Install dependencies
go mod download

# 2. Setup database
# Import: internal/infra/db/mysql/migration.sql

# 3. Configure
cp config.yaml.example config.yaml
# Edit config.yaml

# 4. Run
go run cmd/api/main.go
```

## ⚙️ Configuration

Copy `config.yaml.example` to `config.yaml` and fill it in. `config.yaml` is
gitignored. Point somewhere else with `CONFIG_PATH=/path/to/config.yaml`.

Every setting can also come from the environment, which takes precedence over
the file, so secrets need not be written to disk — `AUTH_API_KEYS`,
`DB_PASSWORD`, `OPENAI_API_KEY`, and the rest are listed at the top of
`config.yaml.example`. A missing config file is fine when the environment
supplies enough.

```yaml
server:
  port: 5000
  shutdownGrace: 30s      # how long to wait for in-flight scans on SIGTERM

database:
  type: mysql             # mysql | postgres
  host: localhost
  port: 3306
  user: root
  password: yourpassword
  name: security_db

minio:
  endpoint: minio.example.com   # host:port, no scheme
  accessKey: minioadmin
  secretKey: minioadmin
  bucketName: security-scans
  region: us-east-1
  useSSL: true

openai:
  apiKey: sk-your-api-key-here  # optional; empty disables AI analysis
  model: gpt-4.1-mini

auth:
  webhookHmacKey: a-long-random-string
  apiKeys:
    - another-long-random-string
  disabled: false         # local development escape hatch

cors:
  allowedOrigins: []      # e.g. ["https://dashboard.example.com"]

rateLimit:
  burst: 20               # token bucket capacity per tenant+IP
  perMinute: 60           # sustained refill rate

scanner:
  maxConcurrent: 2        # simultaneous scanner processes
  timeout: 30m            # ceiling on a single scan
  allowPrivateTargets: false
  allowedHosts: []        # empty = any public host
  workspaceRoot: ""       # required for gitleaks; empty disables path scans
```

The server refuses to start unless `auth.webhookHmacKey` or `auth.apiKeys` is
set, or `auth.disabled: true` is explicit. See [Authentication](#-authentication).

## 🔐 Authentication

Every route except `GET /health` requires a credential.

| Route | Credential |
| --- | --- |
| `POST /v1/{tenant}/webhook/security-scan` | `X-Signature: <hex HMAC-SHA256 of the raw body>`, keyed with `auth.webhookHmacKey` |
| Everything else under `/v1/{tenant}` | `Authorization: Bearer <key>` from `auth.apiKeys` |
| `GET /health`, `/ready`, `/metrics`, `/healthz` | none |

All `/v1` routes are additionally rate limited per tenant+IP (`rateLimit.burst`,
`rateLimit.perMinute`); probe and metrics endpoints are exempt. A malformed
tenant segment is rejected with `400` before any handler runs.

If `auth.webhookHmacKey` is unset, the webhook route falls back to bearer
authentication rather than opening up.

Signing a request body:

```bash
BODY='{"tool":"trivy","image":"nginx:latest"}'
SIG=$(printf '%s' "$BODY" | openssl dgst -sha256 -hmac "$WEBHOOK_KEY" -hex | awk '{print $2}')

curl -X POST http://localhost:5002/v1/acme/webhook/security-scan \
  -H "Content-Type: application/json" \
  -H "X-Signature: $SIG" \
  -d "$BODY"
```

## 📡 API Endpoints

Every path is tenant-scoped: `{tenant}` is an arbitrary identifier you choose,
and scans are only ever read back under the tenant that created them.

| Method | Path | Purpose |
| --- | --- | --- |
| `GET` | `/health` | Liveness probe. No credential. |
| `GET` | `/ready` | Readiness probe. No credential. |
| `GET` | `/metrics` | Request, scan, error, memory, and goroutine counters. No credential. |
| `GET` | `/healthz` | Detailed health including database connectivity. No credential. |
| `POST` | `/v1/{tenant}/webhook/security-scan` | Queue a scan |
| `POST` | `/v1/{tenant}/scans/{id}/retry` | Re-run a scan |
| `GET` | `/v1/{tenant}/scans` | Paginated list |
| `GET` | `/v1/{tenant}/scans/latest` | Cursor-paginated recent scans |
| `GET` | `/v1/{tenant}/scans/{id}` | One scan; `?with=analysis` includes the AI result |
| `GET` | `/v1/{tenant}/scans/{id}/errors` | Recorded failures for a scan |
| `GET` | `/v1/{tenant}/summary` | Severity rollup over the last `?days=N` |
| `POST` | `/v1/{tenant}/ai/analyze` | Queue AI analysis of a scan artifact |
| `GET` | `/v1/{tenant}/ai/analyze` | Paginated analyses |
| `POST` | `/v1/{tenant}/ai/analyze/retry` | Re-run an analysis |

### Queue a scan

```bash
POST /v1/{tenant}/webhook/security-scan
Content-Type: application/json
X-Signature: <hex HMAC-SHA256 of the body>

{
  "tool": "trivy",              // trivy | nuclei | gitleaks | semgrep | osv-scanner | zap | sqlmap
  "image": "nginx:latest",      // trivy
  "target": "https://example.com", // nuclei | zap | sqlmap
  "path": "/workspace/repo",    // gitleaks | semgrep | osv-scanner,
                                // must sit under scanner.workspaceRoot
  "mode": "image",              // optional, free-form
  "source": "github-actions",   // optional
  "commit_sha": "abc123",       // optional
  "branch": "main",             // optional
  "metadata": {"pipeline": "nightly"} // optional, stored verbatim
}
```

Scans run in the background, so the response is immediate:

```json
{
  "status": "queued",
  "tenant": "acme",
  "tool": "trivy",
  "branch": "main",
  "commit": "abc123",
  "message": "scan started in background",
  "queuedAt": "2026-09-05T10:00:00Z"
}
```

| Status | Meaning |
| --- | --- |
| `202 Accepted` | Queued. Poll `GET /v1/{tenant}/scans` for the result. |
| `400 Bad Request` | Malformed body, unknown tool, or a target the policy rejects |
| `401 Unauthorized` | Missing or wrong signature |
| `429 Too Many Requests` | Rate limit hit, or `scanner.maxConcurrent` reached; a `Retry-After` header is sent |

### List scans (offset pagination)

```bash
GET /v1/{tenant}/scans?page=1&page_size=20&tool=trivy&status=success&branch=main&target=example.com
Authorization: Bearer <api-key>
```

Note the parameter is `page_size`, while the response uses `pageSize`:

```json
{
  "data": [ ... ],
  "page": 1,
  "pageSize": 20,
  "totalItems": 100,
  "totalPages": 5
}
```

### Latest scans (cursor pagination)

```bash
GET /v1/{tenant}/scans/latest?limit=20
GET /v1/{tenant}/scans/latest?limit=20&cursor_time=2026-09-05T10:00:00Z&cursor_id=abc-123
```

```json
{
  "data": [ ... ],
  "meta": {
    "limit": 20,
    "has_more": true,
    "is_first_page": true,
    "next_cursor": {
      "cursor_time": "2026-09-05T09:12:00Z",
      "cursor_id": "abc-123-trivy",
      "next_url": "/v1/acme/scans/latest?limit=20&cursor_time=...&cursor_id=..."
    }
  }
}
```

### Retry a scan

```bash
POST /v1/{tenant}/scans/{id}/retry
Authorization: Bearer <api-key>
```

Answers `202`, or `429` when the scanner pool is full. Retries reuse the stored
target, image, and path of the original scan.

### Summary

```bash
GET /v1/{tenant}/summary?days=7
Authorization: Bearer <api-key>
```

```json
{"total_scans": 42, "critical": 3, "high": 11, "medium": 20}
```

### AI analysis

```bash
POST /v1/{tenant}/ai/analyze
Authorization: Bearer <api-key>
Content-Type: application/json

{"scan_id": "abc-123-trivy"}
```

Returns `202` with an `analysis_id`. Read results with
`GET /v1/{tenant}/ai/analyze?page=1&page_size=20`, or fetch a scan with
`GET /v1/{tenant}/scans/{id}?with=analysis`.

## 🔍 Security Tool Examples

All examples assume `WEBHOOK_KEY` holds `auth.webhookHmacKey` and use this helper:

```bash
scan() {
  local body="$1"
  local sig
  sig=$(printf '%s' "$body" | openssl dgst -sha256 -hmac "$WEBHOOK_KEY" -hex | awk '{print $2}')
  curl -X POST http://localhost:5002/v1/acme/webhook/security-scan \
    -H "Content-Type: application/json" \
    -H "X-Signature: $sig" \
    -d "$body"
}
```

### Trivy — container image scanning

```bash
scan '{"tool":"trivy","image":"nginx:latest"}'
```

Scans for vulnerabilities (CVEs), secrets, and misconfigurations.

### Nuclei — web vulnerability scanning

```bash
scan '{"tool":"nuclei","target":"https://example.com"}'
```

Detects known CVEs, misconfigurations, and exposed panels.

### Gitleaks — secret scanning

```bash
scan '{"tool":"gitleaks","path":"/workspace/repo"}'
```

Finds API keys, passwords, private keys, and tokens. The path must resolve
inside `scanner.workspaceRoot`; filesystem scans are refused when that is unset.

### Semgrep — static analysis of source code

```bash
scan '{"tool":"semgrep","path":"/app/workspace/repo"}'
```

Runs `--config auto`, so it pulls the registry rulesets matching the languages
it finds. Severity comes from the rule's triaged rating where it has one, and
from its ERROR/WARNING/INFO level otherwise.

### osv-scanner — dependency vulnerabilities

```bash
scan '{"tool":"osv-scanner","path":"/app/workspace/repo"}'
```

Walks lockfiles recursively (`package-lock.json`, `go.sum`, `requirements.txt`,
`Gemfile.lock`, and the rest) and resolves each dependency against the OSV
database. Complements Trivy: Trivy scans a built image, osv-scanner scans the
source it was built from.

### ZAP — web app security

```bash
scan '{"tool":"zap","target":"https://example.com"}'
```

Tests for XSS, SQL injection, CSRF, and missing security headers.

### SQLMap — SQL injection

```bash
scan '{"tool":"sqlmap","target":"https://example.com/page?id=1"}'
```

### Target restrictions

By default the API refuses to scan loopback, link-local, and RFC1918
destinations — otherwise any caller could point it at `169.254.169.254` or an
internal service and read the findings. Set `scanner.allowPrivateTargets: true`
to allow them, and `scanner.allowedHosts` to restrict scanning to hosts you own.

## 🐳 Docker Services

The docker-compose stack includes:

- **security-api** (port 5002) - Main API with MySQL
- **security-api-pg** (port 5001) - API variant with PostgreSQL
- **postgres** (port 5432) - PostgreSQL database

**Note:** Host port 5002 is used instead of 5000 to avoid conflicts with macOS ControlCenter.

The compose profiles run with `auth.disabled: true` in `config.postgres.yaml`.
That is a local-development setting — set real credentials before exposing the
service to anything but your own machine.

## 🛠️ Development

### Running Tests
```bash
go test ./...
go test -race ./...
```

CI (`.github/workflows/ci.yml`) runs `gofmt`, `go vet`, `go build`,
`go test -race`, `govulncheck`, and a Docker build on every push and PR.

### Building
```bash
# Local build
go build -o security-api ./cmd/api

# Docker build
docker build -t security-api:latest .

# Pin a different scanner version
docker build --build-arg TRIVY_VERSION=0.66.0 -t security-api:latest .
```

The image builds in three stages: a Go stage that compiles the API and
osv-scanner, a fetch stage that downloads the third-party scanners, and a JRE
runtime that receives only the resulting binaries. `wget`, `unzip`, the
tarballs, and the Go toolchain never reach the final image.

### Database Migrations
```bash
# MySQL
mysql -u root -p security_db < internal/infra/db/mysql/migration.sql

# PostgreSQL
psql -U postgres -d security_db -f internal/infra/db/postgres/migration.sql
```

Existing databases need the `path` and `metadata` columns added; both migration
files carry the `ALTER TABLE` statements at the top of the scans section.

## 📊 Response Format

### Scan Result
```json
{
  "id": "scan-123",
  "tenant_id": "default",
  "triggered_at": "2026-09-05T10:00:00Z",
  "tool": "trivy",
  "image": "nginx:latest",
  "status": "success",
  "counts": {
    "critical": 5,
    "high": 12,
    "medium": 8,
    "low": 3,
    "total": 28
  },
  "artifact_url": "https://minio.example.com/scans/artifact.json",
  "raw_format": "json",
  "duration_ms": 45000,
  "source": "github-actions",
  "commit_sha": "abc123",
  "branch": "main",
  "metadata": {"pipeline": "nightly"}
}
```

`status` is one of `running`, `success`, `failed`, or `error`. A scanner that
exits non-zero purely to report findings still counts as `success`; `failed`
means the tool itself failed, and `error` means the scan never produced a
usable artifact.

## 🔐 Security Tools Versions

Pinned as build arguments in the Dockerfile, so they can be bumped without
editing a `RUN` line:

- Trivy: v0.65.0 (`TRIVY_VERSION`)
- Nuclei: v3.3.5 (`NUCLEI_VERSION`)
- Gitleaks: v8.18.1 (`GITLEAKS_VERSION`)
- Semgrep: 1.86.0 (`SEMGREP_VERSION`)
- osv-scanner: v1.9.2 (`OSV_SCANNER_VERSION`)
- ZAP: v2.16.1 (`ZAP_VERSION`)
- SQLMap: not currently installed in the image

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for setup, the checks CI runs, and the
five files a new scanner touches. Security vulnerabilities go through
[private advisories](https://github.com/bryanwahyu/automaton-sec/security/advisories/new),
not public issues — see [SECURITY.md](SECURITY.md).

## 📝 License

MIT — see [LICENSE](LICENSE). Copyright (c) 2025 Bryan Wahyu.

## 🙏 Acknowledgments

- [Trivy](https://github.com/aquasecurity/trivy) - Container security scanner
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret scanner
- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [SQLMap](https://sqlmap.org/) - SQL injection tool
