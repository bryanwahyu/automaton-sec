# Security Policy

## Overview

Automaton-Sec is a security scanning orchestration platform. This document outlines the security measures implemented and best practices for deployment.

## Security Improvements Implemented

### 🔒 **Critical Security Fixes**

#### 1. **Command Injection Prevention**
- **Location**: `internal/infra/executor/docker/runner.go`
- **Fix**: Added comprehensive input validation for all user inputs before command execution
- **Validation includes**:
  - Tool names (whitelist-based)
  - URLs (format, scheme, and SSRF protection)
  - Docker image names (pattern validation)
  - File paths (traversal protection)

#### 2. **SQL Injection Prevention**
- **Location**: `internal/infra/db/mysql/scan_repo.go`, `internal/infra/db/postgres/scan_repo.go`
- **Fix**: Sanitized LIKE patterns and removed unsafe REGEXP queries
- **Implementation**: `escapeLikePattern()` function escapes special characters

#### 3. **CORS Misconfiguration Fix**
- **Location**: `internal/infra/httpserver/router.go`
- **Before**: `AllowedOrigins: ["*"]` (allows any origin - **DANGEROUS**)
- **After**: Read from `cors.allowedOrigins` in config (or `CORS_ALLOWED_ORIGINS`).
  Empty means no cross-origin access; nothing is hardcoded.

#### 4. **Path Traversal Protection**
- **Location**: `internal/domain/scans/validate.go` (`TargetPolicy.ValidatePath`),
  with the older helpers still in `internal/middleware/validator.go`
- **Protection**: Gitleaks paths are resolved and required to stay inside
  `scanner.workspaceRoot`; filesystem scans are refused outright when that is
  unset. Values starting with `-` are rejected so they cannot be read as
  scanner flags.

#### 5. **SSRF (Server-Side Request Forgery) Protection**
- **Location**: `internal/middleware/validator.go`
- **Blocks**:
  - Localhost and internal IP addresses
  - Private IP ranges (10.x.x.x, 192.168.x.x, 172.16-31.x.x)
  - Invalid URL schemes (only http/https allowed)

### 🛡️ **Security Features Added**

#### 1. **Input Validation Middleware**
- **File**: `internal/middleware/validator.go`
- **Features**:
  - Tool name whitelist validation
  - URL format and scheme validation
  - Docker image name pattern validation
  - Path traversal detection
  - Tenant ID format validation
  - String sanitization (removes control characters)

#### 2. **Authentication Middleware** (Optional)
- **File**: `internal/middleware/auth.go`
- **Features**:
  - API key authentication support
  - Constant-time comparison (timing attack protection)
  - Tenant-based access control
- **Usage**: Currently disabled - enable in production by adding to router

#### 3. **Rate Limiting**
- **File**: `internal/middleware/ratelimit.go`
- **Implementation**: Token bucket algorithm
- **Features**:
  - Per-tenant + IP rate limiting
  - Configurable capacity and refill rate
  - Automatic cleanup of old buckets
  - HTTP 429 responses with Retry-After header
- **Usage**: Add to router with `RateLimitMiddleware(capacity, refillRate)`

#### 4. **Logging & Monitoring**
- **File**: `internal/middleware/logging.go`, `internal/middleware/metrics.go`
- **Features**:
  - Structured request/response logging
  - Real-time metrics (requests, scans, errors)
  - Memory and goroutine monitoring
  - Health check endpoints

#### 5. **Health Checks**
- **File**: `internal/middleware/health.go`
- **Endpoints**:
  - `GET /health` - Simple liveness check
  - `GET /ready` - Readiness check
  - `GET /healthz` - Detailed health with database status
  - `GET /metrics` - Application metrics

### ⚙️ **Configuration Security**

#### Environment Variable Support
- **File**: `internal/config/config.go`
- **Security Benefit**: Avoid storing secrets in config files
- **Supported Variables**:
  ```bash
  SERVER_PORT=5000
  DB_TYPE=postgres
  DB_HOST=localhost
  DB_PORT=5432
  DB_USER=username
  DB_PASSWORD=secret
  DB_NAME=dbname
  MINIO_ENDPOINT=minio.example.com
  MINIO_ACCESS_KEY=key
  MINIO_SECRET_KEY=secret
  MINIO_BUCKET=scans
  MINIO_USE_SSL=true
  OPENAI_API_KEY=sk-...
  OPENAI_MODEL=gpt-4-mini
  ```

#### Database Connection Pooling
- **File**: `cmd/api/main.go`
- **Configuration**:
  - MaxOpenConns: 25
  - MaxIdleConns: 5
  - ConnMaxLifetime: 5 minutes
  - ConnMaxIdleTime: 2 minutes
- **Benefit**: Prevents connection exhaustion and improves performance

### 🚨 **Known Security Considerations**

#### 1. **Authentication Currently Disabled**
- The API does not enforce authentication by default
- **Recommendation**: Enable API key authentication in production
- **How to enable**:
  ```go
  // In router.go, add:
  validKeys := map[string]string{
      "tenant1": "secret-key-1",
      "tenant2": "secret-key-2",
  }
  mux.Use(middleware.APIKeyAuth(validKeys))
  ```

#### 2. **Rate Limiting Not Enabled**
- Rate limiting middleware is available but not activated
- **Recommendation**: Enable rate limiting to prevent abuse
- **How to enable**:
  ```go
  // In router.go, add after CORS:
  mux.Use(middleware.RateLimitMiddleware(100, 10)) // 100 capacity, 10 refill/sec
  ```

#### 3. **CORS Origins Need Configuration**
- Set `cors.allowedOrigins` in `config.yaml`, or `CORS_ALLOWED_ORIGINS` in the
  environment. Empty means browsers get no cross-origin access at all.

#### 4. **Secrets in Configuration**
- Every setting can come from the environment, which takes precedence over
  `config.yaml`; see the header of `config.yaml.example` for the variable names.
- **Recommendation**: Keep secrets in the environment or a secret manager
  (AWS Secrets Manager, HashiCorp Vault) rather than on disk.

#### 5. **Background Goroutines**
- Scans run on a bounded worker pool (`scanner.maxConcurrent`) and each one gets
  a `scanner.timeout` deadline, so a hung scanner is cancelled rather than
  running forever. A saturated pool answers `429` with `Retry-After`.
- Shutdown drains the pool within `server.shutdownGrace`.
- **Remaining**: AI analysis still runs in an unbounded goroutine.

### 📋 **Security Checklist for Production**

- [x] **Enable Authentication**: HMAC-signed webhooks and bearer API keys are
      enforced on every route except `/health`, `/ready`, and `/metrics`. The
      server refuses to start unless credentials are configured or
      `auth.disabled: true` is explicit.
- [x] **Enable Rate Limiting**: Token bucket per tenant+IP on all `/v1` routes,
      configured under `rateLimit`.
- [ ] **Configure CORS**: Set `cors.allowedOrigins` to your own domains
- [ ] **Use Environment Variables**: Never commit secrets to git
- [ ] **Enable TLS/HTTPS**: Use reverse proxy (nginx, Caddy) with SSL certificates
- [ ] **Database Security**:
  - [ ] Use strong passwords
  - [ ] Enable SSL/TLS for database connections
  - [ ] Restrict database access to application server only
- [ ] **MinIO/S3 Security**:
  - [ ] Use IAM roles instead of access keys (if on AWS)
  - [ ] Enable bucket encryption
  - [ ] Set proper bucket policies
- [ ] **Network Security**:
  - [ ] Deploy behind firewall
  - [ ] Use VPC/private networks
  - [ ] Implement IP whitelisting if needed
- [ ] **Monitoring**:
  - [ ] Set up alerts for failed scans
  - [ ] Monitor `/metrics` endpoint
  - [ ] Set up log aggregation (ELK, Loki, etc.)
- [ ] **Regular Updates**:
  - [ ] Keep dependencies updated
  - [ ] Monitor security advisories
  - [ ] Scan with `go list -json -m all | nancy sleuth`

### 🔍 **Security Testing**

#### Run Security Scan
```bash
# Install gosec
go install github.com/securego/gosec/v2/cmd/gosec@latest

# Scan codebase
gosec ./...
```

#### Check for Vulnerable Dependencies
```bash
# Install nancy
go install github.com/sonatype-nexus-community/nancy@latest

# Check dependencies
go list -json -m all | nancy sleuth
```

### 📞 **Reporting Security Issues**

If you discover a security vulnerability, please email **security@yourdomain.com** (replace with actual email).

**Please do not**:
- Open public GitHub issues for security vulnerabilities
- Disclose the vulnerability publicly before it's fixed

**Please include**:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

### 📚 **Additional Resources**

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Go Security Checklist](https://github.com/Checkmarx/Go-SCP)
- [Docker Security Best Practices](https://docs.docker.com/engine/security/)

---

**Last Updated**: 2025-12-09
**Security Version**: 1.0.0
