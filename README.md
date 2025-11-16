# Security API

A comprehensive Go-based security scanning platform with multiple security tools integration including Trivy, Nuclei, Gitleaks, ZAP, and SQLMap.

## 🚀 Features

### Security Scanning Tools
- **Trivy** - Container image vulnerability, secret, and misconfiguration scanning
- **Nuclei** - Fast and customizable vulnerability scanner
- **Gitleaks** - Git repository secret scanning
- **ZAP (OWASP ZAP)** - Web application security scanner
- **SQLMap** - SQL injection detection and exploitation

### Core Features
- RESTful API with pagination and filtering
- Real-time scan progress tracking
- AI-powered vulnerability analysis (OpenAI integration)
- MySQL database for scan results
- MinIO/S3 object storage for artifacts
- Docker containerized deployment
- CORS support for web applications
- Comprehensive error handling and logging

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
│   ├── infra/           # Infrastructure layer
│   │   ├── ai/          # OpenAI client
│   │   ├── db/          # Database repositories
│   │   ├── executor/    # Security tool executors
│   │   ├── httpserver/  # HTTP routes and handlers
│   │   └── storage/     # MinIO/S3 storage
│   └── config/          # Configuration management
├── Dockerfile           # Multi-stage build
└── docker-compose.yml   # Service orchestration
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

Create `config.yaml` in the root directory:

```yaml
server:
  port: 8000

database:
  type: mysql  # or postgres
  host: localhost
  port: 3306
  user: root
  password: yourpassword
  name: security_db

minio:
  endpoint: minio.example.com
  accessKey: minioadmin
  secretKey: minioadmin
  bucketName: security-scans
  region: us-east-1
  useSSL: true

openai:
  apiKey: sk-your-api-key-here
  model: gpt-4-mini
```

## 📡 API Endpoints

### Scans

#### Create Scan
```bash
POST /api/scans
Content-Type: application/json

{
  "tool": "trivy",
  "image": "nginx:latest"
}
```

**Available Tools:**
- `trivy` - Container image scanning
- `nuclei` - Web vulnerability scanning
- `gitleaks` - Git secret scanning
- `zap` - Web app security testing
- `sqlmap` - SQL injection testing

#### List Scans (Paginated)
```bash
GET /api/scans?page=1&pageSize=20&tool=trivy&status=completed

Response:
{
  "data": [...],
  "page": 1,
  "pageSize": 20,
  "totalItems": 100,
  "totalPages": 5
}
```

**Query Parameters:**
- `page` - Page number (default: 1)
- `pageSize` - Items per page (default: 20)
- `tool` - Filter by tool (trivy, nuclei, etc.)
- `status` - Filter by status (running, completed, failed)
- `target` - Filter by target (exact match)
- `branch` - Filter by branch

#### Get Scan Details
```bash
GET /api/scans/{id}
```

#### Get Latest Scans
```bash
GET /api/scans/latest?limit=10
```

#### Get Scan Summary
```bash
GET /api/scans/summary?days=7
```

## 🔍 Security Tool Examples

### Trivy - Container Image Scanning
```bash
curl -X POST http://localhost:5002/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "trivy",
    "image": "nginx:latest"
  }'
```

**Scans for:**
- Vulnerabilities (CVEs)
- Secrets (API keys, tokens)
- Misconfigurations

### Nuclei - Web Vulnerability Scanning
```bash
curl -X POST http://localhost:5002/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "nuclei",
    "target": "https://example.com"
  }'
```

**Detects:**
- Known CVEs
- Misconfigurations
- Exposed panels
- Vulnerabilities

### Gitleaks - Secret Scanning
```bash
curl -X POST http://localhost:5002/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "gitleaks",
    "path": "/path/to/repo"
  }'
```

**Finds:**
- API keys
- Passwords
- Private keys
- Tokens

### ZAP - Web App Security
```bash
curl -X POST http://localhost:5002/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "zap",
    "target": "https://example.com"
  }'
```

**Tests for:**
- XSS
- SQL Injection
- CSRF
- Security headers

### SQLMap - SQL Injection
```bash
curl -X POST http://localhost:5002/api/scans \
  -H "Content-Type: application/json" \
  -d '{
    "tool": "sqlmap",
    "target": "https://example.com/page?id=1"
  }'
```

## 🐳 Docker Services

The docker-compose stack includes:

- **security-api** (port 5002) - Main API with MySQL
- **security-api-pg** (port 5001) - API variant with PostgreSQL
- **postgres** (port 5432) - PostgreSQL database

**Note:** Host port 5002 is used instead of 5000 to avoid conflicts with macOS ControlCenter.

## 🛠️ Development

### Running Tests
```bash
go test ./...
```

### Building
```bash
# Local build
go build -o security-api ./cmd/api

# Docker build
docker build -t security-api:latest .
```

### Database Migrations
```bash
# Apply migrations
mysql -u root -p security_db < internal/infra/db/mysql/migration.sql
```

## 📊 Response Format

### Scan Result
```json
{
  "id": "scan-123",
  "tenant_id": "default",
  "triggered_at": "2025-11-16T10:00:00Z",
  "tool": "trivy",
  "target": "nginx:latest",
  "status": "completed",
  "counts": {
    "critical": 5,
    "high": 12,
    "medium": 8,
    "low": 3,
    "total": 28
  },
  "artifact_url": "https://minio.example.com/scans/artifact.json",
  "duration_ms": 45000
}
```

## 🔐 Security Tools Versions

- Trivy: v0.65.0
- Nuclei: v3.3.5
- Gitleaks: v8.18.1
- ZAP: v2.16.1
- SQLMap: Latest

## 🤝 Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

MIT License

Copyright (c) 2025 Bryan Wahyu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## 🙏 Acknowledgments

- [Trivy](https://github.com/aquasecurity/trivy) - Container security scanner
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Vulnerability scanner
- [Gitleaks](https://github.com/gitleaks/gitleaks) - Secret scanner
- [OWASP ZAP](https://www.zaproxy.org/) - Web application security scanner
- [SQLMap](https://sqlmap.org/) - SQL injection tool
