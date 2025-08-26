# Security API

A Go-based RESTful API for security scanning and management, using MySQL and MinIO for storage.

## Features
- RESTful API for security scan management
- MySQL database integration
- MinIO object storage support
- Configurable via YAML
- Graceful shutdown and context-based timeouts

## Requirements
- Go 1.18 or higher
- MySQL database
- MinIO server (or S3-compatible storage)

## Getting Started

### 1. Clone the repository
```bash
git clone https://github.com/bryanwahyu/automation-scan.git
cd automation-scan 
```

### 2. Configuration
Edit `config.yaml` with your database and MinIO credentials:
```yaml
server:
  port: 8000
database:
  host: <your-mysql-host>
  port: 3306
  user: <your-mysql-user>
  password: <your-mysql-password>
  name: <your-database-name>
minio:
  endpoint: <your-minio-endpoint>
  accessKey: <your-minio-access-key>
  secretKey: <your-minio-secret-key>
  bucketName: <your-bucket-name>
  region: us-east-1
  useSSL: false
```

### 3. Install dependencies
```bash
go mod tidy
```

### 4. Run database migrations
Import the SQL schema from `internal/infra/db/mysql/migration.sql` into your MySQL database.

### 5. Run the API server
```bash
go run main.go
```

The API will be available at `http://localhost:8000` by default.

## Project Structure
- `main.go` - Entry point
- `config.yaml` - Configuration file
- `internal/config/` - Config loader and DSN builder
- `internal/infra/db/mysql/` - Database connection and migrations
- `internal/infra/minio/` - MinIO integration
- `internal/services/` - Business logic
- `internal/handlers/` - HTTP handlers

## Environment Variables
You can also use a `.env` file for environment-specific overrides.

## License
MIT License

Copyright (c) 2023 Bryan Wahyu

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights

