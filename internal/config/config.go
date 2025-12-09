package config

import (
	"fmt"
	"os"
	"strconv"

	"gopkg.in/yaml.v3"
)

type Config struct {
    Server struct {
        Port int `yaml:"port"`
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
}

// Load reads config from file and overrides with environment variables
// Environment variables take precedence over config file values
func Load(path string) (*Config, error) {
	var cfg Config

	// Read from file if it exists
	if path != "" {
		data, err := os.ReadFile(path)
		if err == nil {
			if err := yaml.Unmarshal(data, &cfg); err != nil {
				return nil, fmt.Errorf("failed to parse config file: %w", err)
			}
		}
	}

	// Override with environment variables (higher priority)
	if port := os.Getenv("SERVER_PORT"); port != "" {
		if p, err := strconv.Atoi(port); err == nil {
			cfg.Server.Port = p
		}
	}

	// Database configuration
	if dbType := os.Getenv("DB_TYPE"); dbType != "" {
		cfg.Database.Type = dbType
	}
	if dbHost := os.Getenv("DB_HOST"); dbHost != "" {
		cfg.Database.Host = dbHost
	}
	if dbPort := os.Getenv("DB_PORT"); dbPort != "" {
		if p, err := strconv.Atoi(dbPort); err == nil {
			cfg.Database.Port = p
		}
	}
	if dbUser := os.Getenv("DB_USER"); dbUser != "" {
		cfg.Database.User = dbUser
	}
	if dbPass := os.Getenv("DB_PASSWORD"); dbPass != "" {
		cfg.Database.Password = dbPass
	}
	if dbName := os.Getenv("DB_NAME"); dbName != "" {
		cfg.Database.Name = dbName
	}

	// MinIO/S3 configuration
	if minioEndpoint := os.Getenv("MINIO_ENDPOINT"); minioEndpoint != "" {
		cfg.Minio.Endpoint = minioEndpoint
	}
	if minioAccessKey := os.Getenv("MINIO_ACCESS_KEY"); minioAccessKey != "" {
		cfg.Minio.AccessKey = minioAccessKey
	}
	if minioSecretKey := os.Getenv("MINIO_SECRET_KEY"); minioSecretKey != "" {
		cfg.Minio.SecretKey = minioSecretKey
	}
	if minioBucket := os.Getenv("MINIO_BUCKET"); minioBucket != "" {
		cfg.Minio.BucketName = minioBucket
	}
	if minioRegion := os.Getenv("MINIO_REGION"); minioRegion != "" {
		cfg.Minio.Region = minioRegion
	}
	if minioSSL := os.Getenv("MINIO_USE_SSL"); minioSSL != "" {
		cfg.Minio.UseSSL = minioSSL == "true"
	}

	// OpenAI configuration
	if openaiKey := os.Getenv("OPENAI_API_KEY"); openaiKey != "" {
		cfg.OpenAI.APIKey = openaiKey
	}
	if openaiModel := os.Getenv("OPENAI_MODEL"); openaiModel != "" {
		cfg.OpenAI.Model = openaiModel
	}

	// Apply defaults for missing values
	if cfg.Database.Host == "" {
		cfg.Database.Host = "localhost"
	}
	if cfg.Database.Port == 0 {
		if cfg.Database.Type == "postgres" || cfg.Database.Type == "postgresql" {
			cfg.Database.Port = 5432
		} else {
			cfg.Database.Port = 3306
		}
	}
	if cfg.Server.Port == 0 {
		cfg.Server.Port = 5000
	}

	return &cfg, nil
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
    if v := os.Getenv("PG_SSLMODE"); v != "" { sslmode = v }
    return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=%s",
        c.Database.User,
        c.Database.Password,
        c.Database.Host,
        c.Database.Port,
        c.Database.Name,
        sslmode,
    )
}
