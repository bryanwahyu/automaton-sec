package config

import (
	"fmt"
	"os"

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

// Load baca file config.yaml
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
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
