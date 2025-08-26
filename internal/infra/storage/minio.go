package storage

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type Store struct {
	client     *minio.Client
	bucketName string
	region     string
}

// New buat koneksi MinIO
func New(ctx context.Context, endpoint, region, bucket, accessKey, secretKey string, useSSL bool) (*Store, error) {
	cli, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
		Region: region,
	})
	if err != nil {
		return nil, err
	}

	// pastikan bucket ada
	exists, err := cli.BucketExists(ctx, bucket)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := cli.MakeBucket(ctx, bucket, minio.MakeBucketOptions{Region: region}); err != nil {
			return nil, err
		}
	}

	return &Store{client: cli, bucketName: bucket, region: region}, nil
}

// Upload implementasi ArtifactStore
func (s *Store) Upload(ctx context.Context, localPath, key string) (string, error) {
	f, err := os.Open(localPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	// mimeType sederhana
	contentType := "application/octet-stream"
	ext := filepath.Ext(localPath)
	if ext == ".json" {
		contentType = "application/json"
	} else if ext == ".sarif" {
		contentType = "application/json"
	} else if ext == ".html" {
		contentType = "text/html"
	}

	_, err = s.client.FPutObject(ctx, s.bucketName, key, localPath, minio.PutObjectOptions{
		ContentType: contentType,
	})
	if err != nil {
		return "", err
	}

	// URL publik (jika bucket public), kalau private harus generate presigned URL
	url := fmt.Sprintf("http://%s/%s/%s", s.client.EndpointURL().Host, s.bucketName, key)
	return url, nil
}

// UploadAndCleanup upload file ke Minio dan hapus file lokal setelahnya
func (s *Store) UploadAndCleanup(ctx context.Context, localPath, key string) (string, error) {
	// Upload file terlebih dahulu
	url, err := s.Upload(ctx, localPath, key)
	if err != nil {
		return "", err
	}

	// Hapus file lokal setelah berhasil upload
	if removeErr := os.Remove(localPath); removeErr != nil {
		// Log error tapi jangan return error, karena upload sudah berhasil
		fmt.Printf("Warning: failed to remove local file %s: %v\n", localPath, removeErr)
	}

	return url, nil
}
