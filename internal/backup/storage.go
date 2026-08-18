package backup

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// Storage is implemented by any backend that can store and retrieve backup blobs.
type Storage interface {
	Upload(ctx context.Context, name string, data []byte) error
	Download(ctx context.Context, name string) ([]byte, error)
	Delete(ctx context.Context, name string) error
	StorageType() string
}

// LocalStorage writes encrypted backup files to a directory on disk.
type LocalStorage struct {
	dir string
}

// NewLocalStorage creates a LocalStorage writing to dir.
func NewLocalStorage(dir string) (*LocalStorage, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}
	return &LocalStorage{dir: dir}, nil
}

func (l *LocalStorage) StorageType() string { return "local" }

func (l *LocalStorage) Upload(_ context.Context, name string, data []byte) error {
	return os.WriteFile(filepath.Join(l.dir, name), data, 0600)
}

func (l *LocalStorage) Download(_ context.Context, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(l.dir, name))
}

func (l *LocalStorage) Delete(_ context.Context, name string) error {
	err := os.Remove(filepath.Join(l.dir, name))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// S3Storage uploads encrypted backup files to any S3-compatible object store.
type S3Storage struct {
	client *s3Client
	prefix string
}

// NewS3Storage creates an S3Storage. Use pathStyle for MinIO and Garage.
func NewS3Storage(endpoint, bucket, accessKey, secretKey, region, prefix string, pathStyle bool) *S3Storage {
	if prefix != "" && prefix[len(prefix)-1] != '/' {
		prefix += "/"
	}
	return &S3Storage{
		client: newS3Client(endpoint, bucket, accessKey, secretKey, region, pathStyle),
		prefix: prefix,
	}
}

func (s *S3Storage) StorageType() string { return "s3" }

func (s *S3Storage) Upload(ctx context.Context, name string, data []byte) error {
	return s.client.Put(ctx, s.prefix+name, data)
}

func (s *S3Storage) Download(ctx context.Context, name string) ([]byte, error) {
	return s.client.Get(ctx, s.prefix+name)
}

func (s *S3Storage) Delete(ctx context.Context, name string) error {
	return s.client.Delete(ctx, s.prefix+name)
}

// ListKeys returns the object keys (without prefix) of all backups in the bucket.
func (s *S3Storage) ListKeys(ctx context.Context) ([]string, error) {
	objs, err := s.client.List(ctx, s.prefix)
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(objs))
	for _, o := range objs {
		key := o.Key
		if len(key) > len(s.prefix) {
			key = key[len(s.prefix):]
		}
		keys = append(keys, key)
	}
	return keys, nil
}
