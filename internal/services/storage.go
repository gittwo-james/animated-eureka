package services

import (
	"io"
	"os"
	"path/filepath"
)

type StorageService struct {
	BaseDir string
}

func NewStorageService(baseDir string) *StorageService {
	// Ensure directory exists
	_ = os.MkdirAll(baseDir, 0755)
	return &StorageService{BaseDir: baseDir}
}

func (s *StorageService) Save(path string, data []byte) error {
	fullPath := filepath.Join(s.BaseDir, path)
	dir := filepath.Dir(fullPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	return os.WriteFile(fullPath, data, 0644)
}

func (s *StorageService) Read(path string) ([]byte, error) {
	fullPath := filepath.Join(s.BaseDir, path)
	return os.ReadFile(fullPath)
}

func (s *StorageService) ReadStream(path string) (io.ReadCloser, error) {
	fullPath := filepath.Join(s.BaseDir, path)
	return os.Open(fullPath)
}
