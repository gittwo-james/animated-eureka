package repositories

import (
	"citadel-drive/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type FileRepository struct {
	DB *gorm.DB
}

func NewFileRepository(db *gorm.DB) *FileRepository {
	return &FileRepository{DB: db}
}

func (r *FileRepository) Create(file *models.File) error {
	return r.DB.Create(file).Error
}

func (r *FileRepository) GetByID(id uuid.UUID) (*models.File, error) {
	var file models.File
	err := r.DB.Preload("CurrentEncryptionKey").First(&file, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &file, nil
}

func (r *FileRepository) Update(file *models.File) error {
	return r.DB.Save(file).Error
}

func (r *FileRepository) Delete(id uuid.UUID) error {
	return r.DB.Delete(&models.File{}, "id = ?", id).Error
}
