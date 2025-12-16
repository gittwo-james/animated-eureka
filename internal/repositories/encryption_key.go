package repositories

import (
	"citadel-drive/internal/models"

	"github.com/google/uuid"
	"gorm.io/gorm"
)

type EncryptionKeyRepository struct {
	DB *gorm.DB
}

func NewEncryptionKeyRepository(db *gorm.DB) *EncryptionKeyRepository {
	return &EncryptionKeyRepository{DB: db}
}

func (r *EncryptionKeyRepository) Create(key *models.EncryptionKey) error {
	return r.DB.Create(key).Error
}

func (r *EncryptionKeyRepository) GetLatestByFileID(fileID uuid.UUID) (*models.EncryptionKey, error) {
	var key models.EncryptionKey
	err := r.DB.Where("file_id = ?", fileID).Order("created_at desc").First(&key).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}

func (r *EncryptionKeyRepository) GetByID(id uuid.UUID) (*models.EncryptionKey, error) {
	var key models.EncryptionKey
	err := r.DB.First(&key, "id = ?", id).Error
	if err != nil {
		return nil, err
	}
	return &key, nil
}
