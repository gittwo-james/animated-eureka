package repositories

import (
	"citadel-drive/internal/models"
	"time"

	"gorm.io/gorm"
)

type PermissionRepository struct {
	DB *gorm.DB
}

func NewPermissionRepository(db *gorm.DB) *PermissionRepository {
	return &PermissionRepository{DB: db}
}

func (r *PermissionRepository) InvalidateExpiredPermissions() error {
	return r.DB.Where("expires_at < ?", time.Now()).Delete(&models.Permission{}).Error
}
