package repositories

import (
	"citadel-drive/internal/models"

	"gorm.io/gorm"
)

func EnsurePostgresExtensions(db *gorm.DB) error {
	return db.Exec("CREATE EXTENSION IF NOT EXISTS pgcrypto").Error
}

func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&models.Organization{},
		&models.User{},
		&models.File{},
		&models.FileVersion{},
		&models.Permission{},
		&models.UserPermission{},
		&models.AuditLog{},
		&models.Session{},
		&models.EncryptionKey{},
		&models.SharedToken{},
		&models.FileTag{},
		&models.IPBlacklist{},
	)
}
