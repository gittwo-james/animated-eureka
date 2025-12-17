package repositories

import (
    "context"
    "citadel-drive/internal/models"
    "citadel-drive/internal/storage/r2"

    "github.com/google/uuid"
    "go.uber.org/zap"
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

// DeleteFileWithCleanup performs cascade delete with R2 storage cleanup
func (r *FileRepository) DeleteFileWithCleanup(ctx context.Context, fileID uuid.UUID, r2Client *r2.Client, logger *zap.Logger) error {
    var file models.File
    if err := r.DB.First(&file, "id = ?", fileID).Error; err != nil {
        return err
    }

    // Get all file versions for cleanup
    var versions []models.FileVersion
    if err := r.DB.Where("file_id = ?", file.ID).Find(&versions).Error; err != nil {
        return err
    }

    // Delete R2 objects for all versions
    if r2Client != nil {
        for _, version := range versions {
            if err := r2Client.DeleteObject(ctx, version.StoragePathR2); err != nil {
                if logger != nil {
                    logger.Error("failed to delete version from R2", zap.Error(err), zap.String("storage_path", version.StoragePathR2))
                }
                // Continue with other deletions even if one fails
            }
        }
    }

    // Delete upload sessions for this file
    if err := r.DB.Where("file_id = ?", file.ID).Delete(&models.FileUploadSession{}).Error; err != nil {
        if logger != nil {
            logger.Error("failed to cleanup upload sessions", zap.Error(err))
        }
    }

    // Delete file (this will cascade delete versions, permissions, etc.)
    if err := r.DB.Delete(&file).Error; err != nil {
        return err
    }

    return nil
}
