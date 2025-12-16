package handlers

import (
    "net/http"

    "citadel-drive/internal/config"
    "citadel-drive/internal/middleware"
    "citadel-drive/internal/models"
    "citadel-drive/internal/repositories"
    "citadel-drive/internal/services"
    "citadel-drive/pkg/crypto"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "go.uber.org/zap"
    "gorm.io/gorm"
)

type FileHandler struct {
    DB         *gorm.DB
    Config     config.Config
    Log        *zap.Logger
    FileRepo   *repositories.FileRepository
    EncKeyRepo *repositories.EncryptionKeyRepository
    AuditRepo  *repositories.AuditRepository
    Storage    *services.StorageService
}

func (h *FileHandler) Register(r *gin.Engine) {
    files := r.Group("/files")
    files.Use(middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret))

    files.POST("/:fileId/encrypt", h.EncryptFile)
    files.POST("/:fileId/decrypt-download", h.DecryptDownloadFile)
}

func (h *FileHandler) EncryptFile(c *gin.Context) {
    fileIDStr := c.Param("fileId")
    fileID, err := uuid.Parse(fileIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
        return
    }

    userID := h.getUserID(c)
    if userID == uuid.Nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return
    }

    // Fetch file
    file, err := h.FileRepo.GetByID(fileID)
    if err != nil {
        h.Log.Error("failed to fetch file", zap.Error(err), zap.String("file_id", fileIDStr))
        c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
        return
    }

    // Permission check (basic ownership or same org)
    if file.OwnerID != userID {
        role := h.getUserRole(c)
        if role != "admin" {
            c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
            return
        }
    }

    if file.EncryptionKeyID != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "file already encrypted"})
        return
    }

    // Generate key
    key, err := crypto.GenerateKey()
    if err != nil {
        h.Log.Error("failed to generate encryption key", zap.Error(err))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate key"})
        return
    }

    // Read content
    content, err := h.Storage.Read(file.StoragePathR2)
    if err != nil {
        h.Log.Error("failed to read file content", zap.Error(err), zap.String("path", file.StoragePathR2))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file content"})
        return
    }

    // Encrypt
    encrypted, err := crypto.Encrypt(content, key)
    if err != nil {
        h.Log.Error("encryption failed", zap.Error(err))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "encryption failed"})
        return
    }

    // Save back (overwrite)
    if err := h.Storage.Save(file.StoragePathR2, encrypted); err != nil {
        h.Log.Error("failed to save encrypted file", zap.Error(err), zap.String("path", file.StoragePathR2))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save encrypted file"})
        return
    }

    // Store key
    encKey := models.EncryptionKey{
        FileID:      fileID,
        KeyMaterial: key,
        Algorithm:   "AES-256-GCM",
    }
    if err := h.EncKeyRepo.Create(&encKey); err != nil {
        h.Log.Error("failed to save encryption key", zap.Error(err))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save key"})
        return
    }

    // Update file
    file.EncryptionKeyID = &encKey.ID
    if err := h.FileRepo.Update(file); err != nil {
        h.Log.Error("failed to update file record", zap.Error(err))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update file record"})
        return
    }

    // Audit Log
    if err := h.AuditRepo.Log(&userID, "encrypt", "file", fileID, c.ClientIP(), c.Request.UserAgent(), nil); err != nil {
        h.Log.Error("failed to log audit entry", zap.Error(err))
    }

    c.JSON(http.StatusOK, gin.H{"message": "file encrypted successfully"})
}

func (h *FileHandler) DecryptDownloadFile(c *gin.Context) {
    fileIDStr := c.Param("fileId")
    fileID, err := uuid.Parse(fileIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
        return
    }

    userID := h.getUserID(c)
    if userID == uuid.Nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return
    }

    file, err := h.FileRepo.GetByID(fileID)
    if err != nil {
        h.Log.Error("failed to fetch file", zap.Error(err), zap.String("file_id", fileIDStr))
        c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
        return
    }

    // Permission check
    if file.OwnerID != userID {
        role := h.getUserRole(c)
        if role != "admin" {
            c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
            return
        }
    }

    if file.EncryptionKeyID == nil {
        // Not encrypted, just download
        content, err := h.Storage.Read(file.StoragePathR2)
        if err != nil {
            h.Log.Error("failed to read file", zap.Error(err), zap.String("path", file.StoragePathR2))
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
            return
        }
        c.Header("Content-Disposition", "attachment; filename="+file.Name)
        c.Data(http.StatusOK, "application/octet-stream", content)

        if err := h.AuditRepo.Log(&userID, "download", "file", fileID, c.ClientIP(), c.Request.UserAgent(), nil); err != nil {
            h.Log.Error("failed to log audit entry", zap.Error(err))
        }
        return
    }

    // Fetch key
    keyRecord, err := h.EncKeyRepo.GetByID(*file.EncryptionKeyID)
    if err != nil {
        h.Log.Error("failed to fetch encryption key", zap.Error(err))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "key not found"})
        return
    }

    // Read content
    encrypted, err := h.Storage.Read(file.StoragePathR2)
    if err != nil {
        h.Log.Error("failed to read encrypted file", zap.Error(err), zap.String("path", file.StoragePathR2))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to read file"})
        return
    }

    // Decrypt
    decrypted, err := crypto.Decrypt(encrypted, keyRecord.KeyMaterial)
    if err != nil {
        h.Log.Error("decryption failed", zap.Error(err))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "decryption failed"})
        return
    }

    c.Header("Content-Disposition", "attachment; filename="+file.Name)
    c.Data(http.StatusOK, "application/octet-stream", decrypted)

    if err := h.AuditRepo.Log(&userID, "decrypt-download", "file", fileID, c.ClientIP(), c.Request.UserAgent(), nil); err != nil {
        h.Log.Error("failed to log audit entry", zap.Error(err))
    }
}

func (h *FileHandler) getUserID(c *gin.Context) uuid.UUID {
    idStr, exists := c.Get(middleware.ContextUserID)
    if !exists {
        return uuid.Nil
    }
    id, err := uuid.Parse(idStr.(string))
    if err != nil {
        return uuid.Nil
    }
    return id
}

func (h *FileHandler) getUserRole(c *gin.Context) string {
    role, exists := c.Get(middleware.ContextRole)
    if !exists {
        return ""
    }
    return role.(string)
}
