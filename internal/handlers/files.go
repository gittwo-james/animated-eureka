package handlers

import (
    "context"
    "crypto/md5"
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
    "fmt"
    "io"
    "math"
    "net/http"
    "path/filepath"
    "strconv"
    "strings"
    "time"

    "citadel-drive/internal/config"
    "citadel-drive/internal/middleware"
    "citadel-drive/internal/models"
    "citadel-drive/internal/storage/r2"

    "github.com/aws/aws-sdk-go-v2/service/s3/types"
    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "go.uber.org/zap"
    "gorm.io/datatypes"
    "gorm.io/gorm"
)

const (
    uploadStatusInitiated = "initiated"
    uploadStatusCompleted = "completed"
    uploadStatusFailed    = "failed"
)

type FileHandler struct {
    DB     *gorm.DB
    Config config.Config
    Log    *zap.Logger
    R2     *r2.Client
}

func (h FileHandler) Register(r *gin.Engine) {
    g := r.Group("/files")
    g.Use(middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret))

    g.POST("/upload", h.InitiateUpload)
    g.POST("/upload/complete", h.CompleteUpload)

    g.GET("", h.ListFiles)
    g.DELETE("/:fileId", h.DeleteFile)
    g.GET("/:fileId/download", h.Download)
    g.GET("/:fileId/versions", h.ListVersions)
    g.POST("/:fileId/versions/:versionId/restore", h.RestoreVersion)
    g.GET("/:fileId/verify-hash", h.VerifyHash)
}

type initiateUploadRequest struct {
    FileID          string  `json:"file_id"`
    Name            string  `json:"name"`
    FileType        string  `json:"file_type"`
    Size            int64   `json:"size"`
    Multipart       *bool   `json:"multipart"`
    PartSizeMB      *int    `json:"part_size_mb"`
    UploadSessionID string  `json:"upload_session_id"`
    PartNumbers     []int32 `json:"part_numbers"`
}

type multipartPartURL struct {
    PartNumber int32          `json:"part_number"`
    Presigned  r2.PresignedURL `json:"presigned"`
}

func (h FileHandler) InitiateUpload(c *gin.Context) {
    if h.DB == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
        return
    }
    if h.R2 == nil {
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "storage not configured"})
        return
    }

    uid, orgID, role, ok := h.currentIdentity(c)
    if !ok {
        return
    }

    var req initiateUploadRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    if strings.TrimSpace(req.UploadSessionID) != "" {
        h.presignMultipartParts(c, uid, orgID, req)
        return
    }

    name := strings.TrimSpace(req.Name)
    if name == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
        return
    }
    contentType := strings.TrimSpace(req.FileType)
    if contentType == "" {
        c.JSON(http.StatusBadRequest, gin.H{"error": "file_type is required"})
        return
    }
    if !h.allowedContentType(contentType) {
        c.JSON(http.StatusBadRequest, gin.H{"error": "file_type not allowed"})
        return
    }
    if req.Size <= 0 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "size must be > 0"})
        return
    }

    fileID, _, err := h.ensureFileForUpload(c, uid, orgID, role, req.FileID, name, contentType, req.Size)
    if err != nil {
        return
    }

    sessionID := uuid.New()
    storageKey := fmt.Sprintf("organization/%s/files/%s/data/%s", orgID.String(), fileID.String(), sessionID.String())

    partSizeMB := h.Config.FileMultipartPartSizeMB
    if req.PartSizeMB != nil && *req.PartSizeMB > 0 {
        partSizeMB = *req.PartSizeMB
    }
    partSizeBytes := int64(partSizeMB) * 1024 * 1024
    if partSizeBytes <= 0 {
        partSizeBytes = 10 * 1024 * 1024
    }
    if partSizeBytes < 5*1024*1024 {
        partSizeBytes = 5 * 1024 * 1024
    }

    multipart := false
    if req.Multipart != nil {
        multipart = *req.Multipart
    } else {
        multipart = req.Size > partSizeBytes && partSizeBytes > 0
    }

    session := models.FileUploadSession{
        ID:             sessionID,
        FileID:         fileID,
        OrganizationID: orgID,
        CreatedBy:      uid,
        StoragePathR2:  storageKey,
        IsMultipart:    multipart,
        ExpectedSize:   req.Size,
        ContentType:    contentType,
        PartSize:       partSizeBytes,
        Status:         uploadStatusInitiated,
    }

    ctx := c.Request.Context()

    if multipart {
        uploadID, err := h.R2.CreateMultipartUpload(ctx, storageKey, contentType)
        if err != nil {
            h.Log.Error("r2 create multipart upload failed", zap.Error(err))
            c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to initialize upload"})
            return
        }
        session.R2UploadID = &uploadID
        if err := h.DB.Create(&session).Error; err != nil {
            _ = h.R2.AbortMultipartUpload(ctx, storageKey, uploadID)
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create upload session"})
            return
        }

        totalParts := int32(1)
        if partSizeBytes > 0 {
            totalParts = int32(math.Ceil(float64(req.Size) / float64(partSizeBytes)))
        }

        batch := h.Config.FileMultipartPresignBatchSz
        if batch <= 0 {
            batch = 100
        }
        maxPart := int32(batch)
        if totalParts < maxPart {
            maxPart = totalParts
        }

        partURLs := make([]multipartPartURL, 0, maxPart)
        for pn := int32(1); pn <= maxPart; pn++ {
            p, err := h.R2.PresignUploadPart(ctx, storageKey, uploadID, pn)
            if err != nil {
                h.Log.Error("r2 presign upload part failed", zap.Error(err))
                c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to presign part upload"})
                return
            }
            partURLs = append(partURLs, multipartPartURL{PartNumber: pn, Presigned: p})
        }

        h.audit(c, &uid, "file_upload_initiated", "file", fileID, map[string]any{"upload_session_id": sessionID.String(), "multipart": true, "total_parts": totalParts, "part_size": partSizeBytes})

        c.JSON(http.StatusOK, gin.H{
            "file_id":            fileID.String(),
            "upload_session_id":  sessionID.String(),
            "storage_path_r2":    storageKey,
            "multipart":          true,
            "upload_id":          uploadID,
            "part_size_bytes":    partSizeBytes,
            "total_parts":        totalParts,
            "presign_expires_sec": int(h.R2.PresignTTL().Seconds()),
            "parts":              partURLs,
        })
        return
    }

    if err := h.DB.Create(&session).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create upload session"})
        return
    }

    presigned, err := h.R2.PresignPutObject(ctx, storageKey, contentType)
    if err != nil {
        h.Log.Error("r2 presign put failed", zap.Error(err))
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to presign upload"})
        return
    }

    h.audit(c, &uid, "file_upload_initiated", "file", fileID, map[string]any{"upload_session_id": sessionID.String(), "multipart": false})

    c.JSON(http.StatusOK, gin.H{
        "file_id":           fileID.String(),
        "upload_session_id": sessionID.String(),
        "storage_path_r2":   storageKey,
        "multipart":         false,
        "upload":            presigned,
    })
}

func (h FileHandler) presignMultipartParts(c *gin.Context, uid uuid.UUID, orgID uuid.UUID, req initiateUploadRequest) {
    sid, err := uuid.Parse(req.UploadSessionID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid upload_session_id"})
        return
    }

    var session models.FileUploadSession
    if err := h.DB.First(&session, "id = ? AND organization_id = ?", sid, orgID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "upload session not found"})
        return
    }
    if session.CreatedBy != uid {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }
    if session.Status != uploadStatusInitiated {
        c.JSON(http.StatusBadRequest, gin.H{"error": "upload session not active"})
        return
    }
    if !session.IsMultipart || session.R2UploadID == nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "upload session is not multipart"})
        return
    }

    ctx := c.Request.Context()

    partNumbers := req.PartNumbers
    if len(partNumbers) == 0 {
        batch := h.Config.FileMultipartPresignBatchSz
        if batch <= 0 {
            batch = 100
        }

        totalParts := int32(1)
        if session.PartSize > 0 {
            totalParts = int32(math.Ceil(float64(session.ExpectedSize) / float64(session.PartSize)))
        }

        maxPart := int32(batch)
        if totalParts < maxPart {
            maxPart = totalParts
        }
        partNumbers = make([]int32, 0, maxPart)
        for pn := int32(1); pn <= maxPart; pn++ {
            partNumbers = append(partNumbers, pn)
        }
    }

    parts := make([]multipartPartURL, 0, len(partNumbers))
    for _, pn := range partNumbers {
        if pn <= 0 {
            continue
        }
        p, err := h.R2.PresignUploadPart(ctx, session.StoragePathR2, *session.R2UploadID, pn)
        if err != nil {
            h.Log.Error("r2 presign upload part failed", zap.Error(err))
            c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to presign part upload"})
            return
        }
        parts = append(parts, multipartPartURL{PartNumber: pn, Presigned: p})
    }

    totalParts := int32(1)
    if session.PartSize > 0 {
        totalParts = int32(math.Ceil(float64(session.ExpectedSize) / float64(session.PartSize)))
    }

    uploadedPartNumbers := make([]int32, 0)
    uploadedBytes := int64(0)
    if uploaded, err := h.R2.ListUploadedParts(ctx, session.StoragePathR2, *session.R2UploadID); err == nil {
        uploadedPartNumbers = make([]int32, 0, len(uploaded))
        for _, p := range uploaded {
            if p.PartNumber != nil {
                uploadedPartNumbers = append(uploadedPartNumbers, *p.PartNumber)
            }
            if p.Size != nil {
                uploadedBytes += *p.Size
            }
        }
    }

    c.JSON(http.StatusOK, gin.H{
        "file_id":              session.FileID.String(),
        "upload_session_id":    session.ID.String(),
        "storage_path_r2":      session.StoragePathR2,
        "multipart":            true,
        "upload_id":            *session.R2UploadID,
        "part_size_bytes":      session.PartSize,
        "total_parts":          totalParts,
        "uploaded_parts":       uploadedPartNumbers,
        "uploaded_parts_count": len(uploadedPartNumbers),
        "uploaded_bytes":       uploadedBytes,
        "parts":                parts,
    })
}

type completeUploadRequest struct {
    UploadSessionID string `json:"upload_session_id" binding:"required"`
    ExpectedSha256  string `json:"expected_sha256_hash" binding:"required"`
    ExpectedMd5     string `json:"expected_md5_hash"`
    CompletedParts   []struct {
        PartNumber int32  `json:"part_number"`
        ETag       string `json:"etag"`
    } `json:"parts"`
}

func (h FileHandler) CompleteUpload(c *gin.Context) {
    if h.DB == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
        return
    }
    if h.R2 == nil {
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "storage not configured"})
        return
    }

    uid, orgID, _, ok := h.currentIdentity(c)
    if !ok {
        return
    }

    var req completeUploadRequest
    if err := c.ShouldBindJSON(&req); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
        return
    }

    expSha := strings.ToLower(strings.TrimSpace(req.ExpectedSha256))
    if len(expSha) != 64 {
        c.JSON(http.StatusBadRequest, gin.H{"error": "expected_sha256_hash must be 64 hex chars"})
        return
    }
    if _, err := hex.DecodeString(expSha); err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "expected_sha256_hash must be hex"})
        return
    }

    expMd5 := strings.ToLower(strings.TrimSpace(req.ExpectedMd5))
    if expMd5 != "" {
        if len(expMd5) != 32 {
            c.JSON(http.StatusBadRequest, gin.H{"error": "expected_md5_hash must be 32 hex chars"})
            return
        }
        if _, err := hex.DecodeString(expMd5); err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "expected_md5_hash must be hex"})
            return
        }
    }

    sid, err := uuid.Parse(req.UploadSessionID)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid upload_session_id"})
        return
    }

    var session models.FileUploadSession
    if err := h.DB.First(&session, "id = ? AND organization_id = ?", sid, orgID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "upload session not found"})
        return
    }
    if session.CreatedBy != uid {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }
    if session.Status != uploadStatusInitiated {
        c.JSON(http.StatusBadRequest, gin.H{"error": "upload session not active"})
        return
    }

    ctx := c.Request.Context()

    if session.IsMultipart {
        if session.R2UploadID == nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "missing upload id"})
            return
        }
        if len(req.CompletedParts) == 0 {
            c.JSON(http.StatusBadRequest, gin.H{"error": "parts are required for multipart completion"})
            return
        }

        parts := make([]types.CompletedPart, 0, len(req.CompletedParts))
        for _, p := range req.CompletedParts {
            if p.PartNumber <= 0 {
                continue
            }
            partNum := p.PartNumber
            etag := strings.TrimSpace(p.ETag)
            if etag != "" && !strings.HasPrefix(etag, "\"") {
                etag = "\"" + etag + "\""
            }
            parts = append(parts, types.CompletedPart{PartNumber: &partNum, ETag: &etag})
        }

        if err := h.R2.CompleteMultipartUpload(ctx, session.StoragePathR2, *session.R2UploadID, parts); err != nil {
            h.Log.Error("r2 complete multipart upload failed", zap.Error(err))
            msg := err.Error()
            _ = h.DB.Model(&models.FileUploadSession{}).Where("id = ?", session.ID).Updates(map[string]any{"status": uploadStatusFailed, "last_error": msg}).Error
            _ = h.R2.AbortMultipartUpload(ctx, session.StoragePathR2, *session.R2UploadID)
            c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to complete upload"})
            return
        }
    } else {
        if _, err := h.R2.HeadObject(ctx, session.StoragePathR2); err != nil {
            h.Log.Error("r2 head object failed", zap.Error(err))
            c.JSON(http.StatusBadRequest, gin.H{"error": "uploaded object not found"})
            return
        }
    }

    shaHex, md5Hex, size, err := h.computeObjectHashes(ctx, session.StoragePathR2)
    if err != nil {
        h.Log.Error("failed to compute object hash", zap.Error(err))
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to verify upload"})
        return
    }

    if size != session.ExpectedSize {
        h.Log.Warn("uploaded object size mismatch", zap.Int64("expected", session.ExpectedSize), zap.Int64("actual", size))
        _ = h.R2.DeleteObject(ctx, session.StoragePathR2)
        msg := fmt.Sprintf("size mismatch (expected %d, got %d)", session.ExpectedSize, size)
        _ = h.DB.Model(&models.FileUploadSession{}).Where("id = ?", session.ID).Updates(map[string]any{"status": uploadStatusFailed, "last_error": msg}).Error
        c.JSON(http.StatusConflict, gin.H{"error": "size mismatch"})
        return
    }

    if expSha != strings.ToLower(shaHex) {
        h.hashMismatchAlert(c, uid, session.FileID, "sha256", expSha, shaHex)
        _ = h.R2.DeleteObject(ctx, session.StoragePathR2)
        msg := "sha256 mismatch"
        _ = h.DB.Model(&models.FileUploadSession{}).Where("id = ?", session.ID).Updates(map[string]any{"status": uploadStatusFailed, "last_error": msg}).Error
        c.JSON(http.StatusConflict, gin.H{"error": msg, "expected": expSha, "actual": shaHex})
        return
    }
    if expMd5 != "" && expMd5 != strings.ToLower(md5Hex) {
        h.hashMismatchAlert(c, uid, session.FileID, "md5", expMd5, md5Hex)
        _ = h.R2.DeleteObject(ctx, session.StoragePathR2)
        msg := "md5 mismatch"
        _ = h.DB.Model(&models.FileUploadSession{}).Where("id = ?", session.ID).Updates(map[string]any{"status": uploadStatusFailed, "last_error": msg}).Error
        c.JSON(http.StatusConflict, gin.H{"error": msg, "expected": expMd5, "actual": md5Hex})
        return
    }

    now := time.Now()
    tx := h.DB.Begin()

    var maxVer int
    if err := tx.Model(&models.FileVersion{}).Where("file_id = ?", session.FileID).
        Select("COALESCE(MAX(version_number), 0)").Scan(&maxVer).Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to determine version"})
        return
    }
    newVer := maxVer + 1

    version := models.FileVersion{
        FileID:        session.FileID,
        VersionNumber: newVer,
        StoragePathR2: session.StoragePathR2,
        FileSize:      size,
        Sha256Hash:    shaHex,
        Md5Hash:       md5Hex,
        CreatedBy:     uid,
        CreatedAt:     now,
    }
    if err := tx.Create(&version).Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create file version"})
        return
    }

    if err := tx.Model(&models.File{}).Where("id = ?", session.FileID).
        Updates(map[string]any{"size": size, "file_type": session.ContentType, "storage_path_r2": session.StoragePathR2}).Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update file"})
        return
    }

    if err := tx.Model(&models.FileUploadSession{}).Where("id = ?", session.ID).
        Updates(map[string]any{"status": uploadStatusCompleted, "completed_at": now}).Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update session"})
        return
    }

    toDelete, err := h.enforceMaxVersions(tx, session.FileID)
    if err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enforce version policy"})
        return
    }

    if err := tx.Commit().Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to finalize upload"})
        return
    }

    for _, key := range toDelete {
        if err := h.R2.DeleteObject(ctx, key); err != nil {
            h.Log.Warn("failed to delete old version object", zap.String("key", key), zap.Error(err))
        }
    }

    h.audit(c, &uid, "file_upload_completed", "file", session.FileID, map[string]any{"upload_session_id": session.ID.String(), "version_id": version.ID.String(), "version_number": newVer})

    c.JSON(http.StatusOK, gin.H{
        "file_id":        session.FileID.String(),
        "version_id":     version.ID.String(),
        "version_number": newVer,
        "file_size":      size,
        "sha256_hash":    shaHex,
        "md5_hash":       md5Hex,
    })
}

func (h FileHandler) ListFiles(c *gin.Context) {
    if h.DB == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
        return
    }

    uid, orgID, _, ok := h.currentIdentity(c)
    if !ok {
        return
    }

    page := clampInt(parseIntDefault(c.Query("page"), 1), 1, 1_000_000)
    pageSize := clampInt(parseIntDefault(c.Query("page_size"), 20), 1, 100)
    offset := (page - 1) * pageSize

    var files []models.File
    q := h.DB.Where("owner_id = ? AND organization_id = ?", uid, orgID).Order("created_at DESC").Limit(pageSize).Offset(offset)
    if err := q.Find(&files).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list files"})
        return
    }

    resp := make([]gin.H, 0, len(files))
    for _, f := range files {
        resp = append(resp, gin.H{
            "id":              f.ID.String(),
            "name":            f.Name,
            "file_type":       f.FileType,
            "size":            f.Size,
            "storage_path_r2": f.StoragePathR2,
            "created_at":      f.CreatedAt,
            "updated_at":      f.UpdatedAt,
        })
    }

    c.JSON(http.StatusOK, gin.H{"page": page, "page_size": pageSize, "files": resp})
}

func (h FileHandler) DeleteFile(c *gin.Context) {
    if h.DB == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
        return
    }

    uid, orgID, role, ok := h.currentIdentity(c)
    if !ok {
        return
    }

    fileID, err := uuid.Parse(c.Param("fileId"))
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
        return
    }

    var file models.File
    if err := h.DB.First(&file, "id = ? AND organization_id = ?", fileID, orgID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
        return
    }

    if file.OwnerID != uid && role != "admin" {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }

    if err := h.DB.Delete(&file).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete file"})
        return
    }

    h.audit(c, &uid, "file_deleted", "file", file.ID, nil)
    c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h FileHandler) Download(c *gin.Context) {
    if h.DB == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
        return
    }
    if h.R2 == nil {
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "storage not configured"})
        return
    }

    uid, orgID, role, ok := h.currentIdentity(c)
    if !ok {
        return
    }

    fileID, err := uuid.Parse(c.Param("fileId"))
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
        return
    }

    var file models.File
    if err := h.DB.First(&file, "id = ? AND organization_id = ?", fileID, orgID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
        return
    }

    if !h.canReadFile(uid, role, file) {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }

    var version models.FileVersion
    if err := h.DB.Where("file_id = ?", file.ID).Order("version_number DESC").First(&version).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "no versions available"})
        return
    }

    disposition := fmt.Sprintf("attachment; filename=\"%s\"", sanitizeFilename(file.Name))

    presigned, err := h.R2.PresignGetObject(c.Request.Context(), version.StoragePathR2, file.FileType, disposition)
    if err != nil {
        h.Log.Error("r2 presign get failed", zap.Error(err))
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to generate download url"})
        return
    }

    h.audit(c, &uid, "file_download", "file", file.ID, map[string]any{"version_id": version.ID.String(), "version_number": version.VersionNumber})

    c.JSON(http.StatusOK, gin.H{
        "file_id":        file.ID.String(),
        "version_id":     version.ID.String(),
        "version_number": version.VersionNumber,
        "download":       presigned,
        "content_type":   file.FileType,
    })
}

func (h FileHandler) ListVersions(c *gin.Context) {
    if h.DB == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
        return
    }

    uid, orgID, role, ok := h.currentIdentity(c)
    if !ok {
        return
    }

    fileID, err := uuid.Parse(c.Param("fileId"))
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
        return
    }

    var file models.File
    if err := h.DB.First(&file, "id = ? AND organization_id = ?", fileID, orgID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
        return
    }

    if !h.canReadFile(uid, role, file) {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }

    var versions []models.FileVersion
    if err := h.DB.Where("file_id = ?", file.ID).Order("version_number DESC").Find(&versions).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list versions"})
        return
    }

    resp := make([]gin.H, 0, len(versions))
    for _, v := range versions {
        resp = append(resp, gin.H{
            "id":             v.ID.String(),
            "version_number": v.VersionNumber,
            "storage_path_r2": v.StoragePathR2,
            "file_size":      v.FileSize,
            "sha256_hash":    v.Sha256Hash,
            "md5_hash":       v.Md5Hash,
            "created_by":     v.CreatedBy.String(),
            "created_at":     v.CreatedAt,
        })
    }

    c.JSON(http.StatusOK, gin.H{"file_id": file.ID.String(), "versions": resp})
}

func (h FileHandler) RestoreVersion(c *gin.Context) {
    if h.DB == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
        return
    }
    if h.R2 == nil {
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "storage not configured"})
        return
    }

    uid, orgID, role, ok := h.currentIdentity(c)
    if !ok {
        return
    }

    fileID, err := uuid.Parse(c.Param("fileId"))
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
        return
    }
    versionID, err := uuid.Parse(c.Param("versionId"))
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid version id"})
        return
    }

    var file models.File
    if err := h.DB.First(&file, "id = ? AND organization_id = ?", fileID, orgID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
        return
    }

    if !h.canWriteFile(uid, role, file) {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }

    var version models.FileVersion
    if err := h.DB.First(&version, "id = ? AND file_id = ?", versionID, file.ID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "version not found"})
        return
    }

    newKey := fmt.Sprintf("organization/%s/files/%s/data/%s", orgID.String(), file.ID.String(), uuid.New().String())
    if err := h.R2.CopyObject(c.Request.Context(), version.StoragePathR2, newKey, file.FileType); err != nil {
        h.Log.Error("r2 copy object failed", zap.Error(err))
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to restore version"})
        return
    }

    now := time.Now()
    tx := h.DB.Begin()
    var maxVer int
    if err := tx.Model(&models.FileVersion{}).Where("file_id = ?", file.ID).Select("COALESCE(MAX(version_number), 0)").Scan(&maxVer).Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to determine version"})
        return
    }
    newVerNum := maxVer + 1

    newVersion := models.FileVersion{
        FileID:        file.ID,
        VersionNumber: newVerNum,
        StoragePathR2: newKey,
        FileSize:      version.FileSize,
        Sha256Hash:    version.Sha256Hash,
        Md5Hash:       version.Md5Hash,
        CreatedBy:     uid,
        CreatedAt:     now,
    }
    if err := tx.Create(&newVersion).Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create restored version"})
        return
    }

    if err := tx.Model(&models.File{}).Where("id = ?", file.ID).Updates(map[string]any{"storage_path_r2": newKey, "size": version.FileSize}).Error; err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update file"})
        return
    }

    toDelete, err := h.enforceMaxVersions(tx, file.ID)
    if err != nil {
        tx.Rollback()
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enforce version policy"})
        return
    }

    if err := tx.Commit().Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to restore version"})
        return
    }

    for _, key := range toDelete {
        if err := h.R2.DeleteObject(c.Request.Context(), key); err != nil {
            h.Log.Warn("failed to delete old version object", zap.String("key", key), zap.Error(err))
        }
    }

    h.audit(c, &uid, "file_version_restored", "file", file.ID, map[string]any{"restored_from_version_id": version.ID.String(), "new_version_id": newVersion.ID.String(), "new_version_number": newVerNum})

    c.JSON(http.StatusOK, gin.H{
        "file_id":        file.ID.String(),
        "version_id":     newVersion.ID.String(),
        "version_number": newVerNum,
    })
}

func (h FileHandler) VerifyHash(c *gin.Context) {
    if h.DB == nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
        return
    }
    if h.R2 == nil {
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "storage not configured"})
        return
    }

    uid, orgID, role, ok := h.currentIdentity(c)
    if !ok {
        return
    }

    fileID, err := uuid.Parse(c.Param("fileId"))
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
        return
    }

    var file models.File
    if err := h.DB.First(&file, "id = ? AND organization_id = ?", fileID, orgID).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
        return
    }

    if !h.canReadFile(uid, role, file) {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }

    var version models.FileVersion
    if err := h.DB.Where("file_id = ?", file.ID).Order("version_number DESC").First(&version).Error; err != nil {
        c.JSON(http.StatusNotFound, gin.H{"error": "no versions available"})
        return
    }

    shaHex, md5Hex, size, err := h.computeObjectHashes(c.Request.Context(), version.StoragePathR2)
    if err != nil {
        h.Log.Error("failed to compute object hash", zap.Error(err))
        c.JSON(http.StatusServiceUnavailable, gin.H{"error": "failed to verify hash"})
        return
    }

    okSha := strings.EqualFold(version.Sha256Hash, shaHex)
    okMd5 := strings.EqualFold(version.Md5Hash, md5Hex)
    okSize := size == version.FileSize

    if okSha && okMd5 && okSize {
        h.audit(c, &uid, "file_hash_verified", "file", file.ID, map[string]any{"version_id": version.ID.String(), "result": "ok"})
        c.JSON(http.StatusOK, gin.H{"ok": true, "version_id": version.ID.String(), "sha256_hash": shaHex, "md5_hash": md5Hex, "size": size})
        return
    }

    h.hashMismatchAlert(c, uid, file.ID, "integrity", map[string]any{"stored_sha256": version.Sha256Hash, "stored_md5": version.Md5Hash, "stored_size": version.FileSize, "actual_sha256": shaHex, "actual_md5": md5Hex, "actual_size": size})

    c.JSON(http.StatusConflict, gin.H{
        "ok":          false,
        "version_id":  version.ID.String(),
        "stored":      gin.H{"sha256_hash": version.Sha256Hash, "md5_hash": version.Md5Hash, "size": version.FileSize},
        "actual":      gin.H{"sha256_hash": shaHex, "md5_hash": md5Hex, "size": size},
        "match_sha256": okSha,
        "match_md5":    okMd5,
        "match_size":   okSize,
    })
}

func (h FileHandler) ensureFileForUpload(c *gin.Context, uid uuid.UUID, orgID uuid.UUID, role string, fileIDRaw string, name string, contentType string, size int64) (uuid.UUID, *models.File, error) {
    if strings.TrimSpace(fileIDRaw) != "" {
        fid, err := uuid.Parse(fileIDRaw)
        if err != nil {
            c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file_id"})
            return uuid.Nil, nil, err
        }

        var file models.File
        if err := h.DB.First(&file, "id = ? AND organization_id = ?", fid, orgID).Error; err != nil {
            c.JSON(http.StatusNotFound, gin.H{"error": "file not found"})
            return uuid.Nil, nil, err
        }

        if !h.canWriteFile(uid, role, file) {
            c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
            return uuid.Nil, nil, errors.New("forbidden")
        }

        if err := h.DB.Model(&models.File{}).Where("id = ?", file.ID).Updates(map[string]any{"name": name, "file_type": contentType, "size": size}).Error; err != nil {
            c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update file metadata"})
            return uuid.Nil, nil, err
        }

        return file.ID, &file, nil
    }

    fid := uuid.New()
    placeholderPath := fmt.Sprintf("organization/%s/files/%s/data", orgID.String(), fid.String())

    file := models.File{
        ID:             fid,
        OwnerID:        uid,
        OrganizationID: orgID,
        Name:           name,
        FileType:       contentType,
        Size:           size,
        StoragePathR2:  placeholderPath,
    }

    if err := h.DB.Create(&file).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create file"})
        return uuid.Nil, nil, err
    }

    return fid, &file, nil
}

func (h FileHandler) computeObjectHashes(ctx context.Context, storageKey string) (string, string, int64, error) {
    out, err := h.R2.GetObject(ctx, storageKey)
    if err != nil {
        return "", "", 0, err
    }
    defer func() { _ = out.Body.Close() }()

    shaH := sha256.New()
    md5H := md5.New()

    n, err := io.Copy(io.MultiWriter(shaH, md5H), out.Body)
    if err != nil {
        return "", "", 0, err
    }

    return hex.EncodeToString(shaH.Sum(nil)), hex.EncodeToString(md5H.Sum(nil)), n, nil
}

func (h FileHandler) enforceMaxVersions(tx *gorm.DB, fileID uuid.UUID) ([]string, error) {
    limit := h.Config.FileMaxVersions
    if limit <= 0 {
        limit = 50
    }

    var versions []models.FileVersion
    if err := tx.Where("file_id = ?", fileID).Order("version_number DESC").Find(&versions).Error; err != nil {
        return nil, err
    }

    if len(versions) <= limit {
        return nil, nil
    }

    overflow := versions[limit:]
    ids := make([]uuid.UUID, 0, len(overflow))
    keys := make([]string, 0, len(overflow))
    for _, v := range overflow {
        ids = append(ids, v.ID)
        keys = append(keys, v.StoragePathR2)
    }

    if err := tx.Where("id IN ?", ids).Delete(&models.FileVersion{}).Error; err != nil {
        return nil, err
    }

    return keys, nil
}

func (h FileHandler) currentIdentity(c *gin.Context) (uuid.UUID, uuid.UUID, string, bool) {
    uidV, ok := c.Get(middleware.ContextUserID)
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return uuid.Nil, uuid.Nil, "", false
    }
    orgV, ok := c.Get(middleware.ContextOrganizationID)
    if !ok {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return uuid.Nil, uuid.Nil, "", false
    }
    roleV, _ := c.Get(middleware.ContextRole)

    uid, err := uuid.Parse(fmt.Sprintf("%v", uidV))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return uuid.Nil, uuid.Nil, "", false
    }
    orgID, err := uuid.Parse(fmt.Sprintf("%v", orgV))
    if err != nil {
        c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
        return uuid.Nil, uuid.Nil, "", false
    }

    role, _ := roleV.(string)

    return uid, orgID, role, true
}

func (h FileHandler) canReadFile(uid uuid.UUID, role string, file models.File) bool {
    if file.OwnerID == uid {
        return true
    }
    if role == "admin" {
        return true
    }

    var perm models.Permission
    now := time.Now()
    if err := h.DB.Where("user_id = ? AND file_id = ? AND (expires_at IS NULL OR expires_at > ?)", uid, file.ID, now).First(&perm).Error; err != nil {
        return false
    }

    p := strings.ToLower(strings.TrimSpace(perm.PermissionType))
    return p == "read" || p == "write" || p == "admin"
}

func (h FileHandler) canWriteFile(uid uuid.UUID, role string, file models.File) bool {
    if file.OwnerID == uid {
        return true
    }
    if role == "admin" {
        return true
    }

    var perm models.Permission
    now := time.Now()
    if err := h.DB.Where("user_id = ? AND file_id = ? AND (expires_at IS NULL OR expires_at > ?)", uid, file.ID, now).First(&perm).Error; err != nil {
        return false
    }

    p := strings.ToLower(strings.TrimSpace(perm.PermissionType))
    return p == "write" || p == "admin"
}

func (h FileHandler) allowedContentType(contentType string) bool {
    ct := strings.ToLower(strings.TrimSpace(contentType))
    for _, allowed := range h.Config.FileAllowedTypes {
        if strings.ToLower(strings.TrimSpace(allowed)) == ct {
            return true
        }
    }
    return false
}

func (h FileHandler) audit(c *gin.Context, userID *uuid.UUID, action string, resourceType string, resourceID uuid.UUID, metadata map[string]any) {
    if h.DB == nil {
        return
    }

    var meta datatypes.JSON
    if metadata != nil {
        if b, err := json.Marshal(metadata); err == nil {
            meta = datatypes.JSON(b)
        }
    }

    log := models.AuditLog{
        UserID:       userID,
        Action:       action,
        ResourceType: resourceType,
        ResourceID:   resourceID,
        IPAddress:    c.ClientIP(),
        UserAgent:    c.Request.UserAgent(),
        Metadata:     meta,
    }

    if err := h.DB.Create(&log).Error; err != nil {
        if h.Log != nil {
            h.Log.Warn("failed to create audit log", zap.Error(err))
        }
    }
}

func (h FileHandler) hashMismatchAlert(c *gin.Context, uid uuid.UUID, fileID uuid.UUID, kind string, a any, b ...any) {
    meta := map[string]any{"kind": kind}
    switch v := a.(type) {
    case map[string]any:
        for k, val := range v {
            meta[k] = val
        }
    default:
        if len(b) > 0 {
            meta["expected"] = a
            meta["actual"] = b[0]
        }
    }

    h.audit(c, &uid, "file_hash_mismatch", "file", fileID, meta)
    if h.Log != nil {
        h.Log.Error("file hash mismatch", zap.String("file_id", fileID.String()), zap.Any("meta", meta))
    }
}

func sanitizeFilename(name string) string {
    n := strings.TrimSpace(name)
    if n == "" {
        return "download"
    }
    n = filepath.Base(n)
    n = strings.ReplaceAll(n, "\"", "")
    n = strings.ReplaceAll(n, "\r", "")
    n = strings.ReplaceAll(n, "\n", "")
    if n == "." || n == "/" {
        return "download"
    }
    return n
}

func parseIntDefault(v string, fallback int) int {
    v = strings.TrimSpace(v)
    if v == "" {
        return fallback
    }
    i, err := strconv.Atoi(v)
    if err != nil {
        return fallback
    }
    return i
}

func clampInt(v, min, max int) int {
    if v < min {
        return min
    }
    if v > max {
        return max
    }
    return v
}
