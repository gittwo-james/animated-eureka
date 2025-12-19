package handlers

import (
	"net/http"
	"strconv"
	"time"

	"citadel-drive/internal/middleware"
	"citadel-drive/internal/models"
	"citadel-drive/internal/repositories"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type PermissionHandler struct {
	DB        *gorm.DB
	Log       *zap.Logger
	Cache     *repositories.PermissionCache
	JWTSecret string
}

func (h *PermissionHandler) Register(r *gin.Engine) {
	protected := r.Group("/permissions")
	protected.Use(middleware.JWTAuth(h.DB, h.JWTSecret))

	protected.POST("/grant", h.GrantPermission)
	protected.DELETE("/:id", h.RevokePermission)
	protected.GET("/file/:fileId", h.GetFilePermissions)
	protected.GET("/folder/:folderId", h.GetFolderPermissions)
	protected.PUT("/:id", h.UpdatePermission)

	userPerms := protected.Group("/user/:userId")
	userPerms.GET("", h.GetUserPermissions)
}

type grantPermissionRequest struct {
	UserID         string     `json:"user_id" binding:"required"`
	FileID         *string    `json:"file_id"`
	FolderID       *string    `json:"folder_id"`
	PermissionType string     `json:"permission_type" binding:"required"`
	ExpiresAt      *time.Time `json:"expires_at"`
}

func (h *PermissionHandler) GrantPermission(c *gin.Context) {
	var req grantPermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Get current user
	grantedByVal, _ := c.Get(middleware.ContextUserID)
	grantedBy := grantedByVal.(uuid.UUID)

	// Parse user ID
	grantToID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	// Validate that either FileID or FolderID is provided
	if (req.FileID == nil || *req.FileID == "") && (req.FolderID == nil || *req.FolderID == "") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "either file_id or folder_id required"})
		return
	}

	// Check if user has permission to grant permissions
	roleRepo := repositories.NewRoleRepository(h.DB)
	orgIDVal, _ := c.Get(middleware.ContextOrganizationID)
	organizationID := orgIDVal.(uuid.UUID)

	canManage, err := roleRepo.CanUserManagePermissions(grantedBy, organizationID)
	if err != nil || !canManage {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions to grant"})
		return
	}

	permRepo := repositories.NewPermissionRepository(h.DB)
	auditRepo := repositories.NewAuditRepository(h.DB)

	var perm *models.Permission

	if req.FileID != nil && *req.FileID != "" {
		// Grant file permission
		fileID, err := uuid.Parse(*req.FileID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file_id"})
			return
		}

		perm, err = permRepo.GrantPermission(grantToID, fileID, false, req.PermissionType, grantedBy, req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to grant permission"})
			h.Log.Error("failed to grant file permission", zap.Error(err))
			return
		}

		// Invalidate cache
		if h.Cache != nil {
			h.Cache.InvalidateFile(fileID)
		}

		// Log audit
		ipAddr := middleware.ExtractIPFromRequest(c)
		userAgent := c.GetHeader("User-Agent")
		_ = auditRepo.LogPermissionGranted(&grantedBy, grantToID, fileID, req.PermissionType, false, ipAddr, userAgent)

	} else if req.FolderID != nil && *req.FolderID != "" {
		// Grant folder permission
		folderID, err := uuid.Parse(*req.FolderID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid folder_id"})
			return
		}

		perm, err = permRepo.GrantPermission(grantToID, folderID, true, req.PermissionType, grantedBy, req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to grant permission"})
			h.Log.Error("failed to grant folder permission", zap.Error(err))
			return
		}

		// Invalidate cache
		if h.Cache != nil {
			h.Cache.InvalidateFolder(folderID)
		}

		// Log audit
		ipAddr := middleware.ExtractIPFromRequest(c)
		userAgent := c.GetHeader("User-Agent")
		_ = auditRepo.LogPermissionGranted(&grantedBy, grantToID, folderID, req.PermissionType, true, ipAddr, userAgent)
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":              perm.ID,
		"user_id":         perm.UserID,
		"permission_type": perm.PermissionType,
		"expires_at":      perm.ExpiresAt,
		"created_at":      perm.CreatedAt,
	})
}

func (h *PermissionHandler) RevokePermission(c *gin.Context) {
	permissionID := c.Param("id")
	if permissionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "permission id required"})
		return
	}

	permID, err := uuid.Parse(permissionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid permission id"})
		return
	}

	// Get current user
	revokedByVal, _ := c.Get(middleware.ContextUserID)
	revokedBy := revokedByVal.(uuid.UUID)

	// Check permissions
	roleRepo := repositories.NewRoleRepository(h.DB)
	orgIDVal, _ := c.Get(middleware.ContextOrganizationID)
	organizationID := orgIDVal.(uuid.UUID)

	canManage, err := roleRepo.CanUserManagePermissions(revokedBy, organizationID)
	if err != nil || !canManage {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	permRepo := repositories.NewPermissionRepository(h.DB)
	auditRepo := repositories.NewAuditRepository(h.DB)

	// Get the permission before deleting
	var perm models.Permission
	if err := h.DB.First(&perm, "id = ?", permID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "permission not found"})
		return
	}

	// Revoke the permission
	if err := permRepo.RevokePermission(permID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to revoke permission"})
		h.Log.Error("failed to revoke permission", zap.Error(err))
		return
	}

	// Invalidate cache
	if h.Cache != nil {
		if perm.FileID != nil {
			h.Cache.InvalidateFile(*perm.FileID)
		} else if perm.FolderID != nil {
			h.Cache.InvalidateFolder(*perm.FolderID)
		}
		h.Cache.InvalidateUser(perm.UserID)
	}

	// Log audit
	ipAddr := middleware.ExtractIPFromRequest(c)
	userAgent := c.GetHeader("User-Agent")
	_ = auditRepo.LogPermissionRevoked(&revokedBy, permID, ipAddr, userAgent)

	c.JSON(http.StatusOK, gin.H{"message": "permission revoked"})
}

func (h *PermissionHandler) GetFilePermissions(c *gin.Context) {
	fileID := c.Param("fileId")
	if fileID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file id required"})
		return
	}

	parsedFileID, err := uuid.Parse(fileID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
		return
	}

	permRepo := repositories.NewPermissionRepository(h.DB)
	perms, err := permRepo.GetFilePermissions(parsedFileID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get permissions"})
		h.Log.Error("failed to get file permissions", zap.Error(err))
		return
	}

	var result []map[string]interface{}
	for _, perm := range perms {
		result = append(result, map[string]interface{}{
			"id":              perm.ID,
			"user_id":         perm.UserID,
			"permission_type": perm.PermissionType,
			"expires_at":      perm.ExpiresAt,
			"created_at":      perm.CreatedAt,
			"granted_by":      perm.GrantedBy,
		})
	}

	c.JSON(http.StatusOK, gin.H{"permissions": result})
}

func (h *PermissionHandler) GetFolderPermissions(c *gin.Context) {
	folderID := c.Param("folderId")
	if folderID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "folder id required"})
		return
	}

	parsedFolderID, err := uuid.Parse(folderID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid folder id"})
		return
	}

	permRepo := repositories.NewPermissionRepository(h.DB)
	perms, err := permRepo.GetFolderPermissions(parsedFolderID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get permissions"})
		h.Log.Error("failed to get folder permissions", zap.Error(err))
		return
	}

	var result []map[string]interface{}
	for _, perm := range perms {
		result = append(result, map[string]interface{}{
			"id":              perm.ID,
			"user_id":         perm.UserID,
			"permission_type": perm.PermissionType,
			"expires_at":      perm.ExpiresAt,
			"created_at":      perm.CreatedAt,
			"granted_by":      perm.GrantedBy,
		})
	}

	c.JSON(http.StatusOK, gin.H{"permissions": result})
}

type updatePermissionRequest struct {
	PermissionType *string    `json:"permission_type"`
	ExpiresAt      *time.Time `json:"expires_at"`
}

func (h *PermissionHandler) UpdatePermission(c *gin.Context) {
	permissionID := c.Param("id")
	if permissionID == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "permission id required"})
		return
	}

	permID, err := uuid.Parse(permissionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid permission id"})
		return
	}

	// Get current user
	updatedByVal, _ := c.Get(middleware.ContextUserID)
	updatedBy := updatedByVal.(uuid.UUID)

	// Check permissions
	roleRepo := repositories.NewRoleRepository(h.DB)
	orgIDVal, _ := c.Get(middleware.ContextOrganizationID)
	organizationID := orgIDVal.(uuid.UUID)

	canManage, err := roleRepo.CanUserManagePermissions(updatedBy, organizationID)
	if err != nil || !canManage {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	var req updatePermissionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Get the permission before updating
	var perm models.Permission
	if err := h.DB.First(&perm, "id = ?", permID).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "permission not found"})
		return
	}

	oldPermission := perm.PermissionType

	permRepo := repositories.NewPermissionRepository(h.DB)
	auditRepo := repositories.NewAuditRepository(h.DB)

	if err := permRepo.UpdatePermission(permID, req.PermissionType, req.ExpiresAt); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update permission"})
		h.Log.Error("failed to update permission", zap.Error(err))
		return
	}

	// Invalidate cache
	if h.Cache != nil {
		if perm.FileID != nil {
			h.Cache.InvalidateFile(*perm.FileID)
		} else if perm.FolderID != nil {
			h.Cache.InvalidateFolder(*perm.FolderID)
		}
		h.Cache.InvalidateUser(perm.UserID)
	}

	// Log audit if permission type changed
	if req.PermissionType != nil && *req.PermissionType != oldPermission {
		ipAddr := middleware.ExtractIPFromRequest(c)
		userAgent := c.GetHeader("User-Agent")
		_ = auditRepo.LogPermissionUpdated(&updatedBy, permID, oldPermission, *req.PermissionType, ipAddr, userAgent)
	}

	c.JSON(http.StatusOK, gin.H{
		"id":              perm.ID,
		"permission_type": req.PermissionType,
		"expires_at":      req.ExpiresAt,
	})
}

func (h *PermissionHandler) GetUserPermissions(c *gin.Context) {
	userIDStr := c.Param("userId")
	if userIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "user id required"})
		return
	}

	userID, err := uuid.Parse(userIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
		return
	}

	// Pagination
	page := c.DefaultQuery("page", "1")
	pageSize := c.DefaultQuery("page_size", "20")

	pageNum, _ := strconv.Atoi(page)
	pageSizeNum, _ := strconv.Atoi(pageSize)

	if pageNum < 1 {
		pageNum = 1
	}
	if pageSizeNum < 1 || pageSizeNum > 100 {
		pageSizeNum = 20
	}

	offset := (pageNum - 1) * pageSizeNum

	permRepo := repositories.NewPermissionRepository(h.DB)
	perms, err := permRepo.GetUserPermissions(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get permissions"})
		h.Log.Error("failed to get user permissions", zap.Error(err))
		return
	}

	// Simple pagination on results
	if offset > len(perms) {
		offset = len(perms)
	}
	end := offset + pageSizeNum
	if end > len(perms) {
		end = len(perms)
	}
	paginatedPerms := perms[offset:end]

	var result []map[string]interface{}
	for _, perm := range paginatedPerms {
		result = append(result, map[string]interface{}{
			"id":              perm.ID,
			"file_id":         perm.FileID,
			"folder_id":       perm.FolderID,
			"permission_type": perm.PermissionType,
			"expires_at":      perm.ExpiresAt,
			"created_at":      perm.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"permissions": result,
		"pagination": map[string]int{
			"page":      pageNum,
			"page_size": pageSizeNum,
			"total":     len(perms),
		},
	})
}
