package middleware

import (
	"net/http"
	"strings"

	"citadel-drive/internal/repositories"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// RequireFilePermission checks if user has required permission for a file
func RequireFilePermission(db *gorm.DB, cache *repositories.PermissionCache, requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get(ContextUserID)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
			c.Abort()
			return
		}

		userID := userIDVal.(uuid.UUID)
		fileID := c.Param("fileId")

		if fileID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file id required"})
			c.Abort()
			return
		}

		parsedFileID, err := uuid.Parse(fileID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
			c.Abort()
			return
		}

		permRepo := repositories.NewPermissionRepository(db)

		// Check cache first
		if cache != nil {
			if cached, found := cache.Get(userID, parsedFileID); found {
				if cached != nil {
					c.Set("file_permission", cached)
				}
				c.Next()
				return
			}
		}

		// Check actual permission
		canAccess, err := permRepo.CheckUserCanAccessFile(userID, parsedFileID, requiredPermission)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "permission check failed"})
			c.Abort()
			return
		}

		if !canAccess {
			if cache != nil {
				cache.SetNegative(userID, parsedFileID)
			}
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}

		// Get and cache the permission
		perm, err := permRepo.GetUserPermissionForFile(userID, parsedFileID)
		if err == nil && perm != nil && cache != nil {
			cache.Set(userID, parsedFileID, perm)
			c.Set("file_permission", perm)
		}

		c.Next()
	}
}

// RequireFolderPermission checks if user has required permission for a folder
func RequireFolderPermission(db *gorm.DB, cache *repositories.PermissionCache, requiredPermission string) gin.HandlerFunc {
	return func(c *gin.Context) {
		userIDVal, exists := c.Get(ContextUserID)
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "user not authenticated"})
			c.Abort()
			return
		}

		userID := userIDVal.(uuid.UUID)
		folderID := c.Param("folderId")

		if folderID == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "folder id required"})
			c.Abort()
			return
		}

		parsedFolderID, err := uuid.Parse(folderID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid folder id"})
			c.Abort()
			return
		}

		permRepo := repositories.NewPermissionRepository(db)

		// Check cache first
		if cache != nil {
			if cached, found := cache.GetFolder(userID, parsedFolderID); found {
				if cached != nil {
					c.Set("folder_permission", cached)
				}
				c.Next()
				return
			}
		}

		// Check actual permission
		canAccess, err := permRepo.CheckUserCanAccessFolder(userID, parsedFolderID, requiredPermission)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "permission check failed"})
			c.Abort()
			return
		}

		if !canAccess {
			if cache != nil {
				cache.SetFolderNegative(userID, parsedFolderID)
			}
			c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
			c.Abort()
			return
		}

		// Get and cache the permission
		perm, err := permRepo.GetUserPermissionForFolder(userID, parsedFolderID)
		if err == nil && perm != nil && cache != nil {
			cache.SetFolder(userID, parsedFolderID, perm)
			c.Set("folder_permission", perm)
		}

		c.Next()
	}
}

// ExtractUserIDFromHeader extracts user ID from JWT token context
func ExtractUserIDFromContext(c *gin.Context) (uuid.UUID, error) {
	userIDVal, exists := c.Get(ContextUserID)
	if !exists {
		return uuid.UUID{}, nil
	}

	userID, ok := userIDVal.(uuid.UUID)
	if !ok {
		userIDStr, ok := userIDVal.(string)
		if ok {
			return uuid.Parse(userIDStr)
		}
		return uuid.UUID{}, nil
	}

	return userID, nil
}

// ExtractIPFromRequest extracts client IP from request
func ExtractIPFromRequest(c *gin.Context) string {
	// Try to get from X-Forwarded-For header first (for proxied requests)
	if xff := c.GetHeader("X-Forwarded-For"); xff != "" {
		ips := strings.Split(xff, ",")
		if len(ips) > 0 {
			return strings.TrimSpace(ips[0])
		}
	}

	// Try X-Real-IP
	if xri := c.GetHeader("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	return c.ClientIP()
}
