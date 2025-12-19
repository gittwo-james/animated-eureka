package handlers

import (
	"net/http"
	"strconv"

	"citadel-drive/internal/middleware"
	"citadel-drive/internal/repositories"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type RoleHandler struct {
	DB        *gorm.DB
	Log       *zap.Logger
	JWTSecret string
}

func (h *RoleHandler) Register(r *gin.Engine) {
	protected := r.Group("/roles")
	protected.Use(middleware.JWTAuth(h.DB, h.JWTSecret))

	protected.GET("", h.ListAvailableRoles)
	protected.POST("/assign", h.AssignRole)
	protected.DELETE("/assign/:userId", h.RemoveRole)
	protected.GET("/organization/:organizationId", h.GetOrganizationUsers)
}

type assignRoleRequest struct {
	UserID         string `json:"user_id" binding:"required"`
	OrganizationID string `json:"organization_id" binding:"required"`
	Role           string `json:"role" binding:"required"`
}

func (h *RoleHandler) ListAvailableRoles(c *gin.Context) {
	roleRepo := repositories.NewRoleRepository(h.DB)
	roles := roleRepo.GetAvailableRoles()

	var result []map[string]interface{}
	for _, role := range roles {
		perms, _ := roleRepo.GetRolePermissions(role)
		result = append(result, map[string]interface{}{
			"name":        role,
			"permissions": perms,
		})
	}

	c.JSON(http.StatusOK, gin.H{"roles": result})
}

func (h *RoleHandler) AssignRole(c *gin.Context) {
	var req assignRoleRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	// Get current user
	assignedByVal, _ := c.Get(middleware.ContextUserID)
	assignedBy := assignedByVal.(uuid.UUID)

	// Parse IDs
	userID, err := uuid.Parse(req.UserID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
		return
	}

	orgID, err := uuid.Parse(req.OrganizationID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization_id"})
		return
	}

	// Check if user has permission to assign roles
	roleRepo := repositories.NewRoleRepository(h.DB)
	canManage, err := roleRepo.CanUserManagePermissions(assignedBy, orgID)
	if err != nil || !canManage {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	// Assign the role
	userPerm, err := roleRepo.AssignRole(userID, orgID, req.Role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign role"})
		h.Log.Error("failed to assign role", zap.Error(err))
		return
	}

	// Log audit
	auditRepo := repositories.NewAuditRepository(h.DB)
	ipAddr := middleware.ExtractIPFromRequest(c)
	userAgent := c.GetHeader("User-Agent")
	_ = auditRepo.LogRoleAssigned(&assignedBy, userID, req.Role, orgID, ipAddr, userAgent)

	c.JSON(http.StatusCreated, gin.H{
		"id":              userPerm.ID,
		"user_id":         userPerm.UserID,
		"organization_id": userPerm.OrganizationID,
		"role":            userPerm.Role,
		"created_at":      userPerm.CreatedAt,
	})
}

func (h *RoleHandler) RemoveRole(c *gin.Context) {
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

	// Get organization ID from query
	orgIDStr := c.Query("organization_id")
	if orgIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization_id required"})
		return
	}

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization_id"})
		return
	}

	// Get current user
	removedByVal, _ := c.Get(middleware.ContextUserID)
	removedBy := removedByVal.(uuid.UUID)

	// Check if user has permission to remove roles
	roleRepo := repositories.NewRoleRepository(h.DB)
	canManage, err := roleRepo.CanUserManagePermissions(removedBy, orgID)
	if err != nil || !canManage {
		c.JSON(http.StatusForbidden, gin.H{"error": "insufficient permissions"})
		return
	}

	// Remove the role
	if err := roleRepo.RemoveUserRole(userID, orgID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to remove role"})
		h.Log.Error("failed to remove role", zap.Error(err))
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "role removed"})
}

func (h *RoleHandler) GetOrganizationUsers(c *gin.Context) {
	orgIDStr := c.Param("organizationId")
	if orgIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "organization id required"})
		return
	}

	orgID, err := uuid.Parse(orgIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization id"})
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

	roleRepo := repositories.NewRoleRepository(h.DB)
	users, err := roleRepo.GetOrganizationUsers(orgID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get users"})
		h.Log.Error("failed to get organization users", zap.Error(err))
		return
	}

	// Simple pagination on results
	if offset > len(users) {
		offset = len(users)
	}
	end := offset + pageSizeNum
	if end > len(users) {
		end = len(users)
	}
	paginatedUsers := users[offset:end]

	var result []map[string]interface{}
	for _, user := range paginatedUsers {
		result = append(result, map[string]interface{}{
			"id":              user.ID,
			"user_id":         user.UserID,
			"organization_id": user.OrganizationID,
			"role":            user.Role,
			"created_at":      user.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"users": result,
		"pagination": map[string]int{
			"page":      pageNum,
			"page_size": pageSizeNum,
			"total":     len(users),
		},
	})
}
