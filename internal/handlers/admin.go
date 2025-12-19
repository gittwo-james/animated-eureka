package handlers

import (
	"net/http"
	"strconv"
	"time"

	"citadel-drive/internal/config"
	"citadel-drive/internal/middleware"
	"citadel-drive/internal/models"
	"citadel-drive/internal/utils"
	cryptopkg "citadel-drive/pkg/crypto"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type AdminHandler struct {
	DB     *gorm.DB
	Config config.Config
	Log    *zap.Logger
}

func (h *AdminHandler) Register(r *gin.Engine) {
	admin := r.Group("/admin")
	admin.Use(middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret))
	admin.Use(middleware.RequireRole("admin"))

	// Users
	admin.GET("/users", h.ListUsers)
	admin.POST("/users", h.CreateUser)
	admin.PUT("/users/:userId", h.UpdateUser)
	admin.DELETE("/users/:userId", h.DeleteUser)
	admin.GET("/users/:userId/sessions", h.ListUserSessions)
	admin.POST("/users/:userId/force-logout", h.ForceLogoutUser)
	admin.GET("/users/:userId/audit-logs", h.GetUserAuditLogs)

	// Organizations
	admin.GET("/organizations", h.ListOrgs)
	admin.POST("/organizations", h.CreateOrg)
	admin.PUT("/organizations/:orgId", h.UpdateOrg)
	admin.GET("/organizations/:orgId/users", h.ListOrgUsers)
	admin.GET("/organizations/:orgId/storage-usage", h.GetOrgStorageUsage)

	// System Monitoring
	admin.GET("/storage-usage", h.GetSystemStorageUsage)
	admin.GET("/active-sessions", h.GetActiveSessions)
	admin.GET("/failed-logins", h.GetFailedLogins)

	// Security
	admin.GET("/security/ip-blacklist", h.ListIPBlacklist)
	admin.POST("/security/ip-blacklist", h.AddIPBlacklist)
	admin.DELETE("/security/ip-blacklist/:ipId", h.RemoveIPBlacklist)

	// Analytics
	admin.GET("/analytics/storage", h.GetStorageAnalytics)
}

// User Handlers

func (h *AdminHandler) ListUsers(c *gin.Context) {
	var users []models.User
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	limit, offset = utils.ValidatePaginationParams(limit, offset)

	// Preload Org
	if err := h.DB.Preload("Organization").Limit(limit).Offset(offset).Find(&users).Error; err != nil {
		h.Log.Error("failed to fetch users", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch users"})
		return
	}

	var total int64
	h.DB.Model(&models.User{}).Count(&total)

	c.JSON(http.StatusOK, gin.H{"data": users, "total": total, "limit": limit, "offset": offset})
}

func (h *AdminHandler) CreateUser(c *gin.Context) {
	var req struct {
		Email          string `json:"email" binding:"required,email"`
		Password       string `json:"password" binding:"required,min=8"`
		FullName       string `json:"full_name" binding:"required"`
		OrganizationID string `json:"organization_id" binding:"required"`
		Role           string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	orgID, err := uuid.Parse(req.OrganizationID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid org id"})
		return
	}

	// Validate password complexity
	if _, err := cryptopkg.ValidatePasswordComplexity(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password does not meet complexity requirements"})
		return
	}

	pwHash, err := cryptopkg.HashPassword(req.Password)
	if err != nil {
		h.Log.Error("password hash failed", zap.Error(err))
		c.JSON(http.StatusInternalServerError, gin.H{"error": "password hash failed"})
		return
	}

	user := models.User{
		Email:          req.Email,
		PasswordHash:   pwHash,
		FullName:       req.FullName,
		OrganizationID: orgID,
		IsActive:       true,
	}

	tx := h.DB.Begin()
	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create user"})
		return
	}

	// Add role
	perm := models.UserPermission{
		UserID:         user.ID,
		OrganizationID: orgID,
		Role:           req.Role,
	}
	if perm.Role == "" {
		perm.Role = "user"
	}

	if err := tx.Create(&perm).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign role"})
		return
	}

	tx.Commit()
	c.JSON(http.StatusCreated, gin.H{"id": user.ID})
}

func (h *AdminHandler) UpdateUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}

	var req struct {
		FullName string `json:"full_name"`
		IsActive *bool  `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updates := make(map[string]interface{})
	if req.FullName != "" {
		updates["full_name"] = req.FullName
	}
	if req.IsActive != nil {
		updates["is_active"] = *req.IsActive
	}

	if err := h.DB.Model(&models.User{}).Where("id = ?", id).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "update failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func (h *AdminHandler) DeleteUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	// Hard delete
	if err := h.DB.Delete(&models.User{}, "id = ?", id).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "delete failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}

func (h *AdminHandler) ListUserSessions(c *gin.Context) {
	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var sessions []models.Session
	if err := h.DB.Where("user_id = ? AND is_active = ?", id, true).Find(&sessions).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "fetch failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": sessions})
}

func (h *AdminHandler) ForceLogoutUser(c *gin.Context) {
	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	if err := h.DB.Model(&models.Session{}).Where("user_id = ?", id).Update("is_active", false).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "sessions terminated"})
}

func (h *AdminHandler) GetUserAuditLogs(c *gin.Context) {
	id, err := uuid.Parse(c.Param("userId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var logs []models.AuditLog
	if err := h.DB.Where("user_id = ?", id).Order("created_at desc").Limit(50).Find(&logs).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "fetch failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": logs})
}

// Organization Handlers

func (h *AdminHandler) ListOrgs(c *gin.Context) {
	var orgs []models.Organization
	h.DB.Find(&orgs)
	c.JSON(http.StatusOK, gin.H{"data": orgs})
}

func (h *AdminHandler) CreateOrg(c *gin.Context) {
	var req struct {
		Name string `json:"name" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	org := models.Organization{Name: req.Name}
	if err := h.DB.Create(&org).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": org.ID})
}

func (h *AdminHandler) UpdateOrg(c *gin.Context) {
	id, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	c.ShouldBindJSON(&req)
	if err := h.DB.Model(&models.Organization{}).Where("id = ?", id).Update("name", req.Name).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

func (h *AdminHandler) ListOrgUsers(c *gin.Context) {
	id, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var users []models.User
	h.DB.Where("organization_id = ?", id).Find(&users)
	c.JSON(http.StatusOK, gin.H{"data": users})
}

func (h *AdminHandler) GetOrgStorageUsage(c *gin.Context) {
	id, err := uuid.Parse(c.Param("orgId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	var totalSize int64
	h.DB.Model(&models.File{}).Where("organization_id = ?", id).Select("COALESCE(SUM(size), 0)").Scan(&totalSize)
	c.JSON(http.StatusOK, gin.H{"total_size_bytes": totalSize})
}

// Monitoring & Security

func (h *AdminHandler) GetSystemStorageUsage(c *gin.Context) {
	var totalSize int64
	h.DB.Model(&models.File{}).Select("COALESCE(SUM(size), 0)").Scan(&totalSize)
	c.JSON(http.StatusOK, gin.H{"total_size_bytes": totalSize})
}

func (h *AdminHandler) GetActiveSessions(c *gin.Context) {
	var count int64
	h.DB.Model(&models.Session{}).Where("is_active = ? AND expires_at > ?", true, time.Now()).Count(&count)
	c.JSON(http.StatusOK, gin.H{"active_sessions": count})
}

func (h *AdminHandler) GetFailedLogins(c *gin.Context) {
	var count int64
	// Sum failed_login_attempts from users? Or from audit logs?
	// Ticket says "failed login attempts". Users table has `failed_login_attempts` counter (current).
	// Audit logs would have history.
	// Let's sum current failing users.
	h.DB.Model(&models.User{}).Where("failed_login_attempts > 0").Count(&count)
	c.JSON(http.StatusOK, gin.H{"users_with_failed_logins": count})
}

func (h *AdminHandler) ListIPBlacklist(c *gin.Context) {
	var list []models.IPBlacklist
	h.DB.Find(&list)
	c.JSON(http.StatusOK, gin.H{"data": list})
}

func (h *AdminHandler) AddIPBlacklist(c *gin.Context) {
	var req struct {
		IP     string `json:"ip" binding:"required"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ip := models.IPBlacklist{IPAddress: req.IP, Reason: req.Reason}
	if err := h.DB.Create(&ip).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": ip.ID})
}

func (h *AdminHandler) RemoveIPBlacklist(c *gin.Context) {
	id, err := uuid.Parse(c.Param("ipId"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id"})
		return
	}
	h.DB.Delete(&models.IPBlacklist{}, "id = ?", id)
	c.JSON(http.StatusOK, gin.H{"message": "removed"})
}

func (h *AdminHandler) GetStorageAnalytics(c *gin.Context) {
	// Usage by organization
	type OrgUsage struct {
		OrgID     uuid.UUID
		TotalSize int64
	}
	var orgUsages []OrgUsage
	h.DB.Model(&models.File{}).Select("organization_id as org_id, sum(size) as total_size").Group("organization_id").Scan(&orgUsages)

	// Usage by file type
	type TypeUsage struct {
		FileType  string
		TotalSize int64
	}
	var typeUsages []TypeUsage
	h.DB.Model(&models.File{}).Select("file_type, sum(size) as total_size").Group("file_type").Scan(&typeUsages)

	c.JSON(http.StatusOK, gin.H{
		"by_organization": orgUsages,
		"by_file_type":    typeUsages,
	})
}
