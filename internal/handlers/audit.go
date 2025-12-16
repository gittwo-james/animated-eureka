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

type AuditHandler struct {
	DB        *gorm.DB
	Log       *zap.Logger
	JWTSecret string
}

func (h *AuditHandler) Register(r *gin.Engine) {
	protected := r.Group("/audit")
	protected.Use(middleware.JWTAuth(h.DB, h.JWTSecret))

	protected.GET("/logs", h.GetRecentAuditLogs)
	protected.GET("/resource/:resourceId", h.GetResourceAuditLogs)
	protected.GET("/user/:userId", h.GetUserAuditLogs)
}

func (h *AuditHandler) GetRecentAuditLogs(c *gin.Context) {
	limit := c.DefaultQuery("limit", "50")
	limitNum, _ := strconv.Atoi(limit)

	if limitNum < 1 || limitNum > 200 {
		limitNum = 50
	}

	auditRepo := repositories.NewAuditRepository(h.DB)
	logs, err := auditRepo.GetRecentAuditLogs(limitNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get audit logs"})
		h.Log.Error("failed to get recent audit logs", zap.Error(err))
		return
	}

	var result []map[string]interface{}
	for _, log := range logs {
		result = append(result, map[string]interface{}{
			"id":            log.ID,
			"user_id":       log.UserID,
			"action":        log.Action,
			"resource_type": log.ResourceType,
			"resource_id":   log.ResourceID,
			"ip_address":    log.IPAddress,
			"user_agent":    log.UserAgent,
			"metadata":      log.Metadata,
			"created_at":    log.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"logs": result})
}

func (h *AuditHandler) GetResourceAuditLogs(c *gin.Context) {
	resourceIDStr := c.Param("resourceId")
	if resourceIDStr == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "resource id required"})
		return
	}

	resourceID, err := uuid.Parse(resourceIDStr)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid resource id"})
		return
	}

	limit := c.DefaultQuery("limit", "50")
	offset := c.DefaultQuery("offset", "0")

	limitNum, _ := strconv.Atoi(limit)
	offsetNum, _ := strconv.Atoi(offset)

	if limitNum < 1 || limitNum > 200 {
		limitNum = 50
	}
	if offsetNum < 0 {
		offsetNum = 0
	}

	auditRepo := repositories.NewAuditRepository(h.DB)
	logs, err := auditRepo.GetAuditLogs(resourceID, limitNum, offsetNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get audit logs"})
		h.Log.Error("failed to get resource audit logs", zap.Error(err))
		return
	}

	var result []map[string]interface{}
	for _, log := range logs {
		result = append(result, map[string]interface{}{
			"id":            log.ID,
			"user_id":       log.UserID,
			"action":        log.Action,
			"resource_type": log.ResourceType,
			"resource_id":   log.ResourceID,
			"ip_address":    log.IPAddress,
			"user_agent":    log.UserAgent,
			"metadata":      log.Metadata,
			"created_at":    log.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"logs": result})
}

func (h *AuditHandler) GetUserAuditLogs(c *gin.Context) {
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

	limit := c.DefaultQuery("limit", "50")
	offset := c.DefaultQuery("offset", "0")

	limitNum, _ := strconv.Atoi(limit)
	offsetNum, _ := strconv.Atoi(offset)

	if limitNum < 1 || limitNum > 200 {
		limitNum = 50
	}
	if offsetNum < 0 {
		offsetNum = 0
	}

	auditRepo := repositories.NewAuditRepository(h.DB)
	logs, err := auditRepo.GetUserAuditLogs(userID, limitNum, offsetNum)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to get audit logs"})
		h.Log.Error("failed to get user audit logs", zap.Error(err))
		return
	}

	var result []map[string]interface{}
	for _, log := range logs {
		result = append(result, map[string]interface{}{
			"id":            log.ID,
			"user_id":       log.UserID,
			"action":        log.Action,
			"resource_type": log.ResourceType,
			"resource_id":   log.ResourceID,
			"ip_address":    log.IPAddress,
			"user_agent":    log.UserAgent,
			"metadata":      log.Metadata,
			"created_at":    log.CreatedAt,
		})
	}

	c.JSON(http.StatusOK, gin.H{"logs": result})
}
