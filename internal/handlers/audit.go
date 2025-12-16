package handlers

import (
    "net/http"
    "strconv"

    "citadel-drive/internal/config"
    "citadel-drive/internal/middleware"
    "citadel-drive/internal/repositories"
    "citadel-drive/internal/utils"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "go.uber.org/zap"
    "gorm.io/gorm"
)

type AuditHandler struct {
    DB        *gorm.DB
    Config    config.Config
    Log       *zap.Logger
    AuditRepo *repositories.AuditRepository
}

func (h *AuditHandler) Register(r *gin.Engine) {
    g := r.Group("/audit-logs")
    g.Use(middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret))

    g.GET("", middleware.RequireRole("admin"), h.List)
    g.GET("/user/:userId", h.ListByUser)
    g.GET("/file/:fileId", middleware.RequireRole("admin"), h.ListByFile)
    g.GET("/search", middleware.RequireRole("admin"), h.List) // Reuse List for search
}

func (h *AuditHandler) List(c *gin.Context) {
    limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
    offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
    limit, offset = utils.ValidatePaginationParams(limit, offset)

    filter := make(map[string]interface{})
    if uid := c.Query("user_id"); uid != "" {
        filter["user_id"] = uid
    }
    if action := c.Query("action"); action != "" {
        filter["action"] = action
    }
    if resType := c.Query("resource_type"); resType != "" {
        filter["resource_type"] = resType
    }
    if resID := c.Query("resource_id"); resID != "" {
        filter["resource_id"] = resID
    }

    logs, total, err := h.AuditRepo.List(filter, limit, offset)
    if err != nil {
        h.Log.Error("failed to fetch audit logs", zap.Error(err))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"data": logs, "total": total, "limit": limit, "offset": offset})
}

func (h *AuditHandler) ListByUser(c *gin.Context) {
    userIDStr := c.Param("userId")
    userID, err := uuid.Parse(userIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user id"})
        return
    }

    // Security check: only admin or the user themselves can view this
    currentUserID := h.getUserID(c)
    currentRole := h.getUserRole(c)

    if currentRole != "admin" && currentUserID != userID {
        c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
        return
    }

    limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
    offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
    limit, offset = utils.ValidatePaginationParams(limit, offset)

    logs, err := h.AuditRepo.GetByUserID(userID, limit, offset)
    if err != nil {
        h.Log.Error("failed to fetch user audit logs", zap.Error(err), zap.String("user_id", userIDStr))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"data": logs})
}

func (h *AuditHandler) ListByFile(c *gin.Context) {
    fileIDStr := c.Param("fileId")
    fileID, err := uuid.Parse(fileIDStr)
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file id"})
        return
    }

    limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
    offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
    limit, offset = utils.ValidatePaginationParams(limit, offset)

    logs, err := h.AuditRepo.GetByResourceID(fileID, limit, offset)
    if err != nil {
        h.Log.Error("failed to fetch file audit logs", zap.Error(err), zap.String("file_id", fileIDStr))
        c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to fetch logs"})
        return
    }

    c.JSON(http.StatusOK, gin.H{"data": logs})
}

func (h *AuditHandler) getUserID(c *gin.Context) uuid.UUID {
    v, exists := c.Get(middleware.ContextUserID)
    if !exists {
        return uuid.Nil
    }

    switch t := v.(type) {
    case uuid.UUID:
        return t
    case string:
        id, err := uuid.Parse(t)
        if err != nil {
            return uuid.Nil
        }
        return id
    default:
        return uuid.Nil
    }
}

func (h *AuditHandler) getUserRole(c *gin.Context) string {
    role, exists := c.Get(middleware.ContextRole)
    if !exists {
        return ""
    }
    return role.(string)
}
