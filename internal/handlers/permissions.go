package handlers

import (
	"citadel-drive/internal/repositories"

	"github.com/gin-gonic/gin"
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
	// endpoints would go here
}
