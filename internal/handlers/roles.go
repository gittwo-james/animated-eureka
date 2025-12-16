package handlers

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"gorm.io/gorm"
)

type RoleHandler struct {
	DB        *gorm.DB
	Log       *zap.Logger
	JWTSecret string
}

func (h *RoleHandler) Register(r *gin.Engine) {
	// endpoints would go here
}
