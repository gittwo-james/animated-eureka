package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"gorm.io/gorm"
)

type HealthHandler struct {
	DB *gorm.DB
}

func (h HealthHandler) Register(r *gin.Engine) {
	r.GET("/healthz", h.Healthz)
}

func (h HealthHandler) Healthz(c *gin.Context) {
	if h.DB != nil {
		if err := h.DB.Raw("SELECT 1").Error; err != nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"status": "unhealthy", "db": err.Error()})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}
