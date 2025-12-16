package middleware

import (
    "net/http"
    "strings"
    "time"

    jwtpkg "citadel-drive/pkg/jwt"
    "citadel-drive/internal/models"

    "github.com/gin-gonic/gin"
    "github.com/google/uuid"
    "gorm.io/gorm"
)

const (
    ContextUserID         = "user_id"
    ContextOrganizationID = "organization_id"
    ContextRole           = "role"
    ContextSessionID      = "session_id"
)

func JWTAuth(db *gorm.DB, accessSecret string) gin.HandlerFunc {
    secret := []byte(accessSecret)
    return func(c *gin.Context) {
        auth := strings.TrimSpace(c.GetHeader("Authorization"))
        if auth == "" {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
            c.Abort()
            return
        }

        parts := strings.SplitN(auth, " ", 2)
        if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid authorization header"})
            c.Abort()
            return
        }

        tokenString := strings.TrimSpace(parts[1])
        claims, err := jwtpkg.ParseToken(tokenString, secret)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
            c.Abort()
            return
        }
        if claims.TokenType != jwtpkg.TokenTypeAccess {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token type"})
            c.Abort()
            return
        }

        now := time.Now()
        if db != nil {
            tokenHash := jwtpkg.HashToken(tokenString)
            var bl models.TokenBlacklist
            if err := db.Where("token_hash = ? AND expires_at > ?", tokenHash, now).First(&bl).Error; err == nil {
                c.JSON(http.StatusUnauthorized, gin.H{"error": "token revoked"})
                c.Abort()
                return
            }

            if claims.SessionID != "" {
                sid, err := uuid.Parse(claims.SessionID)
                if err != nil {
                    c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
                    c.Abort()
                    return
                }
                var session models.Session
                if err := db.Where("id = ? AND is_active = true AND expires_at > ?", sid, now).First(&session).Error; err != nil {
                    c.JSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
                    c.Abort()
                    return
                }
            }
        }

        uid, err := uuid.Parse(claims.UserID)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
            c.Abort()
            return
        }
        orgID, err := uuid.Parse(claims.OrganizationID)
        if err != nil {
            c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
            c.Abort()
            return
        }

        c.Set(ContextUserID, uid)
        c.Set(ContextOrganizationID, orgID)
        c.Set(ContextRole, claims.Role)
        c.Set(ContextSessionID, claims.SessionID)
        c.Set("claims", claims)

        c.Next()
    }
}

func RequireRole(role string) gin.HandlerFunc {
    return func(c *gin.Context) {
        v, _ := c.Get(ContextRole)
        current, _ := v.(string)
        if current != role {
            c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
            c.Abort()
            return
        }
        c.Next()
    }
}
