package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"image/png"
	"net/http"
	"strings"
	"time"

	"citadel-drive/internal/config"
	"citadel-drive/internal/middleware"
	"citadel-drive/internal/models"
	cryptopkg "citadel-drive/pkg/crypto"
	jwtpkg "citadel-drive/pkg/jwt"
	otppkg "citadel-drive/pkg/otp"

	"github.com/boombuler/barcode"
	"github.com/boombuler/barcode/qr"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"go.uber.org/zap"
	"gorm.io/datatypes"
	"gorm.io/gorm"
)

type AuthHandler struct {
	DB     *gorm.DB
	Config config.Config
	Log    *zap.Logger
}

func (h AuthHandler) Register(r *gin.Engine) {
	g := r.Group("/auth")
	g.POST("/validate-password", h.ValidatePassword)
	g.POST("/register", h.RegisterUser)
	g.POST("/login", h.Login)
	g.POST("/verify-totp", h.VerifyTOTP)
	g.POST("/refresh", h.Refresh)
	g.POST("/logout", middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret), h.Logout)
	g.POST("/setup-2fa", middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret), h.Setup2FA)
	g.POST("/confirm-2fa", middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret), h.Confirm2FA)
	g.POST("/backup-codes", middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret), h.GenerateBackupCodes)

	g.POST("/request-password-reset", h.RequestPasswordReset)
	g.POST("/reset-password", h.ResetPassword)
	g.POST("/request-unlock", h.RequestUnlock)
	g.POST("/unlock", h.UnlockViaToken)

	admin := g.Group("/admin")
	admin.Use(middleware.JWTAuth(h.DB, h.Config.JWTAccessSecret), middleware.RequireRole("admin"))
	admin.POST("/unlock", h.AdminUnlock)
	admin.POST("/force-logout", h.AdminForceLogout)
}

type validatePasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

func (h AuthHandler) ValidatePassword(c *gin.Context) {
	var req validatePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	issues, err := cryptopkg.ValidatePasswordComplexity(req.Password)
	c.JSON(http.StatusOK, gin.H{"valid": err == nil, "issues": issues})
}

type registerRequest struct {
	Email            string `json:"email" binding:"required"`
	Password         string `json:"password" binding:"required"`
	FullName         string `json:"full_name" binding:"required"`
	OrganizationID   string `json:"organization_id"`
	OrganizationName string `json:"organization_name"`
	Role             string `json:"role"`
}

func (h AuthHandler) RegisterUser(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req registerRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	if issues, err := cryptopkg.ValidatePasswordComplexity(req.Password); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password too weak", "issues": issues})
		return
	}

	var userCount int64
	if err := h.DB.Model(&models.User{}).Count(&userCount).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to check users"})
		return
	}
	bootstrap := userCount == 0

	role := strings.TrimSpace(req.Role)
	if role == "" {
		role = "user"
	}
	if bootstrap {
		role = "admin"
	} else {
		claims, ok := h.authenticateAccessToken(c)
		if !ok {
			return
		}
		if claims.Role != "admin" {
			c.JSON(http.StatusForbidden, gin.H{"error": "forbidden"})
			return
		}
	}

	tx := h.DB.Begin()
	orgID, err := h.ensureOrganization(tx, req.OrganizationID, req.OrganizationName)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid organization"})
		return
	}

	pwHash, err := cryptopkg.HashPassword(req.Password)
	if err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	user := models.User{
		Email:          strings.ToLower(strings.TrimSpace(req.Email)),
		PasswordHash:   pwHash,
		FullName:       strings.TrimSpace(req.FullName),
		OrganizationID: orgID,
		IsActive:       true,
	}
	if err := tx.Create(&user).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to create user"})
		return
	}

	perm := models.UserPermission{UserID: user.ID, OrganizationID: orgID, Role: role}
	if err := tx.Create(&perm).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to assign role"})
		return
	}

	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": user.ID.String(), "email": user.Email, "full_name": user.FullName, "organization_id": orgID.String(), "role": role})
}

type loginRequest struct {
	Email    string `json:"email" binding:"required"`
	Password string `json:"password" binding:"required"`
}

func (h AuthHandler) Login(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	var user models.User
	if err := h.DB.Where("email = ?", email).First(&user).Error; err != nil {
		h.recordFailedLogin(c, nil, email, "invalid_credentials")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid credentials"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "account disabled"})
		return
	}

	now := time.Now()
	if user.LockedUntil != nil && user.LockedUntil.After(now) {
		h.recordFailedLogin(c, &user, email, "locked")
		c.JSON(http.StatusLocked, gin.H{"error": "account locked", "locked_until": user.LockedUntil})
		return
	}

	if err := cryptopkg.ComparePassword(user.PasswordHash, req.Password); err != nil {
		lockedUntil := h.applyFailedLogin(c, &user, email)
		resp := gin.H{"error": "invalid credentials"}
		if lockedUntil != nil {
			resp["locked_until"] = lockedUntil
		}
		c.JSON(http.StatusUnauthorized, resp)
		return
	}

	if err := h.DB.Model(&models.User{}).Where("id = ?", user.ID).Updates(map[string]any{"failed_login_attempts": 0, "locked_until": nil}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update user"})
		return
	}

	role := h.userRole(user.ID, user.OrganizationID)

	if user.TotpEnabled {
		totpToken, err := jwtpkg.GenerateToken(jwtpkg.Claims{
			UserID:         user.ID.String(),
			OrganizationID: user.OrganizationID.String(),
			Role:           role,
			TokenType:      jwtpkg.TokenTypeTOTP,
			RegisteredClaims: jwt.RegisteredClaims{
				Issuer:  h.Config.JWTIssuer,
				Subject: user.ID.String(),
			},
		}, []byte(h.Config.JWTAccessSecret), 5*time.Minute)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create totp token"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"totp_required": true, "totp_token": totpToken})
		return
	}

	accessToken, refreshToken, err := h.issueTokens(c, user, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken, "token_type": "Bearer"})
}

type verifyTOTPRequest struct {
	TOTPToken string `json:"totp_token" binding:"required"`
	Code      string `json:"code" binding:"required"`
}

func (h AuthHandler) VerifyTOTP(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req verifyTOTPRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	claims, err := jwtpkg.ParseToken(req.TOTPToken, []byte(h.Config.JWTAccessSecret))
	if err != nil || claims.TokenType != jwtpkg.TokenTypeTOTP {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid totp token"})
		return
	}

	uid, err := uuid.Parse(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid totp token"})
		return
	}

	var user models.User
	if err := h.DB.First(&user, "id = ?", uid).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid totp token"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "account disabled"})
		return
	}

	code := strings.TrimSpace(req.Code)
	ok := false
	if user.TotpEnabled && user.TotpSecret != nil {
		ok = otppkg.ValidateTOTPCodeAt(code, *user.TotpSecret, time.Now())
	}
	if !ok {
		ok, _ = h.consumeBackupCode(user.ID, code)
	}

	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	role := h.userRole(user.ID, user.OrganizationID)
	accessToken, refreshToken, err := h.issueTokens(c, user, role)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create tokens"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": refreshToken, "token_type": "Bearer"})
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

func (h AuthHandler) Refresh(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req refreshRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	claims, err := jwtpkg.ParseToken(req.RefreshToken, []byte(h.Config.JWTRefreshSecret))
	if err != nil || claims.TokenType != jwtpkg.TokenTypeRefresh {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	now := time.Now()
	if err := h.ensureNotBlacklisted(req.RefreshToken, now); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return
	}

	sid, err := uuid.Parse(claims.SessionID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	tokenHash := jwtpkg.HashToken(req.RefreshToken)
	var session models.Session
	if err := h.DB.Where("id = ? AND is_active = true AND expires_at > ? AND token_hash = ?", sid, now, tokenHash).First(&session).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
		return
	}

	uid, err := uuid.Parse(claims.UserID)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	var user models.User
	if err := h.DB.First(&user, "id = ?", uid).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid refresh token"})
		return
	}

	if !user.IsActive {
		c.JSON(http.StatusForbidden, gin.H{"error": "account disabled"})
		return
	}

	role := h.userRole(user.ID, user.OrganizationID)
	accessToken, err := jwtpkg.GenerateToken(jwtpkg.Claims{
		UserID:         user.ID.String(),
		OrganizationID: user.OrganizationID.String(),
		Role:           role,
		SessionID:      session.ID.String(),
		TokenType:      jwtpkg.TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  h.Config.JWTIssuer,
			Subject: user.ID.String(),
		},
	}, []byte(h.Config.JWTAccessSecret), time.Hour)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create access token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"access_token": accessToken, "refresh_token": req.RefreshToken, "token_type": "Bearer"})
}

type logoutRequest struct {
	RefreshToken string `json:"refresh_token"`
}

func (h AuthHandler) Logout(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	claimsAny, _ := c.Get("claims")
	claims, _ := claimsAny.(*jwtpkg.Claims)

	var req logoutRequest
	_ = c.ShouldBindJSON(&req)

	auth := strings.TrimSpace(c.GetHeader("Authorization"))
	parts := strings.SplitN(auth, " ", 2)
	accessToken := ""
	if len(parts) == 2 {
		accessToken = strings.TrimSpace(parts[1])
	}

	if accessToken != "" {
		if err := h.blacklistToken(accessToken, claims); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
			return
		}
	}

	if claims != nil && claims.SessionID != "" {
		sid, err := uuid.Parse(claims.SessionID)
		if err == nil {
			if err := h.DB.Model(&models.Session{}).Where("id = ?", sid).Update("is_active", false).Error; err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
				return
			}
		}
	}

	if strings.TrimSpace(req.RefreshToken) != "" {
		refreshClaims, err := jwtpkg.ParseToken(req.RefreshToken, []byte(h.Config.JWTRefreshSecret))
		if err == nil {
			if err := h.blacklistToken(req.RefreshToken, refreshClaims); err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout"})
				return
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h AuthHandler) Setup2FA(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	uid, ok := h.currentUserID(c)
	if !ok {
		return
	}

	var user models.User
	if err := h.DB.First(&user, "id = ?", uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	key, err := otppkg.GenerateTOTPSecret(otppkg.TOTPConfig{Issuer: h.Config.TOTPIssuer, AccountName: user.Email})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate secret"})
		return
	}

	secret := key.Secret()
	qrB64, err := makeQRCodePNGBase64(key.URL())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate qr code"})
		return
	}

	if err := h.DB.Model(&models.User{}).Where("id = ?", user.ID).Updates(map[string]any{"totp_secret": secret, "totp_enabled": false, "totp_confirmed_at": nil}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save secret"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"secret": secret, "otpauth_url": key.URL(), "qr_code_png_base64": qrB64})
}

type confirm2FARequest struct {
	Code string `json:"code" binding:"required"`
}

func (h AuthHandler) Confirm2FA(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	uid, ok := h.currentUserID(c)
	if !ok {
		return
	}

	var req confirm2FARequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	var user models.User
	if err := h.DB.First(&user, "id = ?", uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if user.TotpSecret == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2fa not setup"})
		return
	}

	if !otppkg.ValidateTOTPCodeAt(strings.TrimSpace(req.Code), *user.TotpSecret, time.Now()) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid code"})
		return
	}

	now := time.Now()
	if err := h.DB.Model(&models.User{}).Where("id = ?", user.ID).Updates(map[string]any{"totp_enabled": true, "totp_confirmed_at": now}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to enable 2fa"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"enabled": true})
}

func (h AuthHandler) GenerateBackupCodes(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	uid, ok := h.currentUserID(c)
	if !ok {
		return
	}

	var user models.User
	if err := h.DB.First(&user, "id = ?", uid).Error; err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}
	if !user.TotpEnabled {
		c.JSON(http.StatusBadRequest, gin.H{"error": "2fa not enabled"})
		return
	}

	codes := make([]string, 0, 10)
	records := make([]models.UserBackupCode, 0, 10)
	for i := 0; i < 10; i++ {
		code, err := randomHumanCode(10)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to generate backup codes"})
			return
		}
		codes = append(codes, code)
		records = append(records, models.UserBackupCode{UserID: user.ID, CodeHash: h.hashWithPepper(code)})
	}

	tx := h.DB.Begin()
	if err := tx.Where("user_id = ?", user.ID).Delete(&models.UserBackupCode{}).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to replace backup codes"})
		return
	}
	if err := tx.Create(&records).Error; err != nil {
		tx.Rollback()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save backup codes"})
		return
	}
	if err := tx.Commit().Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save backup codes"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"backup_codes": codes})
}

type requestPasswordResetRequest struct {
	Email string `json:"email" binding:"required"`
}

func (h AuthHandler) RequestPasswordReset(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req requestPasswordResetRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	var user models.User
	if err := h.DB.Where("email = ?", email).First(&user).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}

	token, err := randomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create reset token"})
		return
	}

	expires := time.Now().Add(time.Hour)
	hash := h.hashWithPepper(token)
	if err := h.DB.Model(&models.User{}).Where("id = ?", user.ID).Updates(map[string]any{"password_reset_token_hash": hash, "password_reset_expires_at": expires}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store reset token"})
		return
	}

	resp := gin.H{"status": "ok"}
	if h.Config.AppEnv != "production" {
		resp["reset_token"] = token
	}
	c.JSON(http.StatusOK, resp)
}

type resetPasswordRequest struct {
	Token       string `json:"token" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

func (h AuthHandler) ResetPassword(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req resetPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	if issues, err := cryptopkg.ValidatePasswordComplexity(req.NewPassword); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "password too weak", "issues": issues})
		return
	}

	now := time.Now()
	tokenHash := h.hashWithPepper(strings.TrimSpace(req.Token))

	var user models.User
	if err := h.DB.Where("password_reset_token_hash = ? AND password_reset_expires_at > ?", tokenHash, now).First(&user).Error; err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	pwHash, err := cryptopkg.HashPassword(req.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to hash password"})
		return
	}

	updates := map[string]any{
		"password_hash":             pwHash,
		"password_reset_token_hash": nil,
		"password_reset_expires_at": nil,
		"failed_login_attempts":     0,
		"locked_until":              nil,
	}
	if err := h.DB.Model(&models.User{}).Where("id = ?", user.ID).Updates(updates).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to reset password"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type requestUnlockRequest struct {
	Email string `json:"email" binding:"required"`
}

func (h AuthHandler) RequestUnlock(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req requestUnlockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	email := strings.ToLower(strings.TrimSpace(req.Email))
	var user models.User
	if err := h.DB.Where("email = ?", email).First(&user).Error; err != nil {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
		return
	}

	token, err := randomToken(32)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create unlock token"})
		return
	}

	expires := time.Now().Add(time.Hour)
	hash := h.hashWithPepper(token)
	if err := h.DB.Model(&models.User{}).Where("id = ?", user.ID).Updates(map[string]any{"unlock_token_hash": hash, "unlock_token_expires_at": expires}).Error; err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to store unlock token"})
		return
	}

	resp := gin.H{"status": "ok"}
	if h.Config.AppEnv != "production" {
		resp["unlock_token"] = token
	}
	c.JSON(http.StatusOK, resp)
}

type unlockViaTokenRequest struct {
	Token string `json:"token" binding:"required"`
}

func (h AuthHandler) UnlockViaToken(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req unlockViaTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	now := time.Now()
	tokenHash := h.hashWithPepper(strings.TrimSpace(req.Token))

	res := h.DB.Model(&models.User{}).
		Where("unlock_token_hash = ? AND unlock_token_expires_at > ?", tokenHash, now).
		Updates(map[string]any{"failed_login_attempts": 0, "locked_until": nil, "unlock_token_hash": nil, "unlock_token_expires_at": nil})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unlock"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type adminUnlockRequest struct {
	Email  string `json:"email"`
	UserID string `json:"user_id"`
}

func (h AuthHandler) AdminUnlock(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req adminUnlockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	q := h.DB.Model(&models.User{})
	if strings.TrimSpace(req.UserID) != "" {
		uid, err := uuid.Parse(req.UserID)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid user_id"})
			return
		}
		q = q.Where("id = ?", uid)
	} else if strings.TrimSpace(req.Email) != "" {
		q = q.Where("email = ?", strings.ToLower(strings.TrimSpace(req.Email)))
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email or user_id required"})
		return
	}

	res := q.Updates(map[string]any{"failed_login_attempts": 0, "locked_until": nil})
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to unlock"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "user not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type adminForceLogoutRequest struct {
	SessionID string `json:"session_id" binding:"required"`
}

func (h AuthHandler) AdminForceLogout(c *gin.Context) {
	if h.DB == nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "database not configured"})
		return
	}

	var req adminForceLogoutRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}

	sid, err := uuid.Parse(req.SessionID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid session_id"})
		return
	}

	res := h.DB.Model(&models.Session{}).Where("id = ?", sid).Update("is_active", false)
	if res.Error != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to logout session"})
		return
	}
	if res.RowsAffected == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "session not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h AuthHandler) authenticateAccessToken(c *gin.Context) (*jwtpkg.Claims, bool) {
	auth := strings.TrimSpace(c.GetHeader("Authorization"))
	parts := strings.SplitN(auth, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "missing authorization header"})
		return nil, false
	}

	tokenString := strings.TrimSpace(parts[1])
	claims, err := jwtpkg.ParseToken(tokenString, []byte(h.Config.JWTAccessSecret))
	if err != nil || claims.TokenType != jwtpkg.TokenTypeAccess {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid token"})
		return nil, false
	}

	if err := h.ensureNotBlacklisted(tokenString, time.Now()); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
		return nil, false
	}

	if claims.SessionID != "" {
		sid, err := uuid.Parse(claims.SessionID)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid session"})
			return nil, false
		}
		var session models.Session
		if err := h.DB.Where("id = ? AND is_active = true AND expires_at > ?", sid, time.Now()).First(&session).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "session expired"})
			return nil, false
		}
	}

	return claims, true
}

func (h AuthHandler) ensureOrganization(tx *gorm.DB, orgID string, orgName string) (uuid.UUID, error) {
	if strings.TrimSpace(orgID) != "" {
		id, err := uuid.Parse(orgID)
		if err != nil {
			return uuid.Nil, err
		}
		var org models.Organization
		if err := tx.First(&org, "id = ?", id).Error; err != nil {
			return uuid.Nil, err
		}
		return org.ID, nil
	}

	name := strings.TrimSpace(orgName)
	if name == "" {
		name = "Default"
	}

	org := models.Organization{Name: name}
	if err := tx.Create(&org).Error; err != nil {
		return uuid.Nil, err
	}
	return org.ID, nil
}

func (h AuthHandler) currentUserID(c *gin.Context) (uuid.UUID, bool) {
	v, ok := c.Get(middleware.ContextUserID)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return uuid.Nil, false
	}

	switch t := v.(type) {
	case uuid.UUID:
		return t, true
	case string:
		uid, err := uuid.Parse(t)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
			return uuid.Nil, false
		}
		return uid, true
	default:
		c.JSON(http.StatusUnauthorized, gin.H{"error": "unauthorized"})
		return uuid.Nil, false
	}
}

func (h AuthHandler) userRole(userID uuid.UUID, orgID uuid.UUID) string {
	if h.DB == nil {
		return "user"
	}
	var perm models.UserPermission
	if err := h.DB.Where("user_id = ? AND organization_id = ?", userID, orgID).First(&perm).Error; err != nil {
		return "user"
	}
	if strings.TrimSpace(perm.Role) == "" {
		return "user"
	}
	return perm.Role
}

func (h AuthHandler) issueTokens(c *gin.Context, user models.User, role string) (string, string, error) {
	refreshTTL := 7 * 24 * time.Hour
	sessionExpiresAt := time.Now().Add(refreshTTL)
	sid := uuid.New()

	refreshClaims := jwtpkg.Claims{
		UserID:         user.ID.String(),
		OrganizationID: user.OrganizationID.String(),
		Role:           role,
		SessionID:      sid.String(),
		TokenType:      jwtpkg.TokenTypeRefresh,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  h.Config.JWTIssuer,
			Subject: user.ID.String(),
		},
	}
	refreshToken, err := jwtpkg.GenerateToken(refreshClaims, []byte(h.Config.JWTRefreshSecret), refreshTTL)
	if err != nil {
		return "", "", err
	}

	tokenHash := jwtpkg.HashToken(refreshToken)

	tx := h.DB.Begin()
	if err := h.enforceSessionLimit(tx, user.ID); err != nil {
		tx.Rollback()
		return "", "", err
	}

	session := models.Session{
		ID:        sid,
		UserID:    user.ID,
		TokenHash: tokenHash,
		IPAddress: c.ClientIP(),
		UserAgent: c.Request.UserAgent(),
		ExpiresAt: sessionExpiresAt,
		IsActive:  true,
	}
	if err := tx.Create(&session).Error; err != nil {
		tx.Rollback()
		return "", "", err
	}
	if err := tx.Commit().Error; err != nil {
		return "", "", err
	}

	accessClaims := jwtpkg.Claims{
		UserID:         user.ID.String(),
		OrganizationID: user.OrganizationID.String(),
		Role:           role,
		SessionID:      sid.String(),
		TokenType:      jwtpkg.TokenTypeAccess,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  h.Config.JWTIssuer,
			Subject: user.ID.String(),
		},
	}
	accessToken, err := jwtpkg.GenerateToken(accessClaims, []byte(h.Config.JWTAccessSecret), time.Hour)
	if err != nil {
		return "", "", err
	}

	return accessToken, refreshToken, nil
}

func (h AuthHandler) enforceSessionLimit(tx *gorm.DB, userID uuid.UUID) error {
	var sessions []models.Session
	now := time.Now()
	if err := tx.Where("user_id = ? AND is_active = true AND expires_at > ?", userID, now).Order("created_at asc").Find(&sessions).Error; err != nil {
		return err
	}
	if len(sessions) < 5 {
		return nil
	}

	toDeactivate := len(sessions) - 4
	for i := 0; i < toDeactivate; i++ {
		if err := tx.Model(&models.Session{}).Where("id = ?", sessions[i].ID).Update("is_active", false).Error; err != nil {
			return err
		}
	}
	return nil
}

func (h AuthHandler) ensureNotBlacklisted(tokenString string, now time.Time) error {
	var bl models.TokenBlacklist
	err := h.DB.Where("token_hash = ? AND expires_at > ?", jwtpkg.HashToken(tokenString), now).First(&bl).Error
	if err == nil {
		return errors.New("token revoked")
	}
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil
	}
	return err
}

func (h AuthHandler) blacklistToken(tokenString string, claims *jwtpkg.Claims) error {
	if h.DB == nil {
		return nil
	}

	exp := time.Now().Add(time.Hour)
	if claims != nil && claims.ExpiresAt != nil {
		exp = claims.ExpiresAt.Time
	}
	if exp.Before(time.Now()) {
		return nil
	}

	bl := models.TokenBlacklist{TokenHash: jwtpkg.HashToken(tokenString), ExpiresAt: exp}
	if err := h.DB.Create(&bl).Error; err != nil {
		if errors.Is(err, gorm.ErrDuplicatedKey) {
			return nil
		}
		return err
	}
	return nil
}

func (h AuthHandler) applyFailedLogin(c *gin.Context, user *models.User, email string) *time.Time {
	if user == nil {
		return nil
	}

	now := time.Now()
	attempts := user.FailedLoginAttempts + 1
	lockUntil := computeLockedUntil(attempts, now)

	updates := map[string]any{"failed_login_attempts": attempts}
	if lockUntil != nil {
		updates["locked_until"] = *lockUntil
	}
	_ = h.DB.Model(&models.User{}).Where("id = ?", user.ID).Updates(updates).Error

	user.FailedLoginAttempts = attempts
	user.LockedUntil = lockUntil

	if lockUntil != nil {
		h.recordFailedLogin(c, user, email, "locked")
	} else {
		h.recordFailedLogin(c, user, email, "invalid_credentials")
	}
	return lockUntil
}

func (h AuthHandler) recordFailedLogin(c *gin.Context, user *models.User, email string, reason string) {
	if h.DB == nil {
		return
	}

	metadata := map[string]any{"email": email, "reason": reason}
	metaBytes, _ := json.Marshal(metadata)

	logEntry := models.AuditLog{
		Action:       "login_failed",
		ResourceType: "user",
		ResourceID:   uuid.Nil,
		IPAddress:    c.ClientIP(),
		UserAgent:    c.Request.UserAgent(),
		Metadata:     datatypes.JSON(metaBytes),
	}
	if user != nil {
		logEntry.UserID = &user.ID
		logEntry.ResourceID = user.ID
	}
	_ = h.DB.Create(&logEntry).Error
}

func computeLockedUntil(attempts int, now time.Time) *time.Time {
	if attempts < 5 {
		return nil
	}

	dur := 15 * time.Minute
	for i := 0; i < attempts-5; i++ {
		dur *= 2
		if dur >= 24*time.Hour {
			dur = 24 * time.Hour
			break
		}
	}

	t := now.Add(dur)
	return &t
}

func (h AuthHandler) consumeBackupCode(userID uuid.UUID, code string) (bool, error) {
	codeHash := h.hashWithPepper(code)
	var bc models.UserBackupCode
	if err := h.DB.Where("user_id = ? AND code_hash = ? AND used_at IS NULL", userID, codeHash).First(&bc).Error; err != nil {
		return false, err
	}
	now := time.Now()
	if err := h.DB.Model(&models.UserBackupCode{}).Where("id = ?", bc.ID).Update("used_at", now).Error; err != nil {
		return false, err
	}
	return true, nil
}

func (h AuthHandler) hashWithPepper(value string) string {
	sum := sha256.Sum256([]byte(h.Config.AuthPepper + ":" + value))
	return hex.EncodeToString(sum[:])
}

func randomToken(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func randomHumanCode(length int) (string, error) {
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	out := make([]byte, length)
	for i := range out {
		out[i] = alphabet[int(b[i])%len(alphabet)]
	}
	return string(out), nil
}

func makeQRCodePNGBase64(url string) (string, error) {
	img, err := qr.Encode(url, qr.M, qr.Auto)
	if err != nil {
		return "", err
	}
	img, err = barcode.Scale(img, 256, 256)
	if err != nil {
		return "", err
	}

	var b strings.Builder
	enc := base64.NewEncoder(base64.StdEncoding, &b)
	if err := png.Encode(enc, img); err != nil {
		_ = enc.Close()
		return "", err
	}
	if err := enc.Close(); err != nil {
		return "", err
	}

	return b.String(), nil
}
