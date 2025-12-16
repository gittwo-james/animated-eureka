package config

import (
	"fmt"
	"strings"

	"citadel-drive/internal/utils"
)

type Config struct {
	AppPort string
	AppEnv  string

	JWTAccessSecret  string
	JWTRefreshSecret string
	JWTIssuer        string
	AuthPepper       string
	TOTPIssuer       string

	DatabaseURL string
	DBHost      string
	DBPort      int
	DBUser      string
	DBPassword  string
	DBName      string
	DBSSLMode   string
	DBTimeZone  string

	DBMaxOpenConns int
	DBMaxIdleConns int

	AutoMigrate    bool
	MetricsEnabled bool
	LogLevel       string

	R2Endpoint        string
	R2Region          string
	R2Bucket          string
	R2AccessKeyID     string
	R2SecretAccessKey string
	R2PresignTTL      int
	R2MaxAttempts     int

	FileAllowedTypes            []string
	FileMaxVersions             int
	FileMultipartPartSizeMB     int
	FileMultipartPresignBatchSz int
}

func Load() Config {
	return Config{
		AppPort: utils.GetEnv("APP_PORT", "8080"),
		AppEnv:  utils.GetEnv("APP_ENV", "development"),

		JWTAccessSecret:  utils.GetEnv("JWT_ACCESS_SECRET", "dev-access-secret-change-me"),
		JWTRefreshSecret: utils.GetEnv("JWT_REFRESH_SECRET", "dev-refresh-secret-change-me"),
		JWTIssuer:        utils.GetEnv("JWT_ISSUER", "citadel-drive"),
		AuthPepper:       utils.GetEnv("AUTH_PEPPER", "dev-pepper-change-me"),
		TOTPIssuer:       utils.GetEnv("TOTP_ISSUER", "Citadel Drive"),

		DatabaseURL: utils.GetEnv("DATABASE_URL", ""),
		DBHost:      utils.GetEnv("DB_HOST", "localhost"),
		DBPort:      utils.GetEnvInt("DB_PORT", 5432),
		DBUser:      utils.GetEnv("DB_USER", "postgres"),
		DBPassword:  utils.GetEnv("DB_PASSWORD", "postgres"),
		DBName:      utils.GetEnv("DB_NAME", "citadel_drive"),
		DBSSLMode:   utils.GetEnv("DB_SSLMODE", "disable"),
		DBTimeZone:  utils.GetEnv("DB_TIMEZONE", "UTC"),

		DBMaxOpenConns: utils.GetEnvInt("DB_MAX_OPEN_CONNS", 25),
		DBMaxIdleConns: utils.GetEnvInt("DB_MAX_IDLE_CONNS", 25),

		AutoMigrate:    utils.GetEnvBool("AUTO_MIGRATE", false),
		MetricsEnabled: utils.GetEnvBool("METRICS_ENABLED", true),
		LogLevel:       utils.GetEnv("LOG_LEVEL", "info"),

		R2Endpoint:        utils.GetEnv("R2_ENDPOINT", ""),
		R2Region:          utils.GetEnv("R2_REGION", "auto"),
		R2Bucket:          utils.GetEnv("R2_BUCKET", ""),
		R2AccessKeyID:     utils.GetEnv("R2_ACCESS_KEY_ID", ""),
		R2SecretAccessKey: utils.GetEnv("R2_SECRET_ACCESS_KEY", ""),
		R2PresignTTL:      utils.GetEnvInt("R2_PRESIGN_TTL_SECONDS", 900),
		R2MaxAttempts:     utils.GetEnvInt("R2_MAX_ATTEMPTS", 5),

		FileAllowedTypes:            parseCSV(utils.GetEnv("FILE_ALLOWED_TYPES", "application/pdf,image/png,image/jpeg,text/plain")),
		FileMaxVersions:             utils.GetEnvInt("FILE_MAX_VERSIONS", 50),
		FileMultipartPartSizeMB:     utils.GetEnvInt("FILE_MULTIPART_PART_SIZE_MB", 10),
		FileMultipartPresignBatchSz: utils.GetEnvInt("FILE_MULTIPART_PRESIGN_BATCH_SIZE", 100),
	}
}

func (c Config) PostgresDSN() string {
	if c.DatabaseURL != "" {
		return c.DatabaseURL
	}

	return fmt.Sprintf(
		"host=%s port=%d user=%s password=%s dbname=%s sslmode=%s TimeZone=%s",
		c.DBHost,
		c.DBPort,
		c.DBUser,
		c.DBPassword,
		c.DBName,
		c.DBSSLMode,
		c.DBTimeZone,
	)
}

func parseCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}
