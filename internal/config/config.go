package config

import (
	"fmt"

	"citadel-drive/internal/utils"
)

type Config struct {
	AppPort string
	AppEnv  string

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
}

func Load() Config {
	return Config{
		AppPort: utils.GetEnv("APP_PORT", "8080"),
		AppEnv:  utils.GetEnv("APP_ENV", "development"),

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
