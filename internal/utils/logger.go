package utils

import (
	"strings"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

func NewLogger(env, level string) (*zap.Logger, error) {
	var cfg zap.Config
	if strings.ToLower(env) == "production" {
		cfg = zap.NewProductionConfig()
	} else {
		cfg = zap.NewDevelopmentConfig()
	}

	lvl := zapcore.InfoLevel
	if err := lvl.Set(strings.ToLower(level)); err == nil {
		cfg.Level = zap.NewAtomicLevelAt(lvl)
	}

	return cfg.Build()
}
