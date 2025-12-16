package main

import (
	"citadel-drive/internal/config"
	"citadel-drive/internal/repositories"
	"citadel-drive/internal/utils"

	"go.uber.org/zap"
)

func main() {
	cfg := config.Load()

	log, err := utils.NewLogger(cfg.AppEnv, cfg.LogLevel)
	if err != nil {
		panic(err)
	}
	defer func() { _ = log.Sync() }()

	dbConn, err := repositories.ConnectPostgres(cfg, log)
	if err != nil {
		log.Fatal("failed to connect to postgres", zap.Error(err))
	}
	defer func() { _ = dbConn.SQL.Close() }()

	if err := repositories.EnsurePostgresExtensions(dbConn.Gorm); err != nil {
		log.Fatal("failed to ensure postgres extensions", zap.Error(err))
	}
	if err := repositories.AutoMigrate(dbConn.Gorm); err != nil {
		log.Fatal("auto-migrate failed", zap.Error(err))
	}

	log.Info("migration complete")
}
