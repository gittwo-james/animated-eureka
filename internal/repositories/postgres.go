package repositories

import (
	"database/sql"
	"time"

	"citadel-drive/internal/config"

	"go.uber.org/zap"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DB struct {
	Gorm *gorm.DB
	SQL  *sql.DB
}

func ConnectPostgres(cfg config.Config, log *zap.Logger) (*DB, error) {
	gormCfg := &gorm.Config{DisableForeignKeyConstraintWhenMigrating: true}
	if log != nil {
		gormCfg.Logger = logger.New(
			zap.NewStdLog(log),
			logger.Config{LogLevel: logger.Warn},
		)
	}

	db, err := gorm.Open(postgres.Open(cfg.PostgresDSN()), gormCfg)
	if err != nil {
		return nil, err
	}

	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}

	sqlDB.SetMaxOpenConns(cfg.DBMaxOpenConns)
	sqlDB.SetMaxIdleConns(cfg.DBMaxIdleConns)
	sqlDB.SetConnMaxLifetime(30 * time.Minute)

	return &DB{Gorm: db, SQL: sqlDB}, nil
}
