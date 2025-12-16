package main

import (
    "context"
    "errors"
    "net/http"
    "os"
    "os/signal"
    "syscall"
    "time"

    "citadel-drive/internal/config"
    "citadel-drive/internal/handlers"
    "citadel-drive/internal/middleware"
    "citadel-drive/internal/repositories"
    "citadel-drive/internal/services"
    "citadel-drive/internal/storage/r2"
    "citadel-drive/internal/utils"

    "github.com/gin-gonic/gin"
    "github.com/prometheus/client_golang/prometheus/promhttp"
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

    if cfg.AutoMigrate {
        if err := repositories.EnsurePostgresExtensions(dbConn.Gorm); err != nil {
            log.Fatal("failed to ensure postgres extensions", zap.Error(err))
        }
        if err := repositories.AutoMigrate(dbConn.Gorm); err != nil {
            log.Fatal("failed to auto-migrate schema", zap.Error(err))
        }
    }

    if cfg.AppEnv == "production" {
        gin.SetMode(gin.ReleaseMode)
    }

    router := gin.New()
    router.Use(gin.Recovery())
    router.Use(middleware.RequestLogger(log))

    if cfg.MetricsEnabled {
        router.Use(middleware.PrometheusMetrics())
        router.GET("/metrics", gin.WrapH(promhttp.Handler()))
    }

    // Initialize permission cache
    permCache := repositories.NewPermissionCache()

    // Start permission expiration cleanup job (every 1 hour)
    go func() {
        ticker := time.NewTicker(1 * time.Hour)
        defer ticker.Stop()
        for range ticker.C {
            permRepo := repositories.NewPermissionRepository(dbConn.Gorm)
            if err := permRepo.InvalidateExpiredPermissions(); err != nil {
                log.Error("failed to invalidate expired permissions", zap.Error(err))
            }
        }
    }()

    // Initialize Repositories
    fileRepo := repositories.NewFileRepository(dbConn.Gorm)
    encKeyRepo := repositories.NewEncryptionKeyRepository(dbConn.Gorm)
    auditRepo := repositories.NewAuditRepository(dbConn.Gorm)

    // Initialize Services
    storageService := services.NewStorageService("/tmp/citadel-drive-storage")

    r2Client, err := r2.New(cfg)
    if err != nil {
        if errors.Is(err, r2.ErrNotConfigured) {
            log.Warn("r2 not configured; r2 file upload/download disabled")
        } else {
            log.Fatal("failed to initialize r2 client", zap.Error(err))
        }
    }

    // Register Handlers
    health := handlers.HealthHandler{DB: dbConn.Gorm}
    health.Register(router)

    auth := handlers.AuthHandler{DB: dbConn.Gorm, Config: cfg, Log: log}
    auth.Register(router)

    perms := handlers.PermissionHandler{DB: dbConn.Gorm, Log: log, Cache: permCache, JWTSecret: cfg.JWTAccessSecret}
    perms.Register(router)

    roles := handlers.RoleHandler{DB: dbConn.Gorm, Log: log, JWTSecret: cfg.JWTAccessSecret}
    roles.Register(router)

    fileHandler := handlers.FileHandler{
        DB:         dbConn.Gorm,
        Config:     cfg,
        Log:        log,
        FileRepo:   fileRepo,
        EncKeyRepo: encKeyRepo,
        AuditRepo:  auditRepo,
        Storage:    storageService,
    }
    fileHandler.Register(router)

    r2Ops := handlers.R2FileOpsHandler{DB: dbConn.Gorm, Config: cfg, Log: log, R2: r2Client, FileRepo: fileRepo, Audit: auditRepo}
    r2Ops.Register(router)

    auditHandler := handlers.AuditHandler{
        DB:        dbConn.Gorm,
        Config:    cfg,
        Log:       log,
        AuditRepo: auditRepo,
    }
    auditHandler.Register(router)

    adminHandler := handlers.AdminHandler{
        DB:     dbConn.Gorm,
        Config: cfg,
        Log:    log,
    }
    adminHandler.Register(router)

    srv := &http.Server{
        Addr:              ":" + cfg.AppPort,
        Handler:           router,
        ReadHeaderTimeout: 10 * time.Second,
    }

    go func() {
        log.Info("api server starting", zap.String("addr", srv.Addr))
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatal("api server failed", zap.Error(err))
        }
    }()

    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit

    ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
    defer cancel()

    log.Info("api server shutting down")
    if err := srv.Shutdown(ctx); err != nil {
        log.Error("api server shutdown error", zap.Error(err))
    }
}
