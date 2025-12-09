package main

import (
    "context"
    "database/sql"
    "fmt"
    "log"
    "net/http"
    "os"
    "os/signal"
	"syscall"
	"time"

	"github.com/bryanwahyu/automaton-sec/internal/application"
	appai "github.com/bryanwahyu/automaton-sec/internal/application/ai"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
    "github.com/bryanwahyu/automaton-sec/internal/config"
    analistdom "github.com/bryanwahyu/automaton-sec/internal/domain/analyst"
    scansdom "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
    serrdom "github.com/bryanwahyu/automaton-sec/internal/domain/scanerrors"
    openai "github.com/bryanwahyu/automaton-sec/internal/infra/ai/openai"
    mysqlp "github.com/bryanwahyu/automaton-sec/internal/infra/db/mysql"
    pgp "github.com/bryanwahyu/automaton-sec/internal/infra/db/postgres"
    dockerrunner "github.com/bryanwahyu/automaton-sec/internal/infra/executor/docker"
    "github.com/bryanwahyu/automaton-sec/internal/infra/httpserver"
    "github.com/bryanwahyu/automaton-sec/internal/middleware"
    minioStore "github.com/bryanwahyu/automaton-sec/internal/infra/storage"
)

func main() {
	// path config.yaml
	path := "config.yaml"
	if v := os.Getenv("CONFIG_PATH"); v != "" {
		path = v
	}

	// load config
	cfg, err := config.Load(path)
	if err != nil {
		log.Fatalf("config load error: %v", err)
	}

	ctx := context.Background()

	// connect DB based on config.Database.Type (mysql|postgres)
    var (
        db          *sql.DB
        repo        scansdom.Repository
        analystRepo analistdom.Repository
        scanErrRepo serrdom.Repository
    )

	switch cfg.Database.Type {
	case "postgres", "postgresql", "pg":
		var err error
		db, err = pgp.Connect(ctx, cfg.PostgresDSN())
		if err != nil { log.Fatalf("postgres connect error: %v", err) }
		repo = pgp.NewScanRepository(db)
		analystRepo = pgp.NewAnalystRepository(db)
		scanErrRepo = pgp.NewScanErrorRepository(db)
	default:
		var err error
		db, err = mysqlp.Connect(ctx, cfg.MySQLDSN())
		if err != nil { log.Fatalf("mysql connect error: %v", err) }
		repo = mysqlp.NewScanRepository(db)
		analystRepo = mysqlp.NewAnalystRepository(db)
		scanErrRepo = mysqlp.NewScanErrorRepository(db)
	}
	defer db.Close()

	// Configure database connection pooling for optimal performance
	db.SetMaxOpenConns(25)                 // Maximum number of open connections
	db.SetMaxIdleConns(5)                  // Maximum number of idle connections
	db.SetConnMaxLifetime(5 * time.Minute) // Maximum lifetime of a connection
	db.SetConnMaxIdleTime(2 * time.Minute) // Maximum idle time of a connection

	// Verify database connection
	if err := db.PingContext(ctx); err != nil {
		log.Fatalf("database ping failed: %v", err)
	}
	log.Println("database connection established successfully")

	// init minio
	store, err := minioStore.New(ctx,
		cfg.Minio.Endpoint,
		cfg.Minio.Region,
		cfg.Minio.BucketName,
		cfg.Minio.AccessKey,
		cfg.Minio.SecretKey,
		cfg.Minio.UseSSL,
	)
	if err != nil {
		log.Fatalf("minio init error: %v", err)
	}

	// init runner
	runner := dockerrunner.NewRunner()

	// init open ai client
    aiClient := openai.NewClient(cfg.OpenAI.APIKey, cfg.OpenAI.Model)

	// init services
	aiSvc := appai.NewService(aiClient).WithRepos(analystRepo, repo)
	scansSvc := &appscans.Service{
		Repo:      repo,
		Runner:    runner,
		Artifacts: store,
		Clock:     application.SystemClock{},
	}

	// init database health checker
	dbHealthChecker := &middleware.DatabaseHealthChecker{DB: db}

	// init router
    router := httpserver.NewRouter(scansSvc, aiSvc, scanErrRepo, dbHealthChecker, nil)

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      router,
		ReadTimeout:  30 * time.Second,  // Increased for long-running scans
		WriteTimeout: 30 * time.Second,  // Increased for large responses
		IdleTimeout:  120 * time.Second, // Increased for keep-alive
	}

	// run server
	go func() {
		log.Printf("server listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down server...")

	ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx2); err != nil {
		log.Printf("shutdown error: %v", err)
	}
}
