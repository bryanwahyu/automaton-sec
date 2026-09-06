package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"
	"google.golang.org/grpc"

	"github.com/bryanwahyu/automaton-sec/internal/application"
	appai "github.com/bryanwahyu/automaton-sec/internal/application/ai"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	"github.com/bryanwahyu/automaton-sec/internal/config"
	analistdom "github.com/bryanwahyu/automaton-sec/internal/domain/analyst"
	serrdom "github.com/bryanwahyu/automaton-sec/internal/domain/scanerrors"
	scansdom "github.com/bryanwahyu/automaton-sec/internal/domain/scans"
	openai "github.com/bryanwahyu/automaton-sec/internal/infra/ai/openai"
	mysqlp "github.com/bryanwahyu/automaton-sec/internal/infra/db/mysql"
	pgp "github.com/bryanwahyu/automaton-sec/internal/infra/db/postgres"
	dockerrunner "github.com/bryanwahyu/automaton-sec/internal/infra/executor/docker"
	"github.com/bryanwahyu/automaton-sec/internal/infra/grpcserver"
	"github.com/bryanwahyu/automaton-sec/internal/infra/httpserver"
	minioStore "github.com/bryanwahyu/automaton-sec/internal/infra/storage"
	"github.com/bryanwahyu/automaton-sec/internal/middleware"
)

// Build information, injected with -ldflags -X at build time and reported by
// GET /version. The defaults are what a plain `go build` produces.
var (
	version   = "dev"
	commit    = ""
	buildDate = ""
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
	if cfg.Auth.Disabled {
		log.Printf("WARNING: auth.disabled is true — every endpoint is open. " +
			"Do not run this way outside local development.")
	}

	log.Printf("automaton-sec %s (commit=%s built=%s)", version, orNone(commit), orNone(buildDate))

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
		if err != nil {
			log.Fatalf("postgres connect error: %v", err)
		}
		repo = pgp.NewScanRepository(db)
		analystRepo = pgp.NewAnalystRepository(db)
		scanErrRepo = pgp.NewScanErrorRepository(db)
	default:
		var err error
		db, err = mysqlp.Connect(ctx, cfg.MySQLDSN())
		if err != nil {
			log.Fatalf("mysql connect error: %v", err)
		}
		repo = mysqlp.NewScanRepository(db)
		analystRepo = mysqlp.NewAnalystRepository(db)
		scanErrRepo = mysqlp.NewScanErrorRepository(db)
	}
	defer db.Close()

	// Connection pool limits: without them a burst of concurrent scans can
	// open an unbounded number of connections.
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetConnMaxIdleTime(2 * time.Minute)

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

	// The policy gates every value that reaches a scanner's command line.
	policy := scansdom.TargetPolicy{
		AllowPrivateTargets: cfg.Scanner.AllowPrivateTargets,
		AllowedHosts:        cfg.Scanner.AllowedHosts,
		WorkspaceRoot:       cfg.Scanner.WorkspaceRoot,
	}
	if policy.AllowPrivateTargets {
		log.Printf("WARNING: scanner.allowPrivateTargets is true — the API will scan " +
			"loopback, link-local and private addresses on request.")
	}

	// init runner
	runner := dockerrunner.NewRunner(policy)

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

	// Bound how many scanners run at once and how long each may take.
	pool := application.NewPool(cfg.Scanner.MaxConcurrent, cfg.Scanner.Timeout.Duration())
	log.Printf("scanner pool: max_concurrent=%d timeout=%s", pool.Capacity(), cfg.Scanner.Timeout.Duration())

	// init router
	mux := chi.NewRouter()
	mux.Mount("/", httpserver.NewRouter(httpserver.Deps{
		ScansSvc: scansSvc,
		AISvc:    aiSvc,
		ScanErrs: scanErrRepo,
		Pool:     pool,
		Policy:   policy,
		Auth: httpserver.AuthConfig{
			Disabled:       cfg.Auth.Disabled,
			WebhookHMACKey: []byte(cfg.Auth.WebhookHMACKey),
			APIKeys:        cfg.Auth.APIKeys,
		},
		Build: httpserver.BuildInfo{
			Version: version,
			Commit:  commit,
			Built:   buildDate,
		},
		ToolVersions:       runner.Versions,
		CORSOrigins:        cfg.CORS.AllowedOrigins,
		DBHealth:           &middleware.DatabaseHealthChecker{DB: db},
		RateLimitBurst:     cfg.RateLimit.Burst,
		RateLimitPerMinute: cfg.RateLimit.PerMinute,
	}))

	addr := fmt.Sprintf(":%d", cfg.Server.Port)
	srv := &http.Server{
		Addr:         addr,
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// run server
	go func() {
		log.Printf("server listening on %s", addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	// The gRPC API is served beside the HTTP one on its own port. It shares
	// every service, the scanner pool and the target policy with the router
	// above, so the two surfaces cannot answer differently.
	//
	// gRPC has no webhook-signature equivalent: the HTTP signature covers the
	// exact bytes of a request body, and a gRPC caller never handles those
	// bytes. It authenticates with API keys, and the signed webhook stays
	// HTTP-only.
	var (
		grpcSrv *grpc.Server
		grpcLis net.Listener
	)
	if cfg.Server.GRPCPort > 0 {
		grpcAddr := fmt.Sprintf(":%d", cfg.Server.GRPCPort)
		grpcLis, err = net.Listen("tcp", grpcAddr)
		if err != nil {
			log.Fatalf("grpc listen error: %v", err)
		}
		grpcSrv = grpcserver.New(grpcserver.Deps{
			ScansSvc: scansSvc,
			AISvc:    aiSvc,
			ScanErrs: scanErrRepo,
			Pool:     pool,
			Policy:   policy,
			Auth: grpcserver.AuthConfig{
				Disabled: cfg.Auth.Disabled,
				APIKeys:  cfg.Auth.APIKeys,
			},
			RateLimitBurst:     cfg.RateLimit.Burst,
			RateLimitPerMinute: cfg.RateLimit.PerMinute,
		})
		go func() {
			log.Printf("grpc server listening on %s", grpcAddr)
			if err := grpcSrv.Serve(grpcLis); err != nil && err != grpc.ErrServerStopped {
				log.Fatalf("grpc server error: %v", err)
			}
		}()
	} else {
		log.Printf("grpc server disabled (server.grpcPort=%d)", cfg.Server.GRPCPort)
	}

	// graceful shutdown
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop
	log.Println("shutting down server...")

	grace := cfg.Server.ShutdownGrace.Duration()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("http shutdown error: %v", err)
	}

	// GracefulStop lets in-flight RPCs — including a WatchScan stream — finish
	// before the listener closes. It is bounded by the same grace window as
	// everything else so a stuck stream cannot hold shutdown open forever.
	if grpcSrv != nil {
		stopped := make(chan struct{})
		go func() {
			grpcSrv.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-shutdownCtx.Done():
			log.Printf("grpc shutdown grace expired; forcing stop")
			grpcSrv.Stop()
		}
	}

	// srv.Shutdown only drains HTTP handlers; scans run detached from the
	// request that started them, so wait for the pool too.
	if n := pool.InFlight(); n > 0 {
		log.Printf("waiting up to %s for %d in-flight scan(s)...", grace, n)
	}
	if err := pool.Wait(shutdownCtx); err != nil {
		log.Printf("shutdown grace expired with %d scan(s) still running; "+
			"their rows stay at status=running and can be retried", pool.InFlight())
	}
	log.Println("shutdown complete")
}

// orNone keeps an unstamped build readable in the startup log.
func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}
