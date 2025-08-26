package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bryanwahyu/automaton-sec/internal/application"
	appscans "github.com/bryanwahyu/automaton-sec/internal/application/scans"
	"github.com/bryanwahyu/automaton-sec/internal/config"
	mysqlp "github.com/bryanwahyu/automaton-sec/internal/infra/db/mysql"
	dockerrunner "github.com/bryanwahyu/automaton-sec/internal/infra/executor/docker"
	"github.com/bryanwahyu/automaton-sec/internal/infra/httpserver"
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

	// connect MySQL
	db, err := mysqlp.Connect(ctx, cfg.MySQLDSN())
	if err != nil {
		log.Fatalf("mysql connect error: %v", err)
	}
	defer db.Close()

	// init repo
	repo := mysqlp.NewScanRepository(db)

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

	// init service
	svc := &appscans.Service{
		Repo:      repo,
		Runner:    runner,
		Artifacts: store,
		Clock:     application.SystemClock{},
	}

	// init router
	mux := chi.NewRouter()
	mux.Mount("/", httpserver.NewRouter(svc, nil))

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
