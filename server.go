package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	internalauth "github.com/adeilh/geminithreehackathon/internal/auth"
	"github.com/adeilh/geminithreehackathon/internal/videoassessment"
	"github.com/adeilh/geminithreehackathon/pkg/router"
	rredis "github.com/adeilh/go-rakh/cache/redis"
	"github.com/adeilh/go-rakh/httpx"
	"github.com/joho/godotenv"
	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"

	dbpg "github.com/adeilh/go-rakh/db/sql/postgres"
)

type serverConfig struct {
	address           string
	authSvc           *internalauth.Service
	assessmentService *videoassessment.Service
}

func parseDurationOrDefault(value string, def time.Duration) time.Duration {
	if value == "" {
		return def
	}
	d, err := time.ParseDuration(value)
	if err != nil {
		if num, errNum := strconv.Atoi(value); errNum == nil {
			return time.Duration(num) * time.Second
		}
		return def
	}
	return d
}

// buildAuthService creates the auth service from environment variables.
func buildAuthService(ctx context.Context) (*internalauth.Service, error) {
	_ = godotenv.Load(".env") // Adjust path as needed, ignore error if file not found in production
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		return nil, errors.New("JWT_SECRET is required")
	}

	pgDSN := os.Getenv("POSTGRES_DSN")
	if pgDSN == "" {
		return nil, errors.New("POSTGRES_DSN is required")
	}

	if err := runMigrations(ctx, pgDSN); err != nil {
		return nil, fmt.Errorf("run migrations: %w", err)
	}

	redisAddr := os.Getenv("REDIS_ADDR")
	if redisAddr == "" {
		redisAddr = "127.0.0.1:6379"
	}

	accessTTL := parseDurationOrDefault(os.Getenv("ACCESS_TOKEN_TTL"), time.Hour)
	sessionTTL := parseDurationOrDefault(os.Getenv("SESSION_TTL"), 24*time.Hour)

	cfg := internalauth.Config{
		PostgresDSN:    pgDSN,
		Redis:          rredis.Options{Addr: redisAddr, Password: os.Getenv("REDIS_PASSWORD")},
		JWTSecret:      jwtSecret,
		JWTAlgorithms:  []string{"HS256"},
		JWTIssuer:      "simulatorboss",
		JWTPrefix:      "",
		AccessTokenTTL: accessTTL,
		SessionPrefix:  "session",
		SessionTTL:     sessionTTL,
		BcryptCost:     0,
	}

	return internalauth.NewService(cfg)
}

func runMigrations(ctx context.Context, dsn string) error {
	db, err := dbpg.Connect(dbpg.WithDSN(dsn))
	if err != nil {
		return err
	}
	defer func(db *sql.DB) {
		err := db.Close()
		if err != nil {
			fmt.Printf("Failed to close database: %v\n", err)
		}
	}(db)

	if err := ensureDefaultMigrationFile("migrations"); err != nil {
		return err
	}

	stmts, err := loadMigrationStatements("migrations")
	if err != nil {
		return err
	}
	if len(stmts) == 0 {
		stmts = []string{defaultMigrationSQL}
	}

	return dbpg.Migrate(ctx, db, stmts...)
}

// buildAuthService creates the auth service from environment variables.
func buildAssessmentService(ctx context.Context) (*videoassessment.Service, error) {
	_ = godotenv.Load(".env") // Adjust path as needed, ignore error if file not found in production

	pgDSN := os.Getenv("POSTGRES_DSN")
	if pgDSN == "" {
		return nil, errors.New("POSTGRES_DSN is required")
	}
	db, err := sql.Open("postgres", pgDSN)
	if err != nil {
		return nil, err
	}

	cfg := videoassessment.Config{
		PostgresDSN:   pgDSN,
		Now:           time.Now,
		GeminiAPIKey:  os.Getenv("GEMINI_API_KEY"),
		GeminiBaseURL: os.Getenv("GEMINI_BASE_URL"),
		GeminiModel:   os.Getenv("GEMINI_MODEL"),
	}

	return videoassessment.NewService(cfg, db), nil
}

func ensureDefaultMigrationFile(dir string) error {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}

	migrationPath := filepath.Join(dir, "000_default_users.sql")
	body := strings.TrimSpace(defaultMigrationSQL) + "\n"
	return os.WriteFile(migrationPath, []byte(body), 0o644)
}

func loadMigrationStatements(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	var stmts []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".sql" {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		stmt := strings.TrimSpace(string(b))
		if stmt != "" {
			stmts = append(stmts, stmt)
		}
	}
	return stmts, nil
}

const defaultMigrationSQL = `
CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY,
    email CITEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    title TEXT NOT NULL,
    password_hash BYTEA NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT TRUE,
    metadata JSONB,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE UNIQUE INDEX IF NOT EXISTS users_email_lower_idx ON users (LOWER(email));`

func runServer() error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	authSvc, err := buildAuthService(ctx)
	if err != nil {
		return fmt.Errorf("build auth service: %w", err)
	}
	defer func(authSvc *internalauth.Service) {
		err := authSvc.Close()
		if err != nil {
			fmt.Printf("Failed to close auth service: %v\n", err)
		}
	}(authSvc)

	assessmentSvc, err := buildAssessmentService(ctx)
	if err != nil {
		return fmt.Errorf("build assessment service: %w", err)
	}
	defer func(assessmentSvc *videoassessment.Service) {
		err := assessmentSvc.Close()
		if err != nil {
			fmt.Printf("Failed to close assessment service: %v\n", err)
		}
	}(assessmentSvc)

	addr := os.Getenv("HTTP_ADDR")
	if addr == "" {
		addr = ":8080"
	}

	srv := newServer(serverConfig{
		address:           addr,
		authSvc:           authSvc,
		assessmentService: assessmentSvc,
	})

	if err := srv.Start(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	return nil
}

func newServer(cfg serverConfig) *httpx.Server {
	corsConfig := &middleware.CORSConfig{
		AllowOrigins:     []string{"http://localhost:8080", "http://127.0.0.1:8080", "http://localhost:5173", "https://cognifyv2-production.up.railway.app", "https://cognifyv2@daiode.com"},
		AllowMethods:     []string{echo.GET, echo.POST, echo.PUT, echo.DELETE, echo.OPTIONS},
		AllowHeaders:     []string{echo.HeaderOrigin, echo.HeaderContentType, echo.HeaderAccept, echo.HeaderAuthorization},
		AllowCredentials: true,
	}

	srv := httpx.NewServer(
		httpx.WithAddress(cfg.address),
		httpx.WithCORS(corsConfig),
	)

	if cfg.authSvc != nil {
		router.RegisterAuthDefault(srv, cfg.authSvc)
	}

	if cfg.assessmentService != nil {
		router.RegisterVideoAssessmentDefault(srv, cfg.assessmentService, cfg.authSvc)
	}

	return srv
}
