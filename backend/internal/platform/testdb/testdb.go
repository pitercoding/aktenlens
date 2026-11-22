// Package testdb gives integration tests a real PostgreSQL (with pgvector)
// running in a throwaway Docker container.
//
// It must only be imported from _test.go files, so Docker is never needed to
// build or run the API.
package testdb

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	// Registers the "pgx" driver for database/sql. goose needs a *sql.DB.
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
)

var (
	// The container starts once per test binary (one package) and is shared.
	// Testcontainers' reaper removes it when the test process exits.
	startOnce sync.Once
	adminURL  string
	startErr  error

	// Makes every database name unique inside the shared container.
	dbCounter atomic.Int64
)

// NewPool returns a pool connected to a brand-new database that already has
// all migrations applied. The database is dropped when the test ends.
func NewPool(t *testing.T) *pgxpool.Pool {
	t.Helper()

	ctx := context.Background()

	startOnce.Do(func() {
		adminURL, startErr = startContainer(ctx)
	})
	if startErr != nil {
		t.Fatalf("start postgres container (is Docker running?): %v", startErr)
	}

	admin, err := pgxpool.New(ctx, adminURL)
	if err != nil {
		t.Fatalf("connect to admin database: %v", err)
	}
	// Registered first, so it runs last (t.Cleanup is LIFO): the test pool
	// closes, the database is dropped, and only then the admin pool closes.
	t.Cleanup(admin.Close)

	// Database names cannot be bound as query parameters. The name is built
	// only from a counter we control, never from outside input.
	name := fmt.Sprintf("test_%d", dbCounter.Add(1))
	if _, err := admin.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatalf("create database %s: %v", name, err)
	}
	t.Cleanup(func() {
		// WITH (FORCE) disconnects anyone still connected, so a leaked
		// connection in a test cannot make the drop fail.
		_, _ = admin.Exec(context.Background(),
			"DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
	})

	url, err := databaseURL(adminURL, name)
	if err != nil {
		t.Fatalf("build database url: %v", err)
	}

	if err := migrate(url); err != nil {
		t.Fatalf("run migrations: %v", err)
	}

	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("connect to %s: %v", name, err)
	}
	t.Cleanup(pool.Close)

	return pool
}

// startContainer boots Postgres and returns the connection URL of its default
// database. The image matches compose.yaml, so tests and dev use the same engine.
func startContainer(ctx context.Context) (string, error) {
	ctr, err := postgres.Run(ctx, "pgvector/pgvector:pg16",
		postgres.WithDatabase("postgres"),
		postgres.WithUsername("test"),
		postgres.WithPassword("test"),
		postgres.BasicWaitStrategies(),
	)
	if err != nil {
		return "", err
	}

	return ctr.ConnectionString(ctx, "sslmode=disable")
}

// databaseURL swaps the database name in a postgres:// URL.
func databaseURL(base, name string) (string, error) {
	cfg, err := pgxpool.ParseConfig(base)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable",
		cfg.ConnConfig.User,
		cfg.ConnConfig.Password,
		cfg.ConnConfig.Host,
		cfg.ConnConfig.Port,
		name,
	), nil
}

// migrate applies every file in backend/db/migrations with goose, the same
// tool and SQL used in production.
func migrate(url string) error {
	db, err := sql.Open("pgx", url)
	if err != nil {
		return err
	}
	// Nothing useful can be done if Close fails in a test helper.
	defer func() { _ = db.Close() }()

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	// A bounded context avoids hanging forever if the database misbehaves.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return goose.UpContext(ctx, db, migrationsDir())
}

// migrationsDir finds backend/db/migrations relative to this source file, so
// the tests work no matter which package's directory `go test` runs in.
func migrationsDir() string {
	_, file, _, _ := runtime.Caller(0)

	// file = .../backend/internal/platform/testdb/testdb.go
	return filepath.Join(filepath.Dir(file), "..", "..", "..", "db", "migrations")
}
