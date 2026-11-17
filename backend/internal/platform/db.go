package platform

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrMissingDatabaseURL is returned when DATABASE_URL is empty, so the API
// stops at startup with a clear message instead of failing later.
var ErrMissingDatabaseURL = errors.New("DATABASE_URL is not set")

// NewDBPool creates the PostgreSQL connection pool. It does not connect:
// connections are opened on first use (see the /readyz handler).
func NewDBPool(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	if databaseURL == "" {
		return nil, ErrMissingDatabaseURL
	}

	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		// Wrap the error without printing databaseURL: it contains the password.
		return nil, fmt.Errorf("create database pool: %w", err)
	}

	return pool, nil
}
