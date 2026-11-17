package platform

import (
	"context"
	"errors"
	"testing"
)

func TestNewDBPool(t *testing.T) {
	t.Run("empty url", func(t *testing.T) {
		_, err := NewDBPool(context.Background(), "")

		if !errors.Is(err, ErrMissingDatabaseURL) {
			t.Fatalf("expected ErrMissingDatabaseURL, got %v", err)
		}
	})

	t.Run("invalid url", func(t *testing.T) {
		if _, err := NewDBPool(context.Background(), "not a url"); err == nil {
			t.Fatal("expected an error for an invalid url")
		}
	})

	// New does not connect: the pool opens connections lazily. This is why
	// the API can start while the database is down and /readyz reports it.
	t.Run("valid url does not need a running database", func(t *testing.T) {
		pool, err := NewDBPool(
			context.Background(),
			"postgres://user:pass@127.0.0.1:1/db?sslmode=disable",
		)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		pool.Close()
	})
}
