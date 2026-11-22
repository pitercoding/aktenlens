package testdb_test

import (
	"context"
	"testing"

	"github.com/pitercoding/aktenlens/backend/internal/platform/testdb"
)

func TestNewPool(t *testing.T) {
	ctx := context.Background()

	t.Run("applies the migrations", func(t *testing.T) {
		pool := testdb.NewPool(t)

		// to_regclass returns NULL when the table does not exist.
		var exists bool
		err := pool.QueryRow(ctx,
			"SELECT to_regclass('public.tenants') IS NOT NULL",
		).Scan(&exists)
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		if !exists {
			t.Fatal("expected table tenants to exist after migrations")
		}
	})

	t.Run("each call gets an isolated database", func(t *testing.T) {
		poolA := testdb.NewPool(t)
		poolB := testdb.NewPool(t)

		_, err := poolA.Exec(ctx, "INSERT INTO tenants (name) VALUES ('only in A')")
		if err != nil {
			t.Fatalf("insert failed: %v", err)
		}

		var count int
		err = poolB.QueryRow(ctx, "SELECT count(*) FROM tenants").Scan(&count)
		if err != nil {
			t.Fatalf("count failed: %v", err)
		}
		if count != 0 {
			t.Fatalf("expected database B to be empty, got %d tenants", count)
		}
	})
}
