package platform

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pitercoding/aktenlens/backend/internal/platform/testdb"
)

// Postgres SQLSTATE codes we expect from the constraints.
const (
	uniqueViolation = "23505"
	checkViolation  = "23514"
)

// requireSQLState fails unless err is a Postgres error with the wanted code.
// Checking the code (not the message) proves WHICH rule rejected the row.
func requireSQLState(t *testing.T, err error, want string) {
	t.Helper()

	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) {
		t.Fatalf("expected postgres error %s, got %v", want, err)
	}
	if pgErr.Code != want {
		t.Fatalf("expected sql state %s, got %s (%s)", want, pgErr.Code, pgErr.Message)
	}
}

func insertTenant(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()

	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO tenants (name) VALUES ('Acme GmbH') RETURNING id`,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert tenant: %v", err)
	}

	return id
}

func insertUser(t *testing.T, pool *pgxpool.Pool, email string) string {
	t.Helper()

	var id string
	err := pool.QueryRow(context.Background(),
		`INSERT INTO users (email, password_hash) VALUES ($1, 'hash') RETURNING id`,
		email,
	).Scan(&id)
	if err != nil {
		t.Fatalf("insert user %q: %v", email, err)
	}

	return id
}

func countRows(t *testing.T, pool *pgxpool.Pool, table string) int {
	t.Helper()

	// table is always a literal from this file, never outside input.
	var n int
	err := pool.QueryRow(context.Background(), "SELECT count(*) FROM "+table).Scan(&n)
	if err != nil {
		t.Fatalf("count %s: %v", table, err)
	}

	return n
}

func TestAuthSchema(t *testing.T) {
	ctx := context.Background()

	t.Run("email must be unique", func(t *testing.T) {
		pool := testdb.NewPool(t)
		insertUser(t, pool, "alice@example.com")

		_, err := pool.Exec(ctx,
			`INSERT INTO users (email, password_hash) VALUES ('alice@example.com', 'hash')`)

		requireSQLState(t, err, uniqueViolation)
	})

	t.Run("email must be lowercase and trimmed", func(t *testing.T) {
		pool := testdb.NewPool(t)

		for _, email := range []string{"Alice@Example.com", " alice@example.com", ""} {
			_, err := pool.Exec(ctx,
				`INSERT INTO users (email, password_hash) VALUES ($1, 'hash')`, email)

			requireSQLState(t, err, checkViolation)
		}
	})

	t.Run("role must be owner, admin or member", func(t *testing.T) {
		pool := testdb.NewPool(t)
		tenantID := insertTenant(t, pool)
		userID := insertUser(t, pool, "alice@example.com")

		_, err := pool.Exec(ctx,
			`INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, 'superuser')`,
			userID, tenantID)

		requireSQLState(t, err, checkViolation)
	})

	t.Run("a user joins a tenant only once", func(t *testing.T) {
		pool := testdb.NewPool(t)
		tenantID := insertTenant(t, pool)
		userID := insertUser(t, pool, "alice@example.com")

		const q = `INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, 'owner')`
		if _, err := pool.Exec(ctx, q, userID, tenantID); err != nil {
			t.Fatalf("first membership: %v", err)
		}

		_, err := pool.Exec(ctx, q, userID, tenantID)

		requireSQLState(t, err, uniqueViolation)
	})

	t.Run("deleting a tenant removes its memberships but keeps the user", func(t *testing.T) {
		pool := testdb.NewPool(t)
		tenantID := insertTenant(t, pool)
		userID := insertUser(t, pool, "alice@example.com")

		_, err := pool.Exec(ctx,
			`INSERT INTO memberships (user_id, tenant_id, role) VALUES ($1, $2, 'owner')`,
			userID, tenantID)
		if err != nil {
			t.Fatalf("insert membership: %v", err)
		}

		if _, err := pool.Exec(ctx, `DELETE FROM tenants WHERE id = $1`, tenantID); err != nil {
			t.Fatalf("delete tenant: %v", err)
		}

		if n := countRows(t, pool, "memberships"); n != 0 {
			t.Fatalf("expected 0 memberships, got %d", n)
		}
		if n := countRows(t, pool, "users"); n != 1 {
			t.Fatalf("expected the user to survive, got %d users", n)
		}
	})

	t.Run("deleting a user removes their sessions", func(t *testing.T) {
		pool := testdb.NewPool(t)
		userID := insertUser(t, pool, "alice@example.com")

		_, err := pool.Exec(ctx,
			`INSERT INTO sessions (token_hash, user_id, expires_at)
			 VALUES ($1, $2, NOW() + interval '1 hour')`,
			make([]byte, 32), userID)
		if err != nil {
			t.Fatalf("insert session: %v", err)
		}

		if _, err := pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Fatalf("delete user: %v", err)
		}

		if n := countRows(t, pool, "sessions"); n != 0 {
			t.Fatalf("expected 0 sessions, got %d", n)
		}
	})

	t.Run("session token hash must be 32 bytes", func(t *testing.T) {
		pool := testdb.NewPool(t)
		userID := insertUser(t, pool, "alice@example.com")

		_, err := pool.Exec(ctx,
			`INSERT INTO sessions (token_hash, user_id, expires_at)
			 VALUES ($1, $2, NOW() + interval '1 hour')`,
			[]byte("plain-token"), userID)

		requireSQLState(t, err, checkViolation)
	})
}
