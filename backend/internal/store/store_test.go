package store_test

import (
	"bytes"
	"context"
	"errors"
	"maps"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/pitercoding/aktenlens/backend/internal/platform/testdb"
	"github.com/pitercoding/aktenlens/backend/internal/store"
)

func newTenant(t *testing.T, q *store.Queries, name string) store.Tenant {
	t.Helper()

	tenant, err := q.CreateTenant(context.Background(), name)
	if err != nil {
		t.Fatalf("create tenant: %v", err)
	}

	return tenant
}

// newMember creates a user and adds it to the tenant with the given role.
func newMember(
	t *testing.T,
	q *store.Queries,
	tenantID uuid.UUID,
	email, role string,
) store.User {
	t.Helper()
	ctx := context.Background()

	user, err := q.CreateUser(ctx, store.CreateUserParams{
		Email:        email,
		PasswordHash: "hash",
	})
	if err != nil {
		t.Fatalf("create user %s: %v", email, err)
	}

	err = q.CreateMembership(ctx, store.CreateMembershipParams{
		UserID:   user.ID,
		TenantID: tenantID,
		Role:     role,
	})
	if err != nil {
		t.Fatalf("create membership for %s: %v", email, err)
	}

	return user
}

func TestGetUserByEmail(t *testing.T) {
	ctx := context.Background()

	t.Run("finds an existing user", func(t *testing.T) {
		q := store.New(testdb.NewPool(t))

		created, err := q.CreateUser(ctx, store.CreateUserParams{
			Email:        "alice@example.com",
			PasswordHash: "hash",
		})
		if err != nil {
			t.Fatalf("create user: %v", err)
		}

		got, err := q.GetUserByEmail(ctx, "alice@example.com")
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		if got.ID != created.ID {
			t.Fatalf("expected id %s, got %s", created.ID, got.ID)
		}
	})

	t.Run("unknown e-mail returns pgx.ErrNoRows", func(t *testing.T) {
		q := store.New(testdb.NewPool(t))

		_, err := q.GetUserByEmail(ctx, "nobody@example.com")

		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expected pgx.ErrNoRows, got %v", err)
		}
	})
}

func TestListMembersByTenant(t *testing.T) {
	ctx := context.Background()
	q := store.New(testdb.NewPool(t))

	tenantA := newTenant(t, q, "Tenant A")
	tenantB := newTenant(t, q, "Tenant B")
	newMember(t, q, tenantA.ID, "alice@example.com", "owner")
	newMember(t, q, tenantA.ID, "carol@example.com", "member")
	newMember(t, q, tenantB.ID, "bob@example.com", "owner")

	// roles maps e-mail -> role, so the check does not depend on row order.
	roles := func(tenantID uuid.UUID) map[string]string {
		members, err := q.ListMembersByTenant(ctx, tenantID)
		if err != nil {
			t.Fatalf("list members: %v", err)
		}

		got := make(map[string]string, len(members))
		for _, m := range members {
			got[m.Email] = m.Role
		}

		return got
	}

	// Tenant isolation: each tenant sees only its own people.
	wantA := map[string]string{"alice@example.com": "owner", "carol@example.com": "member"}
	if got := roles(tenantA.ID); !maps.Equal(got, wantA) {
		t.Fatalf("tenant A: expected %v, got %v", wantA, got)
	}

	wantB := map[string]string{"bob@example.com": "owner"}
	if got := roles(tenantB.ID); !maps.Equal(got, wantB) {
		t.Fatalf("tenant B: expected %v, got %v", wantB, got)
	}
}

func TestGetSessionPrincipal(t *testing.T) {
	ctx := context.Background()

	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	tokenHash := bytes.Repeat([]byte{0xAB}, 32)

	// setup creates one admin user with a session that expires at expiresAt.
	setup := func(t *testing.T, expiresAt time.Time) (*store.Queries, store.GetSessionPrincipalRow) {
		t.Helper()

		q := store.New(testdb.NewPool(t))
		tenant := newTenant(t, q, "Acme GmbH")
		user := newMember(t, q, tenant.ID, "alice@example.com", "admin")

		err := q.CreateSession(ctx, store.CreateSessionParams{
			TokenHash: tokenHash,
			UserID:    user.ID,
			ExpiresAt: expiresAt,
		})
		if err != nil {
			t.Fatalf("create session: %v", err)
		}

		return q, store.GetSessionPrincipalRow{
			UserID:   user.ID,
			Email:    "alice@example.com",
			TenantID: tenant.ID,
			Role:     "admin",
		}
	}

	t.Run("valid session returns user, tenant and role", func(t *testing.T) {
		q, want := setup(t, now.Add(time.Hour))

		got, err := q.GetSessionPrincipal(ctx, store.GetSessionPrincipalParams{
			TokenHash: tokenHash,
			Now:       now,
		})
		if err != nil {
			t.Fatalf("get principal: %v", err)
		}
		if got != want {
			t.Fatalf("expected %+v, got %+v", want, got)
		}
	})

	t.Run("expired session is not found", func(t *testing.T) {
		q, _ := setup(t, now.Add(-time.Second))

		_, err := q.GetSessionPrincipal(ctx, store.GetSessionPrincipalParams{
			TokenHash: tokenHash,
			Now:       now,
		})

		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expected pgx.ErrNoRows, got %v", err)
		}
	})

	t.Run("unknown token is not found", func(t *testing.T) {
		q, _ := setup(t, now.Add(time.Hour))

		_, err := q.GetSessionPrincipal(ctx, store.GetSessionPrincipalParams{
			TokenHash: bytes.Repeat([]byte{0xCD}, 32),
			Now:       now,
		})

		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expected pgx.ErrNoRows, got %v", err)
		}
	})

	t.Run("deleted session is not found (logout)", func(t *testing.T) {
		q, _ := setup(t, now.Add(time.Hour))

		if err := q.DeleteSession(ctx, tokenHash); err != nil {
			t.Fatalf("delete session: %v", err)
		}

		_, err := q.GetSessionPrincipal(ctx, store.GetSessionPrincipalParams{
			TokenHash: tokenHash,
			Now:       now,
		})

		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expected pgx.ErrNoRows, got %v", err)
		}
	})
}
