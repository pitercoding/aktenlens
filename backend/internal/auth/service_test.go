package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
	"github.com/pitercoding/aktenlens/backend/internal/platform/testdb"
	"github.com/pitercoding/aktenlens/backend/internal/store"
)

const validPassword = "correct-horse-battery" // 21 characters

func validInput() auth.RegisterInput {
	return auth.RegisterInput{
		TenantName: "Acme GmbH",
		Email:      "alice@example.com",
		Password:   validPassword,
	}
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

func TestRegister(t *testing.T) {
	ctx := context.Background()

	t.Run("creates tenant, user and owner membership", func(t *testing.T) {
		pool := testdb.NewPool(t)
		svc := auth.NewService(pool)

		got, err := svc.Register(ctx, validInput())
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if got.Email != "alice@example.com" || got.Role != "owner" {
			t.Fatalf("unexpected account: %+v", got)
		}

		q := store.New(pool)

		user, err := q.GetUserByEmail(ctx, "alice@example.com")
		if err != nil {
			t.Fatalf("get user: %v", err)
		}
		if user.ID != got.UserID {
			t.Fatalf("expected user id %s, got %s", got.UserID, user.ID)
		}

		// The password must be stored as an argon2id hash, never as text.
		if user.PasswordHash == validPassword {
			t.Fatal("password was stored in plain text")
		}
		ok, err := auth.VerifyPassword(validPassword, user.PasswordHash)
		if err != nil || !ok {
			t.Fatalf("stored hash does not verify: ok=%v err=%v", ok, err)
		}

		members, err := q.ListMembersByTenant(ctx, got.TenantID)
		if err != nil {
			t.Fatalf("list members: %v", err)
		}
		if len(members) != 1 || members[0].UserID != got.UserID || members[0].Role != "owner" {
			t.Fatalf("expected the user as the only owner, got %+v", members)
		}
	})

	t.Run("normalizes the e-mail", func(t *testing.T) {
		svc := auth.NewService(testdb.NewPool(t))

		in := validInput()
		in.Email = "  Alice@Example.COM "

		got, err := svc.Register(ctx, in)
		if err != nil {
			t.Fatalf("register: %v", err)
		}
		if got.Email != "alice@example.com" {
			t.Fatalf("expected a normalized e-mail, got %q", got.Email)
		}
	})

	t.Run("duplicate e-mail is rejected and leaves no orphan tenant", func(t *testing.T) {
		pool := testdb.NewPool(t)
		svc := auth.NewService(pool)

		if _, err := svc.Register(ctx, validInput()); err != nil {
			t.Fatalf("first register: %v", err)
		}

		second := validInput()
		second.Email = "ALICE@example.com" // same address, different case
		second.TenantName = "Other GmbH"

		_, err := svc.Register(ctx, second)
		if !errors.Is(err, auth.ErrEmailTaken) {
			t.Fatalf("expected ErrEmailTaken, got %v", err)
		}

		// The second tenant was inserted before the user failed, so it only
		// disappears if the whole signup ran in one transaction.
		if n := countRows(t, pool, "tenants"); n != 1 {
			t.Fatalf("expected 1 tenant (rollback), got %d", n)
		}
		if n := countRows(t, pool, "users"); n != 1 {
			t.Fatalf("expected 1 user, got %d", n)
		}
	})
}

func TestRegisterValidation(t *testing.T) {
	ctx := context.Background()
	pool := testdb.NewPool(t)
	svc := auth.NewService(pool)

	cases := []struct {
		name   string
		mutate func(*auth.RegisterInput)
		field  string
	}{
		{"empty e-mail", func(in *auth.RegisterInput) { in.Email = "" }, "email"},
		{"e-mail without @", func(in *auth.RegisterInput) { in.Email = "alice" }, "email"},
		{"e-mail without domain", func(in *auth.RegisterInput) { in.Email = "alice@" }, "email"},
		{"e-mail without local part", func(in *auth.RegisterInput) { in.Email = "@example.com" }, "email"},
		{"e-mail domain without dot", func(in *auth.RegisterInput) { in.Email = "alice@example" }, "email"},
		{"e-mail with display name", func(in *auth.RegisterInput) { in.Email = "Alice <alice@example.com>" }, "email"},
		{"e-mail with space", func(in *auth.RegisterInput) { in.Email = "a b@example.com" }, "email"},
		{"e-mail too long", func(in *auth.RegisterInput) { in.Email = strings.Repeat("a", 250) + "@example.com" }, "email"},

		{"password too short (11)", func(in *auth.RegisterInput) { in.Password = "short-pass1" }, "password"},
		// 11 letters but 22 bytes: proves length is counted in characters.
		{"password too short (11 multibyte)", func(in *auth.RegisterInput) { in.Password = strings.Repeat("ä", 11) }, "password"},
		{"password too long (129)", func(in *auth.RegisterInput) { in.Password = strings.Repeat("a", 129) }, "password"},

		{"empty tenant name", func(in *auth.RegisterInput) { in.TenantName = "" }, "tenant_name"},
		{"blank tenant name", func(in *auth.RegisterInput) { in.TenantName = "   " }, "tenant_name"},
		{"tenant name too long", func(in *auth.RegisterInput) { in.TenantName = strings.Repeat("a", 101) }, "tenant_name"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			in := validInput()
			tc.mutate(&in)

			_, err := svc.Register(ctx, in)

			var verr *auth.ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("expected *ValidationError, got %v", err)
			}
			if _, ok := verr.Fields[tc.field]; !ok {
				t.Fatalf("expected an error for field %q, got %v", tc.field, verr.Fields)
			}
		})
	}

	t.Run("reports every invalid field, not only the first", func(t *testing.T) {
		_, err := svc.Register(ctx, auth.RegisterInput{})

		var verr *auth.ValidationError
		if !errors.As(err, &verr) {
			t.Fatalf("expected *ValidationError, got %v", err)
		}
		for _, field := range []string{"email", "password", "tenant_name"} {
			if _, ok := verr.Fields[field]; !ok {
				t.Fatalf("expected an error for field %q, got %v", field, verr.Fields)
			}
		}
	})

	// Invalid input must be rejected before anything is written.
	if n := countRows(t, pool, "tenants"); n != 0 {
		t.Fatalf("validation failures created %d tenants", n)
	}
}
