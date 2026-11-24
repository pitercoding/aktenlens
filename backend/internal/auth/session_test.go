package auth_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
	"github.com/pitercoding/aktenlens/backend/internal/platform/testdb"
)

// sessionTTL pins the contract: sessions last 7 days.
const sessionTTL = 7 * 24 * time.Hour

// fakeClock lets tests move time forward without sleeping.
type fakeClock struct{ now time.Time }

func (c *fakeClock) Now() time.Time          { return c.now }
func (c *fakeClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

// newTestService returns a service on a fresh database, driven by a fake clock.
func newTestService(t *testing.T) (*auth.Service, *fakeClock, *pgxpool.Pool) {
	t.Helper()

	pool := testdb.NewPool(t)
	clock := &fakeClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}

	return auth.NewService(pool, auth.WithClock(clock.Now)), clock, pool
}

// register creates an account (with its own tenant) using validPassword.
func register(t *testing.T, svc *auth.Service, email string) auth.Account {
	t.Helper()

	account, err := svc.Register(context.Background(), auth.RegisterInput{
		TenantName: "Tenant of " + email,
		Email:      email,
		Password:   validPassword,
	})
	if err != nil {
		t.Fatalf("register %s: %v", email, err)
	}

	return account
}

// login signs in with validPassword and returns the session.
func login(t *testing.T, svc *auth.Service, email string) auth.Session {
	t.Helper()

	session, err := svc.Login(context.Background(), auth.LoginInput{
		Email:    email,
		Password: validPassword,
	})
	if err != nil {
		t.Fatalf("login %s: %v", email, err)
	}

	return session
}

func TestLogin(t *testing.T) {
	ctx := context.Background()

	t.Run("valid credentials create a session that expires in 7 days", func(t *testing.T) {
		svc, clock, pool := newTestService(t)
		register(t, svc, "alice@example.com")

		got := login(t, svc, "alice@example.com")

		if got.Token == "" {
			t.Fatal("expected a token")
		}
		if want := clock.now.Add(sessionTTL); !got.ExpiresAt.Equal(want) {
			t.Fatalf("expected expiry %v, got %v", want, got.ExpiresAt)
		}

		// The database keeps the hash of the token, found by that hash.
		var n int
		err := pool.QueryRow(ctx,
			`SELECT count(*) FROM sessions WHERE token_hash = $1`,
			auth.HashSessionToken(got.Token),
		).Scan(&n)
		if err != nil {
			t.Fatalf("query session: %v", err)
		}
		if n != 1 {
			t.Fatalf("expected 1 stored session for this token hash, got %d", n)
		}
	})

	t.Run("normalizes the e-mail", func(t *testing.T) {
		svc, _, _ := newTestService(t)
		register(t, svc, "alice@example.com")

		_, err := svc.Login(ctx, auth.LoginInput{
			Email:    "  ALICE@Example.com ",
			Password: validPassword,
		})

		if err != nil {
			t.Fatalf("expected login to work, got %v", err)
		}
	})

	t.Run("wrong password and unknown e-mail give the same error", func(t *testing.T) {
		svc, _, pool := newTestService(t)
		register(t, svc, "alice@example.com")

		_, wrongPassword := svc.Login(ctx, auth.LoginInput{
			Email:    "alice@example.com",
			Password: "this-is-not-the-password",
		})
		_, unknownEmail := svc.Login(ctx, auth.LoginInput{
			Email:    "nobody@example.com",
			Password: validPassword,
		})

		if !errors.Is(wrongPassword, auth.ErrInvalidCredentials) {
			t.Fatalf("wrong password: expected ErrInvalidCredentials, got %v", wrongPassword)
		}
		if !errors.Is(unknownEmail, auth.ErrInvalidCredentials) {
			t.Fatalf("unknown e-mail: expected ErrInvalidCredentials, got %v", unknownEmail)
		}
		// Nothing may reveal which of the two happened.
		if wrongPassword.Error() != unknownEmail.Error() {
			t.Fatalf("errors differ: %q vs %q", wrongPassword, unknownEmail)
		}

		if n := countRows(t, pool, "sessions"); n != 0 {
			t.Fatalf("failed logins created %d sessions", n)
		}
	})

	t.Run("oversized input is rejected as invalid credentials", func(t *testing.T) {
		svc, _, _ := newTestService(t)
		register(t, svc, "alice@example.com")

		_, err := svc.Login(ctx, auth.LoginInput{
			Email:    "alice@example.com",
			Password: strings.Repeat("a", 1000),
		})

		if !errors.Is(err, auth.ErrInvalidCredentials) {
			t.Fatalf("expected ErrInvalidCredentials, got %v", err)
		}
	})

	t.Run("each login creates its own session", func(t *testing.T) {
		svc, _, pool := newTestService(t)
		register(t, svc, "alice@example.com")

		first := login(t, svc, "alice@example.com")
		second := login(t, svc, "alice@example.com")

		if first.Token == second.Token {
			t.Fatal("expected different tokens for different logins")
		}
		if n := countRows(t, pool, "sessions"); n != 2 {
			t.Fatalf("expected 2 sessions (two devices), got %d", n)
		}
	})
}

func TestAuthenticate(t *testing.T) {
	ctx := context.Background()

	t.Run("a valid session resolves to the account", func(t *testing.T) {
		svc, _, _ := newTestService(t)
		want := register(t, svc, "alice@example.com")
		session := login(t, svc, "alice@example.com")

		got, err := svc.Authenticate(ctx, session.Token)
		if err != nil {
			t.Fatalf("authenticate: %v", err)
		}
		if got != want {
			t.Fatalf("expected %+v, got %+v", want, got)
		}
	})

	t.Run("each session resolves to its own tenant", func(t *testing.T) {
		svc, _, _ := newTestService(t)
		alice := register(t, svc, "alice@example.com")
		bob := register(t, svc, "bob@example.com")
		aliceSession := login(t, svc, "alice@example.com")
		bobSession := login(t, svc, "bob@example.com")

		gotAlice, err := svc.Authenticate(ctx, aliceSession.Token)
		if err != nil {
			t.Fatalf("authenticate alice: %v", err)
		}
		gotBob, err := svc.Authenticate(ctx, bobSession.Token)
		if err != nil {
			t.Fatalf("authenticate bob: %v", err)
		}

		if gotAlice.TenantID != alice.TenantID || gotBob.TenantID != bob.TenantID {
			t.Fatalf("tenants mixed up: alice=%+v bob=%+v", gotAlice, gotBob)
		}
		if gotAlice.TenantID == gotBob.TenantID {
			t.Fatal("alice and bob must belong to different tenants")
		}
	})

	t.Run("the session stops working exactly when it expires", func(t *testing.T) {
		svc, clock, _ := newTestService(t)
		register(t, svc, "alice@example.com")
		session := login(t, svc, "alice@example.com")

		clock.Advance(sessionTTL - time.Second)
		if _, err := svc.Authenticate(ctx, session.Token); err != nil {
			t.Fatalf("one second before expiry it must still work, got %v", err)
		}

		clock.Advance(time.Second) // now == expires_at
		_, err := svc.Authenticate(ctx, session.Token)
		if !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("at expiry expected ErrUnauthenticated, got %v", err)
		}
	})

	t.Run("unknown and empty tokens are not authenticated", func(t *testing.T) {
		svc, _, _ := newTestService(t)
		register(t, svc, "alice@example.com")
		login(t, svc, "alice@example.com")

		for _, token := range []string{"", "not-a-real-token"} {
			_, err := svc.Authenticate(ctx, token)

			if !errors.Is(err, auth.ErrUnauthenticated) {
				t.Fatalf("token %q: expected ErrUnauthenticated, got %v", token, err)
			}
		}
	})

	t.Run("an unknown role in the database is a server error, not a login", func(t *testing.T) {
		svc, _, pool := newTestService(t)
		register(t, svc, "alice@example.com")
		session := login(t, svc, "alice@example.com")

		// Simulate corrupted data. The CHECK constraint normally makes this
		// impossible, so it is dropped just for this test database.
		_, err := pool.Exec(ctx, `ALTER TABLE memberships DROP CONSTRAINT memberships_role_valid`)
		if err != nil {
			t.Fatalf("drop constraint: %v", err)
		}
		if _, err = pool.Exec(ctx, `UPDATE memberships SET role = 'superuser'`); err != nil {
			t.Fatalf("corrupt role: %v", err)
		}

		_, err = svc.Authenticate(ctx, session.Token)

		if err == nil || errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("expected an internal error, got %v", err)
		}
	})
}

func TestLogout(t *testing.T) {
	ctx := context.Background()

	t.Run("the session stops working on the server", func(t *testing.T) {
		svc, _, _ := newTestService(t)
		register(t, svc, "alice@example.com")
		session := login(t, svc, "alice@example.com")

		if err := svc.Logout(ctx, session.Token); err != nil {
			t.Fatalf("logout: %v", err)
		}

		_, err := svc.Authenticate(ctx, session.Token)
		if !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("expected ErrUnauthenticated after logout, got %v", err)
		}
	})

	t.Run("is idempotent", func(t *testing.T) {
		svc, _, _ := newTestService(t)
		register(t, svc, "alice@example.com")
		session := login(t, svc, "alice@example.com")

		for range 2 {
			if err := svc.Logout(ctx, session.Token); err != nil {
				t.Fatalf("logout: %v", err)
			}
		}
		if err := svc.Logout(ctx, "never-existed"); err != nil {
			t.Fatalf("logout with an unknown token: %v", err)
		}
	})

	t.Run("ends only that session, not the other devices", func(t *testing.T) {
		svc, _, _ := newTestService(t)
		register(t, svc, "alice@example.com")
		phone := login(t, svc, "alice@example.com")
		laptop := login(t, svc, "alice@example.com")

		if err := svc.Logout(ctx, phone.Token); err != nil {
			t.Fatalf("logout: %v", err)
		}

		if _, err := svc.Authenticate(ctx, laptop.Token); err != nil {
			t.Fatalf("the other session must keep working, got %v", err)
		}
	})
}
