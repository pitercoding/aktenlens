package member_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"maps"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
	"github.com/pitercoding/aktenlens/backend/internal/member"
	"github.com/pitercoding/aktenlens/backend/internal/platform/testdb"
	"github.com/pitercoding/aktenlens/backend/internal/store"
	"github.com/pitercoding/aktenlens/backend/internal/tenant"
)

const password = "correct-horse-battery"

// world is two companies, each with people of different roles:
//
//	Tenant A: alice (owner), carol (member)
//	Tenant B: bob (owner),   dave (admin)
//
// The tokens are real sessions, created through the auth service.
type world struct {
	mux     http.Handler
	pool    *pgxpool.Pool
	tenantA uuid.UUID
	tenantB uuid.UUID
	alice   string
	carol   string
	bob     string
	dave    string
}

func newWorld(t *testing.T) world {
	t.Helper()
	ctx := context.Background()

	pool := testdb.NewPool(t)
	svc := auth.NewService(pool)
	q := store.New(pool)

	register := func(email, company string) auth.Account {
		account, err := svc.Register(ctx, auth.RegisterInput{
			TenantName: company,
			Email:      email,
			Password:   password,
		})
		if err != nil {
			t.Fatalf("register %s: %v", email, err)
		}

		return account
	}

	// The service has no "invite" yet, so extra people are added directly.
	addMember := func(tenantID uuid.UUID, email string, role tenant.Role) {
		hash, err := auth.HashPassword(password)
		if err != nil {
			t.Fatalf("hash password: %v", err)
		}

		user, err := q.CreateUser(ctx, store.CreateUserParams{Email: email, PasswordHash: hash})
		if err != nil {
			t.Fatalf("create user %s: %v", email, err)
		}

		err = q.CreateMembership(ctx, store.CreateMembershipParams{
			UserID:   user.ID,
			TenantID: tenantID,
			Role:     string(role),
		})
		if err != nil {
			t.Fatalf("create membership for %s: %v", email, err)
		}
	}

	login := func(email string) string {
		session, err := svc.Login(ctx, auth.LoginInput{Email: email, Password: password})
		if err != nil {
			t.Fatalf("login %s: %v", email, err)
		}

		return session.Token
	}

	a := register("alice@example.com", "Tenant A")
	b := register("bob@example.com", "Tenant B")
	addMember(a.TenantID, "carol@example.com", tenant.RoleMember)
	addMember(b.TenantID, "dave@example.com", tenant.RoleAdmin)

	mux := http.NewServeMux()
	member.NewHandler(svc, q).RegisterRoutes(mux)

	return world{
		mux:     mux,
		pool:    pool,
		tenantA: a.TenantID,
		tenantB: b.TenantID,
		alice:   login("alice@example.com"),
		carol:   login("carol@example.com"),
		bob:     login("bob@example.com"),
		dave:    login("dave@example.com"),
	}
}

// get calls the API. An empty token means no cookie. headers are extra
// request headers, used to try to cheat.
func get(h http.Handler, target, token string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, target, nil)
	if token != "" {
		req.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	}
	for key, value := range headers {
		req.Header.Set(key, value)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

// rolesByEmail reads a members response as a map: e-mail -> role.
func rolesByEmail(t *testing.T, rec *httptest.ResponseRecorder) map[string]string {
	t.Helper()

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}

	var body struct {
		Members []struct {
			Email string `json:"email"`
			Role  string `json:"role"`
		} `json:"members"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not the expected JSON: %v (%s)", err, rec.Body.String())
	}

	got := make(map[string]string, len(body.Members))
	for _, m := range body.Members {
		got[m.Email] = m.Role
	}

	return got
}

func TestListMembers(t *testing.T) {
	const path = "/api/v1/members"
	w := newWorld(t)

	t.Run("an owner sees the members of their own tenant", func(t *testing.T) {
		got := rolesByEmail(t, get(w.mux, path, w.alice, nil))

		want := map[string]string{"alice@example.com": "owner", "carol@example.com": "member"}
		if !maps.Equal(got, want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
	})

	t.Run("an admin sees the members of their own tenant", func(t *testing.T) {
		got := rolesByEmail(t, get(w.mux, path, w.dave, nil))

		want := map[string]string{"bob@example.com": "owner", "dave@example.com": "admin"}
		if !maps.Equal(got, want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
	})

	t.Run("exposes only user_id, email, role and joined_at", func(t *testing.T) {
		rec := get(w.mux, path, w.alice, nil)

		var body struct {
			Members []map[string]any `json:"members"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if len(body.Members) == 0 {
			t.Fatal("expected members")
		}

		for _, m := range body.Members {
			if len(m) != 4 {
				t.Fatalf("expected exactly 4 fields, got %v", m)
			}
			for _, key := range []string{"user_id", "email", "role", "joined_at"} {
				if _, ok := m[key]; !ok {
					t.Fatalf("missing field %q in %v", key, m)
				}
			}
		}
		if strings.Contains(rec.Body.String(), "argon2") {
			t.Fatal("a password hash leaked into the response")
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("expected Cache-Control no-store, got %q", cc)
		}
	})

	t.Run("a plain member is forbidden", func(t *testing.T) {
		rec := get(w.mux, path, w.carol, nil)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
	})

	t.Run("without a session it is unauthorized", func(t *testing.T) {
		for _, token := range []string{"", "not-a-real-token"} {
			if rec := get(w.mux, path, token, nil); rec.Code != http.StatusUnauthorized {
				t.Fatalf("token %q: expected 401, got %d", token, rec.Code)
			}
		}
	})
}

// These tests are the point of multi-tenancy: whatever the client sends, it
// only ever sees its own tenant.
func TestTenantIsolation(t *testing.T) {
	const path = "/api/v1/members"

	t.Run("the tenant cannot be chosen by the client", func(t *testing.T) {
		w := newWorld(t)
		wantA := map[string]string{"alice@example.com": "owner", "carol@example.com": "member"}

		// Alice (tenant A) tries every way to ask for tenant B.
		attempts := []struct {
			name    string
			target  string
			headers map[string]string
		}{
			{"query string", path + "?tenant_id=" + w.tenantB.String(), nil},
			{"camelCase query string", path + "?tenantId=" + w.tenantB.String(), nil},
			{"X-Tenant-ID header", path, map[string]string{"X-Tenant-ID": w.tenantB.String()}},
			{"Tenant-ID header", path, map[string]string{"Tenant-ID": w.tenantB.String()}},
		}

		for _, attempt := range attempts {
			got := rolesByEmail(t, get(w.mux, attempt.target, w.alice, attempt.headers))

			if !maps.Equal(got, wantA) {
				t.Fatalf("%s: tenant A user saw %v", attempt.name, got)
			}
		}
	})

	t.Run("two tenants never see each other", func(t *testing.T) {
		w := newWorld(t)

		a := rolesByEmail(t, get(w.mux, path, w.alice, nil))
		b := rolesByEmail(t, get(w.mux, path, w.bob, nil))

		for email := range a {
			if _, leaked := b[email]; leaked {
				t.Fatalf("%s appears in both tenants", email)
			}
		}
	})

	t.Run("a demoted admin loses access on the very next request", func(t *testing.T) {
		w := newWorld(t)

		if rec := get(w.mux, path, w.alice, nil); rec.Code != http.StatusOK {
			t.Fatalf("before the change: expected 200, got %d", rec.Code)
		}

		// The role is read from the database on every request, never frozen in
		// the session, so a demotion applies immediately.
		_, err := w.pool.Exec(context.Background(),
			`UPDATE memberships SET role = 'member' WHERE tenant_id = $1 AND role = 'owner'`,
			w.tenantA)
		if err != nil {
			t.Fatalf("demote: %v", err)
		}

		if rec := get(w.mux, path, w.alice, nil); rec.Code != http.StatusForbidden {
			t.Fatalf("after the change: expected 403, got %d", rec.Code)
		}
	})
}

// failingMembers simulates a broken database.
type failingMembers struct{}

const secretDetail = "pq: password authentication failed for user app at 10.0.0.5"

func (failingMembers) ListMembersByTenant(context.Context, uuid.UUID) ([]store.ListMembersByTenantRow, error) {
	return nil, errors.New(secretDetail)
}

// adminAuthenticator accepts any token and says the caller is an admin.
type adminAuthenticator struct{}

func (adminAuthenticator) Authenticate(context.Context, string) (auth.Account, error) {
	return auth.Account{UserID: uuid.New(), TenantID: uuid.New(), Email: "x@example.com", Role: tenant.RoleAdmin}, nil
}

func TestListMembersHidesInternalErrors(t *testing.T) {
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	mux := http.NewServeMux()
	member.NewHandler(adminAuthenticator{}, failingMembers{}).RegisterRoutes(mux)

	rec := get(mux, "/api/v1/members", "any-token", nil)

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("internal error leaked to the client: %s", rec.Body.String())
	}
}
