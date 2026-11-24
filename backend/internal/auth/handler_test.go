package auth_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
	"github.com/pitercoding/aktenlens/backend/internal/platform"
)

const (
	registerBody = `{"tenant_name":"Acme GmbH","email":"alice@example.com","password":"correct-horse-battery"}`
	loginBody    = `{"email":"alice@example.com","password":"correct-horse-battery"}`
)

// env bundles everything an endpoint test needs.
type env struct {
	mux   http.Handler
	svc   *auth.Service
	clock *fakeClock
	pool  *pgxpool.Pool
}

// newEnv wires the real service (fresh database, fake clock) to the handlers.
func newEnv(t *testing.T, secureCookies bool) env {
	t.Helper()

	svc, clock, pool := newTestService(t)

	mux := http.NewServeMux()
	auth.NewHandler(svc, secureCookies).RegisterRoutes(mux)

	return env{mux: mux, svc: svc, clock: clock, pool: pool}
}

func postJSON(
	h http.Handler,
	path, body string,
	cookies ...*http.Cookie,
) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func sessionCookie(rec *httptest.ResponseRecorder) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName {
			return c
		}
	}

	return nil
}

func decodeMap(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("body is not JSON: %v (%q)", err, rec.Body.String())
	}

	return body
}

func TestRegisterEndpoint(t *testing.T) {
	const path = "/api/v1/auth/register"

	t.Run("creates the account and returns it without secrets", func(t *testing.T) {
		e := newEnv(t, true)

		rec := postJSON(e.mux, path, registerBody)

		if rec.Code != http.StatusCreated {
			t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
		}

		body := decodeMap(t, rec)
		for _, key := range []string{"user_id", "tenant_id"} {
			id, _ := body[key].(string)
			if _, err := uuid.Parse(id); err != nil {
				t.Fatalf("%s is not a UUID: %v", key, body[key])
			}
		}
		if body["email"] != "alice@example.com" || body["role"] != "owner" {
			t.Fatalf("unexpected body: %v", body)
		}
		// Exactly these four fields: no password, no hash, nothing else.
		if len(body) != 4 {
			t.Fatalf("expected 4 fields, got %v", body)
		}
		// Registering does not log the user in.
		if sessionCookie(rec) != nil {
			t.Fatal("register must not set a session cookie")
		}
	})

	t.Run("invalid data answers 422 with the invalid fields", func(t *testing.T) {
		e := newEnv(t, true)

		rec := postJSON(e.mux, path, `{"tenant_name":"","email":"nope","password":"short"}`)

		if rec.Code != http.StatusUnprocessableEntity {
			t.Fatalf("expected 422, got %d", rec.Code)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("unexpected content type %q", ct)
		}

		fields, _ := decodeMap(t, rec)["errors"].(map[string]any)
		for _, field := range []string{"email", "password", "tenant_name"} {
			if _, ok := fields[field]; !ok {
				t.Fatalf("expected an error for %q, got %v", field, fields)
			}
		}
	})

	t.Run("duplicate e-mail answers 409", func(t *testing.T) {
		e := newEnv(t, true)
		postJSON(e.mux, path, registerBody)

		rec := postJSON(e.mux, path, registerBody)

		if rec.Code != http.StatusConflict {
			t.Fatalf("expected 409, got %d", rec.Code)
		}
	})

	// A client must not be able to choose its own role.
	t.Run("an unknown field such as role is rejected", func(t *testing.T) {
		e := newEnv(t, true)

		rec := postJSON(e.mux, path,
			`{"tenant_name":"Acme","email":"alice@example.com","password":"correct-horse-battery","role":"admin"}`)

		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", rec.Code)
		}
		if n := countRows(t, e.pool, "users"); n != 0 {
			t.Fatalf("a rejected request created %d users", n)
		}
	})

	t.Run("a non-JSON content type answers 415", func(t *testing.T) {
		e := newEnv(t, true)

		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(registerBody))
		req.Header.Set("Content-Type", "text/plain")
		rec := httptest.NewRecorder()
		e.mux.ServeHTTP(rec, req)

		if rec.Code != http.StatusUnsupportedMediaType {
			t.Fatalf("expected 415, got %d", rec.Code)
		}
	})
}

func TestLoginEndpoint(t *testing.T) {
	const path = "/api/v1/auth/login"

	t.Run("sets a hardened session cookie and answers 204", func(t *testing.T) {
		e := newEnv(t, true)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)

		rec := postJSON(e.mux, path, loginBody)

		if rec.Code != http.StatusNoContent || rec.Body.Len() != 0 {
			t.Fatalf("expected an empty 204, got %d %q", rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("expected Cache-Control no-store, got %q", got)
		}

		cookie := sessionCookie(rec)
		if cookie == nil || cookie.Value == "" {
			t.Fatal("expected a session cookie with a value")
		}
		if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" {
			t.Fatalf("cookie is not hardened: %+v", cookie)
		}
		if want := e.clock.now.Add(sessionTTL); !cookie.Expires.Equal(want) {
			t.Fatalf("expected cookie expiry %v, got %v", want, cookie.Expires)
		}

		// The cookie value is a working session.
		account, err := e.svc.Authenticate(context.Background(), cookie.Value)
		if err != nil || account.Email != "alice@example.com" {
			t.Fatalf("cookie is not a valid session: %+v, %v", account, err)
		}
	})

	t.Run("the Secure flag can be off for local HTTP development", func(t *testing.T) {
		e := newEnv(t, false)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)

		cookie := sessionCookie(postJSON(e.mux, path, loginBody))

		if cookie == nil || cookie.Secure || !cookie.HttpOnly {
			t.Fatalf("expected HttpOnly without Secure, got %+v", cookie)
		}
	})

	t.Run("wrong password and unknown e-mail look exactly the same", func(t *testing.T) {
		e := newEnv(t, true)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)

		wrongPassword := postJSON(e.mux, path,
			`{"email":"alice@example.com","password":"definitely-not-it-123"}`)
		unknownEmail := postJSON(e.mux, path,
			`{"email":"nobody@example.com","password":"correct-horse-battery"}`)

		for name, rec := range map[string]*httptest.ResponseRecorder{
			"wrong password": wrongPassword,
			"unknown e-mail": unknownEmail,
		} {
			if rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: expected 401, got %d", name, rec.Code)
			}
			if sessionCookie(rec) != nil {
				t.Fatalf("%s: a failed login must not set a cookie", name)
			}
		}
		if wrongPassword.Body.String() != unknownEmail.Body.String() {
			t.Fatalf("bodies differ:\n%s\n%s", wrongPassword.Body, unknownEmail.Body)
		}
	})
}

func TestLogoutEndpoint(t *testing.T) {
	const path = "/api/v1/auth/logout"

	t.Run("ends the session and clears the cookie", func(t *testing.T) {
		e := newEnv(t, true)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)
		login := sessionCookie(postJSON(e.mux, "/api/v1/auth/login", loginBody))

		rec := postJSON(e.mux, path, "", login)

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}

		cleared := sessionCookie(rec)
		if cleared == nil || cleared.Value != "" || cleared.MaxAge >= 0 {
			t.Fatalf("expected the cookie to be cleared, got %+v", cleared)
		}

		// The important part: the token is dead on the server too.
		_, err := e.svc.Authenticate(context.Background(), login.Value)
		if !errors.Is(err, auth.ErrUnauthenticated) {
			t.Fatalf("expected ErrUnauthenticated after logout, got %v", err)
		}
	})

	t.Run("without a cookie it still answers 204", func(t *testing.T) {
		e := newEnv(t, true)

		rec := postJSON(e.mux, path, "")

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
	})
}

// failingService simulates a broken database: every call fails with an error
// that contains details that must never reach the client.
type failingService struct{}

const secretDetail = "pq: password authentication failed for user app at 10.0.0.5"

func (failingService) Register(context.Context, auth.RegisterInput) (auth.Account, error) {
	return auth.Account{}, errors.New(secretDetail)
}

func (failingService) Login(context.Context, auth.LoginInput) (auth.Session, error) {
	return auth.Session{}, errors.New(secretDetail)
}

func (failingService) Logout(context.Context, string) error {
	return errors.New(secretDetail)
}

func (failingService) Authenticate(context.Context, string) (auth.Account, error) {
	return auth.Account{}, errors.New(secretDetail)
}

func TestHandlersHideInternalErrors(t *testing.T) {
	// The handlers log the real error; keep the test output clean.
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	mux := http.NewServeMux()
	auth.NewHandler(failingService{}, true).RegisterRoutes(mux)

	// A cookie sent BY the client: Secure and HttpOnly only matter in responses.
	clientCookie := &http.Cookie{Name: auth.SessionCookieName, Value: "some-token"} //nolint:gosec // G124: request cookie

	cases := []struct {
		path    string
		body    string
		cookies []*http.Cookie
	}{
		{"/api/v1/auth/register", registerBody, nil},
		{"/api/v1/auth/login", loginBody, nil},
		{"/api/v1/auth/logout", "", []*http.Cookie{clientCookie}},
	}

	for _, tc := range cases {
		t.Run(tc.path, func(t *testing.T) {
			rec := postJSON(mux, tc.path, tc.body, tc.cookies...)

			if rec.Code != http.StatusInternalServerError {
				t.Fatalf("expected 500, got %d", rec.Code)
			}
			if strings.Contains(rec.Body.String(), "10.0.0.5") ||
				strings.Contains(rec.Body.String(), "password authentication") {
				t.Fatalf("internal error leaked to the client: %s", rec.Body.String())
			}
		})
	}
}

// getMe calls GET /api/v1/me. An empty token means no cookie at all.
func getMe(h http.Handler, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	if token != "" {
		req.Header.Set("Cookie", auth.SessionCookieName+"="+token)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func TestMeEndpoint(t *testing.T) {
	t.Run("returns the logged-in account", func(t *testing.T) {
		e := newEnv(t, true)
		registered := decodeMap(t, postJSON(e.mux, "/api/v1/auth/register", registerBody))
		token := sessionCookie(postJSON(e.mux, "/api/v1/auth/login", loginBody)).Value

		rec := getMe(e.mux, token)

		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
		}
		// Same four fields the signup returned: user, tenant, e-mail, role.
		if got := decodeMap(t, rec); !reflect.DeepEqual(got, registered) {
			t.Fatalf("expected %v, got %v", registered, got)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("expected Cache-Control no-store, got %q", cc)
		}
	})

	t.Run("without a cookie answers 401", func(t *testing.T) {
		e := newEnv(t, true)

		if rec := getMe(e.mux, ""); rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("an unknown cookie answers 401", func(t *testing.T) {
		e := newEnv(t, true)

		if rec := getMe(e.mux, "not-a-real-token"); rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401, got %d", rec.Code)
		}
	})

	t.Run("after logout the same cookie answers 401", func(t *testing.T) {
		e := newEnv(t, true)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)
		login := sessionCookie(postJSON(e.mux, "/api/v1/auth/login", loginBody))

		postJSON(e.mux, "/api/v1/auth/logout", "", login)

		if rec := getMe(e.mux, login.Value); rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after logout, got %d", rec.Code)
		}
	})

	t.Run("an expired session answers 401", func(t *testing.T) {
		e := newEnv(t, true)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)
		token := sessionCookie(postJSON(e.mux, "/api/v1/auth/login", loginBody)).Value

		e.clock.Advance(sessionTTL)

		if rec := getMe(e.mux, token); rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 after expiry, got %d", rec.Code)
		}
	})

	// The tenant comes from the database through the session, never from the
	// request, so two users can never see each other's data.
	t.Run("each user sees only their own account and tenant", func(t *testing.T) {
		e := newEnv(t, true)
		const (
			bobRegister = `{"tenant_name":"Bob GmbH","email":"bob@example.com","password":"correct-horse-battery"}`
			bobLogin    = `{"email":"bob@example.com","password":"correct-horse-battery"}`
		)

		alice := decodeMap(t, postJSON(e.mux, "/api/v1/auth/register", registerBody))
		bob := decodeMap(t, postJSON(e.mux, "/api/v1/auth/register", bobRegister))
		aliceToken := sessionCookie(postJSON(e.mux, "/api/v1/auth/login", loginBody)).Value
		bobToken := sessionCookie(postJSON(e.mux, "/api/v1/auth/login", bobLogin)).Value

		gotAlice := decodeMap(t, getMe(e.mux, aliceToken))
		gotBob := decodeMap(t, getMe(e.mux, bobToken))

		if !reflect.DeepEqual(gotAlice, alice) || !reflect.DeepEqual(gotBob, bob) {
			t.Fatalf("accounts mixed up:\nalice: %v\nbob: %v", gotAlice, gotBob)
		}
		if gotAlice["tenant_id"] == gotBob["tenant_id"] {
			t.Fatal("alice and bob must be in different tenants")
		}
	})
}

// The protection is a separate middleware, so these tests prove that the real
// auth routes are covered when it wraps them (as main.go will do).
func TestAuthRoutesBehindCSRFProtection(t *testing.T) {
	// send makes a POST as the browser would. site is the Sec-Fetch-Site
	// value ("" means the header is absent).
	send := func(h http.Handler, site, path, body, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if site != "" {
			req.Header.Set("Sec-Fetch-Site", site)
		}
		if token != "" {
			req.Header.Set("Cookie", auth.SessionCookieName+"="+token)
		}

		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		return rec
	}

	protected := func(t *testing.T) (http.Handler, env) {
		t.Helper()

		e := newEnv(t, true)
		protect, err := platform.CSRFProtection()
		if err != nil {
			t.Fatalf("create protection: %v", err)
		}

		return protect(e.mux), e
	}

	t.Run("a cross-site logout does not end the session", func(t *testing.T) {
		handler, e := protected(t)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)
		token := sessionCookie(postJSON(e.mux, "/api/v1/auth/login", loginBody)).Value

		rec := send(handler, "cross-site", "/api/v1/auth/logout", "", token)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
		if _, err := e.svc.Authenticate(context.Background(), token); err != nil {
			t.Fatalf("the session must survive a blocked logout, got %v", err)
		}
	})

	t.Run("a cross-site login is blocked and sets no cookie", func(t *testing.T) {
		handler, e := protected(t)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)

		rec := send(handler, "cross-site", "/api/v1/auth/login", loginBody, "")

		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", rec.Code)
		}
		if sessionCookie(rec) != nil {
			t.Fatal("a blocked login must not set a cookie")
		}
	})

	t.Run("the same requests work from our own origin", func(t *testing.T) {
		handler, e := protected(t)
		postJSON(e.mux, "/api/v1/auth/register", registerBody)

		rec := send(handler, "same-origin", "/api/v1/auth/login", loginBody, "")

		if rec.Code != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", rec.Code)
		}
	})
}
