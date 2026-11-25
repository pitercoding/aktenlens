package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
	"github.com/pitercoding/aktenlens/backend/internal/platform/testdb"
)

const (
	registerBody = `{"tenant_name":"Acme GmbH","email":"alice@example.com","password":"correct-horse-battery"}`
	loginBody    = `{"email":"alice@example.com","password":"correct-horse-battery"}`
)

// send makes a request to the assembled API. token "" means no cookie.
func send(h http.Handler, method, path, body, token string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
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

// sessionToken reads the session cookie that a response set.
func sessionToken(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()

	for _, c := range rec.Result().Cookies() {
		if c.Name == auth.SessionCookieName && c.Value != "" {
			return c.Value
		}
	}

	t.Fatal("the response did not set a session cookie")

	return ""
}

func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()

	if rec.Code != want {
		t.Fatalf("expected %d, got %d: %s", want, rec.Code, rec.Body.String())
	}
}

// This drives the complete API, wired the way main() wires it.
func TestNewHandlerFullFlow(t *testing.T) {
	pool := testdb.NewPool(t)

	h, err := newHandler(config{SecureCookies: true}, pool, "test-version")
	if err != nil {
		t.Fatalf("assemble the API: %v", err)
	}

	t.Run("health checks are wired", func(t *testing.T) {
		rec := send(h, http.MethodGet, "/healthz", "", "", nil)
		requireStatus(t, rec, http.StatusOK)
		if !strings.Contains(rec.Body.String(), "test-version") {
			t.Fatalf("expected the version in /healthz, got %s", rec.Body.String())
		}

		requireStatus(t, send(h, http.MethodGet, "/readyz", "", "", nil), http.StatusOK)
	})

	// register -> login -> me -> members -> logout, in order.
	requireStatus(t, send(h, http.MethodPost, "/api/v1/auth/register", registerBody, "", nil), http.StatusCreated)

	login := send(h, http.MethodPost, "/api/v1/auth/login", loginBody, "", nil)
	requireStatus(t, login, http.StatusNoContent)
	token := sessionToken(t, login)

	t.Run("me returns the logged-in account", func(t *testing.T) {
		rec := send(h, http.MethodGet, "/api/v1/me", "", token, nil)
		requireStatus(t, rec, http.StatusOK)

		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatalf("invalid JSON: %v", err)
		}
		if body["email"] != "alice@example.com" || body["role"] != "owner" {
			t.Fatalf("unexpected account: %v", body)
		}
	})

	t.Run("the owner can list the members", func(t *testing.T) {
		rec := send(h, http.MethodGet, "/api/v1/members", "", token, nil)

		requireStatus(t, rec, http.StatusOK)
		if !strings.Contains(rec.Body.String(), "alice@example.com") {
			t.Fatalf("expected alice in the list, got %s", rec.Body.String())
		}
	})

	t.Run("protected routes need a session", func(t *testing.T) {
		requireStatus(t, send(h, http.MethodGet, "/api/v1/me", "", "", nil), http.StatusUnauthorized)
		requireStatus(t, send(h, http.MethodGet, "/api/v1/members", "", "", nil), http.StatusUnauthorized)
	})

	t.Run("the CSRF protection wraps every route", func(t *testing.T) {
		crossSite := map[string]string{"Sec-Fetch-Site": "cross-site"}

		// A cross-site logout is blocked, and the session survives.
		rec := send(h, http.MethodPost, "/api/v1/auth/logout", "", token, crossSite)
		requireStatus(t, rec, http.StatusForbidden)
		requireStatus(t, send(h, http.MethodGet, "/api/v1/me", "", token, nil), http.StatusOK)

		// The same request from our own origin works.
		sameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin"}
		requireStatus(t, send(h, http.MethodPost, "/api/v1/auth/logout", "", token, sameOrigin), http.StatusNoContent)
	})

	t.Run("after logout the session is dead", func(t *testing.T) {
		requireStatus(t, send(h, http.MethodGet, "/api/v1/me", "", token, nil), http.StatusUnauthorized)
	})
}

func TestNewHandlerTrustedOrigins(t *testing.T) {
	const frontend = "https://app.aktenlens.example"

	t.Run("a trusted frontend on another origin may register", func(t *testing.T) {
		h, err := newHandler(config{SecureCookies: true, TrustedOrigins: []string{frontend}}, testdb.NewPool(t), "test")
		if err != nil {
			t.Fatalf("assemble the API: %v", err)
		}

		headers := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": frontend}
		rec := send(h, http.MethodPost, "/api/v1/auth/register", registerBody, "", headers)
		requireStatus(t, rec, http.StatusCreated)

		// Another origin is still blocked.
		other := map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}
		rec = send(h, http.MethodPost, "/api/v1/auth/login", loginBody, "", other)
		requireStatus(t, rec, http.StatusForbidden)
	})

	t.Run("an invalid trusted origin stops the API at startup", func(t *testing.T) {
		// The pool is not used before the origin is validated.
		_, err := newHandler(config{TrustedOrigins: []string{"https://app.example.com/path"}}, nil, "test")

		if err == nil {
			t.Fatal("expected an error")
		}
	})
}
