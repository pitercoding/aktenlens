package auth_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
	"github.com/pitercoding/aktenlens/backend/internal/platform"
)

const (
	registerPath = "/api/v1/auth/register"
	loginPath    = "/api/v1/auth/login"
)

func loginJSON(email, password string) string {
	return fmt.Sprintf(`{"email":%q,"password":%q}`, email, password)
}

func registerJSON(email string) string {
	return fmt.Sprintf(`{"tenant_name":"Acme","email":%q,"password":"correct-horse-battery"}`, email)
}

// postWith sends a POST and lets the test change the request first, for
// example to fake the client address.
func postWith(h http.Handler, path, body string, mutate func(*http.Request)) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	mutate(req)

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func fromIP(addr string) func(*http.Request) {
	return func(r *http.Request) { r.RemoteAddr = addr }
}

// requireStatus fails the test unless rec has the wanted status.
func requireStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()

	if rec.Code != want {
		t.Fatalf("expected %d, got %d: %s", want, rec.Code, rec.Body.String())
	}
}

func TestLoginRateLimit(t *testing.T) {
	start := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	wrong := loginJSON("alice@example.com", "wrong-password-123")

	t.Run("the e-mail limit blocks even the right password, until the window passes", func(t *testing.T) {
		clock := &fakeClock{now: start}
		e := newEnv(t, true, auth.WithRateLimits(auth.RateLimits{
			LoginEmail: platform.NewLimiter(3, time.Minute, platform.WithLimiterClock(clock.Now)),
		}))
		postJSON(e.mux, registerPath, registerBody)

		for range 3 {
			requireStatus(t, postJSON(e.mux, loginPath, wrong), http.StatusUnauthorized)
		}

		rec := postJSON(e.mux, loginPath, loginBody) // the RIGHT password
		requireStatus(t, rec, http.StatusTooManyRequests)
		if got := rec.Header().Get("Retry-After"); got != "60" {
			t.Fatalf("expected Retry-After 60, got %q", got)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("expected a problem document, got %q", ct)
		}
		if sessionCookie(rec) != nil {
			t.Fatal("a blocked login must not set a cookie")
		}

		clock.Advance(time.Minute)
		requireStatus(t, postJSON(e.mux, loginPath, loginBody), http.StatusNoContent)
	})

	t.Run("the e-mail limit is per e-mail", func(t *testing.T) {
		e := newEnv(t, true, auth.WithRateLimits(auth.RateLimits{
			LoginEmail: platform.NewLimiter(1, time.Hour),
		}))

		requireStatus(t, postJSON(e.mux, loginPath, wrong), http.StatusUnauthorized)
		requireStatus(t, postJSON(e.mux, loginPath, wrong), http.StatusTooManyRequests)

		other := loginJSON("bob@example.com", "wrong-password-123")
		requireStatus(t, postJSON(e.mux, loginPath, other), http.StatusUnauthorized)
	})

	t.Run("case and spaces do not create a new e-mail bucket", func(t *testing.T) {
		e := newEnv(t, true, auth.WithRateLimits(auth.RateLimits{
			LoginEmail: platform.NewLimiter(3, time.Hour),
		}))

		for _, email := range []string{"ALICE@example.com", "  alice@example.com ", "Alice@Example.com"} {
			requireStatus(t, postJSON(e.mux, loginPath, loginJSON(email, "wrong-password-123")), http.StatusUnauthorized)
		}

		requireStatus(t, postJSON(e.mux, loginPath, wrong), http.StatusTooManyRequests)
	})

	t.Run("the IP limit blocks every e-mail from one address", func(t *testing.T) {
		e := newEnv(t, true, auth.WithRateLimits(auth.RateLimits{
			LoginIP: platform.NewLimiter(2, time.Hour),
		}))
		attacker := fromIP("203.0.113.5:1000")

		requireStatus(t, postWith(e.mux, loginPath, loginJSON("a@example.com", "x-wrong-password"), attacker), http.StatusUnauthorized)
		requireStatus(t, postWith(e.mux, loginPath, loginJSON("b@example.com", "x-wrong-password"), attacker), http.StatusUnauthorized)
		requireStatus(t, postWith(e.mux, loginPath, loginJSON("c@example.com", "x-wrong-password"), attacker), http.StatusTooManyRequests)

		// Someone else is not affected.
		other := fromIP("198.51.100.7:2000")
		requireStatus(t, postWith(e.mux, loginPath, wrong, other), http.StatusUnauthorized)
	})

	t.Run("without a trusted proxy, X-Forwarded-For cannot dodge the limit", func(t *testing.T) {
		e := newEnv(t, true, auth.WithRateLimits(auth.RateLimits{
			LoginIP: platform.NewLimiter(1, time.Hour),
		}))

		forged := func(xff string) func(*http.Request) {
			return func(r *http.Request) {
				r.RemoteAddr = "203.0.113.5:1000"
				r.Header.Set("X-Forwarded-For", xff)
			}
		}

		requireStatus(t, postWith(e.mux, loginPath, wrong, forged("1.1.1.1")), http.StatusUnauthorized)
		requireStatus(t, postWith(e.mux, loginPath, wrong, forged("2.2.2.2")), http.StatusTooManyRequests)
	})

	t.Run("behind a trusted proxy, the limit follows the real client", func(t *testing.T) {
		e := newEnv(t, true,
			auth.WithRateLimits(auth.RateLimits{LoginIP: platform.NewLimiter(1, time.Hour)}),
			auth.WithTrustedProxyHops(1),
		)

		viaProxy := func(xff string) func(*http.Request) {
			return func(r *http.Request) {
				r.RemoteAddr = "10.0.0.1:4000" // always the proxy
				r.Header.Set("X-Forwarded-For", xff)
			}
		}

		requireStatus(t, postWith(e.mux, loginPath, wrong, viaProxy("198.51.100.1")), http.StatusUnauthorized)
		// Another client behind the same proxy is a different bucket.
		requireStatus(t, postWith(e.mux, loginPath, wrong, viaProxy("198.51.100.2")), http.StatusUnauthorized)
		// The first client again: blocked.
		requireStatus(t, postWith(e.mux, loginPath, wrong, viaProxy("198.51.100.1")), http.StatusTooManyRequests)
		// Forging entries on the left changes nothing.
		requireStatus(t, postWith(e.mux, loginPath, wrong, viaProxy("9.9.9.9, 198.51.100.1")), http.StatusTooManyRequests)
	})

	t.Run("limits are on by default", func(t *testing.T) {
		e := newEnv(t, true) // no options
		postJSON(e.mux, registerPath, registerBody)

		for range 5 {
			requireStatus(t, postJSON(e.mux, loginPath, wrong), http.StatusUnauthorized)
		}

		requireStatus(t, postJSON(e.mux, loginPath, wrong), http.StatusTooManyRequests)
	})
}

func TestRegisterRateLimit(t *testing.T) {
	t.Run("the IP limit blocks mass signups from one address", func(t *testing.T) {
		e := newEnv(t, true, auth.WithRateLimits(auth.RateLimits{
			RegisterIP: platform.NewLimiter(2, time.Hour),
		}))

		requireStatus(t, postJSON(e.mux, registerPath, registerJSON("a@example.com")), http.StatusCreated)
		requireStatus(t, postJSON(e.mux, registerPath, registerJSON("b@example.com")), http.StatusCreated)
		requireStatus(t, postJSON(e.mux, registerPath, registerJSON("c@example.com")), http.StatusTooManyRequests)
	})

	t.Run("the e-mail limit blocks repeated attempts for one address", func(t *testing.T) {
		e := newEnv(t, true, auth.WithRateLimits(auth.RateLimits{
			RegisterEmail: platform.NewLimiter(2, time.Hour),
		}))
		body := registerJSON("alice@example.com")

		requireStatus(t, postJSON(e.mux, registerPath, body), http.StatusCreated)
		requireStatus(t, postJSON(e.mux, registerPath, body), http.StatusConflict)
		requireStatus(t, postJSON(e.mux, registerPath, body), http.StatusTooManyRequests)
	})

	t.Run("a blocked signup creates nothing", func(t *testing.T) {
		e := newEnv(t, true, auth.WithRateLimits(auth.RateLimits{
			RegisterIP: platform.NewLimiter(1, time.Hour),
		}))

		requireStatus(t, postJSON(e.mux, registerPath, registerJSON("a@example.com")), http.StatusCreated)
		requireStatus(t, postJSON(e.mux, registerPath, registerJSON("b@example.com")), http.StatusTooManyRequests)

		if n := countRows(t, e.pool, "users"); n != 1 {
			t.Fatalf("expected 1 user, got %d", n)
		}
	})
}
