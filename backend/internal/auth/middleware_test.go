package auth_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/uuid"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
)

// stubAuthenticator replaces the real service: it returns what the test wants
// and remembers how it was called.
type stubAuthenticator struct {
	account auth.Account
	err     error
	calls   int
	token   string
}

func (s *stubAuthenticator) Authenticate(_ context.Context, token string) (auth.Account, error) {
	s.calls++
	s.token = token

	return s.account, s.err
}

func TestRequireAuth(t *testing.T) {
	// The middleware logs unexpected errors; keep the test output clean.
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	want := auth.Account{
		UserID:   uuid.New(),
		TenantID: uuid.New(),
		Email:    "alice@example.com",
		Role:     "admin",
	}

	// run sends one request through the middleware. cookieValue "" means no
	// cookie. It reports the response, what the next handler saw, and whether
	// the next handler ran at all.
	run := func(stub *stubAuthenticator, cookieValue string) (
		rec *httptest.ResponseRecorder, got auth.Account, reached bool,
	) {
		next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			reached = true
			got, _ = auth.AccountFrom(r.Context())
			w.WriteHeader(http.StatusOK)
		})

		req := httptest.NewRequest(http.MethodGet, "/", nil)
		if cookieValue != "" {
			req.Header.Set("Cookie", auth.SessionCookieName+"="+cookieValue)
		}

		rec = httptest.NewRecorder()
		auth.RequireAuth(stub)(next).ServeHTTP(rec, req)

		return rec, got, reached
	}

	t.Run("a valid session reaches the handler with the account", func(t *testing.T) {
		stub := &stubAuthenticator{account: want}

		rec, got, reached := run(stub, "tok-123")

		if !reached || rec.Code != http.StatusOK {
			t.Fatalf("expected the handler to run, got %d (reached=%v)", rec.Code, reached)
		}
		if got != want {
			t.Fatalf("expected account %+v, got %+v", want, got)
		}
		if stub.token != "tok-123" {
			t.Fatalf("expected the cookie value to be authenticated, got %q", stub.token)
		}
		if cc := rec.Header().Get("Cache-Control"); cc != "no-store" {
			t.Fatalf("expected Cache-Control no-store, got %q", cc)
		}
	})

	t.Run("no cookie answers 401 without asking the service", func(t *testing.T) {
		stub := &stubAuthenticator{account: want}

		rec, _, reached := run(stub, "")

		if reached || rec.Code != http.StatusUnauthorized {
			t.Fatalf("expected 401 and no handler, got %d (reached=%v)", rec.Code, reached)
		}
		if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
			t.Fatalf("unexpected content type %q", ct)
		}
		if stub.calls != 0 {
			t.Fatalf("the service must not be called without a cookie, got %d calls", stub.calls)
		}
	})

	t.Run("an unauthenticated session answers 401", func(t *testing.T) {
		for name, err := range map[string]error{
			"plain":   auth.ErrUnauthenticated,
			"wrapped": fmt.Errorf("lookup: %w", auth.ErrUnauthenticated),
		} {
			stub := &stubAuthenticator{err: err}

			rec, _, reached := run(stub, "expired-token")

			if reached || rec.Code != http.StatusUnauthorized {
				t.Fatalf("%s: expected 401 and no handler, got %d (reached=%v)", name, rec.Code, reached)
			}
		}
	})

	t.Run("an unexpected error answers 500 and hides the details", func(t *testing.T) {
		stub := &stubAuthenticator{err: errors.New(secretDetail)}

		rec, _, reached := run(stub, "tok-123")

		if reached || rec.Code != http.StatusInternalServerError {
			t.Fatalf("expected 500 and no handler, got %d (reached=%v)", rec.Code, reached)
		}
		if strings.Contains(rec.Body.String(), "10.0.0.5") {
			t.Fatalf("internal error leaked to the client: %s", rec.Body.String())
		}
	})
}

func TestAccountFromWithoutMiddleware(t *testing.T) {
	if _, ok := auth.AccountFrom(context.Background()); ok {
		t.Fatal("a plain context must not contain an account")
	}
}
