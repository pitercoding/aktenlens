package auth

import (
	"context"
	"errors"
	"net/http"

	"github.com/pitercoding/aktenlens/backend/internal/platform"
	"github.com/pitercoding/aktenlens/backend/internal/tenant"
)

// authenticator is the part of Service the middleware needs.
type authenticator interface {
	Authenticate(ctx context.Context, token string) (Account, error)
}

// accountKey is the context key. It is an unexported type, so no other
// package can read or overwrite the value by accident.
type accountKey struct{}

// AccountFrom returns the account that RequireAuth stored in the context.
// The second result is false when the request did not go through RequireAuth.
func AccountFrom(ctx context.Context) (Account, bool) {
	account, ok := ctx.Value(accountKey{}).(Account)

	return account, ok
}

// RequireAuth protects a handler: without a valid session cookie the request
// is answered with 401 and the handler never runs. With one, the handler can
// call AccountFrom(r.Context()) to know who is calling and for which tenant.
//
// The tenant comes from the database (through the session), never from the
// request, so a client cannot choose someone else's tenant.
func RequireAuth(svc authenticator) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cookie, err := r.Cookie(SessionCookieName)
			if err != nil {
				writeUnauthorized(w)

				return
			}

			account, err := svc.Authenticate(r.Context(), cookie.Value)

			switch {
			case errors.Is(err, ErrUnauthenticated):
				// Missing, unknown, expired and logged-out sessions all look the same.
				writeUnauthorized(w)

			case err != nil:
				writeInternalError(w, "authenticate", err)

			default:
				// Private data: no shared cache may keep this response.
				w.Header().Set("Cache-Control", "no-store")

				ctx := context.WithValue(r.Context(), accountKey{}, account)
				next.ServeHTTP(w, r.WithContext(ctx))
			}
		})
	}
}

// RequireRole allows the request only when the caller has at least the role
// min (owner > admin > member). It must run AFTER RequireAuth:
//
//	RequireAuth(svc)(RequireRole(tenant.RoleAdmin)(handler))
//
// Without a logged-in user it answers 401. With one whose role is too low, 403.
func RequireRole(min tenant.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			account, ok := AccountFrom(r.Context())
			if !ok {
				// Used without RequireAuth: fail closed.
				writeUnauthorized(w)

				return
			}

			if !account.Role.AtLeast(min) {
				platform.WriteProblem(w, http.StatusForbidden, "you do not have permission to do this")

				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

func writeUnauthorized(w http.ResponseWriter) {
	platform.WriteProblem(w, http.StatusUnauthorized, "authentication required")
}
