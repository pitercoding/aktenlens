package auth

import (
	"context"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/pitercoding/aktenlens/backend/internal/platform"
	"github.com/pitercoding/aktenlens/backend/internal/tenant"
)

// SessionCookieName is the cookie that carries the session token. The auth
// middleware (next step) reads it too.
const SessionCookieName = "aktenlens_session"

// authService is the part of Service the handlers need. Declaring it here
// (the consumer) lets tests plug in a service that fails on purpose.
type authService interface {
	Register(ctx context.Context, in RegisterInput) (Account, error)
	Login(ctx context.Context, in LoginInput) (Session, error)
	Logout(ctx context.Context, token string) error
	Authenticate(ctx context.Context, token string) (Account, error)
}

// Handler exposes the auth use cases over HTTP.
type Handler struct {
	svc              authService
	secureCookies    bool
	limits           RateLimits
	trustedProxyHops int
}

// NewHandler returns the auth handlers. secureCookies must be true in
// production (HTTPS). Only local HTTP development needs false.
//
// Rate limits are ON by default (see DefaultRateLimits): forgetting an option
// must never leave login open to unlimited guessing.
func NewHandler(svc authService, secureCookies bool, opts ...HandlerOption) *Handler {
	h := &Handler{svc: svc, secureCookies: secureCookies, limits: DefaultRateLimits()}
	for _, opt := range opts {
		opt(h)
	}

	return h
}

// RegisterRoutes attaches the auth routes to mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/register", h.register)
	mux.HandleFunc("POST /api/v1/auth/login", h.login)
	mux.HandleFunc("POST /api/v1/auth/logout", h.logout)

	// The only route here that needs a session.
	mux.Handle("GET /api/v1/me", RequireAuth(h.svc)(http.HandlerFunc(h.me)))
}

// Request and response bodies live here, not in Service: the service knows
// nothing about JSON, and no internal field reaches the API by accident.
type registerRequest struct {
	TenantName string `json:"tenant_name"`
	Email      string `json:"email"`
	Password   string `json:"password"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type accountResponse struct {
	UserID   uuid.UUID   `json:"user_id"`
	TenantID uuid.UUID   `json:"tenant_id"`
	Email    string      `json:"email"`
	Role     tenant.Role `json:"role"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	// The address is checked before reading the body, which is cheaper.
	if !h.allowIP(w, r, h.limits.RegisterIP) {
		return
	}

	var req registerRequest
	if !platform.DecodeJSON(w, r, &req) {
		return
	}

	if !h.allowEmail(w, h.limits.RegisterEmail, req.Email) {
		return
	}

	// Converting (instead of copying field by field) makes the compiler check
	// that both structs keep exactly the same fields. JSON tags are ignored.
	account, err := h.svc.Register(r.Context(), RegisterInput(req))

	var validationErr *ValidationError

	switch {
	case errors.As(err, &validationErr):
		platform.WriteValidationProblem(w, validationErr.Fields)

	case errors.Is(err, ErrEmailTaken):
		platform.WriteProblem(w, http.StatusConflict, "an account with this e-mail already exists")

	case err != nil:
		writeInternalError(w, "register", err)

	default:
		w.Header().Set("Cache-Control", "no-store")
		// Same idea: if Account ever gains a field (say, a password hash),
		// this line stops compiling instead of leaking it through the API.
		platform.WriteJSON(w, http.StatusCreated, accountResponse(account))
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	if !h.allowIP(w, r, h.limits.LoginIP) {
		return
	}

	var req loginRequest
	if !platform.DecodeJSON(w, r, &req) {
		return
	}

	if !h.allowEmail(w, h.limits.LoginEmail, req.Email) {
		return
	}

	session, err := h.svc.Login(r.Context(), LoginInput(req))

	switch {
	case errors.Is(err, ErrInvalidCredentials):
		platform.WriteProblem(w, http.StatusUnauthorized, "invalid e-mail or password")

	case err != nil:
		writeInternalError(w, "login", err)

	default:
		h.setSessionCookie(w, session.Token, session.ExpiresAt, 0)
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *Handler) logout(w http.ResponseWriter, r *http.Request) {
	// No cookie is fine: logging out twice is not an error.
	if cookie, err := r.Cookie(SessionCookieName); err == nil {
		if err := h.svc.Logout(r.Context(), cookie.Value); err != nil {
			writeInternalError(w, "logout", err)

			return
		}
	}

	// MaxAge < 0 tells the browser to delete the cookie right away.
	h.setSessionCookie(w, "", time.Time{}, -1)
	w.WriteHeader(http.StatusNoContent)
}

// me returns the account of the logged-in user.
func (h *Handler) me(w http.ResponseWriter, r *http.Request) {
	account, ok := AccountFrom(r.Context())
	if !ok {
		// Cannot happen behind RequireAuth. If someone ever registers this
		// route without it, failing closed beats a zero-value account.
		writeUnauthorized(w)

		return
	}

	platform.WriteJSON(w, http.StatusOK, accountResponse(account))
}

// setSessionCookie is the only place that builds the session cookie, so its
// protections cannot be forgotten in one of the handlers:
//   - HttpOnly: JavaScript cannot read it, so an XSS cannot steal the session.
//   - Secure: only sent over HTTPS (off only for local HTTP development).
//   - SameSite=Lax: not sent on cross-site POSTs, the base of CSRF protection.
//
// A zero expires and zero maxAge make a session cookie; maxAge < 0 deletes it.
func (h *Handler) setSessionCookie(w http.ResponseWriter, value string, expires time.Time, maxAge int) {
	//nolint:gosec // G124: Secure is configurable, false only for local HTTP development.
	http.SetCookie(w, &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	})
}

// writeInternalError logs the real error and tells the client nothing about it.
func writeInternalError(w http.ResponseWriter, action string, err error) {
	log.Printf("auth: %s failed: %v", action, err)

	platform.WriteProblem(w, http.StatusInternalServerError, "an unexpected error occurred")
}
