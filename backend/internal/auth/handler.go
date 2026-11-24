package auth

import (
	"context"
	"errors"
	"log"
	"net/http"

	"github.com/google/uuid"

	"github.com/pitercoding/aktenlens/backend/internal/platform"
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
}

// Handler exposes the auth use cases over HTTP.
type Handler struct {
	svc           authService
	secureCookies bool
}

// NewHandler returns the auth handlers. secureCookies must be true in
// production (HTTPS). Only local HTTP development needs false.
func NewHandler(svc authService, secureCookies bool) *Handler {
	return &Handler{svc: svc, secureCookies: secureCookies}
}

// RegisterRoutes attaches the auth routes to mux.
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /api/v1/auth/register", h.register)
	mux.HandleFunc("POST /api/v1/auth/login", h.login)
	mux.HandleFunc("POST /api/v1/auth/logout", h.logout)
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
	UserID   uuid.UUID `json:"user_id"`
	TenantID uuid.UUID `json:"tenant_id"`
	Email    string    `json:"email"`
	Role     string    `json:"role"`
}

func (h *Handler) register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if !platform.DecodeJSON(w, r, &req) {
		return
	}

	account, err := h.svc.Register(r.Context(), RegisterInput{
		TenantName: req.TenantName,
		Email:      req.Email,
		Password:   req.Password,
	})

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
		platform.WriteJSON(w, http.StatusCreated, accountResponse{
			UserID:   account.UserID,
			TenantID: account.TenantID,
			Email:    account.Email,
			Role:     account.Role,
		})
	}
}

func (h *Handler) login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if !platform.DecodeJSON(w, r, &req) {
		return
	}

	session, err := h.svc.Login(r.Context(), LoginInput{
		Email:    req.Email,
		Password: req.Password,
	})

	switch {
	case errors.Is(err, ErrInvalidCredentials):
		platform.WriteProblem(w, http.StatusUnauthorized, "invalid e-mail or password")

	case err != nil:
		writeInternalError(w, "login", err)

	default:
		cookie := h.newCookie(session.Token)
		cookie.Expires = session.ExpiresAt

		http.SetCookie(w, cookie)
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
	cleared := h.newCookie("")
	cleared.MaxAge = -1

	http.SetCookie(w, cleared)
	w.WriteHeader(http.StatusNoContent)
}

// newCookie builds the session cookie with every protection on:
//   - HttpOnly: JavaScript cannot read it, so an XSS cannot steal the session.
//   - Secure: only sent over HTTPS (off only for local HTTP development).
//   - SameSite=Lax: not sent on cross-site POSTs, the base of CSRF protection.
func (h *Handler) newCookie(value string) *http.Cookie {
	return &http.Cookie{
		Name:     SessionCookieName,
		Value:    value,
		Path:     "/",
		HttpOnly: true,
		Secure:   h.secureCookies,
		SameSite: http.SameSiteLaxMode,
	}
}

// writeInternalError logs the real error and tells the client nothing about it.
func writeInternalError(w http.ResponseWriter, action string, err error) {
	log.Printf("auth: %s failed: %v", action, err)

	platform.WriteProblem(w, http.StatusInternalServerError, "an unexpected error occurred")
}
