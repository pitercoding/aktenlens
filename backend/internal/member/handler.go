// Package member exposes the members of the caller's tenant over HTTP.
//
// It lives apart from package tenant on purpose: auth already imports tenant
// (for Role), so tenant cannot import auth without an import cycle. Feature
// packages like this one sit on top of auth and use its middleware.
package member

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/uuid"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
	"github.com/pitercoding/aktenlens/backend/internal/platform"
	"github.com/pitercoding/aktenlens/backend/internal/store"
	"github.com/pitercoding/aktenlens/backend/internal/tenant"
)

// authenticator is what RequireAuth needs. *auth.Service satisfies it.
type authenticator interface {
	Authenticate(ctx context.Context, token string) (auth.Account, error)
}

// memberLister is the query this package uses. *store.Queries satisfies it.
type memberLister interface {
	ListMembersByTenant(ctx context.Context, tenantID uuid.UUID) ([]store.ListMembersByTenantRow, error)
}

// Handler serves the member endpoints.
type Handler struct {
	authn   authenticator
	members memberLister
}

func NewHandler(authn authenticator, members memberLister) *Handler {
	return &Handler{authn: authn, members: members}
}

// RegisterRoutes attaches the member routes to mux. Every route needs a
// session (401 otherwise) and at least the admin role (403 otherwise).
func (h *Handler) RegisterRoutes(mux *http.ServeMux) {
	adminOnly := func(next http.HandlerFunc) http.Handler {
		return auth.RequireAuth(h.authn)(auth.RequireRole(tenant.RoleAdmin)(next))
	}

	mux.Handle("GET /api/v1/members", adminOnly(h.list))
}

type memberResponse struct {
	UserID   uuid.UUID   `json:"user_id"`
	Email    string      `json:"email"`
	Role     tenant.Role `json:"role"`
	JoinedAt time.Time   `json:"joined_at"`
}

// listResponse wraps the list in an object, so fields (like pagination) can
// be added later without breaking clients.
type listResponse struct {
	Members []memberResponse `json:"members"`
}

// list answers with the members of the caller's own tenant.
//
// The tenant ID comes from the authenticated account, which RequireAuth
// loaded from the database. This handler never reads a tenant from the URL,
// the query string, a header or the body, so a client cannot ask for another
// tenant's data.
func (h *Handler) list(w http.ResponseWriter, r *http.Request) {
	account, ok := auth.AccountFrom(r.Context())
	if !ok {
		// Cannot happen behind RequireAuth: fail closed.
		platform.WriteProblem(w, http.StatusUnauthorized, "authentication required")

		return
	}

	rows, err := h.members.ListMembersByTenant(r.Context(), account.TenantID)
	if err != nil {
		writeInternalError(w, "list members", err)

		return
	}

	members := make([]memberResponse, 0, len(rows))

	for _, row := range rows {
		role, ok := tenant.ParseRole(row.Role)
		if !ok {
			// The CHECK constraint makes this impossible: corrupted data.
			writeInternalError(w, "list members", fmt.Errorf("unknown membership role %q", row.Role))

			return
		}

		members = append(members, memberResponse{
			UserID:   row.UserID,
			Email:    row.Email,
			Role:     role,
			JoinedAt: row.JoinedAt,
		})
	}

	platform.WriteJSON(w, http.StatusOK, listResponse{Members: members})
}

// writeInternalError logs the real error and tells the client nothing about it.
// auth has the same helper; when a third package needs it, it moves to platform.
func writeInternalError(w http.ResponseWriter, action string, err error) {
	log.Printf("member: %s failed: %v", action, err)

	platform.WriteProblem(w, http.StatusInternalServerError, "an unexpected error occurred")
}
