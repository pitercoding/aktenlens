package main

import (
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
	"github.com/pitercoding/aktenlens/backend/internal/member"
	"github.com/pitercoding/aktenlens/backend/internal/platform"
	"github.com/pitercoding/aktenlens/backend/internal/store"
)

// newHandler assembles the whole API: every route, wrapped in the CSRF
// protection. This is the only place that knows all the parts and connects
// them (the "composition root"). Keeping it out of main() lets a test drive
// the real, complete API with httptest.
func newHandler(cfg config, pool *pgxpool.Pool, version string) (http.Handler, error) {
	protect, err := platform.CSRFProtection(cfg.TrustedOrigins...)
	if err != nil {
		return nil, err
	}

	authService := auth.NewService(pool)

	mux := http.NewServeMux()
	platform.RegisterRoutes(mux, pool, version)
	auth.NewHandler(authService, cfg.SecureCookies,
		auth.WithTrustedProxyHops(cfg.TrustedProxyHops),
	).RegisterRoutes(mux)
	member.NewHandler(authService, store.New(pool)).RegisterRoutes(mux)

	// The protection wraps the whole mux, not each route: a route added later
	// cannot forget it.
	return protect(mux), nil
}
