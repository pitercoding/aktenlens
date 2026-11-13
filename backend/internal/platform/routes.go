package platform

import "net/http"

// RegisterRoutes attaches all HTTP routes to mux.
// /readyz is added once the database pool exists.
func RegisterRoutes(mux *http.ServeMux) {
	mux.Handle("GET /healthz", NewHealthzHandler())
}
