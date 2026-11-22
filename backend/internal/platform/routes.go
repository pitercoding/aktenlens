package platform

import "net/http"

// RegisterRoutes attaches all HTTP routes to mux. db is only used by /readyz
// and version is reported by /healthz.
func RegisterRoutes(mux *http.ServeMux, db Pinger, version string) {
	mux.Handle("GET /healthz", NewHealthzHandler(version))
	mux.Handle("GET /readyz", NewReadyzHandler(db))
}
