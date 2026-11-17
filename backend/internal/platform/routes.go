package platform

import "net/http"

// RegisterRoutes attaches all HTTP routes to mux. db is only used by /readyz.
func RegisterRoutes(mux *http.ServeMux, db Pinger) {
	mux.Handle("GET /healthz", NewHealthzHandler())
	mux.Handle("GET /readyz", NewReadyzHandler(db))
}
