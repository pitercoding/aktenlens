package platform

import (
	"context"
	"log"
	"net/http"
	"time"
)

// readyzPingTimeout keeps the readiness check fast when the database hangs:
// the hosting platform treats a slow answer as a failure anyway.
const readyzPingTimeout = 2 * time.Second

// Pinger is the part of the database pool the readiness check needs.
// *pgxpool.Pool satisfies it.
type Pinger interface {
	Ping(ctx context.Context) error
}

type healthResponse struct {
	Status string `json:"status"`
}

// NewHealthzHandler is the liveness probe: it answers 200 {"status":"ok"}
// as long as the process can serve requests. It must not touch the
// database, otherwise a database outage would make the platform restart a
// healthy API.
func NewHealthzHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	}
}

// NewReadyzHandler is the readiness probe: it answers 200 {"status":"ok"}
// when the database answers a ping and 503 {"status":"unavailable"}
// otherwise. The database error is only logged, never returned.
func NewReadyzHandler(db Pinger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyzPingTimeout)
		defer cancel()

		if err := db.Ping(ctx); err != nil {
			log.Printf("readyz: database ping failed: %v", err)

			writeJSON(w, http.StatusServiceUnavailable, healthResponse{
				Status: "unavailable",
			})
			return
		}

		writeJSON(w, http.StatusOK, healthResponse{Status: "ok"})
	}
}
