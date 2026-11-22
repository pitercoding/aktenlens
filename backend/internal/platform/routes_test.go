package platform

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestRegisterRoutes goes through the mux, so it also proves the path and
// the HTTP method are wired correctly (not only the handler logic).
func TestRegisterRoutes(t *testing.T) {
	tests := []struct {
		name           string
		method         string
		path           string
		pingErr        error
		expectedStatus int
	}{
		{"healthz with GET", http.MethodGet, "/healthz", nil, http.StatusOK},
		// The "GET /healthz" pattern makes ServeMux answer 405 by itself.
		{"healthz with POST", http.MethodPost, "/healthz", nil, http.StatusMethodNotAllowed},
		// /healthz must not depend on the database.
		{"healthz with database down", http.MethodGet, "/healthz", errors.New("down"), http.StatusOK},
		{"readyz with database up", http.MethodGet, "/readyz", nil, http.StatusOK},
		{"readyz with database down", http.MethodGet, "/readyz", errors.New("down"), http.StatusServiceUnavailable},
		{"unknown path", http.MethodGet, "/nope", nil, http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterRoutes(mux, stubPinger{err: tt.pingErr}, "test")

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(tt.method, tt.path, nil))

			if recorder.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}
		})
	}
}
