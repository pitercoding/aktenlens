package platform

import (
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
		expectedStatus int
	}{
		{"healthz with GET", http.MethodGet, "/healthz", http.StatusOK},
		// The "GET /healthz" pattern makes ServeMux answer 405 by itself.
		{"healthz with POST", http.MethodPost, "/healthz", http.StatusMethodNotAllowed},
		{"unknown path", http.MethodGet, "/nope", http.StatusNotFound},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mux := http.NewServeMux()
			RegisterRoutes(mux)

			recorder := httptest.NewRecorder()
			mux.ServeHTTP(recorder, httptest.NewRequest(tt.method, tt.path, nil))

			if recorder.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, recorder.Code)
			}
		})
	}
}
