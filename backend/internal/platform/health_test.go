package platform

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// stubPinger replaces the real database pool in tests.
type stubPinger struct {
	err error
}

// Ping has the same signature as pgxpool.Pool.Ping, so the real pool
// satisfies the Pinger interface without an adapter.
func (s stubPinger) Ping(ctx context.Context) error {
	return s.err
}

// assertJSONResponse checks status, Content-Type and body in one place so
// every handler test verifies the same contract.
func assertJSONResponse(
	t *testing.T,
	recorder *httptest.ResponseRecorder,
	expectedStatus int,
	expectedBody string,
) {
	t.Helper()

	if recorder.Code != expectedStatus {
		t.Fatalf("expected status %d, got %d", expectedStatus, recorder.Code)
	}

	if contentType := recorder.Header().Get("Content-Type"); contentType != "application/json" {
		t.Errorf("expected Content-Type application/json, got %q", contentType)
	}

	if body := strings.TrimSpace(recorder.Body.String()); body != expectedBody {
		t.Errorf("expected body %s, got %s", expectedBody, body)
	}
}

func TestHealthzHandler(t *testing.T) {
	recorder := httptest.NewRecorder()

	NewHealthzHandler().ServeHTTP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/healthz", nil),
	)

	assertJSONResponse(t, recorder, http.StatusOK, `{"status":"ok"}`)
}

func TestReadyzHandler(t *testing.T) {
	tests := []struct {
		name           string
		pingErr        error
		expectedStatus int
		expectedBody   string
	}{
		{
			name:           "database reachable",
			expectedStatus: http.StatusOK,
			expectedBody:   `{"status":"ok"}`,
		},
		{
			// The database error must not reach the response.
			name:           "database unreachable",
			pingErr:        errors.New("dial tcp 10.0.0.5:5432: connection refused"),
			expectedStatus: http.StatusServiceUnavailable,
			expectedBody:   `{"status":"unavailable"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()

			NewReadyzHandler(stubPinger{err: tt.pingErr}).ServeHTTP(
				recorder,
				httptest.NewRequest(http.MethodGet, "/readyz", nil),
			)

			assertJSONResponse(t, recorder, tt.expectedStatus, tt.expectedBody)
		})
	}
}
