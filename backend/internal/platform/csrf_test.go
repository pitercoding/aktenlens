package platform

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCSRFProtection(t *testing.T) {
	const trusted = "https://app.aktenlens.example"

	protect, err := CSRFProtection(trusted)
	if err != nil {
		t.Fatalf("create protection: %v", err)
	}

	cases := []struct {
		name    string
		method  string
		headers map[string]string
		allowed bool
	}{
		// Not browsers, or browsers on our own site: allowed.
		{"POST without browser headers (curl, scripts)", http.MethodPost, nil, true},
		{"POST from our own origin", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-origin"}, true},
		{"POST typed in the address bar", http.MethodPost, map[string]string{"Sec-Fetch-Site": "none"}, true},
		// httptest requests have Host "example.com".
		{"POST with an Origin equal to Host (older browser)", http.MethodPost, map[string]string{"Origin": "https://example.com"}, true},

		// The attack: another site makes the browser send our cookie.
		{"POST from another site", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"POST from a sibling subdomain", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-site"}, false},
		{"PUT from another site", http.MethodPut, map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"PATCH from another site", http.MethodPatch, map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"DELETE from another site", http.MethodDelete, map[string]string{"Sec-Fetch-Site": "cross-site"}, false},
		{"POST with the Origin of another site (older browser)", http.MethodPost, map[string]string{"Origin": "https://evil.example"}, false},
		{"POST with Origin null (sandboxed iframe)", http.MethodPost, map[string]string{"Origin": "null"}, false},

		// Our own frontend on another origin is trusted, but only exactly.
		{"POST from the trusted frontend", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": trusted}, true},
		{"POST from the trusted frontend (older browser)", http.MethodPost, map[string]string{"Origin": trusted}, true},
		{"POST from the trusted host with another scheme", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "http://app.aktenlens.example"}, false},

		// Safe methods never change data, so they are never blocked.
		{"GET from another site", http.MethodGet, map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
		{"HEAD from another site", http.MethodHead, map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
		{"OPTIONS from another site", http.MethodOptions, map[string]string{"Sec-Fetch-Site": "cross-site"}, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reached := false
			next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				reached = true
				w.WriteHeader(http.StatusOK)
			})

			req := httptest.NewRequest(tc.method, "/", nil)
			for key, value := range tc.headers {
				req.Header.Set(key, value)
			}

			rec := httptest.NewRecorder()
			protect(next).ServeHTTP(rec, req)

			if tc.allowed {
				if !reached || rec.Code != http.StatusOK {
					t.Fatalf("expected the request to pass, got %d (reached=%v)", rec.Code, reached)
				}

				return
			}

			if reached || rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 and no handler, got %d (reached=%v)", rec.Code, reached)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Fatalf("expected a problem document, got content type %q", ct)
			}
		})
	}
}

// A wrong trusted origin must stop the API at startup, not silently protect
// less (or more) than intended.
func TestCSRFProtectionRejectsInvalidOrigins(t *testing.T) {
	invalid := []string{
		"",
		"app.example.com",
		"https://",
		"https://app.example.com/",
		"https://app.example.com/path",
		"https://app.example.com?x=1",
	}

	for _, origin := range invalid {
		t.Run(origin, func(t *testing.T) {
			if _, err := CSRFProtection(origin); err == nil {
				t.Fatalf("expected an error for %q", origin)
			}
		})
	}

	t.Run("a valid origin with a port", func(t *testing.T) {
		if _, err := CSRFProtection("http://localhost:3000"); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})
}
