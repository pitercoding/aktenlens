package platform

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDecodeJSON(t *testing.T) {
	type payload struct {
		Email string `json:"email"`
	}

	// One byte over the limit: must be rejected without reading it all.
	tooBig := `{"email":"` + strings.Repeat("a", maxJSONBodyBytes) + `"}`

	cases := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int    // 0 means the decode must succeed
		wantDetail  string // substring expected in the problem detail
	}{
		{"valid body", "application/json", `{"email":"a@b.c"}`, 0, ""},
		{"content type with charset", "application/json; charset=utf-8", `{"email":"a@b.c"}`, 0, ""},

		{"missing content type", "", `{"email":"a@b.c"}`, http.StatusUnsupportedMediaType, "application/json"},
		{"text/plain", "text/plain", `{"email":"a@b.c"}`, http.StatusUnsupportedMediaType, "application/json"},
		{"html form", "application/x-www-form-urlencoded", "email=a%40b.c", http.StatusUnsupportedMediaType, "application/json"},

		{"truncated JSON", "application/json", `{"email":`, http.StatusBadRequest, "not valid JSON"},
		{"not JSON at all", "application/json", `hello`, http.StatusBadRequest, "not valid JSON"},
		{"empty body", "application/json", ``, http.StatusBadRequest, "must not be empty"},
		{"unknown field", "application/json", `{"email":"a@b.c","admin":true}`, http.StatusBadRequest, "admin"},
		{"wrong field type", "application/json", `{"email":123}`, http.StatusBadRequest, "email"},
		{"two JSON values", "application/json", `{"email":"a"}{"email":"b"}`, http.StatusBadRequest, "single JSON value"},
		{"garbage after the value", "application/json", `{"email":"a"} xyz`, http.StatusBadRequest, "not valid JSON"},

		{"body over the limit", "application/json", tooBig, http.StatusRequestEntityTooLarge, "must not exceed"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(tc.body))
			if tc.contentType != "" {
				req.Header.Set("Content-Type", tc.contentType)
			}

			var got payload
			ok := DecodeJSON(rec, req, &got)

			if tc.wantStatus == 0 {
				if !ok {
					t.Fatalf("expected success, got %d %s", rec.Code, rec.Body.String())
				}
				if got.Email != "a@b.c" {
					t.Fatalf("expected email a@b.c, got %q", got.Email)
				}
				if rec.Body.Len() != 0 {
					t.Fatal("nothing may be written to the response on success")
				}

				return
			}

			if ok {
				t.Fatal("expected the decode to fail")
			}
			if rec.Code != tc.wantStatus {
				t.Fatalf("expected status %d, got %d", tc.wantStatus, rec.Code)
			}
			if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
				t.Fatalf("unexpected content type %q", ct)
			}

			detail, _ := decodeBody(t, rec)["detail"].(string)
			if !strings.Contains(detail, tc.wantDetail) {
				t.Fatalf("expected detail to contain %q, got %q", tc.wantDetail, detail)
			}
		})
	}
}
