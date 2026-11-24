package platform

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

// decodeBody parses a JSON response body into a generic map.
func decodeBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("response body is not JSON: %v (%q)", err, rec.Body.String())
	}

	return body
}

func TestWriteProblem(t *testing.T) {
	t.Run("writes an RFC 9457 problem document", func(t *testing.T) {
		rec := httptest.NewRecorder()

		WriteProblem(rec, http.StatusNotFound, "document not found")

		if rec.Code != http.StatusNotFound {
			t.Fatalf("expected status 404, got %d", rec.Code)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
			t.Fatalf("unexpected content type %q", got)
		}

		want := map[string]any{
			"type":   "about:blank",
			"title":  "Not Found",
			"status": float64(404), // JSON numbers decode as float64
			"detail": "document not found",
		}
		if got := decodeBody(t, rec); !reflect.DeepEqual(got, want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
	})

	t.Run("omits detail when it is empty", func(t *testing.T) {
		rec := httptest.NewRecorder()

		WriteProblem(rec, http.StatusUnauthorized, "")

		if _, found := decodeBody(t, rec)["detail"]; found {
			t.Fatal("expected no detail field")
		}
	})
}

func TestWriteValidationProblem(t *testing.T) {
	rec := httptest.NewRecorder()
	fields := map[string]string{"email": "is not a valid e-mail address"}

	WriteValidationProblem(rec, fields)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected status 422, got %d", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/problem+json" {
		t.Fatalf("unexpected content type %q", got)
	}

	body := decodeBody(t, rec)
	if body["title"] != http.StatusText(http.StatusUnprocessableEntity) {
		t.Fatalf("unexpected title %v", body["title"])
	}

	want := map[string]any{"email": "is not a valid e-mail address"}
	if !reflect.DeepEqual(body["errors"], want) {
		t.Fatalf("expected errors %v, got %v", want, body["errors"])
	}
}
