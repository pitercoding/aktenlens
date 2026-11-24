package platform

import (
	"encoding/json"
	"log"
	"net/http"
)

// WriteJSON writes body as JSON with the given status code.
func WriteJSON(
	w http.ResponseWriter,
	status int,
	body any,
) {
	writeBody(w, status, "application/json", body)
}

// writeBody is shared by WriteJSON and the problem writers. Headers are
// already sent when encoding fails, so the error can only be logged.
func writeBody(
	w http.ResponseWriter,
	status int,
	contentType string,
	body any,
) {
	w.Header().Set("Content-Type", contentType)
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}
