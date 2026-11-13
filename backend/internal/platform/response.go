package platform

import (
	"encoding/json"
	"log"
	"net/http"
)

// writeJSON writes body as JSON with the given status code. Headers are
// already sent when encoding fails, so the error can only be logged.
func writeJSON(
	w http.ResponseWriter,
	status int,
	body any,
) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	if err := json.NewEncoder(w).Encode(body); err != nil {
		log.Printf("failed to encode response: %v", err)
	}
}
