package platform

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
)

// maxJSONBodyBytes limits request bodies (1 MiB). Auth and question bodies
// are a few hundred bytes, so this is generous and still safe.
const maxJSONBodyBytes = 1 << 20

var errTrailingData = errors.New("trailing data after the JSON value")

// DecodeJSON reads the request body into dst, strictly. On any problem it
// writes the error response itself and returns false, so a handler only needs:
//
//	if !platform.DecodeJSON(w, r, &req) { return }
//
// Rules: Content-Type must be application/json, at most maxJSONBodyBytes,
// no unknown fields, and exactly one JSON value.
func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	if !isJSONContentType(r.Header.Get("Content-Type")) {
		WriteProblem(w, http.StatusUnsupportedMediaType, "Content-Type must be application/json")

		return false
	}

	// Passing w lets MaxBytesReader close the connection when the limit is hit.
	r.Body = http.MaxBytesReader(w, r.Body, maxJSONBodyBytes)

	dec := json.NewDecoder(r.Body)
	// An unexpected field is an error, not something to ignore silently.
	// This blocks "mass assignment" (for example, a client sending "role").
	dec.DisallowUnknownFields()

	err := dec.Decode(dst)
	if err == nil {
		// Decode reads only the first value. Anything after it must be an
		// end of file, otherwise the client sent more than one value.
		//
		// RawMessage accepts any JSON. A struct here would also be checked
		// by DisallowUnknownFields and fail with "unknown field" instead.
		var extra json.RawMessage

		switch err = dec.Decode(&extra); {
		case errors.Is(err, io.EOF):
			return true
		case err == nil:
			err = errTrailingData
		}
	}

	writeDecodeProblem(w, err)

	return false
}

func isJSONContentType(header string) bool {
	// ParseMediaType ignores parameters like "; charset=utf-8".
	mediaType, _, err := mime.ParseMediaType(header)

	return err == nil && mediaType == "application/json"
}

// writeDecodeProblem turns a decoding error into a client-friendly problem.
// Messages are written by us, so parser internals never reach the client.
func writeDecodeProblem(w http.ResponseWriter, err error) {
	var (
		syntaxErr *json.SyntaxError
		typeErr   *json.UnmarshalTypeError
		tooBigErr *http.MaxBytesError
	)

	switch {
	case errors.As(err, &tooBigErr):
		WriteProblem(w, http.StatusRequestEntityTooLarge,
			fmt.Sprintf("request body must not exceed %d bytes", tooBigErr.Limit))

	case errors.Is(err, io.EOF):
		WriteProblem(w, http.StatusBadRequest, "request body must not be empty")

	case errors.As(err, &syntaxErr), errors.Is(err, io.ErrUnexpectedEOF):
		WriteProblem(w, http.StatusBadRequest, "request body is not valid JSON")

	case errors.As(err, &typeErr):
		if typeErr.Field != "" {
			WriteProblem(w, http.StatusBadRequest,
				fmt.Sprintf("field %q has the wrong type", typeErr.Field))
		} else {
			WriteProblem(w, http.StatusBadRequest, "request body has the wrong type")
		}

	case errors.Is(err, errTrailingData):
		WriteProblem(w, http.StatusBadRequest, "request body must contain a single JSON value")

	// encoding/json has no typed error for unknown fields, only this text.
	case strings.HasPrefix(err.Error(), "json: unknown field "):
		WriteProblem(w, http.StatusBadRequest, strings.TrimPrefix(err.Error(), "json: "))

	default:
		WriteProblem(w, http.StatusBadRequest, "request body is not valid")
	}
}
