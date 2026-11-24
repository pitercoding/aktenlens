package platform

import "net/http"

// problemContentType is the media type defined by RFC 9457.
const problemContentType = "application/problem+json"

// problem is the RFC 9457 document. Errors is an extension member (the RFC
// allows them) that lists invalid fields: field name -> message.
type problem struct {
	Type   string            `json:"type"`
	Title  string            `json:"title"`
	Status int               `json:"status"`
	Detail string            `json:"detail,omitempty"`
	Errors map[string]string `json:"errors,omitempty"`
}

// WriteProblem answers with an RFC 9457 error. detail must be safe to show to
// the client: never put internal errors (SQL, stack traces) in it. Log those.
func WriteProblem(w http.ResponseWriter, status int, detail string) {
	writeBody(w, status, problemContentType, problem{
		// "about:blank" means "no special meaning beyond the HTTP status".
		Type:   "about:blank",
		Title:  http.StatusText(status),
		Status: status,
		Detail: detail,
	})
}

// WriteValidationProblem answers 422 with one message per invalid field.
// 400 is for requests we cannot even parse; 422 is for well-formed requests
// whose data breaks the rules.
func WriteValidationProblem(w http.ResponseWriter, fields map[string]string) {
	writeBody(w, http.StatusUnprocessableEntity, problemContentType, problem{
		Type:   "about:blank",
		Title:  http.StatusText(http.StatusUnprocessableEntity),
		Status: http.StatusUnprocessableEntity,
		Detail: "one or more fields are invalid",
		Errors: fields,
	})
}
