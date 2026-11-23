package auth

import (
	"maps"
	"net/mail"
	"slices"
	"strings"
	"unicode/utf8"
)

// Limits for user input. Passwords are counted in characters (runes), not bytes.
const (
	minPasswordLength = 12  // OWASP ASVS minimum
	maxPasswordLength = 128 // stops huge inputs from burning CPU in argon2
	maxEmailLength    = 254 // practical limit (RFC 5321); matches the DB CHECK
	minEmailLength    = 3
	maxTenantName     = 100
)

// ValidationError lists every invalid field. Fields maps a field name (as the
// API will expose it) to a message that is safe to show to the user.
type ValidationError struct {
	Fields map[string]string
}

func (e *ValidationError) Error() string {
	return "auth: invalid input: " + strings.Join(slices.Sorted(maps.Keys(e.Fields)), ", ")
}

// normalizeEmail is the single place that defines how e-mails are compared.
// The database CHECK requires exactly this form (lowercase, no spaces).
func normalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// validateRegister expects in to be already normalized. It returns nil or a
// *ValidationError that collects all problems.
func validateRegister(in RegisterInput) error {
	fields := make(map[string]string)

	if msg := checkEmail(in.Email); msg != "" {
		fields["email"] = msg
	}

	if n := utf8.RuneCountInString(in.Password); n < minPasswordLength || n > maxPasswordLength {
		fields["password"] = "must have between 12 and 128 characters"
	}

	if n := utf8.RuneCountInString(in.TenantName); n == 0 || n > maxTenantName {
		fields["tenant_name"] = "must have between 1 and 100 characters"
	}

	if len(fields) > 0 {
		return &ValidationError{Fields: fields}
	}

	return nil
}

// checkEmail returns an error message, or "" when the e-mail is acceptable.
func checkEmail(email string) string {
	const invalid = "is not a valid e-mail address"

	if len(email) < minEmailLength || len(email) > maxEmailLength {
		return invalid
	}

	// ParseAddress also accepts "Alice <a@x.com>". Requiring the parsed
	// address to equal the input rejects display names and quoted forms.
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return invalid
	}

	if _, domain, _ := strings.Cut(email, "@"); !strings.Contains(domain, ".") {
		return invalid
	}

	return ""
}
