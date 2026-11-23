package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// tokenBytes is the size of the random part of a session token: 256 bits.
const tokenBytes = 32

// NewSessionToken creates a random session token.
//
// token goes to the client (in a cookie) and must never be stored or logged.
// tokenHash is what the database keeps (sessions.token_hash).
func NewSessionToken() (token string, tokenHash []byte, err error) {
	raw := make([]byte, tokenBytes)
	// crypto/rand, never math/rand: math/rand is predictable.
	if _, err = rand.Read(raw); err != nil {
		return "", nil, fmt.Errorf("generate session token: %w", err)
	}

	// URL-safe alphabet without padding: no '+', '/' or '=' in the cookie.
	token = base64.RawURLEncoding.EncodeToString(raw)

	return token, HashSessionToken(token), nil
}

// HashSessionToken returns the SHA-256 of a token.
//
// A fast, unsalted hash is correct here, unlike for passwords: the token has
// 256 random bits, so it cannot be guessed, and the database needs to find
// the row by hash with a plain index lookup.
func HashSessionToken(token string) []byte {
	sum := sha256.Sum256([]byte(token))

	return sum[:]
}
