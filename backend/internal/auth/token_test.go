package auth_test

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
)

func TestNewSessionToken(t *testing.T) {
	t.Run("token is 32 random bytes in URL-safe base64", func(t *testing.T) {
		token, _, err := auth.NewSessionToken()
		if err != nil {
			t.Fatalf("new token: %v", err)
		}

		// RawURLEncoding has no '+', '/' or '=', so it is safe in a cookie.
		raw, err := base64.RawURLEncoding.DecodeString(token)
		if err != nil {
			t.Fatalf("token is not URL-safe base64: %v", err)
		}
		if len(raw) != 32 {
			t.Fatalf("expected 32 raw bytes, got %d", len(raw))
		}
		// 32 bytes encode to 43 characters.
		if len(token) != 43 {
			t.Fatalf("expected 43 characters, got %d", len(token))
		}
	})

	t.Run("hash is 32 bytes and matches HashSessionToken", func(t *testing.T) {
		token, hash, err := auth.NewSessionToken()
		if err != nil {
			t.Fatalf("new token: %v", err)
		}

		// sessions.token_hash has CHECK (octet_length(token_hash) = 32).
		if len(hash) != 32 {
			t.Fatalf("expected a 32-byte hash, got %d", len(hash))
		}
		if !bytes.Equal(hash, auth.HashSessionToken(token)) {
			t.Fatal("returned hash must equal HashSessionToken(token)")
		}
	})

	t.Run("tokens are unique", func(t *testing.T) {
		seen := make(map[string]bool)

		for range 1000 {
			token, _, err := auth.NewSessionToken()
			if err != nil {
				t.Fatalf("new token: %v", err)
			}
			if seen[token] {
				t.Fatalf("duplicate token %q", token)
			}
			seen[token] = true
		}
	})
}

func TestHashSessionToken(t *testing.T) {
	t.Run("is SHA-256 (known test vector)", func(t *testing.T) {
		// SHA-256("abc") from FIPS 180-2. Proves it is the real algorithm,
		// not just "some 32 bytes".
		const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"

		got := hex.EncodeToString(auth.HashSessionToken("abc"))

		if got != want {
			t.Fatalf("expected %s, got %s", want, got)
		}
	})

	t.Run("is deterministic", func(t *testing.T) {
		first := auth.HashSessionToken("some-token")
		second := auth.HashSessionToken("some-token")

		if !bytes.Equal(first, second) {
			t.Fatal("same token must always give the same hash")
		}
	})

	t.Run("different tokens give different hashes", func(t *testing.T) {
		first := auth.HashSessionToken("token-a")
		second := auth.HashSessionToken("token-b")

		if bytes.Equal(first, second) {
			t.Fatal("different tokens must not collide")
		}
	})
}
