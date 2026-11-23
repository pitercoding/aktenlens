package auth_test

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"golang.org/x/crypto/argon2"

	"github.com/pitercoding/aktenlens/backend/internal/auth"
)

func TestHashPassword(t *testing.T) {
	t.Run("uses the PHC format with argon2id and our parameters", func(t *testing.T) {
		hash, err := auth.HashPassword("correct horse battery staple")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}

		const prefix = "$argon2id$v=19$m=19456,t=2,p=1$"
		if !strings.HasPrefix(hash, prefix) {
			t.Fatalf("expected prefix %q, got %q", prefix, hash)
		}
	})

	t.Run("same password gives different hashes (random salt)", func(t *testing.T) {
		first, err := auth.HashPassword("same password")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		second, err := auth.HashPassword("same password")
		if err != nil {
			t.Fatalf("hash: %v", err)
		}

		if first == second {
			t.Fatal("expected different hashes because of the random salt")
		}
	})
}

func TestVerifyPassword(t *testing.T) {
	longA := strings.Repeat("a", 100) + "X"
	longB := strings.Repeat("a", 100) + "Y"

	cases := []struct {
		name     string
		password string // used to create the hash
		attempt  string // used to verify
		want     bool
	}{
		{"correct password", "s3cret-Passw0rd", "s3cret-Passw0rd", true},
		{"wrong password", "s3cret-Passw0rd", "s3cret-Passw0rd!", false},
		{"is case sensitive", "Password", "password", false},
		{"unicode password", "pässwörd-日本語", "pässwörd-日本語", true},
		// bcrypt would truncate at 72 bytes and accept this. argon2 must not.
		{"long passwords are not truncated", longA, longB, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash, err := auth.HashPassword(tc.password)
			if err != nil {
				t.Fatalf("hash: %v", err)
			}

			got, err := auth.VerifyPassword(tc.attempt, hash)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got != tc.want {
				t.Fatalf("expected %v, got %v", tc.want, got)
			}
		})
	}

	// Parameters must come from the stored hash, not from our constants.
	// This is what lets us raise the cost later without locking users out.
	t.Run("verifies a hash made with other parameters", func(t *testing.T) {
		b64 := base64.RawStdEncoding
		salt := []byte("0123456789abcdef")
		key := argon2.IDKey([]byte("secret"), salt, 1, 8*1024, 1, 32)

		encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
			argon2.Version, 8*1024, 1, 1, b64.EncodeToString(salt), b64.EncodeToString(key))

		got, err := auth.VerifyPassword("secret", encoded)
		if err != nil {
			t.Fatalf("verify: %v", err)
		}
		if !got {
			t.Fatal("expected the password to verify")
		}
	})
}

// A corrupted hash in the database must produce an error, never a panic.
// argon2.IDKey panics on t < 1 or p < 1, and would try to allocate whatever
// memory the hash asks for, so these must be rejected before hashing.
func TestVerifyPasswordMalformedHash(t *testing.T) {
	const salt = "MDEyMzQ1Njc4OWFiY2RlZg" // 16 bytes in base64
	key := strings.Repeat("A", 43)        // 32 bytes in base64

	build := func(variant, version, params, salt, key string) string {
		return strings.Join([]string{"", variant, version, params, salt, key}, "$")
	}
	const okParams = "m=19456,t=2,p=1"

	cases := []struct {
		name string
		hash string
	}{
		{"empty string", ""},
		{"not a hash", "not-a-hash"},
		{"truncated", "$argon2id$v=19$m=19456,t=2,p=1$" + salt},
		{"extra part", build("argon2id", "v=19", okParams, salt, key) + "$extra"},
		{"other variant (argon2i)", build("argon2i", "v=19", okParams, salt, key)},
		{"other version", build("argon2id", "v=18", okParams, salt, key)},
		{"params are not numbers", build("argon2id", "v=19", "m=abc,t=2,p=1", salt, key)},
		{"params with trailing garbage", build("argon2id", "v=19", okParams+"xyz", salt, key)},
		{"zero iterations (would panic)", build("argon2id", "v=19", "m=19456,t=0,p=1", salt, key)},
		{"zero parallelism (would panic)", build("argon2id", "v=19", "m=19456,t=2,p=0", salt, key)},
		{"absurd memory (4 GiB)", build("argon2id", "v=19", "m=4194304,t=2,p=1", salt, key)},
		{"salt is not base64", build("argon2id", "v=19", okParams, "!!!", key)},
		{"empty salt", build("argon2id", "v=19", okParams, "", key)},
		{"hash is not base64", build("argon2id", "v=19", okParams, salt, "!!!")},
		{"hash has the wrong length", build("argon2id", "v=19", okParams, salt, "AAAA")},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := auth.VerifyPassword("whatever", tc.hash)

			if ok {
				t.Fatal("a malformed hash must never verify")
			}
			if !errors.Is(err, auth.ErrInvalidHash) {
				t.Fatalf("expected ErrInvalidHash, got %v", err)
			}
		})
	}
}
