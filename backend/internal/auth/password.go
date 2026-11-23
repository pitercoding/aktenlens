// Package auth holds the authentication building blocks: password hashing,
// session tokens, and (in later steps) the service and HTTP middleware.
package auth

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Cost parameters for new hashes (OWASP minimum for argon2id: 19 MiB, t=2, p=1).
// Memory is the main cost, and every login in flight holds this much RAM.
// Raising these later is safe: each hash carries its own parameters.
const (
	memoryKiB   uint32 = 19 * 1024
	iterations  uint32 = 2
	parallelism uint8  = 1
	saltLength         = 16
	keyLength   uint32 = 32

	// maxMemoryKiB stops a corrupted hash from making us allocate gigabytes.
	maxMemoryKiB uint32 = 256 * 1024
)

// ErrInvalidHash means the stored hash is malformed. It is not "wrong
// password": that case returns (false, nil).
var ErrInvalidHash = errors.New("auth: invalid password hash")

// b64 is the encoding used by the PHC string format (no padding).
var b64 = base64.RawStdEncoding

// HashPassword returns a self-describing argon2id hash:
//
//	$argon2id$v=19$m=19456,t=2,p=1$<salt>$<key>
func HashPassword(password string) (string, error) {
	salt := make([]byte, saltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}

	key := argon2.IDKey([]byte(password), salt, iterations, memoryKiB, parallelism, keyLength)

	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memoryKiB, iterations, parallelism,
		b64.EncodeToString(salt), b64.EncodeToString(key)), nil
}

// VerifyPassword reports whether password matches encoded. A wrong password
// is (false, nil). Only a malformed hash returns an error.
func VerifyPassword(password, encoded string) (bool, error) {
	h, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}

	// Recompute with the parameters stored in the hash, not our constants.
	got := argon2.IDKey([]byte(password), h.salt, h.iterations, h.memory, h.parallelism, keyLength)

	// Constant time: == would stop at the first different byte and leak timing.
	return subtle.ConstantTimeCompare(got, h.key) == 1, nil
}

type decodedHash struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	salt        []byte
	key         []byte
}

// decodeHash parses and strictly validates a PHC string.
func decodeHash(encoded string) (decodedHash, error) {
	// "$argon2id$v=19$m=..,t=..,p=..$salt$key" splits into 6 parts, the first empty.
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return decodedHash{}, ErrInvalidHash
	}

	if parts[2] != fmt.Sprintf("v=%d", argon2.Version) {
		return decodedHash{}, ErrInvalidHash
	}

	var h decodedHash
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &h.memory, &h.iterations, &h.parallelism); err != nil {
		return decodedHash{}, ErrInvalidHash
	}
	// Sscanf ignores trailing text, so rebuild the string and compare. It
	// must match exactly (this also rejects "+5" and leading zeros).
	if parts[3] != fmt.Sprintf("m=%d,t=%d,p=%d", h.memory, h.iterations, h.parallelism) {
		return decodedHash{}, ErrInvalidHash
	}

	// argon2.IDKey panics when iterations or parallelism is 0.
	if h.iterations < 1 || h.parallelism < 1 || h.memory < 8 || h.memory > maxMemoryKiB {
		return decodedHash{}, ErrInvalidHash
	}

	var err error
	if h.salt, err = b64.DecodeString(parts[4]); err != nil || len(h.salt) == 0 {
		return decodedHash{}, ErrInvalidHash
	}

	// We only ever create 32-byte keys, so any other size is not ours.
	if h.key, err = b64.DecodeString(parts[5]); err != nil || len(h.key) != int(keyLength) {
		return decodedHash{}, ErrInvalidHash
	}

	return h, nil
}
