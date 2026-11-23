package auth

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"github.com/pitercoding/aktenlens/backend/internal/store"
)

// sessionTTL is how long a login stays valid.
const sessionTTL = 7 * 24 * time.Hour

var (
	// ErrInvalidCredentials is the only error a failed login reports. It is
	// the same for "unknown e-mail" and "wrong password" on purpose.
	ErrInvalidCredentials = errors.New("auth: invalid e-mail or password")

	// ErrUnauthenticated means there is no valid session for this token.
	ErrUnauthenticated = errors.New("auth: not authenticated")
)

// dummyHash is a real argon2id hash (same parameters as real ones) that no
// password matches. Verifying against it makes "unknown e-mail" cost as much
// CPU as "wrong password". It is built once, on first use.
var dummyHash = sync.OnceValue(func() string {
	hash, err := HashPassword("password-nobody-will-ever-use")
	if err != nil {
		// Only possible if the system random source is broken: unrecoverable.
		panic(fmt.Sprintf("build dummy password hash: %v", err))
	}

	return hash
})

// LoginInput is what the login form sends.
type LoginInput struct {
	Email    string
	Password string
}

// Session is a freshly created login. Token goes to the client (cookie) and
// must never be logged or stored. ExpiresAt sets the cookie lifetime.
type Session struct {
	Token     string
	ExpiresAt time.Time
}

// Login checks the credentials and creates a session.
func (s *Service) Login(ctx context.Context, in LoginInput) (Session, error) {
	email := normalizeEmail(in.Email)

	// Inputs that can never be valid are rejected before spending CPU on
	// argon2 or touching the database.
	if len(email) > maxEmailLength || utf8.RuneCountInString(in.Password) > maxPasswordLength {
		return Session{}, ErrInvalidCredentials
	}

	user, err := s.q.GetUserByEmail(ctx, email)
	if errors.Is(err, pgx.ErrNoRows) {
		// Burn the same CPU as a real check, so the response time does not
		// reveal that this e-mail has no account. The result is ignored.
		_, _ = VerifyPassword(in.Password, dummyHash())

		return Session{}, ErrInvalidCredentials
	}
	if err != nil {
		return Session{}, fmt.Errorf("get user: %w", err)
	}

	ok, err := VerifyPassword(in.Password, user.PasswordHash)
	if err != nil {
		// A corrupted hash is our bug, not the user's mistake: it must not
		// look like "wrong password".
		return Session{}, fmt.Errorf("verify password: %w", err)
	}
	if !ok {
		return Session{}, ErrInvalidCredentials
	}

	token, tokenHash, err := NewSessionToken()
	if err != nil {
		return Session{}, err
	}

	expiresAt := s.now().Add(sessionTTL)

	err = s.q.CreateSession(ctx, store.CreateSessionParams{
		TokenHash: tokenHash,
		UserID:    user.ID,
		ExpiresAt: expiresAt,
	})
	if err != nil {
		return Session{}, fmt.Errorf("create session: %w", err)
	}

	return Session{Token: token, ExpiresAt: expiresAt}, nil
}

// Authenticate turns a session token into the account that owns it. Any
// problem (empty, unknown, expired, logged out) is ErrUnauthenticated.
func (s *Service) Authenticate(ctx context.Context, token string) (Account, error) {
	if token == "" {
		return Account{}, ErrUnauthenticated
	}

	row, err := s.q.GetSessionPrincipal(ctx, store.GetSessionPrincipalParams{
		TokenHash: HashSessionToken(token),
		Now:       s.now(),
	})
	if errors.Is(err, pgx.ErrNoRows) {
		return Account{}, ErrUnauthenticated
	}
	if err != nil {
		return Account{}, fmt.Errorf("get session: %w", err)
	}

	return Account{
		UserID:   row.UserID,
		TenantID: row.TenantID,
		Email:    row.Email,
		Role:     row.Role,
	}, nil
}

// Logout deletes the session on the server, so the token stops working even
// if someone kept a copy. It is idempotent: an unknown token is not an error.
func (s *Service) Logout(ctx context.Context, token string) error {
	if err := s.q.DeleteSession(ctx, HashSessionToken(token)); err != nil {
		return fmt.Errorf("delete session: %w", err)
	}

	return nil
}
