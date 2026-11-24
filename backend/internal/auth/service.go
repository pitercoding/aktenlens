package auth

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/pitercoding/aktenlens/backend/internal/store"
	"github.com/pitercoding/aktenlens/backend/internal/tenant"
)

// ErrEmailTaken means an account with this e-mail already exists.
var ErrEmailTaken = errors.New("auth: e-mail already registered")

// Postgres error code for unique_violation, and the name Postgres gave to the
// UNIQUE constraint on users.email.
const (
	uniqueViolation = "23505"
	emailConstraint = "users_email_key"
)

// Service holds the authentication use cases: register, login, logout and
// authenticate.
type Service struct {
	pool *pgxpool.Pool
	q    *store.Queries
	now  func() time.Time
}

// Option customizes a Service. Tests use it to control the clock.
type Option func(*Service)

// WithClock replaces time.Now, so tests can move time without sleeping.
func WithClock(now func() time.Time) Option {
	return func(s *Service) { s.now = now }
}

func NewService(pool *pgxpool.Pool, opts ...Option) *Service {
	s := &Service{pool: pool, q: store.New(pool), now: time.Now}

	for _, opt := range opts {
		opt(s)
	}

	return s
}

// RegisterInput is what the signup form sends.
type RegisterInput struct {
	TenantName string
	Email      string
	Password   string
}

// Account is the result of a signup. It deliberately has no password hash.
type Account struct {
	UserID   uuid.UUID
	TenantID uuid.UUID
	Email    string
	Role     tenant.Role
}

// Register creates a tenant, its first user and the owner membership in a
// single transaction: either all three exist afterwards, or none.
func (s *Service) Register(ctx context.Context, in RegisterInput) (Account, error) {
	in.TenantName = strings.TrimSpace(in.TenantName)
	in.Email = normalizeEmail(in.Email)

	if err := validateRegister(in); err != nil {
		return Account{}, err
	}

	// Hash before the transaction: argon2 takes tens of milliseconds, and we
	// should not hold a connection and an open transaction during that time.
	hash, err := HashPassword(in.Password)
	if err != nil {
		return Account{}, fmt.Errorf("hash password: %w", err)
	}

	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Account{}, fmt.Errorf("begin transaction: %w", err)
	}
	// Rollback after a successful Commit does nothing, so this is a safe
	// catch-all for every early return below.
	defer func() { _ = tx.Rollback(ctx) }()

	// A pgx.Tx can be used wherever the pool can, so the same sqlc queries
	// now run inside the transaction.
	q := store.New(tx)

	newTenant, err := q.CreateTenant(ctx, in.TenantName)
	if err != nil {
		return Account{}, fmt.Errorf("create tenant: %w", err)
	}

	user, err := q.CreateUser(ctx, store.CreateUserParams{
		Email:        in.Email,
		PasswordHash: hash,
	})
	if err != nil {
		// No "SELECT first, INSERT later": two concurrent signups would both
		// pass that check. The UNIQUE constraint is the real guarantee.
		if isEmailTaken(err) {
			return Account{}, ErrEmailTaken
		}

		return Account{}, fmt.Errorf("create user: %w", err)
	}

	err = q.CreateMembership(ctx, store.CreateMembershipParams{
		UserID:   user.ID,
		TenantID: newTenant.ID,
		Role:     string(tenant.RoleOwner),
	})
	if err != nil {
		return Account{}, fmt.Errorf("create membership: %w", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return Account{}, fmt.Errorf("commit signup: %w", err)
	}

	return Account{
		UserID:   user.ID,
		TenantID: newTenant.ID,
		Email:    user.Email,
		Role:     tenant.RoleOwner,
	}, nil
}

func isEmailTaken(err error) bool {
	var pgErr *pgconn.PgError

	return errors.As(err, &pgErr) &&
		pgErr.Code == uniqueViolation &&
		pgErr.ConstraintName == emailConstraint
}
