package auth

import (
	"crypto/sha256"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/pitercoding/aktenlens/backend/internal/platform"
)

// RateLimits groups the limiters of the public auth endpoints. A nil limiter
// means "no limit" (only tests should do that).
type RateLimits struct {
	LoginIP       *platform.Limiter
	LoginEmail    *platform.Limiter
	RegisterIP    *platform.Limiter
	RegisterEmail *platform.Limiter
}

// DefaultRateLimits are the production limits. Every attempt counts, right or
// wrong: the point is to make guessing passwords and mass signups too slow.
//
//   - Per e-mail (login): stops guessing the password of one account, even from
//     many addresses. Side effect: someone can block a victim's logins for up
//     to the window by failing on purpose. That trade-off goes in the ADR.
//   - Per IP: stops one address from trying many accounts. People behind the
//     same office or NAT address share it, so it is more generous.
func DefaultRateLimits() RateLimits {
	return RateLimits{
		LoginIP:       platform.NewLimiter(20, 15*time.Minute),
		LoginEmail:    platform.NewLimiter(5, 15*time.Minute),
		RegisterIP:    platform.NewLimiter(5, time.Hour),
		RegisterEmail: platform.NewLimiter(3, time.Hour),
	}
}

// HandlerOption customizes a Handler.
type HandlerOption func(*Handler)

// WithRateLimits replaces the default limits (tests, or tuning).
func WithRateLimits(limits RateLimits) HandlerOption {
	return func(h *Handler) { h.limits = limits }
}

// WithTrustedProxyHops tells the handlers how many reverse proxies of ours sit
// in front of the API, so the client address is read correctly. See
// platform.ClientIP. The default is 0 (clients connect directly).
func WithTrustedProxyHops(hops int) HandlerOption {
	return func(h *Handler) { h.trustedProxyHops = hops }
}

// allowIP applies a limiter to the caller's address.
func (h *Handler) allowIP(w http.ResponseWriter, r *http.Request, limiter *platform.Limiter) bool {
	return h.allow(w, limiter, platform.ClientIP(r, h.trustedProxyHops))
}

// allowEmail applies a limiter to an e-mail address, written the way the
// service will compare it (case and spaces do not create new buckets).
//
// The key is the SHA-256 of the e-mail: it has a fixed size, so a huge e-mail
// in a request cannot fill the memory, and addresses are not kept in RAM.
func (h *Handler) allowEmail(w http.ResponseWriter, limiter *platform.Limiter, email string) bool {
	sum := sha256.Sum256([]byte(normalizeEmail(email)))

	return h.allow(w, limiter, string(sum[:]))
}

// allow checks one limiter. When the limit is hit it answers 429 with a
// Retry-After header itself and returns false.
func (h *Handler) allow(w http.ResponseWriter, limiter *platform.Limiter, key string) bool {
	if limiter == nil {
		return true
	}

	ok, retryAfter := limiter.Allow(key)
	if ok {
		return true
	}

	// Retry-After is in whole seconds. Round up, and never say 0.
	seconds := max(int(math.Ceil(retryAfter.Seconds())), 1)
	w.Header().Set("Retry-After", strconv.Itoa(seconds))
	platform.WriteProblem(w, http.StatusTooManyRequests, "too many attempts, try again later")

	return false
}
