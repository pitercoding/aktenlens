package platform

import (
	"sync"
	"time"
)

// Limiter allows at most limit attempts per key inside a sliding window.
//
// It keeps the time of each recent attempt (a "sliding window log"). That is
// exact: unlike a fixed window, a client cannot make 2x the limit by sending
// half before and half after a window boundary. Each key holds at most limit
// timestamps, so memory stays small.
//
// The state is in memory, so it is per process and lost on restart. That is
// fine for one API instance; several instances would need a shared store.
type Limiter struct {
	mu       sync.Mutex
	limit    int
	window   time.Duration
	now      func() time.Time
	attempts map[string][]time.Time

	// lastSweep is when keys nobody uses anymore were last removed.
	lastSweep time.Time
}

// LimiterOption customizes a Limiter.
type LimiterOption func(*Limiter)

// WithLimiterClock replaces time.Now, so tests can move time without sleeping.
func WithLimiterClock(now func() time.Time) LimiterOption {
	return func(l *Limiter) { l.now = now }
}

// NewLimiter allows limit attempts per key in each window. A non-positive
// limit or window is a programming error and panics at startup, instead of
// silently blocking everyone or nobody.
func NewLimiter(limit int, window time.Duration, opts ...LimiterOption) *Limiter {
	if limit < 1 || window <= 0 {
		panic("platform: limiter needs a positive limit and window")
	}

	l := &Limiter{
		limit:    limit,
		window:   window,
		now:      time.Now,
		attempts: make(map[string][]time.Time),
	}
	for _, opt := range opts {
		opt(l)
	}

	l.lastSweep = l.now()

	return l
}

// Allow records an attempt for key. It returns true when the attempt is
// within the limit. Otherwise it returns false and how long the caller must
// wait until the oldest attempt leaves the window.
//
// Blocked attempts are not recorded, so hammering a blocked key does not
// extend the block.
func (l *Limiter) Allow(key string) (allowed bool, retryAfter time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	l.sweepLocked(now)

	recent := l.recentLocked(key, now)
	if len(recent) >= l.limit {
		l.attempts[key] = recent

		// recent[0] is the oldest attempt still inside the window.
		return false, recent[0].Add(l.window).Sub(now)
	}

	l.attempts[key] = append(recent, now)

	return true, 0
}

// Len returns how many keys are being tracked. It is mostly useful in tests.
func (l *Limiter) Len() int {
	l.mu.Lock()
	defer l.mu.Unlock()

	return len(l.attempts)
}

// recentLocked returns the attempts of key that are still inside the window
// (now-window, now]. An attempt exactly window old has already left it.
func (l *Limiter) recentLocked(key string, now time.Time) []time.Time {
	cutoff := now.Add(-l.window)
	times := l.attempts[key]

	// Attempts are stored in order, so the old ones are at the front.
	i := 0
	for i < len(times) && !times[i].After(cutoff) {
		i++
	}

	return times[i:]
}

// sweepLocked removes keys whose attempts are all outside the window. It runs
// at most once per window, so Allow stays cheap and no background goroutine
// is needed.
func (l *Limiter) sweepLocked(now time.Time) {
	if now.Sub(l.lastSweep) < l.window {
		return
	}
	l.lastSweep = now

	cutoff := now.Add(-l.window)
	for key, times := range l.attempts {
		if len(times) == 0 || !times[len(times)-1].After(cutoff) {
			delete(l.attempts, key)
		}
	}
}
