package platform

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stepClock lets tests move time forward without sleeping.
type stepClock struct{ now time.Time }

func (c *stepClock) Now() time.Time          { return c.now }
func (c *stepClock) Advance(d time.Duration) { c.now = c.now.Add(d) }

func newTestLimiter(limit int, window time.Duration) (*Limiter, *stepClock) {
	clock := &stepClock{now: time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)}

	return NewLimiter(limit, window, WithLimiterClock(clock.Now)), clock
}

func TestLimiterAllow(t *testing.T) {
	const window = time.Minute

	t.Run("allows up to the limit, then blocks and says how long to wait", func(t *testing.T) {
		l, _ := newTestLimiter(3, window)

		for i := range 3 {
			if ok, _ := l.Allow("k"); !ok {
				t.Fatalf("attempt %d should be allowed", i+1)
			}
		}

		ok, retryAfter := l.Allow("k")
		if ok {
			t.Fatal("the 4th attempt should be blocked")
		}
		if retryAfter != window {
			t.Fatalf("expected to wait %v, got %v", window, retryAfter)
		}
	})

	t.Run("the time to wait shrinks as time passes", func(t *testing.T) {
		l, clock := newTestLimiter(1, window)
		l.Allow("k")

		clock.Advance(20 * time.Second)

		ok, retryAfter := l.Allow("k")
		if ok || retryAfter != 40*time.Second {
			t.Fatalf("expected blocked for 40s, got allowed=%v retry=%v", ok, retryAfter)
		}
	})

	t.Run("is allowed again once the window has passed", func(t *testing.T) {
		l, clock := newTestLimiter(1, window)
		l.Allow("k")

		clock.Advance(window - time.Second)
		if ok, _ := l.Allow("k"); ok {
			t.Fatal("one second before the end it must still be blocked")
		}

		clock.Advance(time.Second) // exactly one window after the attempt
		if ok, _ := l.Allow("k"); !ok {
			t.Fatal("after a full window it must be allowed")
		}
	})

	// A fixed window would reset at t=60s and allow 3 more at once.
	t.Run("the window slides instead of resetting all at once", func(t *testing.T) {
		l, clock := newTestLimiter(3, window)

		l.Allow("k") // t=0
		clock.Advance(30 * time.Second)
		l.Allow("k") // t=30
		clock.Advance(29 * time.Second)
		l.Allow("k") // t=59

		ok, retryAfter := l.Allow("k")
		if ok || retryAfter != time.Second {
			t.Fatalf("t=59: expected blocked for 1s, got allowed=%v retry=%v", ok, retryAfter)
		}

		clock.Advance(time.Second) // t=60: only the t=0 attempt left the window
		if ok, _ := l.Allow("k"); !ok {
			t.Fatal("t=60: one slot should be free")
		}

		ok, retryAfter = l.Allow("k")
		if ok || retryAfter != 30*time.Second {
			t.Fatalf("t=60: expected blocked for 30s, got allowed=%v retry=%v", ok, retryAfter)
		}
	})

	t.Run("blocked attempts do not extend the block", func(t *testing.T) {
		l, clock := newTestLimiter(1, window)
		l.Allow("k")

		clock.Advance(30 * time.Second)
		if ok, _ := l.Allow("k"); ok {
			t.Fatal("should be blocked")
		}

		clock.Advance(30 * time.Second) // one window after the ALLOWED attempt
		if ok, _ := l.Allow("k"); !ok {
			t.Fatal("the blocked attempt must not have restarted the window")
		}
	})

	t.Run("keys are independent", func(t *testing.T) {
		l, _ := newTestLimiter(1, window)
		l.Allow("alice")

		if ok, _ := l.Allow("bob"); !ok {
			t.Fatal("bob must not be affected by alice")
		}
		if ok, _ := l.Allow("alice"); ok {
			t.Fatal("alice should be blocked")
		}
	})

	t.Run("keys nobody uses anymore are removed", func(t *testing.T) {
		l, clock := newTestLimiter(1, window)
		for i := range 100 {
			l.Allow(fmt.Sprintf("key-%d", i))
		}
		if l.Len() != 100 {
			t.Fatalf("expected 100 keys, got %d", l.Len())
		}

		clock.Advance(2 * window)
		l.Allow("fresh")

		if l.Len() != 1 {
			t.Fatalf("expected only the fresh key to remain, got %d", l.Len())
		}
	})

	// Run with -race in CI: without the mutex this test would be flaky.
	t.Run("is safe for concurrent use", func(t *testing.T) {
		l, _ := newTestLimiter(10, window)

		var allowed atomic.Int64
		var wg sync.WaitGroup
		for range 100 {
			wg.Add(1)
			go func() {
				defer wg.Done()

				if ok, _ := l.Allow("k"); ok {
					allowed.Add(1)
				}
			}()
		}
		wg.Wait()

		if got := allowed.Load(); got != 10 {
			t.Fatalf("expected exactly 10 allowed attempts, got %d", got)
		}
	})
}

func TestNewLimiterRejectsInvalidConfig(t *testing.T) {
	cases := []struct {
		name   string
		limit  int
		window time.Duration
	}{
		{"zero limit", 0, time.Minute},
		{"negative limit", -1, time.Minute},
		{"zero window", 3, 0},
		{"negative window", 3, -time.Minute},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if recover() == nil {
					t.Fatal("expected a panic")
				}
			}()

			NewLimiter(tc.limit, tc.window)
		})
	}
}
