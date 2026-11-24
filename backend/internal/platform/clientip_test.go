package platform

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	cases := []struct {
		name   string
		hops   int
		remote string
		xff    []string // each item is one X-Forwarded-For header line
		want   string
	}{
		// Direct connections: the header is never trusted.
		{"no proxy uses the connection address", 0, "203.0.113.7:51234", nil, "203.0.113.7"},
		{"no proxy ignores X-Forwarded-For (it can be forged)", 0, "203.0.113.7:51234", []string{"1.2.3.4"}, "203.0.113.7"},
		{"negative hops behave like zero", -1, "203.0.113.7:1", []string{"1.2.3.4"}, "203.0.113.7"},
		{"IPv6 connection address", 0, "[2001:db8::1]:443", nil, "2001:db8::1"},
		{"address without a port", 0, "203.0.113.7", nil, "203.0.113.7"},
		{"IPv4-mapped IPv6 is normalized", 0, "[::ffff:203.0.113.7]:80", nil, "203.0.113.7"},

		// Behind our own proxies: count from the right.
		{"one proxy uses the last entry", 1, "10.0.0.1:1111", []string{"198.51.100.9"}, "198.51.100.9"},
		{"one proxy ignores forged entries on the left", 1, "10.0.0.1:1111", []string{"6.6.6.6, 198.51.100.9"}, "198.51.100.9"},
		{"several header lines count as one list", 1, "10.0.0.1:1111", []string{"6.6.6.6", "198.51.100.9"}, "198.51.100.9"},
		{"two proxies use the second entry from the right", 2, "10.0.0.1:1111", []string{"198.51.100.9, 10.0.0.5"}, "198.51.100.9"},
		{"spaces are trimmed", 1, "10.0.0.1:1111", []string{"  198.51.100.9  "}, "198.51.100.9"},
		{"IPv6 client", 1, "10.0.0.1:1111", []string{"2001:db8::7"}, "2001:db8::7"},

		// Anything odd falls back to the connection address.
		{"no header falls back", 1, "10.0.0.1:1111", nil, "10.0.0.1"},
		{"fewer entries than hops falls back", 2, "10.0.0.1:1111", []string{"198.51.100.9"}, "10.0.0.1"},
		{"garbage entry falls back", 1, "10.0.0.1:1111", []string{"not-an-ip"}, "10.0.0.1"},
		{"empty last entry falls back", 1, "10.0.0.1:1111", []string{"198.51.100.9,"}, "10.0.0.1"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/", nil)
			req.RemoteAddr = tc.remote
			for _, line := range tc.xff {
				req.Header.Add("X-Forwarded-For", line)
			}

			if got := ClientIP(req, tc.hops); got != tc.want {
				t.Fatalf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}
