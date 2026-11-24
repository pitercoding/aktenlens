package platform

import (
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// ClientIP returns the address of whoever is calling, for rate limiting.
//
// trustedProxyHops is how many reverse proxies of ours sit in front of the
// API (0 when clients connect directly, 1 behind a single load balancer).
//
//   - With 0 hops the X-Forwarded-For header is ignored: a client can write
//     anything in it, so trusting it would let an attacker dodge every limit.
//   - With N hops, each of our proxies appends the address it saw to the END
//     of the header. The entry N places from the right is the first one added
//     by infrastructure we trust. Entries to its left can be forged.
//
// If the header is missing or malformed, it falls back to the connection
// address, which is never forged.
func ClientIP(r *http.Request, trustedProxyHops int) string {
	remote := remoteIP(r)
	if trustedProxyHops <= 0 {
		return remote
	}

	// A proxy may send several header lines; they count as one list.
	header := strings.Join(r.Header.Values("X-Forwarded-For"), ",")
	if header == "" {
		return remote
	}

	entries := strings.Split(header, ",")
	if len(entries) < trustedProxyHops {
		return remote
	}

	candidate := strings.TrimSpace(entries[len(entries)-trustedProxyHops])

	addr, err := netip.ParseAddr(candidate)
	if err != nil {
		return remote
	}

	return addr.Unmap().String()
}

// remoteIP is the address of the TCP connection, without the port.
func remoteIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}

	// Unmap turns "::ffff:1.2.3.4" into "1.2.3.4", so one client has one key.
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.Unmap().String()
	}

	return host
}
