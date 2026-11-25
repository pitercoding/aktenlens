package main

import (
	"fmt"
	"strconv"
	"strings"
)

// maxTrustedProxyHops is a sanity limit. Nobody has ten reverse proxies in
// front of this API, so a bigger number is a typo.
const maxTrustedProxyHops = 10

// config holds the settings that come from environment variables and that
// change how the API behaves. (DATABASE_URL and PORT are read in main.)
type config struct {
	// SecureCookies makes the session cookie HTTPS-only. True by default:
	// forgetting the variable must never weaken production.
	SecureCookies bool

	// TrustedProxyHops is how many reverse proxies of ours sit in front of the
	// API. It decides how the client address is read (see platform.ClientIP).
	TrustedProxyHops int

	// TrustedOrigins are other origins (for example a frontend on another
	// domain) allowed to call state-changing endpoints (see platform.CSRFProtection).
	TrustedOrigins []string
}

// loadConfig reads and validates the settings. getenv is os.Getenv in
// production and a fake in tests. A wrong value is an error, so the API
// refuses to start instead of running with a setting nobody intended.
func loadConfig(getenv func(string) string) (config, error) {
	var (
		cfg config
		err error
	)

	if cfg.SecureCookies, err = parseSecureCookies(getenv("COOKIE_SECURE")); err != nil {
		return config{}, fmt.Errorf("COOKIE_SECURE: %w", err)
	}

	if cfg.TrustedProxyHops, err = parseTrustedProxyHops(getenv("TRUSTED_PROXY_HOPS")); err != nil {
		return config{}, fmt.Errorf("TRUSTED_PROXY_HOPS: %w", err)
	}

	cfg.TrustedOrigins = parseList(getenv("TRUSTED_ORIGINS"))

	return cfg, nil
}

// parseSecureCookies accepts only "true" or "false" (any case). Empty means
// the safe default: true.
func parseSecureCookies(value string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "true":
		return true, nil
	case "false":
		return false, nil
	default:
		return false, fmt.Errorf("must be true or false (got %q)", value)
	}
}

// parseTrustedProxyHops accepts a whole number from 0 to maxTrustedProxyHops.
// Empty means 0: clients connect directly and X-Forwarded-For is ignored.
func parseTrustedProxyHops(value string) (int, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, nil
	}

	n, err := strconv.Atoi(value)
	if err != nil || n < 0 || n > maxTrustedProxyHops {
		return 0, fmt.Errorf("must be a whole number from 0 to %d (got %q)", maxTrustedProxyHops, value)
	}

	return n, nil
}

// parseList splits a comma-separated list, trimming spaces and ignoring empty
// items. It returns nil for an empty list. The items themselves are validated
// where they are used.
func parseList(value string) []string {
	var items []string

	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			items = append(items, item)
		}
	}

	return items
}
