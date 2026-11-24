package platform

import (
	"fmt"
	"net/http"
)

// CSRFProtection returns a middleware that blocks cross-site requests which
// change data (POST, PUT, PATCH, DELETE). GET, HEAD and OPTIONS always pass,
// so they must never change anything.
//
// It uses the standard library's http.CrossOriginProtection: browsers tell
// the server where a request comes from (Sec-Fetch-Site, Origin), and a
// request started by another site is refused. Requests without those headers
// (curl, scripts) are not browser requests and pass.
//
// trustedOrigins lists origins ("scheme://host[:port]", no path) that may call
// the API even though they are another site, for example a frontend served
// from a different domain. An invalid origin is an error, so a typo in the
// configuration stops the API at startup.
func CSRFProtection(trustedOrigins ...string) (func(http.Handler) http.Handler, error) {
	protection := http.NewCrossOriginProtection()

	for _, origin := range trustedOrigins {
		if err := protection.AddTrustedOrigin(origin); err != nil {
			return nil, fmt.Errorf("csrf protection: %w", err)
		}
	}

	// Answer with the same Problem Details format as every other error.
	protection.SetDenyHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		WriteProblem(w, http.StatusForbidden, "cross-origin request blocked")
	}))

	return protection.Handler, nil
}
