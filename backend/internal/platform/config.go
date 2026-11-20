package platform

import (
	"errors"
	"fmt"
	"strconv"
)

// defaultPort is used when PORT is not set, which is the normal case in
// local development. Hosting platforms like Render set PORT themselves.
const defaultPort = "8080"

// ErrInvalidPort is returned when PORT is set but is not a usable port number.
var ErrInvalidPort = errors.New("PORT must be a number between 1 and 65535")

// ListenAddr turns the value of the PORT environment variable into an address
// for net.Listen (for example ":8080"). An empty value means the default port.
// The value comes from outside the program, so it is validated here and the
// API refuses to start if it is wrong.
func ListenAddr(port string) (string, error) {
	if port == "" {
		port = defaultPort
	}

	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", fmt.Errorf("%w (got %q)", ErrInvalidPort, port)
	}

	// Itoa normalizes the number (for example "08080" becomes "8080").
	return ":" + strconv.Itoa(n), nil
}
