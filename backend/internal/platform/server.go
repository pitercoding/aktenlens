package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

const (
	// readHeaderTimeout is the main defense against Slowloris: a client that
	// sends its headers byte by byte cannot hold a connection forever.
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 15 * time.Second
	writeTimeout      = 30 * time.Second
	idleTimeout       = 60 * time.Second

	// shutdownTimeout is how long in-flight requests have to finish after a
	// stop signal. It stays below the 10s Docker waits before killing a container.
	shutdownTimeout = 8 * time.Second
)

// NewServer returns an http.Server with timeouts. http.ListenAndServe has none,
// so one slow or malicious client could keep connections open forever.
func NewServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		WriteTimeout:      writeTimeout,
		IdleTimeout:       idleTimeout,
	}
}

// Serve runs srv on ln until ctx is canceled, then shuts it down gracefully:
// no new connections, and in-flight requests get shutdownTimeout to finish.
func Serve(ctx context.Context, srv *http.Server, ln net.Listener) error {
	serveErr := make(chan error, 1)
	go func() {
		serveErr <- srv.Serve(ln)
	}()

	select {
	case err := <-serveErr:
		// The server stopped by itself, before any stop signal.
		return err
	case <-ctx.Done():
	}

	// ctx is already canceled, so the shutdown needs a fresh context.
	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		return fmt.Errorf("graceful shutdown: %w", err)
	}

	// After Shutdown, Serve returns http.ErrServerClosed. That is the expected
	// result, not a failure.
	if err := <-serveErr; !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
