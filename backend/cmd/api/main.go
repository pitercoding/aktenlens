package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/pitercoding/aktenlens/backend/internal/platform"
)

// version is set at build time with -ldflags "-X main.version=<commit>".
// Without it (go run, local builds) it stays "dev".
var version = "dev"

func main() {
	// log.Fatal calls os.Exit, which skips deferred calls. Keeping the work in
	// run() lets the deferred cleanups execute before the process ends.
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	// ctx is canceled on Ctrl+C (os.Interrupt) or when Docker stops the
	// container (SIGTERM).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := platform.NewDBPool(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	// Deferred calls run in reverse order: the HTTP server stops first (Serve
	// returns), and only then the pool closes, so in-flight requests can still
	// use the database.
	defer pool.Close()

	mux := http.NewServeMux()
	platform.RegisterRoutes(mux, pool, version)

	// PORT is set by hosting platforms (Render); locally it falls back to 8080.
	addr, err := platform.ListenAddr(os.Getenv("PORT"))
	if err != nil {
		return err
	}

	srv := platform.NewServer(addr, mux)

	ln, err := net.Listen("tcp", srv.Addr)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", srv.Addr, err)
	}

	log.Printf("Aktenlens API %s listening on %s", version, ln.Addr())

	return platform.Serve(ctx, srv, ln)
}
