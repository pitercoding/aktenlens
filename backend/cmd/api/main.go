package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/pitercoding/aktenlens/backend/internal/platform"
)

func main() {
	// log.Fatal calls os.Exit, which skips deferred calls. Keeping the work in
	// run() lets "defer pool.Close()" execute before the process ends.
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	pool, err := platform.NewDBPool(context.Background(), os.Getenv("DATABASE_URL"))
	if err != nil {
		return err
	}
	defer pool.Close()

	mux := http.NewServeMux()
	platform.RegisterRoutes(mux, pool)

	log.Println("Aktenlens API running on http://localhost:8080")

	return http.ListenAndServe(":8080", mux)
}
