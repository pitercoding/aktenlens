package main

import (
	"log"
	"net/http"

	"github.com/pitercoding/aktenlens/backend/internal/platform"
)

func main() {
	mux := http.NewServeMux()

	platform.RegisterRoutes(mux)

	log.Println("Aktenlens API running on http://localhost:8080")

	if err := http.ListenAndServe(":8080", mux); err != nil {
		log.Fatal(err)
	}
}
