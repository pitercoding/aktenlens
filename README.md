# Aktenlens

[![ci-backend](https://github.com/pitercoding/aktenlens/actions/workflows/ci-backend.yml/badge.svg)](https://github.com/pitercoding/aktenlens/actions/workflows/ci-backend.yml)

Aktenlens is a multi-tenant AI document intelligence platform.
It is in early development.

## What works today

- A Go API with two health endpoints:
  - `GET /healthz` answers `200` when the process is alive.
  - `GET /readyz` answers `200` when the database is reachable, and `503` when it is not.
- An HTTP server with timeouts and graceful shutdown.
- A PostgreSQL connection pool.
- PostgreSQL with the pgvector extension, running in Docker Compose.
- Database migrations with goose (first migration: the `tenants` table).
- Automated checks on every pull request: formatting, `go vet`, tests with the race detector, `golangci-lint` (with gosec) and `govulncheck`.

## Requirements

- Go 1.26 or newer
- Docker
- `make` and a bash shell (on Windows, use Git Bash)

## Run it locally

```bash
# 1. Create your local settings, then open .env and replace "change-me"
cp .env.example .env

# 2. Start PostgreSQL in Docker
make db

# 3. Create the database tables
make migrate

# 4. Start the API on http://localhost:8080
make run
```

In another terminal:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

Run `make help` to see all commands.

## Tests

```bash
make test        # all backend tests
make test-race   # same, with the race detector (needs a 64-bit C compiler)
```

## Project layout

```text
backend/    Go code (API, database migrations)
compose.yaml  PostgreSQL for local development
Makefile    shortcuts for the common commands
```

## License

MIT
