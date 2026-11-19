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
- A small Docker image for the API (multi-stage build, distroless, runs as a non-root user).
- Automated checks on every pull request: formatting, `go vet`, tests with the race detector, `golangci-lint` (with gosec) and `govulncheck`.

## Requirements

- Go 1.26 or newer (needed for the tests and for `make migrate`)
- Docker
- `make` and a bash shell (on Windows, use Git Bash)

## Run it locally

First, create your local settings. Open `.env` and replace `change-me` with a password (letters and digits only):

```bash
cp .env.example .env
```

### Option 1: everything in Docker

```bash
# Start PostgreSQL and the API (press Ctrl+C to stop)
make dev
```

In another terminal, create the database tables:

```bash
make migrate
```

### Option 2: only PostgreSQL in Docker, the API on your machine

Good for development, because Go recompiles without rebuilding an image.

```bash
make db        # start PostgreSQL
make migrate   # create the database tables
make run       # start the API
```

Do not use both options at the same time: they use the same port (8080).

### Check that it works

The API listens on <http://localhost:8080>:

```bash
curl http://localhost:8080/healthz
curl http://localhost:8080/readyz
```

Both should answer `200` with `{"status":"ok"}`.

Run `make help` to see all commands.

## Tests

```bash
make test        # all backend tests
make test-race   # same, with the race detector (needs a 64-bit C compiler)
```

## Project layout

```text
backend/       Go code (API, Dockerfile, database migrations)
compose.yaml   PostgreSQL and the API for local development
Makefile       shortcuts for the common commands
.github/       GitHub Actions workflows (CI)
```

## License

MIT
