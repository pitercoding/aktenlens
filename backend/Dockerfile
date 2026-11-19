# syntax=docker/dockerfile:1

# ---------- Stage 1: build ----------
# Same Go version as backend/go.mod, so no toolchain download at build time.
FROM golang:1.26.11 AS build

WORKDIR /src

# Copy only the dependency files first: this layer is cached until
# go.mod or go.sum change, so rebuilds after a code change are fast.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# CGO_ENABLED=0 -> static binary (the final image has no libc).
# -trimpath removes local file paths from the binary.
# -s -w strips debug info, which makes the binary smaller.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath -ldflags="-s -w" \
    -o /out/api ./cmd/api

# ---------- Stage 2: runtime ----------
# distroless: no shell, no package manager. "nonroot" runs as uid 65532.
FROM gcr.io/distroless/static-debian13:nonroot

COPY --from=build /out/api /api

# Documentation only: the API listens on 8080 (set in cmd/api/main.go).
EXPOSE 8080

USER nonroot:nonroot

# Exec form: the Go binary is PID 1 and receives SIGTERM from "docker stop",
# which triggers the graceful shutdown.
ENTRYPOINT ["/api"]
