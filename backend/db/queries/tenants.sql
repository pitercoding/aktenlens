-- name: CreateTenant :one
INSERT INTO tenants (name)
VALUES ($1)
RETURNING *;
