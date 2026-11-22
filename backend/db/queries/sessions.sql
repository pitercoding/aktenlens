-- name: CreateSession :exec
INSERT INTO sessions (token_hash, user_id, expires_at)
VALUES (
        sqlc.arg(token_hash),
        sqlc.arg(user_id),
        sqlc.arg(expires_at)
    );
-- Resolves a session cookie into who is calling and for which tenant.
-- The tenant comes from the membership stored in the database, never from
-- the request. "now" is a parameter so tests can control the clock.
-- Phase 1: one user, one tenant. ORDER BY + LIMIT 1 keeps the result
-- deterministic if that ever changes.
-- name: GetSessionPrincipal :one
SELECT u.id AS user_id,
    u.email,
    m.tenant_id,
    m.role
FROM sessions s
    JOIN users u ON u.id = s.user_id
    JOIN memberships m ON m.user_id = u.id
WHERE s.token_hash = sqlc.arg(token_hash)
    AND s.expires_at > sqlc.arg(now)
ORDER BY m.created_at,
    m.tenant_id
LIMIT 1;
-- name: DeleteSession :exec
DELETE FROM sessions
WHERE token_hash = $1;
