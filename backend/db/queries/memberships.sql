-- name: CreateMembership :exec
INSERT INTO memberships (user_id, tenant_id, role)
VALUES (
        sqlc.arg(user_id),
        sqlc.arg(tenant_id),
        sqlc.arg(role)
    );
-- Tenant-scoped: always filtered by tenant_id.
-- Columns are listed on purpose, so password_hash can never leak from here.
-- name: ListMembersByTenant :many
SELECT u.id AS user_id,
    u.email,
    m.role,
    m.created_at AS joined_at
FROM memberships m
    JOIN users u ON u.id = m.user_id
WHERE m.tenant_id = $1
ORDER BY m.created_at,
    u.id;
