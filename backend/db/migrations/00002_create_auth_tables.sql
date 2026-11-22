-- +goose Up
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- The app normalizes e-mails, but the database enforces it too. Without
    -- this, 'A@x.com' and 'a@x.com' could become two different accounts.
    CONSTRAINT users_email_normalized CHECK (
        email = lower(btrim(email))
        AND length(email) BETWEEN 3 AND 254
    ),
    CONSTRAINT users_password_hash_not_blank CHECK (length(password_hash) > 0)
);
-- One row per (user, tenant). The primary key also blocks duplicates.
-- Role is TEXT + CHECK instead of an ENUM: changing the list of roles later
-- is a simple constraint swap, while removing an ENUM value is painful.
CREATE TABLE memberships (
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    tenant_id UUID NOT NULL REFERENCES tenants (id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, tenant_id),
    CONSTRAINT memberships_role_valid CHECK (role IN ('owner', 'admin', 'member'))
);
-- The primary key starts with user_id. This index serves the other direction:
-- "who belongs to this tenant?".
CREATE INDEX memberships_tenant_id_idx ON memberships (tenant_id);
-- Only the SHA-256 of the session token is stored, never the token itself.
-- If the database leaks, the hashes cannot be used as cookies.
CREATE TABLE sessions (
    token_hash BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- SHA-256 is always 32 bytes. A different size means a bug (for example,
    -- the raw token was stored by mistake).
    CONSTRAINT sessions_token_hash_sha256 CHECK (octet_length(token_hash) = 32)
);
CREATE INDEX sessions_user_id_idx ON sessions (user_id);
-- Lets a cleanup job delete expired sessions without scanning the table.
CREATE INDEX sessions_expires_at_idx ON sessions (expires_at);
-- +goose Down
-- Reverse order of creation: children first, because of the foreign keys.
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS users;