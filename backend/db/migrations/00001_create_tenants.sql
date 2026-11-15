-- +goose Up
-- pgvector is needed from phase 5 (embeddings). Enabling it now proves that
-- the database image supports it.
CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE tenants (
    id         UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name       TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- NOT NULL still accepts '' and '   ', so reject blank names here too.
    CONSTRAINT tenants_name_not_blank CHECK (length(btrim(name)) > 0)
);

-- +goose Down
-- The vector extension is kept on purpose: other tables may use it later,
-- and dropping it would also drop their vector columns.
DROP TABLE IF EXISTS tenants;
