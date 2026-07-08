-- Legacy per-mudurl token store.  Populated only by the Phase-3 legacy
-- fallback path in gitmud/app.py.  Phase 3.5 will drop this table once
-- cached browsers have drained.
CREATE TABLE gitmud(mudurl, token, scope_val, mudfile);

-- Phase 3 session bearer store.  gitmud.app._ensure_schema() also
-- creates this table on existing databases (idempotent), but the
-- fresh-install path applies it here so the very first request after
-- container start does not race the ensure-schema call.
CREATE TABLE sessions (
    session_id    TEXT PRIMARY KEY,
    github_login  TEXT NOT NULL,
    access_token  TEXT NOT NULL,
    mudurl        TEXT NOT NULL,
    scope         TEXT,
    token_type    TEXT,
    created_at    INTEGER NOT NULL,
    last_used_at  INTEGER NOT NULL
);
CREATE INDEX sessions_by_login ON sessions(github_login);
CREATE INDEX sessions_by_created ON sessions(created_at);
