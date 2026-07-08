#!/bin/sh
# Initialise the gitmud SQLite database on first run, then exec the supplied
# command (typically gunicorn). Safe to run on every container start because
# the schema is only created when the database file is missing, and the
# in-app _ensure_schema() call handles new tables (e.g. Phase 3 ``sessions``)
# on existing databases idempotently.

set -eu

DB_PATH="${GITMUD_DB_PATH:-/var/lib/gitmud/mudbase.db}"
DB_DIR="$(dirname "${DB_PATH}")"

mkdir -p "${DB_DIR}"

if [ ! -f "${DB_PATH}" ]; then
    echo "gitmud: initialising database at ${DB_PATH}" >&2
    python - <<PY
import sqlite3
with open("/usr/local/share/gitmud/initdb.sql", "r", encoding="utf-8") as f:
    schema = f.read()
conn = sqlite3.connect("${DB_PATH}")
try:
    conn.executescript(schema)
    conn.commit()
finally:
    conn.close()
PY
fi

# T-18 remediation: the token store contains bearer credentials.
# Keep it readable only by the gitmud user regardless of umask history.
chmod 600 "${DB_PATH}"

exec "$@"
