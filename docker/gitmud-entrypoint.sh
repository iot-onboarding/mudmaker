#!/bin/sh
# Initialise the gitmud SQLite database on first run, then exec the supplied
# command (typically gunicorn). Safe to run on every container start because
# the schema is only created when the database file is missing.

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

exec "$@"
