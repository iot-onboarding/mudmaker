#!/bin/sh
set -eu

/usr/local/bin/mudzipserver &
mudzip_pid="$!"

sleep 1
if ! kill -0 "$mudzip_pid" 2>/dev/null; then
	wait "$mudzip_pid"
	exit "$?"
fi

apache2-foreground &
apache_pid="$!"

shutdown() {
	kill "$apache_pid" "$mudzip_pid" 2>/dev/null || true
	wait "$apache_pid" 2>/dev/null || true
	wait "$mudzip_pid" 2>/dev/null || true
}

trap 'shutdown; exit 0' INT TERM

if wait "$apache_pid"; then
	status=0
else
	status="$?"
fi

kill "$mudzip_pid" 2>/dev/null || true
wait "$mudzip_pid" 2>/dev/null || true
exit "$status"
