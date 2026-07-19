# GitHub-facing remediation plan

**Status: Phases 1–5 shipped 2026-07-08.** Phase 3.5 (retire legacy
mudurl fallback) and Phase 4 hard-removal (return `410` for
`got_token`) are deferred pending production metrics; the code and
config knobs to flip them are in place. See §7 for the exact cutover
procedure.

Companion documents:
- [THREAT_MODEL.md](THREAT_MODEL.md) — what each threat is and why.
- [DEPLOYMENT_PLAYBOOK.md](DEPLOYMENT_PLAYBOOK.md) — how to deploy and
  smoke-test each phase.

## 1. Threat status

| ID | Threat | Phase | Status |
|----|--------|-------|--------|
| T-01 | mudurl-as-capability | 3 | ✅ closed (session bearer required; legacy fallback behind config flag) |
| T-02 | `/gottoken` presence oracle | 3 | ✅ closed (route deleted) |
| T-03 | `/oAuthv2` legacy `got_tok` alias | 4 | ⚠️ deprecation warning fires; hard-removal deferred (§7) |
| T-04 | No CSRF / no `Origin` check | 2 + 3 | ✅ closed (origin guard + bearer) |
| T-06 | `/therest` trusts caller-declared `user` | 3 | ✅ closed (`user` comes from `request.session["login"]`) |
| T-07 | Path traversal via `mfg`/`model` -> GitHub REST | 1 | ✅ closed (`_sanitise_ref_component`) |
| T-08 | Unencoded `filename`/`branch` in `existing_file` | 1 | ✅ closed (`_github_path` + `quote(..., safe="")`) |
| T-09 | Legacy JSON path of `/therest` skips sanitisation | 1 | ✅ closed (same sanitiser applied) |
| T-10 | `re.sub(' ','-')` only, no ref-char validation | 1 | ✅ closed (`_sanitise_ref_component`) |
| T-11 | `git_putpost` logs raw GitHub response body | 1 | ✅ closed (`_safe_log`) |
| T-18 | OAuth tokens plaintext, retained forever | 3 | ✅ closed (janitor + TTL + chmod 600 + `/signout`) |
| T-26 | No user-facing sign-out / GitHub revocation | 3 | ✅ closed (`/signout` calls GitHub token-revocation) |
| T-28 | `mudcerts` cloned at build without SHA pin | 5 | ✅ closed (40-char SHA + `go mod verify` + CI guard) |

Non-GitHub threats (T-05, T-12–T-17, T-19–T-25, T-27, T-29, T-30) are
tracked in [THREAT_MODEL.md](THREAT_MODEL.md) and its general
remediation plan.

## 2. Guiding design decisions (unchanged)

The following decisions drove the shipped implementation and remain
the reference for future work in this area.

**D-1 Session-keyed authorisation.** The SQLite `sessions` table
(`session_id -> (access_token, github_login, mudurl, scope, token_type,
created_at, last_used_at)`) replaced the mudurl-keyed `gitmud` table
as the source of authority. `session_id` is a 32-byte
`secrets.token_urlsafe(32)` value minted at OAuth completion, returned
to the browser once, and re-presented on every subsequent gitmud call
as `Authorization: Bearer <session_id>`. The mudurl is still recorded
for audit but never gates authorisation on its own.

**D-2 `sessionStorage`, not `localStorage`, not a cookie.** No cookie
means no ambient authority — a cross-origin page cannot cause the
browser to attach the session to a request. `sessionStorage` scopes
the bearer to a single tab so closing the tab logs the user out for
free.

**D-3 Same-origin only, defence-in-depth.** A `before_request`
`_origin_guard()` refuses any non-GET/HEAD/OPTIONS request whose
`Origin` (or fallback `Referer`) is outside `[security]
allowed_origins`.

**D-4 GitHub API surface = untrusted string sink.** Every path
segment is fed through `urllib.parse.quote(..., safe="")` via
`_github_path()`, and every input that becomes a Git ref/path
component (mfg, model, branch, filename segment) goes through the
whitelist-only `_sanitise_ref_component()`. No silent rewriting;
rejection with `400` on any violation.

**D-5 GitHub response bodies are untrusted for logging.** `_safe_log()`
strips CR/LF/control chars, truncates to 200 chars, and `repr()`s the
remainder so nothing attacker-influenced can reach the log formatter
unfiltered.

**D-6 Rollout order mattered.** Sanitisation (P1) required no client
change. Session bearer (P3) shipped with the legacy mudurl fallback
still enabled so cached browsers keep working across the transition.

## 3. What shipped, by phase

| Phase | Ship-blocker at merge | Client-side change? | DB change? | Status |
|-------|-----------------------|---------------------|-----------|--------|
| 1. GitHub-input hardening | No | No | No | ✅ shipped 2026-07-08 |
| 2. Origin allowlist + log sanitisation | No | No | No | ✅ shipped 2026-07-08 |
| 3. Session bearer + sign-out + TTL | Yes | Yes | Yes (additive `sessions` table) | ✅ shipped 2026-07-08 (legacy fallback ON) |
| 3.5. Retire legacy fallback | — | No | No (drop `gitmud` table) | ⏳ deferred; §7 |
| 4. Return `410` for `got_token` | No | Client already migrated | No | ⏳ deferred; §7 |
| 5. Pin `mudcerts` supply chain | No | No | No | ✅ shipped 2026-07-08 |

## 4. Phase 1 — GitHub-input hardening (T-07/T-08/T-09/T-10)

**As shipped.** Two module-level helpers plus a whitelist regex now
gate every value that becomes a GitHub REST path segment or a Git
ref:

- `_sanitise_ref_component(name, field_name)` — NFKC-normalise,
  lowercase, reject any control char up front, collapse ASCII
  space/tab to `-`, reject the Git-forbidden set (`..`, `//`, `@{`,
  leading `.`/`-`, trailing `.`, `~^:?*[\`), and require final match
  `[a-z0-9][a-z0-9._-]{0,63}`.
- `_github_path(*segments)` — URL-quote each segment with `safe=""`
  so `/`, `?`, `#` inside a segment cannot escape.
- Call sites migrated: `repo_exists`, `branch_exists`,
  `create_branch`, `existing_file`, `upload_file`, `pr_exists`
  (query-string), and the direct `git_get(...heads/main...)` in
  `/branch`.
- `/branch` and `/therest` validate `mfg`/`model` before use; the
  legacy `application/json` `/therest` branch runs through the same
  sanitiser (T-09).
- Sanitiser failures return `400 {"error": "<field>: <reason>"}`. The
  reflected message contains **only** developer-authored literals from
  `_sanitise_ref_component`; user-supplied `name` is never
  interpolated (so this is safe against `py/stack-trace-exposure`,
  and the sites carry `# lgtm[py/stack-trace-exposure]` / `#
  codeql[py/stack-trace-exposure]` suppressions to keep a future
  auto-accepted CodeQL suggestion from breaking the client UX).

**Files shipped:** [gitmud/gitmud/app.py](gitmud/gitmud/app.py).

**Tests pinning this behaviour:**
- [tests/test_ref_sanitise.py](tests/test_ref_sanitise.py) — 5 groups:
  canonical inputs accepted, non-ASCII rejected, git-forbidden chars
  rejected, control chars/RTL override rejected, shape rules
  (bounds/edges/empty) rejected, `_github_path` URL-quoting,
  `_safe_log` scrubbing.
- [tests/test_session_bearer.py](tests/test_session_bearer.py) —
  `/therest` traversal-in-mfg and `/branch` traversal-in-model both
  return `400`.

## 5. Phase 2 — Origin allowlist + log sanitisation (T-04 partial, T-11)

**As shipped.**

- `_safe_log(text)` — the single log-scrubber used by `git_get`,
  `git_putpost`, `_origin_guard`, and the legacy-fallback log lines
  in `@requires_session`. Strips 0x00–0x1F/0x7F, truncates to 200
  chars, `repr()`-quotes the remainder.
- `git_putpost` no longer surfaces the raw GitHub response body in
  the `GithubProblem` exception message (previously
  `raise GithubProblem("request failed: " + resp.text)`); the
  exception carries only the sanitised endpoint + status code.
- `@app.before_request _origin_guard()` — refuses non-safe methods
  whose `Origin` (or fallback `Referer`) is outside
  `[security] allowed_origins`. GET/HEAD/OPTIONS exempt. No-origin
  no-referer requests (curl, monitoring probes) are allowed so
  operational tooling keeps working.
- Config: `[security] allowed_origins = <comma list>` in
  [gitmud/config.ini](gitmud/config.ini). Empty value disables the
  guard (dev/test only). CI stubs set it to empty.

**Files shipped:** [gitmud/gitmud/app.py](gitmud/gitmud/app.py),
[gitmud/config.ini](gitmud/config.ini),
[.github/workflows/ci.yml](.github/workflows/ci.yml).

**Tests pinning this behaviour:**
- [tests/test_session_bearer.py](tests/test_session_bearer.py) —
  cross-origin POST refused (403); same-origin POST allowed through;
  GET exempt; Referer-fallback blocks foreign referer; no-origin
  no-referer allowed (curl).
- [tests/test_ref_sanitise.py](tests/test_ref_sanitise.py) —
  `_safe_log` scrubs `\r\n` and truncates.

## 6. Phase 3 — Session bearer, sign-out, TTL (T-01/T-02/T-04/T-06/T-18/T-26)

**As shipped.**

### 6.1 Schema

The `sessions` table is created idempotently at import via
`_ensure_schema()` (`CREATE TABLE IF NOT EXISTS`), and also shipped
in [gitmud/initdb.sql](gitmud/initdb.sql) for the fresh-install path.
Columns:

```sql
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
```

The legacy `gitmud` table is retained for the Phase 3 transition
window; §7 covers dropping it.

### 6.2 Auth helpers

- `_new_session(gitresp, github_login, mudurl)` inserts a row and
  returns the fresh bearer.
- `_resolve_session(bearer)` returns
  `{"session_id", "login", "token", "mudurl"}` for a live bearer,
  transparently deletes and returns `None` for a TTL-expired one,
  and touches `last_used_at` on success.
- `_delete_session(session_id)` — used by `/signout`.
- `_bearer_from_request()` parses `Authorization: Bearer …`.
- `@requires_session` — the decorator. Prefer bearer; fall back to
  mudurl-keyed lookup **only when** `_LEGACY_MUDURL_FALLBACK` is
  `true` in `[security]`. On the legacy path it logs
  `legacy mudurl fallback used origin=… login=…` so operators can
  see when it fires.

### 6.3 Routes

- `POST /oAuthv2` — mints and returns
  `{"user": login, "session": <bearer>}` on successful code exchange.
- `GET /whoami` — bearer-only; `{"login": <login>}` or `401`.
- `POST /signout` — deletes the local row and best-effort calls GitHub
  `DELETE /applications/{client_id}/token` with HTTP Basic
  (client_id, client_secret). Returns `204` idempotently.
- `POST /dorepo`, `/branch`, `/therest` — `@requires_session`. `user`
  is taken from `request.session["login"]`; any `user` field in the
  request body is ignored (kills T-01/T-06).
- `GET /gottoken` — **deleted** (kills T-02).

### 6.4 Background sweeper

`_janitor_loop()` runs in a daemon thread (`_start_janitor()`,
guarded to spawn at most once per interpreter). Every
`_JANITOR_INTERVAL_SECONDS` (default 3600) it runs
`DELETE FROM sessions WHERE created_at < ?`. Idempotent under
multiple workers. Can be disabled for tests via
`GITMUD_DISABLE_JANITOR=1`.

### 6.5 Client changes

- [assets/js/omud.js](assets/js/omud.js) — `oAuthP1Navigate` uses a
  local session probe (`fetch("/whoami", …)` with the cached bearer)
  instead of the deleted `/gottoken` shortcut. The OAuth request now
  asks for `scope=public_repo` (down from `repo`). `oAuthP2` reads
  the returned `session` field and stores it under the
  `mudmaker_session` sessionStorage key. `_authHeaders()` attaches
  `Authorization: Bearer …` to every subsequent
  `/dorepo`/`/branch`/`/therest` call. The `user` body field is no
  longer sent to `/branch` or `/therest`.
- [assets/js/tabs.js](assets/js/tabs.js) — the `/gottoken` fetch on
  publish-tab open is gone.
- [assets/js/mudmaker-reload.js](assets/js/mudmaker-reload.js) —
  clears `mudmaker_session` (as well as the legacy `gottoken` key)
  on tab reload.
- [mudmaker.html](mudmaker.html) — new **Sign out of GitHub** button
  on the publish tab that calls `mudmakerSignOut()`.

### 6.6 Backward compatibility (Phase 3 transition window)

`_LEGACY_MUDURL_FALLBACK = true` in `[security]` keeps
`@requires_session` accepting the pre-Phase-3 request shape
(no bearer, `mudurl` in body). Cached browsers continue to publish.
See §7 for the flip-off procedure.

### 6.7 Filesystem hardening (T-18)

[docker/gitmud-entrypoint.sh](docker/gitmud-entrypoint.sh) now
`chmod 600 ${DB_PATH}` on every start, so a fresh volume, an old
volume, and every restart converge on `-rw-------`.

### 6.8 Tests pinning this behaviour

[tests/test_session_bearer.py](tests/test_session_bearer.py) — 15
assertions covering: origin allowlist (5), `/whoami` bearer required
(2), `/therest` bearer-only with session-driven user (1),
`/therest` ignores body `user` (1), session TTL expiry with row
sweep (1), `/therest` traversal rejection (1), `/branch` traversal
rejection (1), `/signout` idempotent (2), `/dorepo` no-auth rejected
(1).

Also [tests/test_publish_multi.py](tests/test_publish_multi.py) —
exercises the legacy fallback path end-to-end (four cases, all
sanitised names now lowercase).

## 7. Phase 3.5 and Phase 4 — deferred cutovers

The code and config knobs are in place. The flips themselves are
gated on metrics.

### 7.1 Signals to watch

```bash
# Deprecation warnings per day (drives Phase 4)
docker-compose logs --since 24h gitmud \
  | grep -c "DEPRECATED got_token"

# Legacy-fallback hits per day (drives Phase 3.5)
docker-compose logs --since 24h gitmud \
  | grep -c "legacy mudurl fallback used"

# Denominator: successful publishes per day
docker-compose logs --since 24h gitmud \
  | grep -c "POST /therest"
```

### 7.2 Phase 3.5 — flip `legacy_mudurl_fallback = false`

**Criteria (all three):**
1. At least 6 weeks since 2026-07-08.
2. `legacy fallback used` events < 1% of successful `/therest`
   publishes for 7 consecutive days.
3. Fewer than 5 `legacy fallback` events per day for 3 consecutive
   days.

**Action:**

```bash
$EDITOR /containers/www.mudmaker.org/gitmud/config.ini
# under [security]:  legacy_mudurl_fallback = false
cd /containers/www.mudmaker.org
docker-compose up -d --force-recreate gitmud mudmaker
```

Then re-run the §4 checks in
[DEPLOYMENT_PLAYBOOK.md](DEPLOYMENT_PLAYBOOK.md), especially
§4.5 – §4.7.

**Optional follow-up:** drop the now-unused `gitmud` table.

```bash
docker exec -it wwwmudmakerorg-gitmud-1 \
  sqlite3 /var/lib/gitmud/mudbase.db 'DROP TABLE gitmud;'
```

Safe once §7.2 criteria are met — the code path that reads it
(`token_in_db` / `db_store` / `delete_token`) is only reachable from
the legacy fallback and from the `got_token` shortcut, both of which
are then either off (fallback) or logging-only warnings (shortcut).

### 7.3 Phase 4 — return `410` for `got_token`/`got_tok`

**Criteria:** `DEPRECATED got_token` counter stays at zero for 2
weeks after §7.2 has shipped.

**Action:** in [gitmud/gitmud/app.py](gitmud/gitmud/app.py)
`complete_oauth()`, replace the `legacy_shortcut` branch with:

```python
if legacy_shortcut:
    return jsonify({"error":
                    "legacy path removed; please reload"}), 410
```

Redeploy. Verify:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST https://mudmaker.org/gitShovel/oAuthv2 \
  -H "Origin: https://mudmaker.org" \
  -H "Content-Type: application/json" \
  -d '{"mudurl":"x","got_token":true}'
# expected: 410
```

The client already never sends `got_token` after 2026-07-08 (see
Phase 3.5 client changes), so this closes the loop server-side.

## 8. Phase 5 — pin the `mudcerts` supply chain (T-28)

**As shipped.**

[Dockerfile](Dockerfile) now:

```dockerfile
ARG MUDCERTS_REF=46fc87dae8d88b9306d03c507d54910840dc24c2

RUN case "${MUDCERTS_REF}" in \
      [0-9a-f]*) : ;; \
      *) echo "MUDCERTS_REF must be a 40-char commit SHA, got: ${MUDCERTS_REF}" >&2; exit 1 ;; \
    esac \
    && test "$(printf '%s' "${MUDCERTS_REF}" | wc -c)" = "40" \
    && git clone https://github.com/iot-onboarding/mudcerts.git /src/mudcerts \
    && cd /src/mudcerts \
    && git checkout "${MUDCERTS_REF}" \
    && test "$(git rev-parse HEAD)" = "${MUDCERTS_REF}" \
    && go mod download \
    && go mod verify \
    && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
       -o /out/mudzipserver ./web
```

Belt-and-braces:
- `MUDCERTS_REF` shape is checked twice (`case` prefix match + wc
  length check) at build time; a branch name like `main` fails
  early.
- `git rev-parse HEAD` compared against the requested SHA to catch a
  mismatched tag/branch overwrite between clone and checkout.
- `go mod verify` before build catches a tampered `go.sum`.

**CI guard** ([.github/workflows/ci.yml](.github/workflows/ci.yml)):
`docker-build → Verify MUDCERTS_REF is pinned to a commit SHA (T-28)`
fails PRs whose Dockerfile regresses to a branch name or a
partial-length hex value.

**Bump procedure** when mudcerts releases:

1. Note the target commit SHA on
   `https://github.com/iot-onboarding/mudcerts/commits/main`.
2. Update `ARG MUDCERTS_REF=…` in [Dockerfile](Dockerfile).
3. Update the SHA in `/memories/repo/deployment.md`.
4. PR → CI runs the guard → merge → redeploy per
   [DEPLOYMENT_PLAYBOOK.md](DEPLOYMENT_PLAYBOOK.md) §3.

## 9. Also shipped (defence-in-depth)

Not part of the numbered plan, but landed in the same wave because
they close adjacent gaps identified during rollout:

- **[.github/workflows/ci.yml](.github/workflows/ci.yml) — Dockerfile
  guard rail.** New first-step check on the `lint-and-unit` job:
  fails a PR whose Dockerfile ever tries to `COPY .*/config.ini`,
  `ENV SECRET|TOKEN|PASSWORD|API_KEY|CREDENTIAL|PRIVATE_KEY`, or the
  same in `ARG`. Prevents accidental secret baking in future edits.
- **Client OAuth scope narrowed** from `repo` → `public_repo` in
  [assets/js/omud.js](assets/js/omud.js). Reduces the consent
  screen's ask and shrinks the blast radius of a stolen token.
- **Deprecated log for the got_token shortcut** already in
  place server-side (Phase 4 step 1 of the plan; drives the §7.3
  timing decision).

## 10. Explicit out-of-scope

- **Rewriting `mudgen_pcap.py` to sandbox scapy** (T-12) — general
  plan, unrelated to GitHub.
- **Per-IP rate limiting** (T-14) — general plan.
- **`markupsafe.escape` on reflected fields** (T-19) — already in
  place from an earlier CodeQL alert, unchanged.
- **Rotate the GitHub OAuth client secret** — operational task, done
  in lockstep with the Phase 3 deploy per
  [DEPLOYMENT_PLAYBOOK.md](DEPLOYMENT_PLAYBOOK.md) §2.3. Not a code
  change.
- **GitHub Enterprise / self-hosted forks** — `api_url` and
  `mud_repo` config knobs unchanged; if you use them, re-run
  [DEPLOYMENT_PLAYBOOK.md](DEPLOYMENT_PLAYBOOK.md) §4.8 end-to-end
  against your fork.
- **Migrate the OAuth App to a GitHub App** — recommended future
  work (mentioned in the earlier GitHub-side notes). Would remove
  the long-lived user token model entirely in favour of 1-hour
  installation tokens; deferred to a separate follow-up.

## 11. Cross-reference (files + tests)

| Threat | Files touched (shipped) | Tests |
|--------|-------------------------|-------|
| T-01 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py), [gitmud/initdb.sql](gitmud/initdb.sql), [assets/js/omud.js](assets/js/omud.js), [assets/js/tabs.js](assets/js/tabs.js), [assets/js/mudmaker-reload.js](assets/js/mudmaker-reload.js), [mudmaker.html](mudmaker.html) | [tests/test_session_bearer.py](tests/test_session_bearer.py) — bearer-only, session-driven user, body-user ignored |
| T-02 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (route deleted), [assets/js/tabs.js](assets/js/tabs.js) | Verified in [DEPLOYMENT_PLAYBOOK.md](DEPLOYMENT_PLAYBOOK.md) §4.5 (GET `/gottoken` → 404) |
| T-03 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py), [assets/js/omud.js](assets/js/omud.js) | [tests/test_oauth_complete.py](tests/test_oauth_complete.py) pins the deprecation branch; §7.3 handles removal |
| T-04 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (`_origin_guard`), [gitmud/config.ini](gitmud/config.ini), [assets/js/omud.js](assets/js/omud.js) | [tests/test_session_bearer.py](tests/test_session_bearer.py) — 5 origin-guard cases |
| T-06 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) | [tests/test_session_bearer.py](tests/test_session_bearer.py) — body `user` ignored |
| T-07 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (`_sanitise_ref_component`) | [tests/test_ref_sanitise.py](tests/test_ref_sanitise.py), [tests/test_session_bearer.py](tests/test_session_bearer.py) traversal cases |
| T-08 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (`_github_path`, `quote`) | [tests/test_ref_sanitise.py](tests/test_ref_sanitise.py) URL-quoting case |
| T-09 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (legacy JSON branch) | [tests/test_publish_multi.py](tests/test_publish_multi.py) case 4 |
| T-10 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (`_sanitise_ref_component`) | [tests/test_ref_sanitise.py](tests/test_ref_sanitise.py) |
| T-11 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (`_safe_log`) | [tests/test_ref_sanitise.py](tests/test_ref_sanitise.py) `_safe_log` case |
| T-18 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (janitor + TTL), [docker/gitmud-entrypoint.sh](docker/gitmud-entrypoint.sh) (chmod 600), [gitmud/initdb.sql](gitmud/initdb.sql) | [tests/test_session_bearer.py](tests/test_session_bearer.py) TTL case; chmod verified in [DEPLOYMENT_PLAYBOOK.md](DEPLOYMENT_PLAYBOOK.md) §4.12 |
| T-26 | [gitmud/gitmud/app.py](gitmud/gitmud/app.py) (`/signout`), [assets/js/omud.js](assets/js/omud.js), [mudmaker.html](mudmaker.html) | [tests/test_session_bearer.py](tests/test_session_bearer.py) — idempotent + GitHub revoke called |
| T-28 | [Dockerfile](Dockerfile), [.github/workflows/ci.yml](.github/workflows/ci.yml) | CI job `Verify MUDCERTS_REF is pinned to a commit SHA (T-28)` |

## 12. Change log

- **2026-07-08** — Phases 1, 2, 3 (session bearer + legacy fallback
  on), 4 (client side + server-side deprecation warning), 5 (mudcerts
  pin) shipped in a single wave. Companion
  [DEPLOYMENT_PLAYBOOK.md](DEPLOYMENT_PLAYBOOK.md) authored the same
  day. `mudcerts` pinned at
  `46fc87dae8d88b9306d03c507d54910840dc24c2`.
- **Later — deferred** — Phase 3.5
  (`legacy_mudurl_fallback = false` + drop `gitmud` table) and
  Phase 4 step 2 (`410` for `got_token`), gated on metrics per §7.
