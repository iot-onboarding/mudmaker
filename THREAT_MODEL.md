# MudMaker threat model and remediation plan

Date: 2026-07-07.
Scope: the mudmaker.org web application as shipped in this repository
(container Apache + `gitmud` Flask app + `mudzipserver` Go binary +
static browser UI + support scripts). External services (GitHub API,
outer host Apache vhost) are covered only where they interact with the
in-repo code.

## 1. Interface inventory

| # | Interface | Where | Trust boundary | Data |
|---|-----------|-------|----------------|------|
| A | Outer TLS vhost | Host `w1`, `:443` | Internet -> host | HTTP requests, reverse-proxied to `127.0.0.1:8081` |
| B | Container Apache | `mudmaker` service, `:8081` | Host loopback -> container | Serves static site + proxies `/mudzip`, `/gitShovel/*`, `/pcap2mud` (see [docker/mudzip-proxy.conf](docker/mudzip-proxy.conf)) |
| C | `mudzipserver` HTTP | `mudmaker-mudzipserver`, `:8085` (compose net only) | Compose net -> container | `POST /mudzip`: JSON in, ZIP out. `limitBody(150 KiB)` + `concurrencyLimiter(NumCPU,100ms)` |
| D | `gitmud` Flask (Gunicorn) | `mudmaker-gitmud`, `:8000` (compose net only) | Compose net -> container | 6 routes; see below |
| D1 | `GET /gottoken` | [gitmud/gitmud/app.py:363](gitmud/gitmud/app.py#L363) | Public (via proxy) | oracle: "is a token stored for this mudurl?" |
| D2 | `POST /oAuthv2` | [gitmud/gitmud/app.py:394](gitmud/gitmud/app.py#L394) | Public | completes GitHub OAuth, persists token |
| D3 | `POST /dorepo` | [gitmud/gitmud/app.py:444](gitmud/gitmud/app.py#L444) | Public | forks `iot-onboarding/mudfiles` as the token user |
| D4 | `POST /branch` | [gitmud/gitmud/app.py:481](gitmud/gitmud/app.py#L481) | Public | creates a branch on user's fork |
| D5 | `POST /therest` | [gitmud/gitmud/app.py:531](gitmud/gitmud/app.py#L531) | Public | commits MUD JSON + pcaps, opens PR |
| D6 | `POST /pcap2mud` | [gitmud/gitmud/app.py:724](gitmud/gitmud/app.py#L724) | Public | runs `mudgen_pcap.py` on uploaded pcaps |
| E | `mudgen_pcap.py` | Subprocess of D6 | Called with validated CLI args on a temp dir | Parses attacker-supplied pcap bytes with scapy |
| F | SQLite token store | `/var/lib/gitmud/mudbase.db` (named volume) | Filesystem inside container | Plaintext GitHub OAuth tokens keyed by mudurl |
| G | Config file | `/etc/gitmud/config.ini` (bind mount) | Filesystem | GitHub OAuth client secret, Flask secret key |
| H | Static site (browser) | Assets under `/mudmaker` | Public | HTML/JS/CSS + downloadable helper scripts and JSON examples |
| I | Helper shell scripts | [lldpmud.sh](lldpmud.sh), [signmudfile.sh](signmudfile.sh) | Downloaded and run on user's own host | POSIX shell |
| J | Docker build pipeline | [Dockerfile](Dockerfile), [docker-compose.yml](docker-compose.yml) | Build host -> registry | Multi-stage: Go 1.26, python:3.14-slim, httpd:2.4; clones external `mudcerts` at build |

Deploy tooling under `deploy/` is out of scope for edits per repo policy
(gitignored, PR #104).

## 2. Threat catalogue

Notation: **STRIDE** tag (`S`poofing / `T`ampering / `R`epudiation /
`I`nfo-disclosure / `D`enial-of-service / `E`levation-of-privilege),
followed by a severity estimate (low/med/high) that assumes the
production deployment described above.

### 2.1 Authentication & access control

**T-01 [S/E, high] Mudurl-as-capability**
The gitmud SQLite table maps `mudurl -> access_token`. Any client that
knows a mudurl string can call `/dorepo`, `/branch`, `/therest` and act
as the GitHub user whose token happens to be stored for that mudurl.
The design assumption is that the browser session which minted the row
is the same one publishing, but nothing in the request enforces that.
Mudurls are meant to be publicly known well-known URLs — knowledge of
a mudurl is not a secret. A second party who ever loads mudmaker with
someone else's mudurl in the form can hijack the row (D2 will happily
overwrite the token) or piggyback on the existing token (D3/D4/D5).

*Impact*: attacker can push commits and open PRs on the mudfiles repo
under the victim's GitHub identity, or (post-hijack) capture the OAuth
code intended for the victim.

**T-02 [I, med] `/gottoken` presence oracle**
`GET /gottoken?mudurl=X` returns yes/no. This lets an attacker
enumerate which mudurls have active OAuth grants — useful reconnaissance
before mounting T-01.

**T-03 [S, med] `/oAuthv2` accepts legacy `got_tok`**
The route accepts either `got_token` or historical `got_tok`. This is
documented as a compatibility shim for cached browsers. Every extra
accepted spelling of a "skip the OAuth dance" flag increases the
chance of a client-side bug turning into a silent auth bypass — the
flag says "trust the cached token in the DB", which is exactly what
T-01 abuses.

**T-04 [E, med] No CSRF token / no `SameSite` / no CORS lockdown**
gitmud routes accept `application/json` and `multipart/form-data`
POSTs with no origin check, no CSRF token, and no auth cookie. The
site does not currently issue any cookie, so classic CSRF is limited,
but any origin the victim visits can drive `/oAuthv2`, `/dorepo`,
`/branch`, `/therest` in the victim's name once the victim has a cached
token (T-01) — the browser will happily send the mudurl body. The
Flask app has `secret_key` set (leaked into logs on error) but does
not otherwise use sessions.

**T-05 [I, med] `secret_key` in-tree template is low entropy**
[gitmud/config.ini](gitmud/config.ini) is `.gitignore`d, but the
committed template comment shows a placeholder secret_key of
`234569023y04598623408576234897569782345` — 39 ASCII characters that
are all digits/letters and clearly not from `secrets.token_urlsafe`.
Developers copy-paste. If anyone ever ships that value into
production, session cookies (should the app ever start using them) are
trivially forgeable.

**T-06 [T, med] `/therest` trusts caller-declared `user`**
The route now cross-checks `token_user == user` (defence added
against directing writes at an arbitrary account name), which mostly
closes the pre-existing bug where any caller could target commits at
somebody else's fork. The check still relies entirely on the token
row that T-01 lets the attacker choose.

### 2.2 Injection

**T-07 [T, high] Path traversal in GitHub commit filename**
`do_the_rest` derives `mfg` and `model` from the *body* of the MUD
JSON:
```python
mfg = re.sub(' ','-', mud["ietf-mud:mud"]["mfg-name"])
model = re.sub(' ','-', mud["ietf-mud:mud"]["systeminfo"])
branch_name = mfg + "-" + model
...
upload["filename"] = f"{mfg}/{model}/{model}.json"
```
Only ASCII spaces are collapsed. `mfg = "../foo"` writes into
`../foo/<model>/…` under `contents/`. Because
`upload_file()` composes the GitHub REST path with raw string
concatenation, the request that leaves gitmud is
`PUT /repos/<user>/mudfiles/contents/../foo/<model>/<model>.json`.
GitHub normalises the URL and may reject `..`, but embedded slashes,
Unicode NFC-collapsers, `?ref=` and URL-encoded control chars are not
filtered. Same story for `branch_name` (used as a branch ref on
GitHub) and PR title.

**T-08 [T, med] Unencoded query parameters in `existing_file`**
```python
git_get("/repos/" + user + "/mudfiles/contents/" + filename
        + "?ref=" + branch, token)
```
`filename` and `branch` are pasted into a URL without
`urllib.parse.quote`. Attacker-controlled `mfg` / `model` (per T-07)
can inject additional query parameters.

**T-09 [T, low] Legacy `application/json` path of `/therest` skips
pcap filename sanitisation**
The multipart branch runs uploads through `_sanitise_pcap_filename`;
the legacy JSON branch just stores the base64 blob under
`{mfg}/{model}.pcap`. Any T-07 abuse of `mfg`/`model` reaches the
same code path.

**T-10 [T, low] `re.sub` collapses only spaces**
Neither `mfg` nor `model` is validated. Control chars, right-to-left
override, homoglyphs, and Git-forbidden ref chars (`~^:?*[\`) all
pass through into the branch and file path.

**T-11 [T, low] `git_putpost` echoes raw GitHub response into logs**
```python
log.warning("git_%s %s -> %s: %s",
            which.lower(), endpoint, resp.status_code, resp.text[:200])
```
GitHub's error body is trusted here, but the payload includes the
attacker's filename verbatim; logs then contain unescaped
attacker-controlled bytes (log-forgery / newline injection into
gunicorn access log format).

**T-12 [E, high] Untrusted binary parsed by scapy in `/pcap2mud`**
`rdpcap()` reads attacker-controlled bytes. Scapy has a recurring
history of CVEs (heap corruption in specific dissectors, unbounded
recursion, infinite loops). The subprocess is time-limited to 60 s
and runs as the unprivileged `gitmud` user (uid 1001), but there is
no seccomp/AppArmor profile, no memory limit, and the process shares
the container filesystem, `/etc/gitmud/config.ini`, and the SQLite DB
via the same mount points as the Flask app.

**T-13 [T, low] File-extension check only**
`pcap2mud` accepts anything whose filename ends in `.pcap`/`.pcapng`.
`_sanitise_pcap_filename` (used by `/therest`) is stricter about the
stored name but doesn't magic-sniff the content either. A file of
zeros is fine for scapy (returns empty), so the concern is purely
DoS/CVE-in-scapy per T-12.

### 2.3 Denial of service

**T-14 [D, high] No rate limiting anywhere in gitmud**
Two gunicorn sync workers, 180 s timeout, 60 s scapy timeout per
`/pcap2mud`. An attacker sending two concurrent 20 MiB pcaps that
scapy chews on can pin both workers for a minute. No per-IP,
per-mudurl, or per-endpoint throttle. `mudzipserver` has its own
concurrency limiter — gitmud has none.

**T-15 [D, med] No worker recycling**
`gunicorn --workers 2 --timeout 180` without `--max-requests`. Scapy
leaks, plus long-lived process, plus 20 MiB parses -> steadily growing
RSS.

**T-16 [D, low] Unbounded SQLite growth**
Every OAuth completion inserts a row. There is no TTL, no cap, and no
janitor. A determined attacker with many GitHub accounts can bloat
the DB.

**T-17 [D, low] Outer Apache DNS cache pitfall**
Documented in memory: `mod_proxy_http` in the container Apache caches
the resolved IP of `mudzipserver` and does not re-resolve after a
partial restart -> service outage until both containers are recreated
together. Operational, not attacker-driven, but a self-inflicted DoS.

### 2.4 Data exposure

**T-18 [I, high] OAuth tokens stored plaintext, forever**
`gitmud` table stores raw bearer tokens. Anyone with read access to
`/var/lib/gitmud/mudbase.db` (root inside the container, root on the
host, backups) sees every user's GitHub token. No token is ever
proactively refreshed or revoked; `delete_token` fires only when
GitHub itself rejects the token. Users have no "sign out" path.

**T-19 [I, low] Reflected `mudurl` echoed back**
`/therest` returns `mudurl`, `user`, `mfg`, `model` in JSON, escaped
with `markupsafe.escape` (mitigation already in place per
CodeQL). Good; keep it.

**T-20 [I, low] `foo` file at repo root**
Contains what looks like an Apache access-log excerpt including
`GET /gottoken?mudurl=...` request lines. If this is truly log data,
it belongs in `.gitignore`, not the repo, and should be scrubbed.

**T-21 [I, low] `gitmud/setup.cfg~` committed**
A backup file with `~` suffix is tracked in git. Should not ship.

### 2.5 Browser / client-side

**T-22 [T, med] `innerHTML` string-templating in `addEntry`**
[assets/js/mudmaker.js:406](assets/js/mudmaker.js#L406) builds a
control block by concatenating strings into `innerHTML`. Today all
interpolated values (`fieldName`, `typefield`, `pattern`,
`placeholder`, `fieldinfo`, `hidden`) come from a hard-coded dispatch
table keyed by `entry.id`, so nothing crosses the trust boundary. A
routine change that pipes any user-supplied value in (a loaded MUD
file's ACE name, for example) becomes an immediate XSS. The repo
already ships [assets/js/dom-safe.js](assets/js/dom-safe.js) with a
sanitised `MudSafeDom.element(...)` builder; `addEntry` is the only
remaining `innerHTML` builder that could be migrated to it.

**T-23 [I, low] No `Content-Security-Policy`, `X-Frame-Options`,
`X-Content-Type-Options`, `Strict-Transport-Security`,
`Referrer-Policy`, `Permissions-Policy`**
Neither the container Apache config nor the Flask app sets any
security-response header. The outer vhost may set HSTS on `:443` but
we cannot rely on that from inside the repo.

**T-24 [T, low] Third-party JS shipped without SRI**
`jquery.min.js`, `skel.min.js`, `qrcodejs/`, and PIE fallback all live
in-repo (good — no CDN dependence). If any of these ever moves to a
CDN, an SRI hash and a lockdown CSP would be required.

**T-25 [I, low] `URL.createObjectURL` never revoked**
[assets/js/mudmaker.js:517](assets/js/mudmaker.js#L517) creates a
blob URL for the mudzip download and never calls `URL.revokeObjectURL`.
Memory retention nit only.

### 2.6 Supporting scripts

**T-26 [T, low] `lldpmud.sh` uses unquoted positional arg**
`echo $mudurl | egrep '^https://'` — if a user pastes a URL with
shell globbing chars into a shell that treats `$mudurl` as an
expandable glob, output is misleading. The subsequent `$lldpcli`
invocation only uses `$odval`, which is hex only, so this is client
side and cosmetic.

**T-27 [T, low] `signmudfile.sh` uses unquoted `$mudfile`**
Same class as T-26. Client side, breaks on spaces in filenames.

### 2.7 Build & runtime pipeline

**T-28 [T, med] `mudcerts` cloned at build without pinning**
```dockerfile
ARG MUDCERTS_REF=main
RUN git clone https://github.com/iot-onboarding/mudcerts.git /src/mudcerts \
    && git checkout "${MUDCERTS_REF}" && go mod download && ...
```
Default is `main`. A compromised or force-pushed `main` in the
upstream repo becomes the production `mudzipserver` binary at the next
image rebuild. There is no commit-hash pinning, no signature check,
no `go.sum` verification against an in-tree copy.

**T-29 [T, med] Base images floating**
`golang:1.26-bookworm`, `python:3.14-slim`, `httpd:2.4` — no digest
pins in the FROM lines. Reproducibility and supply-chain integrity
depend on Docker Hub not being tampered with between builds.

**T-30 [I, low] No `.dockerignore` audit**
The Dockerfile copies specific files by name (defence-in-depth
already, good) so the risk of shipping `.git/` or `foo` into the image
is low. `.dockerignore` presence should be re-confirmed as the file
list grows.

## 3. Prioritised remediation plan

Priorities: **P0** = ship-blocking / trivial fix, **P1** = next
maintenance window, **P2** = design work required. Each item lists
the threats it closes and the concrete change to make.

### P0 — hygiene, immediate

1. **Remove `foo` and `gitmud/setup.cfg~` from the repo** (T-20, T-21).
   ```bash
   git rm foo gitmud/setup.cfg~
   ```
   Add `**/*~` to `.gitignore` alongside the existing `*.bak`.
2. **Replace the sample `secret_key` in [gitmud/config.ini](gitmud/config.ini)
   with an obvious placeholder** such as `CHANGE_ME` (T-05). Keep the
   existing generation instructions.
3. **Add a repository `SECURITY.md` triage line** pointing to a
   monitored contact — already exists; verify the address still
   resolves.

### P1 — auth, hardening, headers

4. **Add Apache response headers in
   [docker/mudzip-proxy.conf](docker/mudzip-proxy.conf)** (T-23):
   ```apache
   Header always set X-Content-Type-Options "nosniff"
   Header always set X-Frame-Options "DENY"
   Header always set Referrer-Policy "no-referrer"
   Header always set Content-Security-Policy \
       "default-src 'self'; img-src 'self' data:; script-src 'self'; \
        style-src 'self' 'unsafe-inline'; connect-src 'self'; \
        frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
   Header always set Strict-Transport-Security \
       "max-age=31536000; includeSubDomains"
   ```
   Enable `mod_headers` in the Dockerfile `sed` block.
5. **Encode filename and branch in `existing_file`** (T-08):
   ```python
   from urllib.parse import quote
   git_get("/repos/" + user + "/mudfiles/contents/"
           + quote(filename, safe="/") + "?ref="
           + quote(branch, safe=""), token)
   ```
6. **Sanitise `mfg` and `model` before use as ref/path** (T-07, T-10):
   introduce a helper `_sanitise_ref_component(s, max_len=64)` that
   lowercases, strips leading `.`/`-`, rejects `/`, `..`, `~`, `^`,
   `:`, `?`, `*`, `[`, `\`, control chars, and any codepoint outside
   `[a-z0-9._-]`, then apply it to `mfg` and `model` in
   `do_branch`, `do_the_rest`. Reject the request with 400 on
   violation rather than silently rewriting.
7. **Retire the legacy `got_tok` alias** (T-03) once the browser
   deploys past a full cache-max-age. Log a warning when it is used to
   drive the migration.
8. **Sanitise log output in `git_putpost`/`git_get`** (T-11) by
   truncating and stripping `\n`/`\r` from `resp.text` before it
   reaches the log formatter.
9. **Add `--max-requests 500 --max-requests-jitter 50` to the gunicorn
   command** in the Dockerfile (T-15).
10. **Add per-endpoint rate limiting** using `flask-limiter` (T-14):
    e.g. `10/minute` on `/pcap2mud`, `30/minute` on `/therest`,
    `60/minute` on the OAuth routes; keyed by the outer Apache's
    `X-Forwarded-For` (which the container Apache should be configured
    to set with `ProxyPreserveHost On` + a trusted-proxy allowlist).
11. **Kill-switch env var for `/pcap2mud`** (T-12, T-14): default
    `PCAP2MUD_ENABLED=1`, so an operator can flip a compromised or
    scapy-CVE-affected endpoint off without redeploying.

### P1 — data hygiene

12. **Chmod the SQLite DB to `0600`** in
    [docker/gitmud-entrypoint.sh](docker/gitmud-entrypoint.sh) after
    initialisation (T-18):
    ```sh
    chmod 600 "${DB_PATH}"
    ```
    Same for any newly-created file.
13. **Add a token TTL / janitor** (T-16, T-18, T-26): store
    `created_at`, evict rows older than `N` days from a small
    background thread or a cron job in the container. Suggested
    default: 90 days.
14. **Add a `/signout?mudurl=...` route** that deletes the token row
    and calls the GitHub `DELETE /applications/{client_id}/token`
    endpoint to revoke it upstream (T-18, T-26). Link from the UI.
15. **Revisit T-01 (mudurl-as-capability)**: at minimum, bind the
    token row to the OAuth-completion IP or a browser-generated
    session id stored alongside `mudurl`, and require a match on
    `/dorepo`/`/branch`/`/therest`. Ideal fix is to key the DB on
    `(mudurl, github_login)` and require the client to prove
    ownership per request (e.g. sign a nonce with a short-lived
    per-tab secret). This is P2-sized design work.

### P1 — client-side

16. **Migrate `addEntry` in
    [assets/js/mudmaker.js](assets/js/mudmaker.js#L378) off
    `innerHTML`** to `MudSafeDom.element(...)` from
    [assets/js/dom-safe.js](assets/js/dom-safe.js) (T-22). Preserves
    the current inputs and hardens against future refactor mistakes.
17. **Call `URL.revokeObjectURL(url)`** after the download click at
    [assets/js/mudmaker.js:527](assets/js/mudmaker.js#L527) (T-25).

### P1 — supply chain

18. **Pin `MUDCERTS_REF` to a specific commit SHA** in
    [Dockerfile](Dockerfile#L3) (T-28). Update on each mudcerts
    release with a corresponding PR here.
19. **Pin base images by digest** (T-29):
    ```dockerfile
    FROM golang:1.26-bookworm@sha256:...
    FROM python:3.14-slim@sha256:...
    FROM httpd:2.4@sha256:...
    ```
    Refresh in a monthly maintenance PR.
20. **Add a CI job that runs `pip-audit`, `npm audit --production`
    (none for us today), and `trivy image` on the built images**;
    fail on high/critical. Wire into
    [.github/workflows/ci.yml](.github/workflows/ci.yml).

### P2 — design work

21. **Redesign the token store** (T-01, T-04): move the "am I
    authenticated?" check off the mudurl and onto a per-browser bearer
    minted at OAuth completion time. The bearer is sent by the client
    on each subsequent gitmud call. Retire the `got_token` shortcut
    entirely.
22. **Sandbox `mudgen_pcap.py`** (T-12): run it in a stripped-down
    child container (`docker exec` into a scapy sidecar) or under
    `bubblewrap`/`firejail` with no network, no `/etc/gitmud`, no
    `/var/lib/gitmud`, a private tmpfs, and RSS/CPU cgroup limits.
    Timeout stays 60 s; add a memory ceiling.
23. **CSRF for gitmud** (T-04): once (21) introduces a per-session
    bearer, require it on every mutating route. Reject `Origin`
    headers outside `mudmaker.org`.

### P2 — operational

24. **Runbook enforcement for the mudzipserver DNS pitfall** (T-17):
    add a health-check script in `deploy/` (or, since `deploy/` is
    out of scope, in ops docs) that verifies `POST /mudzip` returns
    200 within 5 s of any container restart, and pages otherwise.
    Update the CI smoke to fail on the same signal.
25. **Structured logging with a `request_id`** across the container
    Apache and gitmud so token-abuse investigations can correlate
    entries without cross-referencing timestamps.

## 4. Cross-reference matrix

| Threat | Priority | Remediation item(s) |
|--------|----------|---------------------|
| T-01 mudurl-as-capability | P2 | 15, 21 |
| T-02 gottoken oracle | P2 | 21 (removes the endpoint) |
| T-03 `got_tok` alias | P1 | 7 |
| T-04 CSRF / no origin check | P2 | 23 |
| T-05 low-entropy sample key | P0 | 2 |
| T-06 caller-declared user | (mitigated) | keep the existing check |
| T-07 path traversal | P1 | 6, 5 |
| T-08 unencoded URL | P1 | 5 |
| T-09 legacy JSON path | P1 | 6, 7 |
| T-10 unsanitised ref chars | P1 | 6 |
| T-11 log forgery | P1 | 8 |
| T-12 scapy on hostile bytes | P1 / P2 | 11, 22 |
| T-13 extension-only check | P2 | 22 |
| T-14 no rate limit | P1 | 10, 11 |
| T-15 no worker recycle | P1 | 9 |
| T-16 unbounded SQLite | P1 | 13 |
| T-17 stale DNS in Apache | P2 | 24 |
| T-18 plaintext tokens forever | P1 | 12, 13, 14 |
| T-19 reflected mudurl | (mitigated) | — |
| T-20 `foo` in repo | P0 | 1 |
| T-21 `~` backup in repo | P0 | 1 |
| T-22 innerHTML templating | P1 | 16 |
| T-23 missing headers | P1 | 4 |
| T-24 no SRI | (contingent) | if a CDN is ever adopted |
| T-25 blob URL leak | P1 | 17 |
| T-26 no sign-out | P1 | 14 |
| T-27 `lldpmud.sh` quoting | (client) | quote positional args |
| T-28 `signmudfile.sh` quoting | (client) | quote positional args |
| T-29 unpinned mudcerts | P1 | 18 |
| T-30 unpinned base images | P1 | 19 |

## 5. What was NOT flagged

For completeness, the following were reviewed and found to be
adequate:

* SQLite queries use parameter placeholders (`?`); no injection risk.
* `subprocess.run` in `/pcap2mud` uses a list argv; no shell
  metachar risk.
* `/pcap2mud` field validation (regex-anchored allow-list for
  `mfg`/`model`/`systeminfo`, URL scheme check for `documentation`
  and `mud_url`, MAC regex).
* `_sanitise_pcap_filename` and `_dedupe_target_names` on the
  multipart path of `/therest`.
* `20 MiB` request-body cap enforced at both Apache
  (`LimitRequestBody`) and Flask (`MAX_CONTENT_LENGTH`).
* Reflected fields in `/therest` are HTML-escaped with
  `markupsafe.escape` (CodeQL `py/reflective-xss`).
* Container process runs as non-root uid 1001 (`USER gitmud` in
  [Dockerfile](Dockerfile#L53)).
* `mudzipserver` enforces `limitBody(150 KiB)` and
  `concurrencyLimiter(NumCPU, 100ms)` at the front door.
* No CORS wildcard, no `Access-Control-Allow-Credentials: true`.
* Static site loads only same-origin resources; no external CDN
  dependencies today.
