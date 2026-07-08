# Deployment playbook: GitHub-security refactor

Rollout guide for the security changes introduced on 2026-07-08 (five
phases of [GITHUB_REMEDIATION_PLAN.md](GITHUB_REMEDIATION_PLAN.md)).

The emphasis of this document is **testing**: every change ships with a
verifiable behaviour, and every verifiable behaviour has a smoke test
here that an operator can copy-paste against a staging or production
container. If a smoke test does not pass, do not proceed to the next
step.

Companion documents:
- [THREAT_MODEL.md](THREAT_MODEL.md) — what each check protects against.
- [GITHUB_REMEDIATION_PLAN.md](GITHUB_REMEDIATION_PLAN.md) — the design.
- Repo memory (`/memories/repo/deployment.md`) — host layout, deploy quirks.

## 0. Deployment shape (recap)

- Host: `w1`, compose project rooted at `/containers/www.mudmaker.org/`.
- Outer host Apache terminates TLS on `:443` and proxies to
  `127.0.0.1:8081`.
- Only the `mudmaker` container publishes a port (`8081`). `gitmud`
  and `mudzipserver` sit on the compose-internal network.
- Restart rule: never restart `gitmud` or `mudzipserver` alone —
  always pair with `mudmaker` or use `--force-recreate` on the whole
  stack (see repo memory for the DNS-cache root cause).

## 1. Prerequisites (do this before touching `w1`)

### 1.1 GitHub side (one-time)

- **Secret scanning + push protection** enabled on both
  `iot-onboarding/mudmaker` and `iot-onboarding/mudcerts` (see
  Settings → Advanced Security in the 2026 GitHub UI).
- **OAuth App** (`Ov23licSoRbhBHkeDqPJ`) callback URL includes
  `https://mudmaker.org/mudpublish.html` and nothing outside that
  origin.
- **OAuth App consent scope** — the browser now requests
  `public_repo` instead of `repo`. Load `mudmaker.html`, click
  Publish once, and confirm the GitHub consent screen text reads
  *"Access public repositories"*, not *"Full control of private
  repositories"*. If it still says "Full control", the browser is
  cached — hard-reload or wait for cache expiry.
- **Client secret rotated** at the same time as this deploy (see §2.3).
  Old secret revoked on the OAuth App page.

Verify programmatically:

```bash
gh api /repos/iot-onboarding/mudmaker --jq '.security_and_analysis'
# expected: both statuses "enabled"
```

### 1.2 Host side

- Confirm the host `config.ini` exists at
  `/containers/www.mudmaker.org/gitmud/config.ini` and is `0600`,
  owned by the user compose runs as:
  ```bash
  stat -c '%a %U %G %n' /containers/www.mudmaker.org/gitmud/config.ini
  # expected: 600 root root
  ```
- The file must now contain a `[security]` section (see §2.2).
- Sqlite DB path (`/var/lib/gitmud/mudbase.db` inside the container,
  backed by the `gitmud-data` volume) — no manual action; the
  entrypoint chmods it to `0600` on every start.

### 1.3 Have a rollback plan

Before deploying, capture:

```bash
cd /containers/www.mudmaker.org
docker-compose ps
docker inspect wwwmudmakerorg-gitmud-1 --format '{{.Image}}' > /tmp/rollback-gitmud-image
docker inspect wwwmudmakerorg-mudmaker-1 --format '{{.Image}}' > /tmp/rollback-mudmaker-image
docker inspect wwwmudmakerorg-mudzipserver-1 --format '{{.Image}}' > /tmp/rollback-mudzipserver-image
docker exec wwwmudmakerorg-gitmud-1 sqlite3 /var/lib/gitmud/mudbase.db .schema > /tmp/rollback-schema.sql
```

Rollback = `docker tag <captured-image-id> mudmaker-gitmud:latest`
etc., then `docker-compose up -d --force-recreate`. See §7.

## 2. Pre-deploy checklist

### 2.1 CI must be green on `main`

Every job in [.github/workflows/ci.yml](.github/workflows/ci.yml)
must be passing before you cut the deploy:

```bash
gh run list --workflow ci --branch main --limit 1
```

Confirm the `Dockerfile guard rail — no secrets in image layers` step
and the `Verify MUDCERTS_REF is pinned to a commit SHA (T-28)` step
are both green.

### 2.2 Host `config.ini` has the new `[security]` block

Required minimum (values may be edited):

```ini
[security]
allowed_origins = https://mudmaker.org,https://www.mudmaker.org
session_ttl_seconds = 7776000
janitor_interval_seconds = 3600
legacy_mudurl_fallback = true
```

Copy from [gitmud/config.ini](gitmud/config.ini) if starting fresh.
The `legacy_mudurl_fallback` MUST be `true` on the first deploy so
cached browsers keep working; §6 covers when to flip it to `false`.

### 2.3 Rotate the GitHub OAuth client secret

Do this in the same window as the deploy so any in-flight tokens are
invalidated at the same moment as the schema change. On GitHub:

1. github.com/settings/developers → the mudmaker OAuth App →
   *Generate a new client secret*.
2. Paste the new value into the host's `config.ini`
   (`[github] client_secret = ...`), keeping file mode `0600`.
3. Revoke the old secret on the same GitHub page.

### 2.4 Confirm the mudcerts SHA pin matches what you expect

```bash
grep '^ARG MUDCERTS_REF=' Dockerfile
# expected: ARG MUDCERTS_REF=<40-char SHA>
```

If bumping mudcerts as part of this deploy, update
`/memories/repo/deployment.md` and the Dockerfile in the same PR.

## 3. Deploy

The compose-based deploy on `w1` uses the existing (out-of-scope)
`deploy/deploy-new.sh` which already does `docker-compose down && up
-d`. For an ad-hoc deploy without that script:

```bash
cd /containers/www.mudmaker.org
git fetch --all
git checkout <sha>          # the tested commit
docker-compose build        # builds all three services
docker-compose down
docker-compose up -d
docker-compose ps           # all three services Up
docker-compose logs --no-color --tail=30 gitmud
docker-compose logs --no-color --tail=30 mudmaker
docker-compose logs --no-color --tail=30 mudzipserver
```

Expected log lines in `gitmud`:

- `gitmud: initialising database at /var/lib/gitmud/mudbase.db` (first
  run only) OR nothing if reusing an existing volume.
- A gunicorn `Listening at: http://0.0.0.0:8000` line.
- **Nothing** matching `could not ensure schema at import`.

## 4. Post-deploy smoke tests

Run these from `w1` (or an on-network host) against
`http://127.0.0.1:8081`. In §4.10 the same tests are repeated against
`https://mudmaker.org` to confirm the outer vhost too.

Set once for the session:

```bash
BASE=http://127.0.0.1:8081
```

### 4.1 Static site + proxy still up

```bash
curl -fsS -o /dev/null $BASE/mudmaker.html && echo "html OK"
curl -sS -o /dev/null -w '%{http_code}\n' $BASE/pcap2mud
# expected: 405 (route exists, GET not allowed) — proves gitmud proxy alive
curl -sS -o /dev/null -w '%{http_code}\n' $BASE/gitShovel/whoami
# expected: 401 (no bearer, no legacy row for the caller) — Phase 3 route registered
```

### 4.2 Phase 1 — input hardening (T-07, T-08, T-09, T-10)

Send a bad `mfg-name` and confirm the request is refused **before**
any GitHub call would be made. `client_id=ci-stub`-style credentials
in `config.ini` will make real dance attempts fail; that's fine — we
only need the 400 path here.

```bash
BAD_MUD=$(python3 -c 'import base64, json; \
print(base64.b64encode(json.dumps({ \
  "ietf-mud:mud": { \
    "mud-url":"https://example.com/.well-known/mud/x.json", \
    "mfg-name":"../evil", "systeminfo":"Widget" \
  }, \
  "ietf-access-control-list:acls":{"acl":[]}}).encode()).decode())')

curl -sS -X POST $BASE/gitShovel/therest \
  -F "mudFile=$BAD_MUD" -F "email=x@example.com" | jq .
# expected: {"error":"mfg-name: forbidden characters"}  (400)
```

Traversal in `/branch` too (with a fake bearer — the sanitiser runs
before auth resolves for these fields):

```bash
curl -sS -X POST $BASE/gitShovel/branch \
  -H "Authorization: Bearer nonexistent" \
  -H "Content-Type: application/json" \
  -d '{"mfg":"acme","model":"../evil"}'
# expected 401 (bearer not found) OR 400 (sanitiser hits first);
# both are acceptable -- what MUST NOT happen is a 200.
```

### 4.3 Phase 2 — Origin allowlist (T-04)

Cross-origin POST is refused:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST $BASE/gitShovel/oAuthv2 \
  -H "Origin: https://evil.example" \
  -H "Content-Type: application/json" -d '{"mudurl":"x"}'
# expected: 403
```

Same-origin POST passes the guard (and gets rejected downstream for
lack of a code — that's the correct behaviour):

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST $BASE/gitShovel/oAuthv2 \
  -H "Origin: https://mudmaker.org" \
  -H "Content-Type: application/json" -d '{"mudurl":"x"}'
# expected: 400
```

GET/HEAD are always exempt:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  $BASE/gitShovel/whoami -H "Origin: https://evil.example"
# expected: 401 (auth check, not origin block)
```

### 4.4 Phase 2 — Log scrubbing (T-11)

Provoke a failed GitHub call (real API URL, ci-stub token) and
inspect the log line — it must show `_safe_log()`-repr'd content, not
raw bytes:

```bash
docker-compose logs --no-color --tail=200 gitmud | grep -E 'git_(get|put|post)' | tail -5
# expected: lines contain `'...'` (repr quoted) and no literal \r\n
```

### 4.5 Phase 3 — `/gottoken` removed (T-02)

```bash
curl -sS -o /dev/null -w '%{http_code}\n' $BASE/gitShovel/gottoken?mudurl=x
# expected: 404
```

### 4.6 Phase 3 — `/whoami` requires bearer

```bash
curl -sS -o /dev/null -w '%{http_code}\n' $BASE/gitShovel/whoami
# expected: 401

curl -sS -o /dev/null -w '%{http_code}\n' $BASE/gitShovel/whoami \
  -H "Authorization: Bearer definitely-not-a-real-session"
# expected: 401
```

### 4.7 Phase 3 — `/signout` is idempotent

```bash
curl -sS -o /dev/null -w '%{http_code}\n' -X POST $BASE/gitShovel/signout
# expected: 204 (no session -> ok, per plan)

curl -sS -o /dev/null -w '%{http_code}\n' -X POST $BASE/gitShovel/signout \
  -H "Authorization: Bearer fake"
# expected: 204 (unknown bearer -> ok, idempotent)
```

### 4.8 Phase 3 — Full publish round-trip (manual)

Best done in a real browser against a staging origin. Steps:

1. Open the site (`https://staging.mudmaker.org/mudmaker.html`).
2. DevTools → Application → Session storage → confirm no
   `mudmaker_session` key.
3. Build a MUD, click **Publish**, complete GitHub OAuth.
4. On the redirect back to `mudpublish.html`:
   - Check DevTools → Application → Session storage. There should now
     be a `mudmaker_session` key with a ~43-char URL-safe string.
   - Check Network → the initial `/gitShovel/oAuthv2` POST returns
     `{"user":"<login>","session":"<...>"}`.
   - Every subsequent `/gitShovel/{dorepo,branch,therest}` call has
     an `Authorization: Bearer …` request header.
5. PR appears in `<login>/mudfiles` — same behaviour as before, but
   the credential travelled by header, not by URL.

### 4.9 Phase 3 — Sign-out UI

On the publish tab of `mudmaker.html`, click **Sign out of GitHub**:

- Status text changes to `Signed out.`
- Session storage `mudmaker_session` key is gone.
- gitmud container log shows one `POST /signout` returning `204`.
- Optional: on GitHub → Settings → Applications → *Authorized OAuth
  Apps*, the mudmaker entry is gone.

### 4.10 Phase 4 — Deprecation warning fires

Cached browsers with the old JS will keep sending `got_token=true`.
Simulate one:

```bash
curl -sS -o /dev/null -X POST $BASE/gitShovel/oAuthv2 \
  -H "Content-Type: application/json" \
  -H "Origin: https://mudmaker.org" \
  -d '{"mudurl":"https://example.com/x","got_token":true}'
docker-compose logs --no-color --tail=50 gitmud | grep DEPRECATED
# expected: at least one line with
#   "DEPRECATED got_token/got_tok shortcut used origin=... ua=..."
```

Count these over the first week. When they drop below your Phase 3.5
threshold (see §6), the legacy fallback is safe to remove.

### 4.11 Phase 5 — mudcerts binary is the pinned commit

Confirm the running mudzipserver was built from the expected SHA:

```bash
docker inspect wwwmudmakerorg-mudzipserver-1 \
  --format '{{index .Config.Labels "org.opencontainers.image.revision"}}' 2>/dev/null || true

# The definitive check: rebuild locally with the same SHA and diff the
# binary hash.  A single-line sanity check:
grep '^ARG MUDCERTS_REF=' Dockerfile
docker exec wwwmudmakerorg-mudzipserver-1 /mudzipserver -version 2>&1 || true
```

If mudcerts starts emitting its git-commit at startup (recommended
follow-up), that log line should match `ARG MUDCERTS_REF=` in this
repo's Dockerfile.

### 4.12 Runtime file modes (T-18)

The entrypoint chmods the sqlite DB on every start. Verify:

```bash
docker exec wwwmudmakerorg-gitmud-1 stat -c '%a %U %n' \
  /var/lib/gitmud/mudbase.db
# expected: 600 gitmud /var/lib/gitmud/mudbase.db
```

### 4.13 External smoke test through the outer vhost

Repeat §4.1, §4.3, §4.5, §4.6 with `BASE=https://mudmaker.org`. The
outer Apache MUST forward Host/Origin unchanged; if the origin
allowlist trips on a legitimate same-origin request, that is a proxy
misconfig (see repo memory: the outer vhost had `ProxyPreserveHost
On` issues in the past).

## 5. Automated smoke suite

Add the following to any cron / uptime tooling. Each command is
idempotent and safe to run every minute:

```bash
# 1. Site up
curl -fsS -o /dev/null https://mudmaker.org/mudmaker.html

# 2. Origin allowlist active
test "$(curl -sS -o /dev/null -w '%{http_code}' \
  -X POST https://mudmaker.org/gitShovel/oAuthv2 \
  -H 'Origin: https://evil.example' \
  -H 'Content-Type: application/json' -d '{}')" = "403"

# 3. /gottoken removed
test "$(curl -sS -o /dev/null -w '%{http_code}' \
  https://mudmaker.org/gitShovel/gottoken?mudurl=x)" = "404"

# 4. /whoami rejects unauth
test "$(curl -sS -o /dev/null -w '%{http_code}' \
  https://mudmaker.org/gitShovel/whoami)" = "401"

# 5. /signout idempotent
test "$(curl -sS -o /dev/null -w '%{http_code}' \
  -X POST https://mudmaker.org/gitShovel/signout)" = "204"
```

Any of these five failing = page the operator.

## 6. Phase 3.5 / Phase 4 cutover criteria

The Phase 3 deploy leaves the legacy mudurl fallback ON and the
`got_token` shortcut accepted (with a deprecation log). Do NOT flip
these off until data says it's safe.

### 6.1 Signal to watch

```bash
# Deprecation warnings per day
docker-compose logs --since 24h gitmud \
  | grep -c "DEPRECATED got_token"

# Legacy fallback hits per day
docker-compose logs --since 24h gitmud \
  | grep -c "legacy mudurl fallback used"

# Sanity denominator: successful publishes per day
docker-compose logs --since 24h gitmud \
  | grep -c "POST /therest"
```

### 6.2 Phase 3.5 (flip `legacy_mudurl_fallback = false`)

Criteria (all three):

1. **Time**: at least 6 weeks since Phase 3 shipped.
2. **Rate**: `legacy fallback used` events per day < 1% of successful
   `/therest` publishes for 7 consecutive days.
3. **Absolute**: fewer than 5 `legacy fallback` events per day for 3
   consecutive days.

Action:

```bash
# On w1:
$EDITOR /containers/www.mudmaker.org/gitmud/config.ini
# under [security]: legacy_mudurl_fallback = false
cd /containers/www.mudmaker.org && docker-compose up -d --force-recreate gitmud mudmaker
```

Re-run §4.5 – §4.7 to confirm nothing regressed.

### 6.3 Phase 4 (return `410` for `got_token`)

Criteria: same as Phase 3.5 but for the `DEPRECATED got_token`
counter. When it stays at zero for 2 weeks after 3.5 has shipped,
edit [gitmud/gitmud/app.py](gitmud/gitmud/app.py) `complete_oauth()`:

```python
if legacy_shortcut:
    return jsonify({"error": "legacy path removed; please reload"}), 410
```

Redeploy. Confirm:

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -X POST https://mudmaker.org/gitShovel/oAuthv2 \
  -H "Origin: https://mudmaker.org" \
  -H "Content-Type: application/json" \
  -d '{"mudurl":"x","got_token":true}'
# expected: 410
```

## 7. Rollback

If any post-deploy smoke test in §4 fails, roll back before
investigating.

### 7.1 Image rollback

```bash
cd /containers/www.mudmaker.org
docker tag $(cat /tmp/rollback-gitmud-image)      mudmaker-gitmud:latest
docker tag $(cat /tmp/rollback-mudmaker-image)    mudmaker:latest
docker tag $(cat /tmp/rollback-mudzipserver-image) mudmaker-mudzipserver:latest
docker-compose up -d --force-recreate
```

### 7.2 Schema

`_ensure_schema()` uses `CREATE TABLE IF NOT EXISTS`, so the new
`sessions` table is additive. A rollback to the previous image does
not require dropping it — the old code simply ignores it. Only drop
the table if you are also permanently downgrading:

```bash
docker exec -it wwwmudmakerorg-gitmud-1 \
  sqlite3 /var/lib/gitmud/mudbase.db 'DROP TABLE sessions;'
```

### 7.3 Config

If the rollback image predates the `[security]` section, the app will
tolerate a missing section (defaults kick in). No config revert
needed. If in doubt:

```bash
cp /tmp/rollback-config.ini /containers/www.mudmaker.org/gitmud/config.ini
```

(Only relevant if you captured a rollback copy per §1.3.)

## 8. Post-mortem template

If anything went wrong, capture:

1. Which smoke test failed (§4.x).
2. `docker-compose logs --no-color --tail=200 <service>` for the
   affected container.
3. `gh run view <ci-run-id>` output for the CI run that shipped the
   commit (in case a guard-rail was disabled).
4. Output of `gh api /repos/iot-onboarding/mudmaker --jq
   '.security_and_analysis'` to confirm secret scanning didn't get
   accidentally disabled.
5. Latest 10 `DEPRECATED got_token` events and 10 `legacy mudurl
   fallback` events, to see whether the failure hit new-code or
   legacy-code paths.

Append findings to `/memories/repo/deployment.md` under a new
heading — the file is the authoritative operator memory.

## 9. Change-log for this playbook

- 2026-07-08 — initial version covering Phases 1–5 of
  [GITHUB_REMEDIATION_PLAN.md](GITHUB_REMEDIATION_PLAN.md).
