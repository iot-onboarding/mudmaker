# CI/CD Plan for `mudmaker`

## Goals
1. Catch regressions in the three runtime surfaces — static site, `gitmud`
   Flask app, and `mudzipserver` Go binary — before merge.
2. Exercise the same docker stack that ships to production, not a mocked
   variant.
3. Stay on GitHub-hosted runners (no self-hosted infrastructure) and finish
   in well under the 360-minute job ceiling.
4. Surface enough forensics on failure (logs, downloaded zip, screenshots,
   MUD JSON) to diagnose without re-running.

## Test inventory & how each fits CI

| Layer | Test | Runner needs | CI fit |
|---|---|---|---|
| Pure Python | `tests/test_pcap_sanitise.py` | python3 + `gitmud` on path | trivial; runs in lint job |
| Flask in-proc | `tests/test_publish_multi.py` | python3 + Flask deps | trivial; runs in unit job |
| JS via Node | `tests/test_acl_dedupe.py` | python3 + node | unit job |
| pcap→MUD integration | `tests/smoke_smartercoffee.py` | live stack on :8081 + SmarterCoffee pcaps | docker-compose job |
| Browser end-to-end signing | (new) playwright + system Chrome | live stack + chrome + openssl | docker-compose job |

The SmarterCoffee pcaps live under `tmp/captures_IoT-Sentinel/` — if that
directory is gitignored, the integration job needs to fetch them from the
upstream archive (or we cache a trimmed fixture in the repo under
`tests/fixtures/`).

## Workflow files

### `.github/workflows/ci.yml` — main PR / push gate

Trigger: `pull_request`, `push` to `main`. Concurrency-group cancels
superseded runs.

Three jobs, run in parallel where possible:

**`lint-and-unit`** (ubuntu-latest, ~2 min)
- `actions/checkout`
- `actions/setup-python@v5` (3.12) with `cache: pip` keyed on
  `gitmud/requirements.txt`
- `actions/setup-node@v4` (LTS) — needed by the JS dedupe test
- `pip install -r gitmud/requirements.txt pytest`
- `python -m pyflakes gitmud/ mudgen_pcap.py` (cheap static check)
- `python -m pytest tests/test_pcap_sanitise.py tests/test_publish_multi.py
  tests/test_acl_dedupe.py -v`
- HTML lint: `npx --yes htmlhint *.html`
- JS syntax sanity: `node --check assets/js/*.js`

**`docker-build`** (ubuntu-latest, ~5–8 min cold, ~2 min warm)
- `docker/setup-buildx-action@v3`
- `docker/build-push-action@v6` with `cache-from: type=gha,scope=mudmaker`
  and `cache-to: type=gha,mode=max` for each of the three targets
  (`mudmaker`, `mudzipserver`, `gitmud`).
- `docker compose config` to validate the compose file.
- Save image tarballs as artifacts (or push to ghcr.io on `main` only; see
  release section) so downstream jobs reuse them.

**`integration`** (ubuntu-latest, ~5 min, `needs: docker-build`)
- Load the built images (`docker load`) from the previous job's artifacts.
- Write a stub `gitmud/config.ini` from a templated string (no real OAuth
  secret — `/pcap2mud` and `/mudzip` don't need GitHub).
- `docker compose up -d`; `wait-on http://127.0.0.1:8081/mudmaker.html`.
- Run `python tests/smoke_smartercoffee.py` (download SmarterCoffee pcaps
  from the IoT-Sentinel mirror with `actions/cache` keyed on archive sha if
  not in repo).
- Run the new `tests/test_signing_chrome.py` Playwright smoke test (see
  below).
- Always-run step: `docker compose logs --no-color > compose.log`; upload
  `compose.log`, downloaded `SmokeWidget.zip`, and any Playwright
  screenshots/traces as artifacts on failure.

**Path filters** — annotate triggers so doc-only PRs skip the docker job:

```yaml
on:
  pull_request:
    paths-ignore: ['**.md', 'images/**', 'CODE_OF_CONDUCT.md', 'CONTRIBUTING.md']
```

### New browser test: `tests/test_signing_chrome.py`

A Python wrapper around the proven flow we just ran (form-fill → Sign →
download → unzip → `openssl cms -verify`). Implemented with
`playwright[python]` so the dependency footprint matches `gitmud/`:

```python
# pseudo-code outline
sync_playwright().chromium.launch(channel="chrome")   # system Chrome on the runner
page.goto("http://127.0.0.1:8081/mudmaker.html")
# fill mudhost, model_name, mfg-name, systeminfo, documentation, email_addr;
# select_option country
page.get_by_role("button", name="Publish/Save/Continue Work").click()
with page.expect_download() as dl:
    page.locator('button[name="Sign"]').click()
download.save_as(zip_path)
subprocess.check_call(["unzip", "-o", zip_path, "-d", extract_dir])
subprocess.check_call([
    "openssl", "cms", "-verify", "-in", f"{extract_dir}/{model}.p7s",
    "-inform", "DER",
    "-content", f"{extract_dir}/{model}.json", "-CAfile", f"{extract_dir}/ca.pem",
    "-purpose", "any", "-binary", "-out", "/dev/null"])
```

Pre-step installs Chrome on the runner via `browser-actions/setup-chrome@v1`
and `pip install playwright`; **no** `playwright install` is needed because
we use `channel="chrome"`.

### `.github/workflows/release.yml` — main-branch publishing

Trigger: `push` to `main`, or `workflow_dispatch`, or tag `v*`.

- `needs: [lint-and-unit, integration]` (`workflow_run` after CI succeeds,
  or run the same jobs first).
- `docker/login-action@v3` against `ghcr.io` with `GITHUB_TOKEN`.
- Build + push the three images tagged `:sha-${GITHUB_SHA::7}`, `:main`, and
  (on tag) `:${{ github.ref_name }}`.
- Generate an SBOM with `anchore/sbom-action@v0` and attach to the release.

### `.github/workflows/codeql.yml` — security

- `github/codeql-action` with `languages: python, javascript, go`.
- Weekly schedule + push to `main`.

### `.github/dependabot.yml`

- `pip` (`gitmud/requirements.txt`), `docker` (Dockerfile base images),
  `github-actions` (workflow versions), `gomod` (mudcerts pin if vendored).
  Weekly cadence.

## Secrets & config strategy

- **Zero secrets required for CI** — the integration job uses a generated
  dummy `config.ini` (random Flask secret, empty `client_secret`, sqlite
  path under `/tmp`). The `/pcap2mud`, `/mudzip`, and `/therest`-test-client
  paths exercised in CI don't touch GitHub OAuth.
- **`GHCR_TOKEN` / `GITHUB_TOKEN`** only needed in `release.yml` for image
  publishing.
- Never run the OAuth-dependent `/oAuthv2` or live `/therest` flows in CI;
  cover them with the in-process `test_publish_multi.py` (which already
  monkeypatches GitHub).

## Caching

- `actions/setup-python` `cache: pip` keyed on `gitmud/requirements.txt`.
- `actions/setup-node` `cache: npm` if we add a `package.json` for htmlhint
  / playwright.
- `actions/cache` for the SmarterCoffee pcap archive (URL+sha key),
  avoiding repeated mirror downloads.
- Buildx GHA cache (`type=gha,mode=max`) per docker target — biggest single
  time saver because the Go stage is otherwise expensive.

## Failure-forensic artifacts

Uploaded only on `if: failure()`:

- `compose.log` (`docker compose logs`)
- `tests/_artifacts/SmokeWidget.zip` and `extracted/`
- Playwright `trace.zip` + screenshot on the page where the failure
  occurred
- pytest `--junit-xml` so the GitHub UI shows the failed test list

## Status checks to require on `main`

`lint-and-unit`, `docker-build`, `integration`, `codeql`. Branch protection
blocks merge until they pass.

## Roll-out order (low → high risk)

1. Land `lint-and-unit` alone — covers the three unit tests we already pass
   locally; cheap and proves the workflow scaffolding.
2. Add `docker-build` with build cache; verify warm runtime.
3. Add `integration` with `smoke_smartercoffee.py` only (no browser yet).
4. Add `tests/test_signing_chrome.py` + Playwright/Chrome setup.
5. Add `release.yml` + ghcr publishing once 1–4 are green for a week.
6. Enable Dependabot + CodeQL.
