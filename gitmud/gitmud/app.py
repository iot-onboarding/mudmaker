"""
App to manage oauth tokens for mud files, and to generate PRs.
"""

import base64
import configparser
import json
import logging
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import unicodedata
from functools import wraps
from pathlib import Path
from time import sleep
from urllib.parse import quote, urlparse
from flask import Flask, request, jsonify
from markupsafe import escape
import requests

log = logging.getLogger("gitmud")
# Surface INFO-level diagnostics (e.g. per-PUT trail in git_putpost) to
# the gunicorn stderr stream.  Without an explicit handler the default
# "lastResort" handler only emits WARNING+.  Honour LOG_LEVEL if set.
if not log.handlers:
    _h = logging.StreamHandler()
    _h.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s gitmud: %(message)s"))
    log.addHandler(_h)
    log.setLevel(os.environ.get("LOG_LEVEL", "INFO").upper())
    log.propagate = False


def _load_config():
    """
    Locate and parse the gitmud configuration file.

    Search order:
      1. $GITMUD_CONFIG (if set)
      2. /etc/gitmud/config.ini
      3. ../../config.ini relative to this module (the top of the
         gitmud subproject in a source checkout)
    """
    candidates = []
    env_path = os.environ.get("GITMUD_CONFIG")
    if env_path:
        candidates.append(Path(env_path))
    candidates.append(Path("/etc/gitmud/config.ini"))
    candidates.append(Path(__file__).resolve().parent.parent / "config.ini")

    for path in candidates:
        if path.is_file():
            parser = configparser.ConfigParser()
            parser.read(path, encoding="utf-8")
            return parser, path

    raise RuntimeError(
        "gitmud config file not found. Set GITMUD_CONFIG or install one of: "
        + ", ".join(str(p) for p in candidates)
    )


_CONFIG, _CONFIG_PATH = _load_config()

app = Flask(__name__)
app.url_map.strict_slashes = False
app.secret_key = _CONFIG["flask"]["secret_key"]

GITHUB_API_URL = _CONFIG["github"].get("api_url", "https://api.github.com")
GITHUB_CLIENT_ID = _CONFIG["github"]["client_id"]
GITHUB_SECRET_KEY = _CONFIG["github"]["client_secret"]
MUD_REPO = _CONFIG["github"].get("mud_repo", "/repos/iot-onboarding/mudfiles")

MUD_DB = _CONFIG["storage"]["db_path"]

# ---------------------------------------------------------------------------
# Phase 2 / Phase 3 security config.  The [security] section is optional in
# the config file so existing deployments keep working; the defaults below
# match a same-origin production install of mudmaker.org.
# ---------------------------------------------------------------------------
_SECURITY = _CONFIG["security"] if _CONFIG.has_section("security") else {}

_ALLOWED_ORIGINS = {
    o.strip() for o in _SECURITY.get(
        "allowed_origins",
        "https://mudmaker.org,https://www.mudmaker.org").split(",")
    if o.strip()
}

SESSION_TTL_SECONDS = int(_SECURITY.get(
    "session_ttl_seconds", str(90 * 24 * 3600)))

_JANITOR_INTERVAL_SECONDS = int(_SECURITY.get(
    "janitor_interval_seconds", "3600"))

# When True the mutating routes (/dorepo, /branch, /therest) will fall
# back to the pre-Phase-3 mudurl-keyed token lookup if a request arrives
# without a session bearer.  Phase 3.5 flips this to False after metrics
# show cached browsers have drained; Phase 4 deletes the fallback code.
_LEGACY_MUDURL_FALLBACK = _SECURITY.get(
    "legacy_mudurl_fallback", "true").strip().lower() == "true"


class GithubProblem(Exception):
    """
    When soemething blows up with Github
    """


def github_dance(code):
    """
    Take a code and turn it into a bearer token.
    """
    resp= requests.request("POST",
                           "https://github.com/login/oauth/access_token",
                           json={
                               'client_id' : GITHUB_CLIENT_ID,
                               'client_secret' : GITHUB_SECRET_KEY,
                               'code' : code
                           },
                           headers = {
                               'Accept' : 'application/json'
                           },
                           timeout=10
                           )
    return resp


# ---------------------------------------------------------------------------
# Phase 1 helpers: input hardening.
#
# Every value that becomes a GitHub REST path segment or a Git ref must
# pass through _sanitise_ref_component() first.  Every REST URL is built
# via _github_path()/_github_url() so path segments are URL-quoted with
# no `safe` characters.  Kills T-07, T-08, T-10.
# ---------------------------------------------------------------------------
_GIT_REF_COMPONENT_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")
_GIT_REF_FORBIDDEN_RE = re.compile(
    r"(\.\.|@\{|//|^-|^\.|/\.|\.$|[\x00-\x1f\x7f~^:?*\[\\ ])"
)


def _sanitise_ref_component(name, field_name):
    """Return *name* if it is safe to use as a single GitHub path segment
    or Git ref component.  Raise ValueError otherwise.

    Rules:
      * NFKC-normalise, lowercase, strip;
      * reject any control character (0x00-0x1F, 0x7F) before further
        rewriting -- newlines in particular must never survive to
        become log-forgery in later warnings;
      * collapse internal ASCII space/tab to "-";
      * reject empty, `..`, `//`, `@{`, leading `-`/`.`, trailing `.`,
        `/`, `~`, `^`, `:`, `?`, `*`, `[`, `\\`;
      * require final match `[a-z0-9][a-z0-9._-]{0,63}`.
    """
    if name is None or str(name).strip() == "":
        raise ValueError(f"{field_name}: missing")
    normalised = unicodedata.normalize("NFKC", str(name)).strip().lower()
    # Reject control chars first so \n/\r/\x1b cannot be quietly
    # collapsed to "-" by the whitespace pass below.
    for ch in normalised:
        if ord(ch) < 0x20 or ord(ch) == 0x7f:
            raise ValueError(f"{field_name}: control character present")
    normalised = re.sub(r"[ \t]+", "-", normalised)
    if _GIT_REF_FORBIDDEN_RE.search(normalised):
        raise ValueError(f"{field_name}: forbidden characters")
    if not _GIT_REF_COMPONENT_RE.match(normalised):
        raise ValueError(
            f"{field_name}: must match [a-z0-9][a-z0-9._-]{{0,63}}")
    return normalised


def _github_path(*segments):
    """Compose a GitHub REST path from validated segments.

    Each segment is URL-quoted with an empty `safe` charset so `/`, `?`,
    `#` and query separators cannot escape a segment.  Empty/None
    segments are dropped.
    """
    return "/" + "/".join(quote(str(s), safe="")
                          for s in segments if s not in (None, ""))


_LOG_TRUNC = 200


def _safe_log(text):
    """Return a repr-quoted, CR/LF/control-stripped, truncated version
    of *text* suitable for inclusion in a log record.  Kills T-11.
    """
    if text is None:
        return ""
    trimmed = str(text)[:_LOG_TRUNC].translate(
        {c: None for c in list(range(0, 32)) + [127]})
    return repr(trimmed)

def db_store(gitresp,mudurl):
    """
    Remove old information, store new information for a given mud-url.
    """
    con=sqlite3.connect(MUD_DB)
    cur = con.cursor()
    auth_code = gitresp["access_token"]
    scope = gitresp["scope"]
    token_type = gitresp["token_type"]
    cur.execute("DELETE from gitmud where mudurl = ?",(mudurl,))
    cur.execute("INSERT INTO gitmud VALUES (?,?,?,?)",
                (mudurl,auth_code,scope,token_type))
    con.commit()
    return True

def token_in_db(mudurl):
    """
    Check to see if a token is indeed already stored, and return if so.
    """
    con=sqlite3.connect(MUD_DB)
    cur = con.cursor()

    cur.execute("SELECT token from gitmud where mudurl = ?",(mudurl,))
    ans = cur.fetchone()
    if not ans:
        return False
    return ans[0]


def delete_token(mudurl):
    """
    Drop any stored token for this mudurl. Used when GitHub rejects the
    cached token (revoked, expired, wrong client, etc.) so the next request
    falls through to a fresh OAuth dance.
    """
    con = sqlite3.connect(MUD_DB)
    cur = con.cursor()
    cur.execute("DELETE FROM gitmud WHERE mudurl = ?", (mudurl,))
    con.commit()


# ---------------------------------------------------------------------------
# Phase 3: session bearer store.
#
# The ``sessions`` table is the Phase-3 replacement for the mudurl-keyed
# ``gitmud`` table.  Every successful OAuth completion mints a fresh
# ``secrets.token_urlsafe(32)`` and binds it to the resolved GitHub
# login + access token.  Mutating routes look up the bearer in the
# Authorization header rather than trusting a mudurl-in-body.
#
# The old ``gitmud`` table is kept for a single release so cached
# browsers continue to work; see _LEGACY_MUDURL_FALLBACK above and the
# ``@requires_session`` decorator below.
# ---------------------------------------------------------------------------

def _ensure_schema():
    """Idempotently create tables used by this app.  Runs at import.

    ``sessions`` is new in Phase 3; ``gitmud`` is the legacy table
    still populated by the fallback path.  Both use IF NOT EXISTS so
    the entrypoint's fresh-install path (``initdb.sql``) and the
    upgrade path (existing DB, new columns) both succeed.
    """
    con = sqlite3.connect(MUD_DB)
    with con:
        con.execute(
            "CREATE TABLE IF NOT EXISTS gitmud"
            "(mudurl, token, scope_val, mudfile)")
        con.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id    TEXT PRIMARY KEY,
                github_login  TEXT NOT NULL,
                access_token  TEXT NOT NULL,
                mudurl        TEXT NOT NULL,
                scope         TEXT,
                token_type    TEXT,
                created_at    INTEGER NOT NULL,
                last_used_at  INTEGER NOT NULL
            )
        """)
        con.execute("CREATE INDEX IF NOT EXISTS sessions_by_login "
                    "ON sessions(github_login)")
        con.execute("CREATE INDEX IF NOT EXISTS sessions_by_created "
                    "ON sessions(created_at)")


def _new_session(gitresp, github_login, mudurl):
    """Insert a new session row and return the freshly-minted bearer."""
    session_id = secrets.token_urlsafe(32)
    now = int(time.time())
    con = sqlite3.connect(MUD_DB)
    with con:
        con.execute(
            "INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?)",
            (session_id, github_login,
             gitresp["access_token"], mudurl,
             gitresp.get("scope"), gitresp.get("token_type"),
             now, now))
    return session_id


def _resolve_session(bearer):
    """Return dict(session_id, login, token, mudurl) for a live bearer,
    or None.  Expired rows are deleted and treated as absent.
    """
    if not bearer:
        return None
    con = sqlite3.connect(MUD_DB)
    row = con.execute(
        "SELECT session_id, github_login, access_token, mudurl, "
        "created_at FROM sessions WHERE session_id = ?",
        (bearer,)).fetchone()
    if not row:
        return None
    session_id, login, token, mudurl, created = row
    if int(time.time()) - int(created) > SESSION_TTL_SECONDS:
        with con:
            con.execute("DELETE FROM sessions WHERE session_id = ?",
                        (session_id,))
        return None
    with con:
        con.execute("UPDATE sessions SET last_used_at = ? "
                    "WHERE session_id = ?",
                    (int(time.time()), session_id))
    return {"session_id": session_id, "login": login,
            "token": token, "mudurl": mudurl}


def _delete_session(session_id):
    con = sqlite3.connect(MUD_DB)
    with con:
        con.execute("DELETE FROM sessions WHERE session_id = ?",
                    (session_id,))


def _bearer_from_request():
    header = request.headers.get("Authorization", "")
    if header.startswith("Bearer "):
        return header[7:].strip() or None
    return None


def requires_session(fn):
    """Decorator: reject the request with 401 unless the caller
    presents a live session bearer, OR (during the Phase 3 legacy
    window) supplies a ``mudurl`` in the body that resolves to a
    stored token.  Sets ``request.session`` and ``request.legacy``.
    """
    @wraps(fn)
    def wrapper(*a, **kw):
        # Preferred path: Authorization: Bearer <session_id>.
        sess = _resolve_session(_bearer_from_request())
        if sess is not None:
            request.session = sess
            request.legacy = False
            return fn(*a, **kw)

        # Legacy path: mudurl-in-body -> token lookup, kept behind a
        # config flag until Phase 3.5 flips it off.  Cached browsers
        # keep working during the transition; new clients never take
        # this branch.
        if _LEGACY_MUDURL_FALLBACK:
            mudurl = None
            if request.is_json:
                body = request.get_json(silent=True) or {}
                mudurl = body.get("mudurl")
            if not mudurl and request.form:
                mudurl = request.form.get("mudurl")
            if not mudurl:
                # /therest legacy path carries the mudurl inside the
                # base-64 MUD JSON; extract it if present so the
                # fallback survives that shape too.
                mud64 = None
                if request.is_json:
                    mud64 = (request.get_json(silent=True) or {}).get("mudFile")
                if not mud64 and request.form:
                    mud64 = request.form.get("mudFile")
                if mud64:
                    try:
                        mud = json.loads(base64.b64decode(mud64))
                        mudurl = mud["ietf-mud:mud"]["mud-url"]
                    except Exception:  # noqa: BLE001
                        mudurl = None
            if mudurl:
                token = token_in_db(mudurl)
                if token:
                    login = get_gituser(token)
                    if login:
                        log.info("legacy mudurl fallback used "
                                 "origin=%s login=%s",
                                 _safe_log(request.headers.get("Origin")),
                                 _safe_log(login))
                        request.session = {
                            "session_id": None,
                            "login": login,
                            "token": token,
                            "mudurl": mudurl,
                        }
                        request.legacy = True
                        return fn(*a, **kw)
                    # Cached row that GitHub no longer honours;
                    # evict as before.
                    log.info("legacy fallback: token for %s rejected; "
                             "evicting", _safe_log(mudurl))
                    delete_token(mudurl)

        return jsonify({"error": "not authenticated"}), 401
    return wrapper


# ---------------------------------------------------------------------------
# Origin allowlist (Phase 2, defence-in-depth part of T-04).
#
# gitmud is only ever reached via the mudmaker.org proxy chain, so any
# mutating cross-origin request is by definition suspect.  GET/HEAD/OPTIONS
# are safe methods (RFC 9110) and are left unfiltered so tests and
# non-browser tooling (curl, health probes) keep working.
# ---------------------------------------------------------------------------

@app.before_request
def _origin_guard():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None
    if not _ALLOWED_ORIGINS:
        # No allowlist configured -> allow everything (dev / test).
        return None
    origin = request.headers.get("Origin")
    if origin is not None:
        if origin not in _ALLOWED_ORIGINS:
            log.warning("origin-guard rejecting origin=%s path=%s",
                        _safe_log(origin), _safe_log(request.path))
            return jsonify({"error": "cross-origin refused"}), 403
        return None
    # No Origin header (curl, server-to-server) -- fall back to Referer.
    referer = request.headers.get("Referer")
    if referer:
        try:
            u = urlparse(referer)
            probe = f"{u.scheme}://{u.netloc}"
        except ValueError:
            probe = None
        if probe and probe not in _ALLOWED_ORIGINS:
            log.warning("origin-guard rejecting referer=%s path=%s",
                        _safe_log(referer), _safe_log(request.path))
            return jsonify({"error": "cross-origin refused"}), 403
    return None


# ---------------------------------------------------------------------------
# Sessions janitor: expire rows older than SESSION_TTL_SECONDS.  Runs in
# a daemon thread so no external cron is required.  Idempotent under
# concurrent workers because DELETE ... WHERE created_at < ? is safe to
# run in parallel.
# ---------------------------------------------------------------------------

def _janitor_loop():
    while True:
        try:
            cutoff = int(time.time()) - SESSION_TTL_SECONDS
            con = sqlite3.connect(MUD_DB)
            with con:
                con.execute("DELETE FROM sessions WHERE created_at < ?",
                            (cutoff,))
        except Exception:  # noqa: BLE001
            log.exception("sessions janitor failed")
        time.sleep(_JANITOR_INTERVAL_SECONDS)


def _start_janitor():
    """Start the janitor exactly once per interpreter.  Guarded so the
    Flask test client (which imports the module multiple times in
    some workflows) does not spawn duplicate threads.
    """
    if getattr(_start_janitor, "_started", False):
        return
    if os.environ.get("GITMUD_DISABLE_JANITOR", "").lower() in (
            "1", "true", "yes"):
        return
    t = threading.Thread(target=_janitor_loop,
                         name="gitmud-sessions-janitor",
                         daemon=True)
    t.start()
    _start_janitor._started = True


# Bring the schema up to date and kick off the janitor at import time.
try:
    _ensure_schema()
except Exception:  # noqa: BLE001
    # In tests the DB path may point at a not-yet-created file; the
    # first real request will retry via the entrypoint script.
    log.exception("could not ensure schema at import")

_start_janitor()


def git_get(endpoint, token, key = None):
    """
    Do a get and retrieve one or more objects.
    """
    resp = requests.request("GET",GITHUB_API_URL + endpoint,
                            headers = {
                                "Authorization" : "Bearer " + token,
                                "Accept" : "application/vnd.github+json",
                                "X-GitHub-Api-Version" : "2022-11-28"
                                },
                            timeout = 10)

    if not resp.ok:
        log.warning("git_get %s -> %s: %s",
                    endpoint, resp.status_code, _safe_log(resp.text))
        return False
    rsp_json = resp.json()
    if key:
        if key in rsp_json:
            return rsp_json[key]
        return False
    return rsp_json

def git_putpost(which, endpoint, token, content):
    """
    Do either a git PUT or POST and return the results.
    """
    log.info("git_%s %s start", which.lower(), endpoint)
    resp = requests.request(which, GITHUB_API_URL + endpoint,
                            headers = {
                                "Authorization" : "Bearer " + token,
                                "Accept" : "application/vnd.github+json",
                                "X-GitHub-Api-Version" : "2022-11-28"
                            },
                            json = content,
                            timeout = 10
                            )

    if not resp.ok:
        log.warning("git_%s %s -> %s: %s",
                    which.lower(), endpoint, resp.status_code,
                    _safe_log(resp.text))
        # Do NOT surface the raw GitHub response body to the caller.
        # Callers turn GithubProblem into a generic 400/502 already;
        # keeping the detail out of the exception message avoids
        # reflecting attacker-influenced GitHub replies back to the
        # client and into higher-level logs.
        raise GithubProblem(
            f"git_{which.lower()} {endpoint} -> {resp.status_code}")
    log.info("git_%s %s -> %s ok", which.lower(), endpoint, resp.status_code)
    return resp.json()

def git_post(endpoint, token, content):
    """
    Do a POST and return the results.
    """
    return git_putpost("POST",endpoint, token,content)

def git_put(endpoint, token, content):
    """
    Do a PUT and return the results.
    """
    return git_putpost("PUT",endpoint,token,content)


def get_gituser(token):
    """
    get user information.
    """
    return git_get("/user",token,"login")

def repo_exists(user,token):
    """
    Check to see if MUD file repo already exists.
    """
    return git_get(_github_path("repos", user, "mudfiles"), token)

def fork_repo(token):
    """
    Fork the mudfiles repo.
    """
    return git_post(MUD_REPO + "/forks", token, {
        "name" : "mudfiles",
        "default_branch_only" : False
    })

def branch_exists(branch_name, user, token):
    """
    Check to see if a branch already exists.
    """
    return git_get(
        _github_path("repos", user, "mudfiles", "branches", branch_name),
        token)

def create_branch(branch_name,head,user,token):
    """
    Create a new branch for MUD file.
    """
    return git_post(
        _github_path("repos", user, "mudfiles", "git", "refs"),
        token,
        {
            "ref" : "refs/heads/" + branch_name,
            "sha" : head
        })

def existing_file(user, branch, filename, token):
    """
    return the SHA of the file if it exists, or False
    """
    # ``filename`` may legitimately contain path separators (e.g.
    # ``Acme/Widget/Widget.json``).  Split, sanitise each segment, and
    # rebuild via _github_path so `/`, `?`, and `#` inside a segment
    # cannot escape.  The trailing ``?ref=`` is added with a fresh
    # quote() call so its value cannot smuggle further query params.
    segments = [s for s in filename.split("/") if s]
    for seg in segments:
        _sanitise_ref_component(seg, "filename segment")
    path = _github_path("repos", user, "mudfiles", "contents", *segments)
    resp = git_get(path + "?ref=" + quote(branch, safe=""), token)
    if resp:
        return resp['sha']
    return False


def upload_file(upload):
    """
    Generic upload.  Takes an upload struct of the form:
    {
        branch_name :
        user :
        filename : 
        content :
        email : 
        token :
    }
    """

    branch_name=upload["branch_name"]
    filename = upload['filename']
    user = upload['user']
    email = upload['email']
    token = upload['token']
    content = upload['content']
    jsonbody = {
        "message" : "add " + filename + " to repo",
        "committer[name]" : user,
        "committer[email]" : email,
        "branch" : branch_name,
        "content" : content
    }
    sha = existing_file(user, branch_name, filename, token)
    if sha:
        jsonbody['sha'] = sha

    segments = [s for s in filename.split("/") if s]
    for seg in segments:
        _sanitise_ref_component(seg, "filename segment")
    return git_put(
        _github_path("repos", user, "mudfiles", "contents", *segments),
        token,
        jsonbody
    )

# Filenames sent in to /therest as user-supplied pcaps are sanitised
# before they are committed to the MUD repo.  The rules:
#   * lowercase
#   * strip path components (defence-in-depth against ``../``)
#   * collapse anything outside [a-z0-9._-] to ``_``
#   * collapse runs of ``_``
#   * require a ``.pcap`` / ``.pcapng`` extension
# Returns the sanitised name, or ``None`` if the input cannot be made
# acceptable (no extension match, empty stem, etc.).
_PCAP_NAME_SANITISE_RE = re.compile(r"[^a-z0-9._-]+")
_PCAP_NAME_COLLAPSE_RE = re.compile(r"_+")
_PCAP_ALLOWED_EXT = (".pcap", ".pcapng")


def _sanitise_pcap_filename(name):
    """Return a safe pcap filename, or None if the input is unusable."""
    if not name:
        return None
    # Always discard any directory components the browser sent.
    name = os.path.basename(name).strip().lower()
    if not name:
        return None
    matched_ext = None
    for ext in _PCAP_ALLOWED_EXT:
        if name.endswith(ext):
            matched_ext = ext
            break
    if matched_ext is None:
        return None
    stem = name[: -len(matched_ext)]
    stem = _PCAP_NAME_SANITISE_RE.sub("_", stem)
    stem = _PCAP_NAME_COLLAPSE_RE.sub("_", stem).strip("_.-")
    if not stem:
        return None
    return stem + matched_ext


def _dedupe_target_names(names):
    """Given an ordered list of sanitised filenames, ensure uniqueness
    by appending ``-1``, ``-2``, ... before the extension on
    collisions.  Returns a new list of the same length and order.
    """
    seen = {}
    out = []
    for name in names:
        if name not in seen:
            seen[name] = 0
            out.append(name)
            continue
        # Bump the collision counter until we find an unused name.
        stem, dot, ext = name.rpartition(".")
        while True:
            seen[name] += 1
            candidate = f"{stem}-{seen[name]}.{ext}"
            if candidate not in seen:
                seen[candidate] = 0
                out.append(candidate)
                break
    return out


def pr_exists(user, branch_name, token):
    """
    Checks the existence of a PR.
    """
    # ``user`` and ``branch_name`` are attacker-influenced strings that
    # become the value of the ``head=`` query parameter.  Sanitised by
    # the caller and URL-quoted here as defence in depth.
    head = quote(user, safe="") + ":" + quote(branch_name, safe="")
    return git_get(MUD_REPO + "/pulls?head=" + head, token)


def create_pr(branch_name,token, user, mfg, model):
    """
    Generate a PR
    """
    return git_post(MUD_REPO + "/pulls",token, {
        "title" : "Proposed MUD file for a " + mfg + " " + model,
        "head" : user + ":" + branch_name,
        "body" : "This PR was generated by the gitmud tool",
        "base" : "main"
    }
    )

# ---------------------------------------------------------------------------
# Phase 3 routes.
#
# - /oAuthv2 mints a per-browser session bearer on successful GitHub
#   code exchange.  For the Phase-3 legacy window it still populates the
#   old ``gitmud`` table so cached browsers can complete a publish.  The
#   legacy ``got_token``/``got_tok`` shortcut is logged as deprecated
#   (Phase 4 step 1) and will be removed in Phase 4 step 2.
# - /whoami reports the current session's GitHub login.
# - /signout revokes the OAuth grant upstream and deletes the local row.
# - /dorepo, /branch, /therest use @requires_session and take the
#   authenticated GitHub login from request.session rather than trusting
#   any caller-declared "user" field.  Kills T-01, T-06.
# ---------------------------------------------------------------------------


def _exchange_code(code, mudurl):
    """
    Run the GitHub OAuth code-for-token exchange, store the result in
    the legacy ``gitmud`` table for the Phase-3 fallback window, and
    return (token_dict, error_response). On success error_response is
    None; on failure token_dict is None and error_response is a
    (body, status) tuple suitable for returning directly from a Flask
    view.
    """
    resp = github_dance(code)
    if not resp.ok:
        log.warning("github_dance http error: %s", _safe_log(resp.text))
        return None, ("github OAuth exchange failed", 400)
    response_json = resp.json()
    if 'error' in response_json:
        # GitHub returns e.g. {"error": "bad_verification_code", ...}
        # on a stale/reused code.  Do not reflect the raw string back.
        log.warning("github_dance oauth error: %s",
                    _safe_log(response_json.get("error")))
        return None, ("github OAuth exchange failed", 400)
    if 'access_token' not in response_json or not response_json['access_token']:
        log.warning("github_dance: no access_token in response")
        return None, ("github OAuth exchange failed", 400)
    if not db_store(response_json, mudurl):
        return None, ("db_store fail", 500)
    return response_json, None


@app.route('/oAuthv2', methods=['POST'])
def complete_oauth():
    """
    Complete the OAuth transaction and mint a session bearer.

    Request JSON:
      mudurl : the MUD URL currently being published
      one of:
        code       : fresh GitHub OAuth code (preferred)
        got_token  : sentinel "reuse the mudurl-keyed cached token"
                     (legacy, Phase 4 step 1 deprecation warning)
        got_tok    : historical alias of got_token

    Response 200 JSON:
      user    : GitHub login
      session : opaque bearer to send as Authorization: Bearer <...>
                on all subsequent gitmud calls.  Absent on the legacy
                shortcut so old clients that do not know about
                sessions keep functioning via the mudurl fallback.
    """
    req = request.get_json(silent=True) or {}
    try:
        mudurl = req['mudurl']
    except KeyError:
        log.warning("complete_oauth missing mudurl")
        return jsonify({"error": "invalid request payload"}), 400

    legacy_shortcut = "got_token" in req or "got_tok" in req
    code = req.get("code")

    if legacy_shortcut:
        # T-03 deprecation warning (Phase 4 step 1).  Track how many
        # callers still rely on this so we know when Phase 4 step 2
        # (return 410) is safe to ship.
        log.warning(
            "DEPRECATED got_token/got_tok shortcut used origin=%s ua=%s",
            _safe_log(request.headers.get("Origin")),
            _safe_log(request.headers.get("User-Agent")))
        token = token_in_db(mudurl)
        user = get_gituser(token) if token else False
        if not user:
            if token:
                log.info("legacy shortcut: token for %s rejected; evicting",
                         _safe_log(mudurl))
                delete_token(mudurl)
            return jsonify({"error": "no valid token; please reload "
                                     "the page to re-authenticate"}), 401
        # No new session minted; old client will use the legacy
        # fallback in @requires_session for subsequent calls.
        return jsonify({"user": user}), 200

    if not code:
        return jsonify({"error": "missing code"}), 400

    gitresp, err = _exchange_code(code, mudurl)
    if err:
        body, status = err
        return jsonify({"error": body}), status

    login = get_gituser(gitresp["access_token"])
    if not login:
        log.warning("freshly minted token for %s failed /user lookup",
                    _safe_log(mudurl))
        delete_token(mudurl)
        return jsonify({"error": "github token did not authenticate"}), 401

    session_id = _new_session(gitresp, login, mudurl)
    return jsonify({"user": login, "session": session_id}), 200


@app.route('/whoami', methods=['GET'])
def whoami():
    """Return the GitHub login bound to the caller's session bearer.

    Bearer-only (no legacy fallback -- this route is new so cached
    browsers never call it).  Returns 401 with an empty body when no
    live session is present, which the UI treats as "not signed in".
    """
    sess = _resolve_session(_bearer_from_request())
    if not sess:
        return jsonify({"login": None}), 401
    return jsonify({"login": sess["login"]}), 200


@app.route('/signout', methods=['POST'])
def signout():
    """Revoke the caller's session.

    * Deletes the local sessions row.
    * Best-effort: asks GitHub to revoke the OAuth grant upstream via
      DELETE /applications/{client_id}/token, using HTTP Basic with
      the app's (client_id, client_secret).  A failure here is logged
      but does not fail the request -- the local row is already gone.

    Returns 204 on success (even if there was no session -- signout is
    idempotent).
    """
    sess = _resolve_session(_bearer_from_request())
    if not sess:
        return "", 204

    _delete_session(sess["session_id"])

    try:
        rev = requests.request(
            "DELETE",
            GITHUB_API_URL + "/applications/" +
            quote(GITHUB_CLIENT_ID, safe="") + "/token",
            auth=(GITHUB_CLIENT_ID, GITHUB_SECRET_KEY),
            json={"access_token": sess["token"]},
            headers={
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=10,
        )
        if rev.status_code not in (204, 404, 422):
            log.warning("signout: github revoke returned %s: %s",
                        rev.status_code, _safe_log(rev.text))
    except requests.RequestException:
        log.exception("signout: github revoke request failed")

    return "", 204


@app.route("/dorepo", methods=['POST'])
@requires_session
def do_repo():
    """
    Fork the repo if it doesn't exist.  Auth is via the session bearer
    (or the legacy mudurl fallback); the caller's ``user`` field, if
    any, is ignored.
    """
    user = request.session["login"]
    token = request.session["token"]
    resp = repo_exists(user, token)
    if not resp:
        resp = fork_repo(token)
        if not resp:
            return jsonify({"error": "fork failed"}), 400
        # give github a chance to create the fork.
        loop = 0
        while not repo_exists(user, token) and loop < 5:
            loop = loop + 1
            sleep(3)
    # even when the repo claims to exist, it might not yet.
    sleep(3)
    return jsonify({"user": user}), 200


@app.route("/branch", methods=['POST'])
@requires_session
def do_branch():
    """
    Handle branching.  The authoritative GitHub user is
    ``request.session["login"]``; any ``user`` field in the request
    body is ignored (kills T-01/T-06).
    """
    req = request.get_json(silent=True) or {}
    user = request.session["login"]
    token = request.session["token"]

    try:
        mfg = _sanitise_ref_component(req.get("mfg"), "mfg")
        model = _sanitise_ref_component(req.get("model"), "model")
    except ValueError as exc:
        log.warning("Invalid branch request payload: %s", exc)
        return jsonify({"error": "invalid request payload"}), 400

    ref_obj = git_get(
        _github_path("repos", user, "mudfiles", "git", "refs",
                     "heads", "main"),
        token, "object")
    if not ref_obj:
        return jsonify({"error": "could not read repo head"}), 400
    head = ref_obj['sha']
    branch_name = mfg + "-" + model

    # check if branch exists, and create it if it does not.
    if not branch_exists(branch_name, user, token):
        try:
            resp = create_branch(branch_name, head, user, token)
            if not resp:
                return jsonify({"error": "failed to create branch"}), 400
        except GithubProblem:
            log.exception("create_branch failed")
            return jsonify({"error": "failed to create branch"}), 400

    return jsonify({"branch": branch_name}), 200


@app.route("/therest", methods=['POST'])
@requires_session
def do_the_rest():
    """
    Branch and PR code.  Auth via session bearer or legacy mudurl
    fallback (@requires_session).  Any ``user`` field in the request
    body is ignored -- the authoritative GitHub login is
    ``request.session["login"]``.

    Accepts two request encodings:

    * ``multipart/form-data`` (preferred):
        - form field ``mudFile`` - base64 of the MUD JSON
        - form field ``email``
        - file field ``pcap`` - repeated, one per attached pcap
    * ``application/json`` (legacy, kept for one release):
        - body keys ``mudFile``, ``email``, and an optional single
          base64 ``pcap``
    """
    pcap_uploads = []   # list[(target_name, b64_content, original_name)]
    legacy_pcap_b64 = None

    ctype = (request.content_type or "").split(";", 1)[0].strip().lower()
    if ctype == "application/json":
        # Legacy single-pcap path.
        req = request.get_json(silent=True) or {}
        try:
            mud64 = req["mudFile"]
            email = req["email"]
            mud = json.loads(base64.b64decode(mud64))
            _ = mud["ietf-mud:mud"]["mud-url"]  # required
            if "pcap" in req and req["pcap"]:
                legacy_pcap_b64 = req["pcap"]
        except (KeyError, ValueError):
            return jsonify({"error": "invalid request payload"}), 400
    else:
        # Multipart path.
        try:
            mud64 = request.form["mudFile"]
            email = request.form["email"]
            mud = json.loads(base64.b64decode(mud64))
            _ = mud["ietf-mud:mud"]["mud-url"]
        except (KeyError, ValueError):
            return jsonify({
                "error": "invalid request payload",
                "received_file_fields": sorted(request.files.keys()),
                "received_form_fields": sorted(request.form.keys()),
                "content_type": request.content_type,
            }), 400

        raw_pcaps = request.files.getlist("pcap")
        sanitised = []
        for upload in raw_pcaps:
            original = upload.filename or ""
            target = _sanitise_pcap_filename(original)
            if target is None:
                return jsonify({
                    "error": (f"pcap filename {original!r} is not allowed "
                              f"(must end in .pcap or .pcapng)")
                }), 400
            sanitised.append((target, upload, original))
        deduped = _dedupe_target_names([s[0] for s in sanitised])
        for (orig_target, upload, original), final in zip(sanitised, deduped):
            content_b64 = base64.b64encode(upload.read()).decode("ascii")
            pcap_uploads.append((final, content_b64, original))

    user = request.session["login"]
    token = request.session["token"]

    # mfg/model come from the MUD JSON body; validate before use as
    # GitHub ref/path segments (kills T-07/T-09/T-10).
    try:
        mfg = _sanitise_ref_component(
            mud["ietf-mud:mud"].get("mfg-name"), "mfg-name")
        model = _sanitise_ref_component(
            mud["ietf-mud:mud"].get("systeminfo"), "systeminfo")
    except ValueError as exc:
        log.info("Invalid ref component in request payload: %s", exc)
        return jsonify({"error": "invalid request payload"}), 400
    branch_name = mfg + "-" + model

    pcaps_result = []   # list[{original, stored, sha}]

    try:
        # Upload the MUD JSON.  It lives in the same directory as the
        # attached pcaps (``<mfg>/<model>/<model>.json``) so a reviewer
        # looking at the PR sees the rule file and its supporting
        # captures side-by-side.
        upload = {
            "branch_name": branch_name,
            "user": user,
            "filename": f"{mfg}/{model}/{model}.json",
            "content": mud64,
            "email": email,
            "token": token,
        }
        resp = upload_file(upload)
        if not resp:
            return jsonify({"error": "upload failed"}), 400

        # Legacy single-pcap path keeps the historical filename layout
        # ("<mfg>/<model>.pcap") so existing branches don't suddenly
        # see two homes for "the" pcap.  Also passes the pcap filename
        # through the sanitiser to keep T-09 closed.
        if legacy_pcap_b64:
            legacy_pcap_name = model + ".pcap"
            upload["filename"] = f"{mfg}/{legacy_pcap_name}"
            upload["content"] = legacy_pcap_b64
            resp = upload_file(upload)
            if not resp:
                return jsonify({"error": "PCAP upload failed"}), 502
            pcaps_result.append({
                "original": "(legacy single pcap)",
                "stored": upload["filename"],
                "sha": (resp.get("content") or {}).get("sha"),
            })

        # Multipart-supplied pcaps: each lands under <mfg>/<model>/<name>.
        for target, content_b64, original in pcap_uploads:
            upload["filename"] = f"{mfg}/{model}/{target}"
            upload["content"] = content_b64
            resp = upload_file(upload)
            if not resp:
                return jsonify({
                    "error": f"PCAP upload failed for {original!r}",
                    "pcaps": pcaps_result,
                }), 502
            pcaps_result.append({
                "original": original,
                "stored": upload["filename"],
                "sha": (resp.get("content") or {}).get("sha"),
            })

    except GithubProblem:
        log.exception("GitHub operation failed during MUD/PCAP upload flow")
        return jsonify({
            "error": "Request could not be processed.",
            "pcaps": pcaps_result,
        }), 400

    # create the PR only if the branch doesn't already exist
    resp = pr_exists(user, branch_name, token)
    if not resp:
        resp = create_pr(branch_name, token, user, mfg, model)
        if not resp:
            return jsonify({"error": "PR failed"}), 400

    return jsonify({
        # ``mfg`` and ``model`` have already been sanitised above so
        # they are safe ASCII, but keep escape() as belt-and-braces
        # against future refactors (CodeQL py/reflective-xss).
        "mfg": str(escape(mfg)),
        "model": str(escape(model)),
        "user": str(escape(user)),
        "mudurl": str(escape(request.session["mudurl"])),
        "pcaps": pcaps_result,
    }), 200


# ---------------------------------------------------------------------------
# /pcap2mud: take user-uploaded pcap files, invoke mudgen_pcap.py, and
# return the generated MUD JSON.
# ---------------------------------------------------------------------------

# 20 MiB total upload cap.  Set on the Flask app so the body is rejected
# before it ever reaches the route.
app.config.setdefault("MAX_CONTENT_LENGTH", 20 * 1024 * 1024)

# Path to mudgen_pcap.py.  In the gitmud Docker image it is installed at
# /usr/local/bin/mudgen_pcap.py.  In a local source checkout the file
# lives at the repository root, two directories above this module.
_MUDGEN_PCAP_CANDIDATES = [
    Path(os.environ.get("MUDGEN_PCAP", "/nonexistent")),
    Path("/usr/local/bin/mudgen_pcap.py"),
    Path(__file__).resolve().parent.parent.parent / "mudgen_pcap.py",
]

_MAC_RE = re.compile(r"^[0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}$")
_ALLOWED_PCAP_EXT = (".pcap", ".pcapng")
_MUDGEN_TIMEOUT_SECONDS = 60


def _locate_mudgen_pcap():
    for candidate in _MUDGEN_PCAP_CANDIDATES:
        if candidate.is_file():
            return candidate
    return None


@app.route("/pcap2mud", methods=["POST"])
def pcap2mud():
    """
    Accept one or more pcap files plus optional metadata, run
    mudgen_pcap.py against them, and return the resulting MUD JSON
    (or a structured error).
    """
    script = _locate_mudgen_pcap()
    if script is None:
        return jsonify({"error": "mudgen_pcap.py not installed"}), 500

    files = request.files.getlist("pcap")
    if not files:
        # Help the caller diagnose why no files arrived (wrong field
        # name, browser dropped the body, proxy strip, etc.).
        all_file_keys = sorted(set(request.files.keys()))
        all_form_keys = sorted(set(request.form.keys()))
        return jsonify({
            "error": "no pcap files supplied",
            "received_file_fields": all_file_keys,
            "received_form_fields": all_form_keys,
            "content_length": request.content_length,
            "content_type": request.content_type,
        }), 400

    mac = (request.form.get("mac") or "").strip()
    if mac and not _MAC_RE.match(mac):
        return jsonify({"error": f"invalid MAC: {mac!r}"}), 400

    workdir = tempfile.mkdtemp(prefix="pcap2mud-")
    try:
        for upload in files:
            name = os.path.basename(upload.filename or "")
            if not name.lower().endswith(_ALLOWED_PCAP_EXT):
                return jsonify({
                    "error": f"file {name!r} is not a .pcap or .pcapng"
                }), 400
            upload.save(os.path.join(workdir, name))

        if mac:
            with open(os.path.join(workdir, "_iotdevice-mac.txt"),
                      "w", encoding="ascii") as fh:
                fh.write(mac + "\n")

        _SAFE_TEXT_ARG_RE = re.compile(r"^[A-Za-z0-9._,()\- ]+$")

        def _validated_text_cli_value(field_name, raw_value, max_len=128):
            if raw_value is None:
                return None
            value = raw_value.strip()
            if not value:
                return None
            if len(value) > max_len:
                raise ValueError(f"{field_name} is too long")
            if not _SAFE_TEXT_ARG_RE.fullmatch(value):
                raise ValueError(f"invalid characters in {field_name}")
            return value

        def _validated_url_cli_value(field_name, raw_value, max_len=512):
            if raw_value is None:
                return None
            value = raw_value.strip()
            if not value:
                return None
            if len(value) > max_len:
                raise ValueError(f"{field_name} is too long")
            parsed = urlparse(value)
            if parsed.scheme not in ("http", "https") or not parsed.netloc:
                raise ValueError(f"invalid URL in {field_name}")
            return value

        argv = [sys.executable, str(script), workdir]
        try:
            for opt, field_name, validator in (
                ("--mfg", "mfg", _validated_text_cli_value),
                ("--model", "model", _validated_text_cli_value),
                ("--systeminfo", "systeminfo", _validated_text_cli_value),
                ("--documentation", "documentation", _validated_url_cli_value),
                ("--mud-url", "mud_url", _validated_url_cli_value),
            ):
                value = validator(field_name, request.form.get(field_name))
                if value:
                    argv += [opt, value]
        except ValueError as exc:
            log.warning("Invalid request parameters for mudgen_pcap invocation", exc_info=True)
            return jsonify({"error": "Invalid request parameters"}), 400

        try:
            proc = subprocess.run(argv, capture_output=True,
                                  text=True,
                                  timeout=_MUDGEN_TIMEOUT_SECONDS,
                                  check=False)
        except subprocess.TimeoutExpired:
            return jsonify({"error": "mudgen_pcap.py timed out"}), 504

        if proc.returncode != 0:
            err_lines = [
                line for line in (proc.stderr or "").splitlines()
                if line.strip()
                and not line.startswith("inferred device MAC:")
            ]
            if not err_lines:
                err_lines = [(proc.stdout or "mudgen_pcap.py failed").strip()]
            return jsonify({
                "error": " ".join(err_lines).strip()
            }), 400

        try:
            mud = json.loads(proc.stdout)
        except json.JSONDecodeError:
            log.exception("mudgen_pcap.py produced invalid JSON")
            return jsonify({
                "error": "mudgen_pcap.py produced invalid JSON"
            }), 500

        notes = (proc.stderr or "").strip()
        result = {"mud": mud}
        if notes:
            result["notes"] = notes
        return jsonify(result), 200
    finally:
        shutil.rmtree(workdir, ignore_errors=True)


#       return redirect("mudpublish.html?stored=ok")
#    return redirect("mudbad.html")

# if __name__ == '__main__':
#    app.run(debug=False, port=5000)
