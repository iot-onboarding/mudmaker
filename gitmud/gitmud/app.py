"""
App to manage oauth tokens for mud files, and to generate PRs.
"""

import json
import logging
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import base64
import configparser
from pathlib import Path
from time import sleep
from urllib.parse import urlparse
from flask import Flask,request, jsonify
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
                    endpoint, resp.status_code, resp.text[:200])
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
                    which.lower(), endpoint, resp.status_code, resp.text[:200])
        raise GithubProblem("request failed: " + resp.text)
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
    return git_get("/repos/" + user + "/mudfiles", token)

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
    return git_get("/repos/" + user + "/mudfiles/branches/" + branch_name, token)

def create_branch(branch_name,head,user,token):
    """
    Create a new branch for MUD file.
    """
    return git_post("/repos/" + user + "/mudfiles/git/refs", token,
                    {
                        "ref" : "refs/heads/" + branch_name,
                        "sha" : head
                    })

def existing_file(user, branch, filename, token):
    """
    return the SHA of the file if it exists, or False
    """
    resp= git_get("/repos/" + user + "/mudfiles/contents/" + filename + "?ref=" + branch, token)
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

    return git_put("/repos/" + user + "/mudfiles/contents/" + filename,
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
    return git_get(MUD_REPO + f'/pulls?head={user}:{branch_name}',token)


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

@app.route('/gottoken',methods=['GET'])
def got_token():
    """
    return a yes/no answer.  Takes argument "mudurl".
    """
    mudurl=request.args.get("mudurl")
    if token_in_db(mudurl):
        return jsonify({"answer" : "yes"}), 200
    return jsonify({"answer" : "no"}), 400


def _exchange_code(code, mudurl):
    """
    Run the GitHub OAuth code-for-token exchange, store the result, and
    return (token, error_response). On success error_response is None; on
    failure token is None and error_response is a (body, status) tuple
    suitable for returning directly from a Flask view.
    """
    resp = github_dance(code)
    if not resp.ok:
        return None, ("github_dance: " + resp.text, 400)
    response_json = resp.json()
    if 'error' in response_json:
        return None, ("github_dance: error " + response_json['error'], 400)
    if 'access_token' not in response_json or not response_json['access_token']:
        return None, ("github_dance: no access_token in response", 400)
    if not db_store(response_json, mudurl):
        return None, ("db_store fail", 500)
    return response_json["access_token"], None


@app.route('/oAuthv2',methods=['POST'])
def complete_oauth():
    """
    Just complete the oauth transaction.  Takes as input:
       mudFile (b64) and one of:
        token: a token to commplete OAUTH
        OR
        got_token, signalling that no github dance is required.
        (``got_tok`` is accepted as a legacy alias so that older
        client builds still in browser caches keep working.)
    Returns: 200/400/401
    """
    req=request.json

    try:
        mudurl = req['mudurl']
        code = None
        # ``got_token`` is the canonical flag; ``got_tok`` is the
        # historical client spelling kept for backward compatibility.
        if "got_token" not in req and "got_tok" not in req:
            code = req["code"]
    except KeyError:
        log.warning("complete_oauth missing required request field", exc_info=True)
        return "invalid request payload", 400

    token = token_in_db(mudurl)
    user = get_gituser(token) if token else False

    if not user:
        # Either no row, or the cached token no longer works (revoked,
        # expired, or minted by a different OAuth app). Drop it and try a
        # fresh dance if the client supplied a fresh code.
        if token:
            log.info("stored token for %s rejected by GitHub; evicting", mudurl)
            delete_token(mudurl)
        if not code:
            return "no valid token and no code to exchange", 401
        token, err = _exchange_code(code, mudurl)
        if err:
            return err
        user = get_gituser(token)
        if not user:
            # Token came back from GitHub but won't authenticate /user.
            # Don't keep it.
            log.warning("freshly minted token for %s failed /user lookup", mudurl)
            delete_token(mudurl)
            return "github token did not authenticate", 401

    return jsonify({"user" : user}), 200

@app.route("/dorepo",methods=['POST'])
def do_repo():
    """
    Fork the repo if it doesn't exist.
    """
    req=request.json

    try:
        mudurl=req['mudurl']
    except KeyError as e:
        return "Repo Check: Bad Parameter: " + str(e), 400

    token = token_in_db(mudurl)
    if not token:
        return "not authenticated", 401
    user = get_gituser(token)
    if not user:
        log.info("do_repo: stored token for %s rejected; evicting", mudurl)
        delete_token(mudurl)
        return "github token did not authenticate", 401
    resp = repo_exists(user,token)
    if not resp:
        resp = fork_repo(token)
        if not resp:
            return "fork failed", 400
        # give github a chance to create the fork.
        resp = repo_exists(user,token)
        loop = 0
        while not repo_exists(user,token) and loop < 5:
            loop=loop + 1
            sleep(3)
    # even when the repo claims to exist, it might not yet.  Give a few
    # more seconds.
    sleep(3)
    return jsonify({"user" : user}), 200


@app.route("/branch",methods=['POST'])
def do_branch():
    """
    Handle branching.
    """
    req=request.json
    try:
        mudurl = req['mudurl']
        mfg = req["mfg"]
        model = req["model"]
        user = req["user"]

    except KeyError as e:
        return "Parameter problem: " + str(e), 400

    token = token_in_db(mudurl)
    if not token:
        return "not authenticated", 401
    # Confirm the caller-supplied user matches the token holder; otherwise
    # an attacker who knows a mudurl could direct writes to an arbitrary
    # account name.
    token_user = get_gituser(token)
    if not token_user:
        log.info("do_branch: stored token for %s rejected; evicting", mudurl)
        delete_token(mudurl)
        return "github token did not authenticate", 401
    if token_user != user:
        return "user does not match token", 403
    # capture head
    ref_obj  = git_get("/repos/" + user + "/mudfiles/git/refs/heads/main",
                    token, "object")
    if not ref_obj:
        return "could not read repo head", 400
    head = ref_obj['sha']
    # branch name
    mfg = re.sub(' ','-',mfg)
    model = re.sub(' ','-',model)
    branch_name = mfg +  "-" + model

    # check if branch exists, and create it if it does not.
    if not branch_exists(branch_name, user, token):
        try:
            resp=create_branch(branch_name, head, user, token)
            if not resp:
                return "failed to create branch", 400
        except GithubProblem as e:
            return str(e), 400

    return jsonify({"branch" : branch_name}), 200

@app.route("/therest",methods=['POST'])
def do_the_rest():
    """
    Branch and PR code.

    Accepts two request encodings:

    * ``multipart/form-data`` (preferred):
        - form field ``mudFile`` — base64 of the MUD JSON
        - form field ``email``
        - form field ``user``
        - file field ``pcap`` — repeated, one per attached pcap
    * ``application/json`` (legacy, kept for one release):
        - body keys ``mudFile``, ``email``, ``user``, and an optional
          single base64 ``pcap``
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
            user = req["user"]
            mud = json.loads(base64.b64decode(mud64))
            mudurl = mud["ietf-mud:mud"]["mud-url"]
            if "pcap" in req and req["pcap"]:
                legacy_pcap_b64 = req["pcap"]
        except KeyError as e:
            return "Parameter problem: " + str(e), 400
    else:
        # Multipart path.  Read scalar metadata from form fields and the
        # pcaps from repeated file fields.
        try:
            mud64 = request.form["mudFile"]
            email = request.form["email"]
            user = request.form["user"]
            mud = json.loads(base64.b64decode(mud64))
            mudurl = mud["ietf-mud:mud"]["mud-url"]
        except KeyError as e:
            return jsonify({
                "error": "Parameter problem: " + str(e),
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
        # Resolve intra-request filename collisions.
        deduped = _dedupe_target_names([s[0] for s in sanitised])
        for (orig_target, upload, original), final in zip(sanitised, deduped):
            content_b64 = base64.b64encode(upload.read()).decode("ascii")
            pcap_uploads.append((final, content_b64, original))

    token = token_in_db(mudurl)
    if not token:
        return "not authenticated", 401
    token_user = get_gituser(token)
    if not token_user:
        log.info("do_the_rest: stored token for %s rejected; evicting", mudurl)
        delete_token(mudurl)
        return "github token did not authenticate", 401
    if token_user != user:
        return "user does not match token", 403

    # branch name
    mfg = re.sub(' ','-',mud["ietf-mud:mud"]["mfg-name"])
    model = re.sub(' ','-',mud["ietf-mud:mud"]["systeminfo"])
    branch_name = mfg +  "-" + model

    pcaps_result = []   # list[{original, stored, sha}]

    try:
        # Upload the MUD JSON.  It lives in the same directory as the
        # attached pcaps (``<mfg>/<model>/<model>.json``) so a reviewer
        # looking at the PR sees the rule file and its supporting
        # captures side-by-side.
        upload = {
                "branch_name" : branch_name,
                "user" : user,
                "filename" : f"{mfg}/{model}/{model}.json",
                "content" : mud64,
                "email" :    email,
                "token" : token
        }
        resp = upload_file(upload)
        if not resp:
            return "upload failed", 400

        # Legacy single-pcap path keeps the historical filename layout
        # ("<mfg>/<model>.pcap") so existing branches don't suddenly
        # see two homes for "the" pcap.
        if legacy_pcap_b64:
            upload["filename"] = mfg + "/" + model + ".pcap"
            upload["content"] = legacy_pcap_b64
            resp = upload_file(upload)
            if not resp:
                return "PCAP upload failed", 502
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
            "error": "Request could not be processed."
        }), 400

    # create the PR only if the branch doesn't already exist
    resp =  pr_exists(user,branch_name,token)
    if not resp:
        resp = create_pr(branch_name,token, user, mfg, model)
        if not resp:
            return "PR failed", 400

    return {
        # ``mfg`` and ``model`` are derived from request-controlled MUD
        # content and reflected back to the caller; HTML-escape them so
        # downstream HTML renderers cannot execute injected markup.
        "mfg" : str(escape(mfg)),
        "model" : str(escape(model)),
        # ``user`` and ``mudurl`` come from request input and are
        # reflected back to the caller; HTML-escape them so any
        # downstream consumer that renders them as HTML cannot be
        # tricked into running injected markup.  See CodeQL alert
        # py/reflective-xss.
        "user" : str(escape(user)),
        "mudurl" : str(escape(mudurl)),
        "pcaps" : pcaps_result,
    }, 200


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
