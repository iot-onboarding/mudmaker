"""Tests for the Phase-2 Origin allowlist and the Phase-3 session
bearer / /whoami / /signout / /therest flow.

Run from the repository root:
    python3 tests/test_session_bearer.py

Requires a config with a writable [storage] db_path and a real
[security] section (see gitmud/config.ini or the CI fixture).
"""
import base64
import io
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "gitmud" / "gitmud"))

import app  # noqa: E402


def install_fakes(user="alice"):
    """Offline stubs for every GitHub-touching helper."""
    app.get_gituser = lambda tok: user
    app.repo_exists = lambda u, t: True
    app.fork_repo = lambda t: {"name": "mudfiles"}
    app.branch_exists = lambda b, u, t: True
    app.create_branch = lambda b, h, u, t: {"ref": "refs/heads/" + b}
    app.existing_file = lambda u, br, fn, t: False
    app.pr_exists = lambda u, b, t: True
    _uploaded = []
    def _fake_upload(upload):
        _uploaded.append(dict(upload))
        return {"content": {"sha": "sha-" + str(len(_uploaded))}}
    app.upload_file = _fake_upload
    return _uploaded


def build_mud_b64():
    mud = {
        "ietf-mud:mud": {
            "mud-url": "https://example.com/.well-known/mud/test.json",
            "mfg-name": "Acme",
            "systeminfo": "Widget",
        },
        "ietf-access-control-list:acls": {"acl": []},
    }
    return base64.b64encode(json.dumps(mud).encode()).decode("ascii")


def _mint_session(login="alice", token="ghp_fake", mudurl=None):
    """Create a session row and return its bearer."""
    if mudurl is None:
        mudurl = "https://example.com/.well-known/mud/test.json"
    return app._new_session(
        {"access_token": token, "scope": "public_repo",
         "token_type": "bearer"},
        login, mudurl)


def main():
    app.app.config["TESTING"] = True
    client = app.app.test_client()

    # -- Phase 2: Origin allowlist ----------------------------------
    # The local config sets allowed_origins to empty so tests are
    # unaffected by it -- flip the allowlist on transiently.
    app._ALLOWED_ORIGINS = {"https://mudmaker.org"}

    resp = client.post("/oAuthv2",
                       data=json.dumps({"mudurl": "x"}),
                       content_type="application/json",
                       headers={"Origin": "https://evil.example"})
    assert resp.status_code == 403, resp.status_code
    assert resp.get_json()["error"] == "cross-origin refused"
    print("ok origin-guard: cross-origin POST refused (403)")

    resp = client.post("/oAuthv2",
                       data=json.dumps({"mudurl": "x"}),
                       content_type="application/json",
                       headers={"Origin": "https://mudmaker.org"})
    # Passes the guard, gets rejected downstream with 400 for missing
    # code -- that's fine, we're only testing the guard here.
    assert resp.status_code == 400, resp.status_code
    print("ok origin-guard: same-origin POST allowed through")

    resp = client.get("/whoami",
                      headers={"Origin": "https://evil.example"})
    # GET is exempt from origin-guard (safe method per RFC 9110).
    assert resp.status_code == 401, resp.status_code
    print("ok origin-guard: GET exempt")

    # Referer fallback -- no Origin, foreign Referer -> 403.
    resp = client.post("/oAuthv2",
                       data=json.dumps({"mudurl": "x"}),
                       content_type="application/json",
                       headers={"Referer": "https://evil.example/x"})
    assert resp.status_code == 403, resp.status_code
    print("ok origin-guard: Referer fallback blocks foreign referer")

    # No Origin, no Referer (curl-style) -> allowed.
    resp = client.post("/oAuthv2",
                       data=json.dumps({"mudurl": "x"}),
                       content_type="application/json")
    assert resp.status_code == 400, resp.status_code
    print("ok origin-guard: no-Origin no-Referer allowed (curl)")

    # Restore permissive defaults for the rest of the tests.
    app._ALLOWED_ORIGINS = set()

    # -- Phase 3: bearer required by /whoami ------------------------
    resp = client.get("/whoami")
    assert resp.status_code == 401, resp.status_code
    assert resp.get_json() == {"login": None}
    print("ok /whoami: unauthenticated -> 401")

    bearer = _mint_session()
    resp = client.get("/whoami",
                      headers={"Authorization": "Bearer " + bearer})
    assert resp.status_code == 200, resp.status_code
    assert resp.get_json() == {"login": "alice"}
    print("ok /whoami: bearer -> {login: alice}")

    # -- Phase 3: /therest with bearer, no user in body -------------
    uploaded = install_fakes(user="alice")
    bearer = _mint_session(login="alice")
    fd_headers = {"Authorization": "Bearer " + bearer}
    # Multipart, no `user` field (server should read it from session).
    from werkzeug.test import EnvironBuilder
    builder = EnvironBuilder(method="POST", path="/therest")
    builder.form["mudFile"] = build_mud_b64()
    builder.form["email"] = "alice@example.com"
    for k, v in fd_headers.items():
        builder.headers.add(k, v)
    env = builder.get_environ()
    resp = client.open(environ_overrides=env, method="POST", path="/therest")
    body = resp.get_json()
    assert resp.status_code == 200, (resp.status_code, body)
    assert body["user"] == "alice", body
    # /therest never received a "user" field in the body; it came
    # entirely from the session -- kills T-01/T-06.
    assert uploaded[0]["user"] == "alice", uploaded
    print("ok /therest: bearer-only, session drives user")

    # -- Phase 3: /therest ignores body user field even if supplied -
    uploaded = install_fakes(user="alice")
    bearer = _mint_session(login="alice")
    builder = EnvironBuilder(method="POST", path="/therest")
    builder.form["mudFile"] = build_mud_b64()
    builder.form["email"] = "alice@example.com"
    builder.form["user"] = "attacker"     # <-- would-be spoof
    for k, v in {"Authorization": "Bearer " + bearer}.items():
        builder.headers.add(k, v)
    env = builder.get_environ()
    resp = client.open(environ_overrides=env, method="POST", path="/therest")
    body = resp.get_json()
    assert resp.status_code == 200, (resp.status_code, body)
    assert body["user"] == "alice", body
    assert uploaded[0]["user"] == "alice", uploaded
    print("ok /therest: caller-declared user in body is ignored")

    # -- Phase 3: session TTL expiry --------------------------------
    bearer = _mint_session(login="carol")
    # Rewind created_at past the TTL.
    import sqlite3
    con = sqlite3.connect(app.MUD_DB)
    with con:
        con.execute("UPDATE sessions SET created_at = 0 "
                    "WHERE session_id = ?", (bearer,))
    resp = client.get("/whoami",
                      headers={"Authorization": "Bearer " + bearer})
    assert resp.status_code == 401, resp.status_code
    # And the expired row must have been swept.
    row = con.execute("SELECT 1 FROM sessions WHERE session_id = ?",
                      (bearer,)).fetchone()
    assert row is None, "expired session row was not deleted"
    print("ok session TTL: expired bearer -> 401 + row deleted")

    # -- Phase 3: rejecting a bad mfg from the MUD body -------------
    install_fakes(user="alice")
    bearer = _mint_session(login="alice")
    bad_mud = {
        "ietf-mud:mud": {
            "mud-url": "https://example.com/.well-known/mud/x.json",
            "mfg-name": "../evil",   # T-07 attempt
            "systeminfo": "Widget",
        },
        "ietf-access-control-list:acls": {"acl": []},
    }
    bad64 = base64.b64encode(json.dumps(bad_mud).encode()).decode("ascii")
    builder = EnvironBuilder(method="POST", path="/therest")
    builder.form["mudFile"] = bad64
    builder.form["email"] = "alice@example.com"
    for k, v in {"Authorization": "Bearer " + bearer}.items():
        builder.headers.add(k, v)
    env = builder.get_environ()
    resp = client.open(environ_overrides=env, method="POST", path="/therest")
    body = resp.get_json()
    assert resp.status_code == 400, (resp.status_code, body)
    assert "mfg-name" in body["error"], body
    print("ok /therest: traversal-in-mfg rejected (400)")

    # -- Phase 3: /branch enforces sanitisation --------------------
    resp = client.post("/branch",
                       data=json.dumps({"mfg": "acme", "model": "../evil"}),
                       content_type="application/json",
                       headers={"Authorization": "Bearer " + bearer})
    body = resp.get_json()
    assert resp.status_code == 400, (resp.status_code, body)
    print("ok /branch: traversal-in-model rejected (400)")

    # -- Phase 3: /signout is idempotent ---------------------------
    resp = client.post("/signout")
    assert resp.status_code == 204, resp.status_code
    print("ok /signout: no session -> 204 (idempotent)")

    # /signout with a bearer: mock the GitHub revoke call so we don't
    # hit the network, then verify the local row is gone.
    bearer = _mint_session(login="dave")
    called = []
    class _Resp:
        status_code = 204
        text = ""
    def _fake_request(method, url, **kw):
        called.append((method, url, kw.get("auth"), kw.get("json")))
        return _Resp()
    real_request = app.requests.request
    app.requests.request = _fake_request
    try:
        resp = client.post("/signout",
                           headers={"Authorization": "Bearer " + bearer})
    finally:
        app.requests.request = real_request
    assert resp.status_code == 204, resp.status_code
    assert called and called[0][0] == "DELETE", called
    assert "/applications/" in called[0][1], called
    # Local row is gone.
    row = con.execute("SELECT 1 FROM sessions WHERE session_id = ?",
                      (bearer,)).fetchone()
    assert row is None, "signout did not delete the local row"
    print("ok /signout: bearer -> local row deleted + GitHub revoke called")

    # -- Phase 3: /dorepo without a bearer AND without a mudurl -> 401
    # (only when legacy_mudurl_fallback would fail too)
    resp = client.post("/dorepo",
                       data=json.dumps({}),
                       content_type="application/json")
    assert resp.status_code == 401, resp.status_code
    print("ok /dorepo: no bearer + no mudurl -> 401")

    print("OK")


if __name__ == "__main__":
    main()
