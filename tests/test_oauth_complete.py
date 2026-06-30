"""Tests for the /oAuthv2 entry point in gitmud.

The endpoint exists so the client can either:

  * complete a fresh GitHub OAuth dance (by passing a ``code``), or
  * tell the server "I already have a token cached server-side, just
    look it up and confirm" by setting a sentinel boolean field.

Historically the client and server disagreed about the sentinel name
(client sent ``got_tok``; server checked for ``got_token``), so the
no-dance branch was unreachable and any "I already have a token"
request returned ``invalid request payload (400)``.  This test pins
both spellings so the regression cannot return.

Run from the repository root:
    python3 tests/test_oauth_complete.py
"""
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "gitmud" / "gitmud"))

import app  # noqa: E402


def install_fakes(user="alice", token="tok"):
    """Stub out the DB + GitHub helpers so the endpoint is offline."""
    app.token_in_db = lambda mudurl: token
    app.get_gituser = lambda tok: user if tok == token else None
    # Should never be reached in the no-code paths exercised here.
    app.delete_token = lambda mudurl: None


def post(client, payload):
    return client.post(
        "/oAuthv2",
        data=json.dumps(payload),
        content_type="application/json",
    )


def main():
    install_fakes()
    app.app.config["TESTING"] = True
    client = app.app.test_client()

    # Canonical spelling: server should not demand "code", look up the
    # stored token, and return the user it resolves to.
    resp = post(client, {"mudurl": "https://example.com/m.json",
                         "got_token": True})
    assert resp.status_code == 200, (resp.status_code, resp.get_data(as_text=True))
    assert resp.get_json() == {"user": "alice"}, resp.get_json()
    print("ok got_token=true: stored token resolved without a code")

    # Legacy spelling: must continue to work so old client builds in
    # browser caches do not 400.
    resp = post(client, {"mudurl": "https://example.com/m.json",
                         "got_tok": True})
    assert resp.status_code == 200, (resp.status_code, resp.get_data(as_text=True))
    assert resp.get_json() == {"user": "alice"}, resp.get_json()
    print("ok got_tok=true: legacy spelling still honoured")

    # Neither flag and no code -> still a 400 because the request is
    # genuinely incomplete.
    resp = post(client, {"mudurl": "https://example.com/m.json"})
    assert resp.status_code == 400, (resp.status_code, resp.get_data(as_text=True))
    print("ok missing both flag and code: 400 as expected")

    print("OK")


if __name__ == "__main__":
    main()
