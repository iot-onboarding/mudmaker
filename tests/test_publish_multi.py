"""Smoke test for /therest with multipart and multiple pcaps.

Uses the Flask test client and monkeypatches every function that would
otherwise talk to GitHub.  Records the per-file uploads so we can assert
that:
  * the MUD JSON lands at <mfg>/<model>.json
  * each pcap lands at <mfg>/<model>/<sanitised-name>
  * intra-request filename collisions are resolved with a -N suffix
  * the JSON response carries a ``pcaps`` array of {original, stored, sha}

Run from the repository root:
    python3 tests/test_publish_multi.py
"""
import base64
import json
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "gitmud" / "gitmud"))

import app  # noqa: E402

uploaded = []   # list[dict]: every upload_file() call argument


def fake_upload_file(upload):
    """Record the upload and pretend GitHub returned a content+sha."""
    uploaded.append(dict(upload))
    return {"content": {"path": upload["filename"], "sha": "sha-" + str(len(uploaded))}}


def install_fakes(monkey_user="alice"):
    """Replace every GitHub-touching helper with offline stubs."""
    app.token_in_db = lambda mudurl: "tok"
    app.get_gituser = lambda token: monkey_user
    app.delete_token = lambda mudurl: None
    app.upload_file = fake_upload_file
    # PR creation: pretend the PR already exists so the flow doesn't
    # try to POST one (and we don't have to fake create_pr/pr_exists
    # response shapes any more thoroughly than necessary).
    app.pr_exists = lambda user, branch, token: True


def build_mud_b64():
    mud = {
        "ietf-mud:mud": {
            "mud-version": 1,
            "mud-url": "https://example.com/.well-known/mud/test.json",
            "mfg-name": "Acme Devices",
            "systeminfo": "Acme Thermostat",
        },
        "ietf-access-control-list:acls": {"acl": []},
    }
    return base64.b64encode(json.dumps(mud).encode()).decode("ascii")


def post_multipart(client, mud_b64, pcaps):
    """``pcaps`` is a list of (filename, bytes) tuples."""
    data = {"mudFile": mud_b64, "email": "alice@example.com", "user": "alice"}
    files = [("pcap", (name, body, "application/vnd.tcpdump.pcap"))
             for name, body in pcaps]
    # Flask's test client expects file fields as 'pcap': (BytesIO/bytes, name)
    # via the same key.  We build the data dict manually so multiple pcap
    # entries are preserved.
    import io
    full = dict(data)
    # The werkzeug EnvironBuilder accepts a list of tuples for repeated
    # file fields; pass it via the ``data`` arg.
    full_data = list(data.items()) + [
        ("pcap", (io.BytesIO(body), name)) for name, body in pcaps
    ]
    return client.post("/therest", data=dict(full_data),
                       content_type="multipart/form-data")


def main():
    install_fakes()
    app.app.config["TESTING"] = True
    client = app.app.test_client()

    # -- Case 1: three pcaps, two of which collide after sanitisation. --
    uploaded.clear()
    mud_b64 = build_mud_b64()
    # Note: 'Setup A.pcap' and 'setup_a.pcap' both sanitise to 'setup_a.pcap'.
    pcaps = [
        ("Setup-1.pcap", b"\xd4\xc3\xb2\xa1" + b"hello1"),
        ("Setup A.pcap", b"\xd4\xc3\xb2\xa1" + b"hello2"),
        ("setup_a.pcap", b"\xd4\xc3\xb2\xa1" + b"hello3"),
    ]
    # The test client only supports a single value per key in the data
    # dict; submit via werkzeug EnvironBuilder directly.
    from werkzeug.test import EnvironBuilder
    builder = EnvironBuilder(method="POST", path="/therest")
    builder.form["mudFile"] = mud_b64
    builder.form["email"] = "alice@example.com"
    builder.form["user"] = "alice"
    for name, body in pcaps:
        import io
        builder.files.add_file("pcap", io.BytesIO(body), filename=name,
                               content_type="application/vnd.tcpdump.pcap")
    env = builder.get_environ()
    resp = client.open(environ_overrides=env, method="POST", path="/therest")
    body = resp.get_json()
    assert resp.status_code == 200, (resp.status_code, body)
    assert body["mfg"] == "Acme-Devices", body
    assert body["model"] == "Acme-Thermostat", body
    stored = [p["stored"] for p in body["pcaps"]]
    assert stored == [
        "Acme-Devices/Acme-Thermostat/setup-1.pcap",
        "Acme-Devices/Acme-Thermostat/setup_a.pcap",
        "Acme-Devices/Acme-Thermostat/setup_a-1.pcap",
    ], stored
    # 1 MUD JSON + 3 pcaps = 4 uploads, all in the same directory
    assert len(uploaded) == 4, [u["filename"] for u in uploaded]
    assert uploaded[0]["filename"] == \
        "Acme-Devices/Acme-Thermostat/Acme-Thermostat.json"
    print("ok case 1: 3 pcaps including a collision uploaded with -N suffix")

    # -- Case 2: zero pcaps -> only the MUD JSON is uploaded. --
    uploaded.clear()
    builder = EnvironBuilder(method="POST", path="/therest")
    builder.form["mudFile"] = mud_b64
    builder.form["email"] = "alice@example.com"
    builder.form["user"] = "alice"
    env = builder.get_environ()
    resp = client.open(environ_overrides=env, method="POST", path="/therest")
    body = resp.get_json()
    assert resp.status_code == 200, (resp.status_code, body)
    assert body["pcaps"] == [], body
    assert len(uploaded) == 1, [u["filename"] for u in uploaded]
    print("ok case 2: zero pcaps -> only MUD JSON uploaded")

    # -- Case 3: bad extension -> 400. --
    uploaded.clear()
    builder = EnvironBuilder(method="POST", path="/therest")
    builder.form["mudFile"] = mud_b64
    builder.form["email"] = "alice@example.com"
    builder.form["user"] = "alice"
    import io
    builder.files.add_file("pcap", io.BytesIO(b"x"), filename="bogus.txt",
                           content_type="text/plain")
    env = builder.get_environ()
    resp = client.open(environ_overrides=env, method="POST", path="/therest")
    body = resp.get_json()
    assert resp.status_code == 400, (resp.status_code, body)
    assert "not allowed" in body["error"], body
    assert len(uploaded) == 0, "no GitHub call should have happened"
    print("ok case 3: bad extension rejected before any GitHub call")

    # -- Case 4: legacy JSON body path still works. --
    uploaded.clear()
    legacy_payload = {
        "mudFile": mud_b64,
        "email": "alice@example.com",
        "user": "alice",
        "pcap": base64.b64encode(b"legacy bytes").decode(),
    }
    resp = client.post("/therest", json=legacy_payload)
    body = resp.get_json()
    assert resp.status_code == 200, (resp.status_code, body)
    # legacy path keeps the historical pcap filename layout, but the
    # JSON now lives next to it under the model directory.
    assert uploaded[0]["filename"] == \
        "Acme-Devices/Acme-Thermostat/Acme-Thermostat.json", uploaded
    assert uploaded[1]["filename"] == "Acme-Devices/Acme-Thermostat.pcap", \
        uploaded
    assert body["pcaps"][0]["stored"] == "Acme-Devices/Acme-Thermostat.pcap"
    print("ok case 4: legacy JSON body still uploads as <mfg>/<model>.pcap")

    print("OK")


if __name__ == "__main__":
    main()
