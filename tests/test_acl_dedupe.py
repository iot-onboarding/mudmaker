"""Unit tests for the JS dedupe helpers _aclDirections / _aceSignature.

Runs the relevant pieces of assets/js/mudmaker.js through Node and
verifies that mirror from-device / to-device ACE pairs produce
identical signatures (so the UI collapses them into one row), while
unrelated entries remain distinct.

Run from the repository root:
    python3 tests/test_acl_dedupe.py
"""
import json
import shutil
import subprocess
import sys
import textwrap
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
JS = (REPO / "assets" / "js" / "mudmaker.js").read_text()

if shutil.which("node") is None:
    sys.exit("node not installed; skipping")

# Extract the two helpers via a tiny harness — we can't load mudmaker.js
# wholesale (it touches the DOM) so we paste only the two function
# definitions into the Node script.  Each helper is self-contained and
# referenced by name below.
def _extract(name):
    needle = "function " + name + "("
    start = JS.index(needle)
    # Walk braces to find the matching closing brace.
    depth = 0
    i = JS.index("{", start)
    while i < len(JS):
        c = JS[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return JS[start:i + 1]
        i += 1
    raise RuntimeError("function not found: " + name)


harness = "\n".join([
    _extract("_aclDirections"),
    _extract("_aceSignature"),
    textwrap.dedent("""
        let raw = '';
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', (c) => { raw += c; });
        process.stdin.on('end', () => {
            const cases = JSON.parse(raw);
            const out = cases.map(function(c) {
                if (c.kind === 'dirs') {
                    return _aclDirections(c.mf);
                }
                if (c.kind === 'sig') {
                    return _aceSignature(c.ace, c.direction);
                }
                throw new Error('unknown kind: ' + c.kind);
            });
            process.stdout.write(JSON.stringify(out));
        });
    """),
])


def run_js(cases):
    result = subprocess.run(
        ["node", "-e", harness],
        input=json.dumps(cases),
        check=False, capture_output=True, text=True,
    )
    if result.returncode != 0:
        print("node stderr:", result.stderr, file=sys.stderr)
        sys.exit(result.returncode)
    return json.loads(result.stdout)


def check(actual, expected, label):
    if actual != expected:
        print(f"FAIL {label}: got {actual!r}, expected {expected!r}")
        sys.exit(1)
    print(f"  ok   {label}")


def test_directions():
    print("aclDirections:")
    mf = {
        "from-device-policy": {"access-lists": {"access-list": [
            {"name": "fripv4-acl1"}, {"name": "fripv6-acl1"}
        ]}},
        "to-device-policy": {"access-lists": {"access-list": [
            {"name": "toipv4-acl1"}, {"name": "toipv6-acl1"}
        ]}},
    }
    out = run_js([{"kind": "dirs", "mf": mf}])[0]
    check(out, {"fripv4-acl1": "from", "fripv6-acl1": "from",
                "toipv4-acl1": "to", "toipv6-acl1": "to"},
          "harvests both policy sides")

    out = run_js([{"kind": "dirs", "mf": {}}])[0]
    check(out, {}, "empty mud -> empty map")

    out = run_js([{"kind": "dirs", "mf": {"from-device-policy": {}}}])[0]
    check(out, {}, "missing access-lists -> empty map")


def _dns_pair():
    fr = {"name": "frace7", "matches": {
        "ipv4": {"protocol": 6, "ietf-acldns:dst-dnsname": "iot.acme.com"},
        "tcp": {"destination-port": {"operator": "eq", "port": 443}}}}
    to = {"name": "toace7", "matches": {
        "ipv4": {"protocol": 6, "ietf-acldns:src-dnsname": "iot.acme.com"},
        "tcp": {"source-port": {"operator": "eq", "port": 443}}}}
    return fr, to


def _net_pair():
    fr = {"name": "frace3", "matches": {
        "ipv4": {"protocol": 17,
                 "destination-ipv4-network": "192.0.2.0/24"},
        "udp": {"destination-port": {"operator": "eq", "port": 53}}}}
    to = {"name": "toace3", "matches": {
        "ipv4": {"protocol": 17,
                 "source-ipv4-network": "192.0.2.0/24"},
        "udp": {"source-port": {"operator": "eq", "port": 53}}}}
    return fr, to


def _mud_pair():
    fr = {"name": "frace1", "matches": {
        "ipv4": {"protocol": 6},
        "ietf-mud:mud": {"my-controller": [None]},
        "tcp": {"destination-port": {"operator": "eq", "port": 2081}}}}
    to = {"name": "toace1", "matches": {
        "ipv4": {"protocol": 6},
        "ietf-mud:mud": {"my-controller": [None]},
        "tcp": {"source-port": {"operator": "eq", "port": 2081}}}}
    return fr, to


def test_signatures():
    print("aceSignature collapses mirror pairs:")
    for label, (fr, to) in [("dns", _dns_pair()),
                            ("net", _net_pair()),
                            ("mud", _mud_pair())]:
        out = run_js([
            {"kind": "sig", "ace": fr, "direction": "from"},
            {"kind": "sig", "ace": to, "direction": "to"},
        ])
        check(out[0], out[1], label + " mirror sigs match")

    print("aceSignature keeps distinct flows distinct:")
    fr_a = _dns_pair()[0]
    fr_b = {"name": "frace8", "matches": {
        "ipv4": {"protocol": 6, "ietf-acldns:dst-dnsname": "other.example"},
        "tcp": {"destination-port": {"operator": "eq", "port": 443}}}}
    sigs = run_js([
        {"kind": "sig", "ace": fr_a, "direction": "from"},
        {"kind": "sig", "ace": fr_b, "direction": "from"},
    ])
    if sigs[0] == sigs[1]:
        print(f"FAIL distinct dns names should differ: {sigs!r}")
        sys.exit(1)
    print("  ok   different DNS names produce different sigs")

    print("aceSignature without direction still collapses port mirror:")
    fr, to = _dns_pair()
    sigs = run_js([
        {"kind": "sig", "ace": fr, "direction": None},
        {"kind": "sig", "ace": to, "direction": None},
    ])
    check(sigs[0], sigs[1], "unknown-direction fallback still pairs")


if __name__ == "__main__":
    test_directions()
    test_signatures()
    print("OK")
