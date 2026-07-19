"""Unit tests for the mudextras (directed-broadcasts,
multicast-across-segments) helpers in assets/js/mudmaker.js.

Runs the JS helpers through Node.js and verifies that:

  * setDirectedBroadcasts / getDirectedBroadcasts / removeDirectedBroadcasts
    round-trip correctly using the RFC 7951 module-qualified key
    (``mud-directed-broadcasts:directed-broadcasts``).
  * setDirectedBroadcasts adds the ``directed-broadcasts`` token to the
    ``extensions`` array, and removeDirectedBroadcasts removes it.
  * setMulticastAcrossSegments toggles the marker token.
  * normalizeDirectedBroadcasts (invoked via normalizeMUDFile) migrates
    the bare ``directed-broadcasts`` key to the module-qualified form,
    matching the example prose in draft-lear-iotops-mudextras.

Run from the repository root::

    python3 tests/test_mudextras_extensions.py
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


def _extract(name):
    needle = "function " + name + "("
    start = JS.index(needle)
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


# The helpers we need + their transitive dependencies from mudmaker.js.
CONSTANTS = "\n".join([
    "var EXT_DIRECTED_BROADCASTS = 'directed-broadcasts';",
    "var EXT_MULTICAST_ACROSS_SEGMENTS = 'multicast-across-segments';",
    "var MUD_DB_KEY = 'mud-directed-broadcasts:directed-broadcasts';",
])

FUNCS = "\n".join([
    _extract("addMudExtension"),
    _extract("removeMudExtension"),
    _extract("getDirectedBroadcasts"),
    _extract("setDirectedBroadcasts"),
    _extract("removeDirectedBroadcasts"),
    _extract("hasMulticastAcrossSegments"),
    _extract("setMulticastAcrossSegments"),
    _extract("normalizeDirectedBroadcasts"),
])

HARNESS = "\n".join([
    CONSTANTS, FUNCS, textwrap.dedent("""
        let raw = '';
        process.stdin.setEncoding('utf8');
        process.stdin.on('data', (c) => { raw += c; });
        process.stdin.on('end', () => {
            const cases = JSON.parse(raw);
            const out = cases.map(function(c) {
                const mf = c.mf;
                switch (c.op) {
                    case 'setDB':
                        setDirectedBroadcasts(mf, c.flags);
                        return mf;
                    case 'getDB':
                        return getDirectedBroadcasts(mf);
                    case 'removeDB':
                        removeDirectedBroadcasts(mf);
                        return mf;
                    case 'setMcast':
                        setMulticastAcrossSegments(mf, c.enabled);
                        return mf;
                    case 'hasMcast':
                        return hasMulticastAcrossSegments(mf);
                    case 'normalizeDB':
                        normalizeDirectedBroadcasts(mf);
                        return mf;
                }
                throw new Error('unknown op: ' + c.op);
            });
            process.stdout.write(JSON.stringify(out));
        });
    """),
])


def run_js(cases):
    result = subprocess.run(
        ["node", "-e", HARNESS],
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


def _empty_mud():
    return {"ietf-mud:mud": {"mud-version": 1}}


def test_set_get_directed_broadcasts():
    print("setDirectedBroadcasts / getDirectedBroadcasts:")
    mf = _empty_mud()
    out = run_js([
        {"op": "setDB", "mf": mf,
         "flags": {"inbound": True, "outbound": True}},
    ])[0]
    mud = out["ietf-mud:mud"]
    check(mud.get("mud-directed-broadcasts:directed-broadcasts"),
          {"inbound": True, "outbound": True},
          "both flags -> container with both booleans (module-qualified key)")
    check(mud.get("extensions"), ["directed-broadcasts"],
          "extensions array contains 'directed-broadcasts'")

    # Round-trip: getDirectedBroadcasts on the produced file.
    got = run_js([{"op": "getDB", "mf": out}])[0]
    check(got, {"inbound": True, "outbound": True},
          "getDirectedBroadcasts returns both flags")

    # Outbound only.
    mf = _empty_mud()
    out = run_js([
        {"op": "setDB", "mf": mf,
         "flags": {"inbound": False, "outbound": True}},
    ])[0]
    check(out["ietf-mud:mud"]
             ["mud-directed-broadcasts:directed-broadcasts"],
          {"outbound": True},
          "outbound-only container omits false inbound leaf")
    got = run_js([{"op": "getDB", "mf": out}])[0]
    check(got, {"inbound": False, "outbound": True},
          "getDirectedBroadcasts reports outbound-only correctly")


def test_both_false_removes_container():
    print("setDirectedBroadcasts(false,false) removes container+extension:")
    mf = _empty_mud()
    out = run_js([
        {"op": "setDB", "mf": mf,
         "flags": {"inbound": True, "outbound": True}},
        {"op": "setDB", "mf": _empty_mud(),  # fresh mud to avoid mutation
         "flags": {"inbound": False, "outbound": False}},
    ])
    step1 = out[0]["ietf-mud:mud"]
    step2 = out[1]["ietf-mud:mud"]
    assert "mud-directed-broadcasts:directed-broadcasts" in step1
    check("mud-directed-broadcasts:directed-broadcasts" in step2, False,
          "container removed when both flags false")
    check(step2.get("extensions"), None,
          "extensions dropped when empty")


def test_remove_directed_broadcasts():
    print("removeDirectedBroadcasts:")
    mf = {
        "ietf-mud:mud": {
            "mud-version": 1,
            "extensions": ["directed-broadcasts", "multicast-across-segments"],
            "mud-directed-broadcasts:directed-broadcasts": {
                "inbound": True, "outbound": True,
            },
        }
    }
    out = run_js([{"op": "removeDB", "mf": mf}])[0]
    mud = out["ietf-mud:mud"]
    check("mud-directed-broadcasts:directed-broadcasts" in mud, False,
          "container gone")
    check("directed-broadcasts" in (mud.get("extensions") or []), False,
          "'directed-broadcasts' removed from extensions")
    check("multicast-across-segments" in (mud.get("extensions") or []), True,
          "unrelated 'multicast-across-segments' preserved")


def test_multicast_marker():
    print("setMulticastAcrossSegments / hasMulticastAcrossSegments:")
    mf = _empty_mud()
    out = run_js([{"op": "setMcast", "mf": mf, "enabled": True}])[0]
    check(out["ietf-mud:mud"].get("extensions"),
          ["multicast-across-segments"],
          "enabling adds marker token to extensions")
    got = run_js([{"op": "hasMcast", "mf": out}])[0]
    check(got, True, "hasMulticastAcrossSegments reports true after enable")

    out2 = run_js([{"op": "setMcast", "mf": out, "enabled": False}])[0]
    check(out2["ietf-mud:mud"].get("extensions"), None,
          "disabling removes marker (and drops empty extensions array)")
    got = run_js([{"op": "hasMcast", "mf": out2}])[0]
    check(got, False, "hasMulticastAcrossSegments reports false after disable")


def test_normalize_legacy_bare_key():
    print("normalizeDirectedBroadcasts migrates bare key:")
    mf = {
        "ietf-mud:mud": {
            "mud-version": 1,
            "extensions": ["directed-broadcasts"],
            # Bare key as spelled in the draft's example prose.
            "directed-broadcasts": {"inbound": True, "outbound": True},
        }
    }
    out = run_js([{"op": "normalizeDB", "mf": mf}])[0]
    mud = out["ietf-mud:mud"]
    check(mud.get("mud-directed-broadcasts:directed-broadcasts"),
          {"inbound": True, "outbound": True},
          "container moved to module-qualified key")
    check("directed-broadcasts" in mud, False,
          "bare key removed")
    check(mud.get("extensions"), ["directed-broadcasts"],
          "extensions token unchanged")

    # Idempotent: running normalize again on the already-qualified file
    # leaves the container in place.
    out2 = run_js([{"op": "normalizeDB", "mf": out}])[0]
    check(out2["ietf-mud:mud"]
             ["mud-directed-broadcasts:directed-broadcasts"],
          {"inbound": True, "outbound": True},
          "normalize is idempotent")


if __name__ == "__main__":
    test_set_get_directed_broadcasts()
    test_both_false_removes_container()
    test_remove_directed_broadcasts()
    test_multicast_marker()
    test_normalize_legacy_bare_key()
    print("OK")
